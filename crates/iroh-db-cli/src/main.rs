//! Command-line operations for iroh-db.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use iroh_db::{BackupOptions, IrohDb, backup_closed, restore_backup};

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("iroh-db: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let Some(command) = arguments.next().and_then(|value| value.into_string().ok()) else {
        return Err(usage().into());
    };
    match command.as_str() {
        "verify" => {
            let path = required_path(arguments.next(), "database path")?;
            reject_extra(arguments)?;
            let database = IrohDb::open(path).await?;
            let report = database.verify().await?;
            println!(
                "commits={} orphans={} derived_consistent={} state_root={}",
                report.commits(),
                report.orphan_commits(),
                report.derived_consistent(),
                hex(&report.state_root())
            );
            database.close().await?;
        }
        "repair-indexes" => {
            let path = required_path(arguments.next(), "database path")?;
            reject_extra(arguments)?;
            let database = IrohDb::open(path).await?;
            let report = database.repair_indexes().await?;
            println!("state_root={}", hex(&report.state_root()));
            database.close().await?;
        }
        "backup" => {
            let source = required_path(arguments.next(), "source database path")?;
            let destination = required_path(arguments.next(), "backup destination")?;
            let include_keys = match arguments.next() {
                Some(value) if value == "--include-keys" => true,
                Some(_) => return Err(format!("unexpected argument\n{}", usage()).into()),
                None => false,
            };
            reject_extra(arguments)?;
            let report = backup_closed(source, destination, BackupOptions { include_keys })?;
            println!("files={} bytes={}", report.files(), report.bytes());
        }
        "restore" => {
            let source = required_path(arguments.next(), "backup path")?;
            let destination = required_path(arguments.next(), "restore destination")?;
            reject_extra(arguments)?;
            let report = restore_backup(source, destination)?;
            println!("files={} bytes={}", report.files(), report.bytes());
        }
        _ => return Err(usage().into()),
    }
    Ok(())
}

fn required_path(
    value: Option<std::ffi::OsString>,
    name: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    value
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing {name}\n{}", usage()).into())
}

fn reject_extra(mut arguments: impl Iterator<Item = std::ffi::OsString>) -> Result<(), String> {
    if arguments.next().is_some() {
        Err(format!("unexpected arguments\n{}", usage()))
    } else {
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    output
}

fn usage() -> &'static str {
    "usage: iroh-db-cli verify <db> | repair-indexes <db> | backup <db> <backup> [--include-keys] | restore <backup> <db>"
}
