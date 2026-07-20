//! Command-line operations for iroh-db.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use iroh_db::{
    AuthorId, BackupOptions, IrohDb, backup_closed, restore_backup, restore_backup_from,
};

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
        "inspect" => {
            let path = required_path(arguments.next(), "database path")?;
            reject_extra(arguments)?;
            let database = IrohDb::open(path).await?;
            let metrics = database.operational_metrics()?;
            println!(
                "author={} domain={} commits={} frontier={} records={} domains={} snapshot_age_seconds={}",
                database.author_id(),
                database.domain_id(),
                metrics.accepted_commits(),
                metrics.frontier_size(),
                metrics.materialized_records(),
                metrics.local_domains(),
                metrics
                    .snapshot_age()
                    .map_or_else(|| "none".into(), |age| age.as_secs().to_string())
            );
            database.close().await?;
        }
        "verify" => {
            let path = required_path(arguments.next(), "database path")?;
            reject_extra(arguments)?;
            let database = IrohDb::open(path).await?;
            let report = database.verify().await?;
            println!(
                "commits={} orphans={} typed_rebuild={} derived_consistent={} state_root={}",
                report.commits(),
                report.orphan_commits(),
                report.typed_rebuild_performed(),
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
            println!(
                "typed_rebuild={} derived_consistent={} state_root={}",
                report.typed_rebuild_performed(),
                report.derived_consistent(),
                hex(&report.state_root())
            );
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
            println!(
                "files={} bytes={} signer={}",
                report.files(),
                report.bytes(),
                report.signer()
            );
        }
        "restore" => {
            let source = required_path(arguments.next(), "backup path")?;
            let destination = required_path(arguments.next(), "restore destination")?;
            let expected_signer = match arguments.next() {
                Some(value) if value == "--expect-signer" => {
                    Some(required_author(arguments.next(), "expected backup signer")?)
                }
                Some(_) => return Err(format!("unexpected argument\n{}", usage()).into()),
                None => None,
            };
            reject_extra(arguments)?;
            let report = if let Some(expected_signer) = expected_signer {
                restore_backup_from(source, destination, expected_signer)?
            } else {
                restore_backup(source, destination)?
            };
            println!(
                "files={} bytes={} signer={}",
                report.files(),
                report.bytes(),
                report.signer()
            );
        }
        _ => return Err(usage().into()),
    }
    Ok(())
}

fn required_author(
    value: Option<std::ffi::OsString>,
    name: &str,
) -> Result<AuthorId, Box<dyn std::error::Error>> {
    value
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| format!("missing {name}\n{}", usage()).into())
        .and_then(|value| value.parse().map_err(Into::into))
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
    "usage: iroh-db-cli inspect <db> | verify <db> | repair-indexes <db> | backup <db> <backup> [--include-keys] | restore <backup> <db> [--expect-signer <author-id>]"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_exact_backup_signer() {
        let encoded = "07".repeat(32);
        let parsed = required_author(Some(encoded.into()), "signer").unwrap();
        assert_eq!(parsed, AuthorId::from_bytes([7; 32]));
    }

    #[test]
    fn rejects_a_malformed_backup_signer() {
        assert!(required_author(Some("not-an-id".into()), "signer").is_err());
    }
}
