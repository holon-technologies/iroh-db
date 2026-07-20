use std::{
    fmt::Write as _,
    fs::OpenOptions,
    path::{Component, Path, PathBuf},
};

use fs2::FileExt as _;
use iroh_db_security::open_commit;

use crate::{DbError, IrohDb};

const BACKUP_FORMAT: &str = "iroh-db-backup 1\n";
const MANIFEST_FILE: &str = "BACKUP-MANIFEST.v1";

/// Controls whether a closed-directory backup includes the separately encrypted local key vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BackupOptions {
    pub include_keys: bool,
}

/// Summary of a verified filesystem backup or restore.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupReport {
    files: usize,
    bytes: u64,
}

impl BackupReport {
    pub const fn files(self) -> usize {
        self.files
    }

    pub const fn bytes(self) -> u64 {
        self.bytes
    }
}

/// Evidence from immutable-object and derived-state verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    commits: usize,
    orphan_commits: usize,
    derived_consistent: bool,
    state_root: [u8; 32],
}

/// Low-cardinality operational counters that never contain record or capability values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationalMetrics {
    accepted_commits: usize,
    frontier_size: usize,
    materialized_records: usize,
    local_domains: usize,
    active_migrations: usize,
    staged_migration_records: usize,
    frozen_migrations: usize,
}

impl OperationalMetrics {
    pub const fn accepted_commits(self) -> usize {
        self.accepted_commits
    }

    pub const fn frontier_size(self) -> usize {
        self.frontier_size
    }

    pub const fn materialized_records(self) -> usize {
        self.materialized_records
    }

    pub const fn local_domains(self) -> usize {
        self.local_domains
    }

    pub const fn active_migrations(self) -> usize {
        self.active_migrations
    }

    pub const fn staged_migration_records(self) -> usize {
        self.staged_migration_records
    }

    pub const fn frozen_migrations(self) -> usize {
        self.frozen_migrations
    }
}

impl VerificationReport {
    pub const fn commits(&self) -> usize {
        self.commits
    }

    pub const fn orphan_commits(&self) -> usize {
        self.orphan_commits
    }

    pub const fn derived_consistent(&self) -> bool {
        self.derived_consistent
    }

    pub const fn state_root(&self) -> [u8; 32] {
        self.state_root
    }
}

impl IrohDb {
    /// Returns a low-cardinality operational snapshot safe for metrics exporters.
    pub fn operational_metrics(&self) -> Result<OperationalMetrics, DbError> {
        let (active_migrations, staged_migration_records, frozen_migrations) =
            self.inner.store.migration_counts(self.domain_id())?;
        Ok(OperationalMetrics {
            accepted_commits: self
                .inner
                .store
                .list_stored_commit_ids(self.domain_id())?
                .len(),
            frontier_size: self.inner.store.frontier(self.domain_id())?.len(),
            materialized_records: self
                .inner
                .store
                .export_materialized(self.domain_id())?
                .len(),
            local_domains: self.domains()?.len(),
            active_migrations,
            staged_migration_records,
            frozen_migrations,
        })
    }

    /// Verifies content hashes, signatures, encryption, dependency presence, and rebuild equality.
    pub async fn verify(&self) -> Result<VerificationReport, DbError> {
        let _control_reader = self.inner.control_gate.read().await;
        let _writer = self.inner.writer.lock().await;
        self.verify_unlocked().await
    }

    async fn verify_unlocked(&self) -> Result<VerificationReport, DbError> {
        if !self
            .inner
            .store
            .authority_checkpoint_consistent(self.domain_id())?
        {
            return Err(DbError::Operation(
                "authority checkpoint evidence is incomplete".into(),
            ));
        }
        if !self
            .inner
            .store
            .subject_revocations_consistent(self.domain_id())?
        {
            return Err(DbError::Operation(
                "subject revocation index differs from signed control".into(),
            ));
        }
        let commit_ids = self.inner.store.list_stored_commit_ids(self.domain_id())?;
        for commit_id in &commit_ids {
            let envelope = self.inner.store.load_commit(*commit_id).await?;
            if envelope.header().domain_id() != self.domain_id() {
                return Err(DbError::Operation("commit domain mismatch".into()));
            }
            let key = self
                .inner
                .credentials
                .load_domain_epoch(self.domain_id(), envelope.header().epoch())?
                .domain_key();
            open_commit(&envelope, &key)?;
            for dependency in envelope.header().dependencies() {
                if !self
                    .inner
                    .store
                    .contains_commit(self.domain_id(), *dependency)?
                {
                    return Err(DbError::Operation(format!(
                        "commit dependency is absent: {dependency}"
                    )));
                }
            }
        }
        let orphans = self.inner.store.scan_commit_orphans().await?;
        let current = canonical_records(self.inner.store.export_materialized(self.domain_id())?)?;
        let derived_consistent = canonical_records(self.rebuild_mutations().await?)? == current;
        Ok(VerificationReport {
            commits: commit_ids.len(),
            orphan_commits: orphans.len(),
            derived_consistent,
            state_root: self.state_root()?,
        })
    }

    /// Rebuilds typed materialized state in memory and swaps it in one metadata transaction.
    pub async fn repair(&self) -> Result<VerificationReport, DbError> {
        let _control_reader = self.inner.control_gate.read().await;
        let _writer = self.inner.writer.lock().await;
        let rebuilt = self.rebuild_mutations().await?;
        self.inner
            .store
            .repair_subject_revocations(self.domain_id())?;
        self.inner
            .store
            .replace_materialized(self.domain_id(), &rebuilt)?;
        self.verify_unlocked().await
    }

    /// Rewrites existing materialized/index tables atomically when application record types are absent.
    pub async fn repair_indexes(&self) -> Result<VerificationReport, DbError> {
        let _control_reader = self.inner.control_gate.read().await;
        let _writer = self.inner.writer.lock().await;
        let exported = self.inner.store.export_materialized(self.domain_id())?;
        self.inner
            .store
            .repair_subject_revocations(self.domain_id())?;
        self.inner
            .store
            .replace_materialized(self.domain_id(), &exported)?;
        self.verify_unlocked().await
    }
}

/// Creates a checksummed backup from a database directory that is not currently open.
pub fn backup_closed(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    options: BackupOptions,
) -> Result<BackupReport, DbError> {
    let source = source.as_ref();
    let destination = destination.as_ref();
    if !source.join("FORMAT").is_file() || destination.exists() {
        return Err(operation_error(
            "source is not a database or destination exists",
        ));
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(source.join("locks/writer.lock"))
        .map_err(io_operation)?;
    lock.try_lock_exclusive()
        .map_err(|_| operation_error("database must be closed before backup"))?;
    std::fs::create_dir(destination).map_err(io_operation)?;
    let mut files = Vec::new();
    collect_files(source, source, options, &mut files)?;
    files.sort();
    let mut manifest = String::from(BACKUP_FORMAT);
    let mut total = 0_u64;
    for relative in &files {
        let bytes = std::fs::read(source.join(relative)).map_err(io_operation)?;
        let target = destination.join(relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(io_operation)?;
        }
        std::fs::write(&target, &bytes).map_err(io_operation)?;
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| operation_error("backup byte count overflow"))?;
        writeln!(
            manifest,
            "{}\t{}\t{}",
            blake3::hash(&bytes).to_hex(),
            bytes.len(),
            relative.to_string_lossy()
        )
        .map_err(|_| operation_error("backup manifest formatting failed"))?;
    }
    std::fs::write(destination.join(MANIFEST_FILE), manifest).map_err(io_operation)?;
    drop(lock);
    Ok(BackupReport {
        files: files.len(),
        bytes: total,
    })
}

/// Verifies every backup file before copying into a new, non-existent restore directory.
pub fn restore_backup(
    backup: impl AsRef<Path>,
    destination: impl AsRef<Path>,
) -> Result<BackupReport, DbError> {
    let backup = backup.as_ref();
    let destination = destination.as_ref();
    if destination.exists() {
        return Err(operation_error("restore destination already exists"));
    }
    let manifest = std::fs::read_to_string(backup.join(MANIFEST_FILE)).map_err(io_operation)?;
    let mut lines = manifest.lines();
    if lines.next() != Some(BACKUP_FORMAT.trim_end()) {
        return Err(operation_error("unsupported backup format"));
    }
    let mut verified = Vec::new();
    let mut total = 0_u64;
    for line in lines {
        let mut fields = line.splitn(3, '\t');
        let hash = fields
            .next()
            .ok_or_else(|| operation_error("invalid manifest"))?;
        let size: usize = fields
            .next()
            .ok_or_else(|| operation_error("invalid manifest"))?
            .parse()
            .map_err(|_| operation_error("invalid manifest size"))?;
        let relative = PathBuf::from(
            fields
                .next()
                .ok_or_else(|| operation_error("invalid manifest"))?,
        );
        validate_relative(&relative)?;
        let bytes = std::fs::read(backup.join(&relative)).map_err(io_operation)?;
        if bytes.len() != size || blake3::hash(&bytes).to_hex().as_str() != hash {
            return Err(operation_error("backup checksum mismatch"));
        }
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| operation_error("restore byte count overflow"))?;
        verified.push((relative, bytes));
    }
    std::fs::create_dir(destination).map_err(io_operation)?;
    for (relative, bytes) in &verified {
        let target = destination.join(relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(io_operation)?;
        }
        std::fs::write(&target, bytes).map_err(io_operation)?;
        set_restored_permissions(relative, &target)?;
    }
    Ok(BackupReport {
        files: verified.len(),
        bytes: total,
    })
}

#[cfg(unix)]
fn set_restored_permissions(relative: &Path, target: &Path) -> Result<(), DbError> {
    use std::os::unix::fs::PermissionsExt as _;

    if relative.starts_with("keys") {
        std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o600))
            .map_err(io_operation)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_restored_permissions(_relative: &Path, _target: &Path) -> Result<(), DbError> {
    Ok(())
}

fn canonical_records(
    records: Vec<iroh_db_store::MaterializedRecord>,
) -> Result<Vec<Vec<u8>>, DbError> {
    let mut records = records
        .into_iter()
        .map(|record| record.encode_canonical().map_err(DbError::from))
        .collect::<Result<Vec<_>, _>>()?;
    records.sort();
    Ok(records)
}

fn collect_files(
    root: &Path,
    directory: &Path,
    options: BackupOptions,
    files: &mut Vec<PathBuf>,
) -> Result<(), DbError> {
    for entry in std::fs::read_dir(directory).map_err(io_operation)? {
        let entry = entry.map_err(io_operation)?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| operation_error("backup path escaped source"))?;
        if relative.starts_with("tmp")
            || relative == Path::new("locks/writer.lock")
            || (!options.include_keys && relative.starts_with("keys"))
        {
            continue;
        }
        let file_type = entry.file_type().map_err(io_operation)?;
        if file_type.is_symlink() {
            return Err(operation_error("backup refuses symbolic links"));
        }
        if file_type.is_dir() {
            collect_files(root, &path, options, files)?;
        } else if file_type.is_file() {
            files.push(relative.to_path_buf());
        }
    }
    Ok(())
}

fn validate_relative(path: &Path) -> Result<(), DbError> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(operation_error("backup contains an unsafe path"));
    }
    Ok(())
}

fn operation_error(message: &str) -> DbError {
    DbError::Operation(message.into())
}

#[allow(clippy::needless_pass_by_value)]
fn io_operation(error: std::io::Error) -> DbError {
    DbError::Operation(error.to_string())
}
