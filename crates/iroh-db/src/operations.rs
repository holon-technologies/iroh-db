use std::{
    fs::OpenOptions,
    io::{Read as _, Write as _},
    path::{Component, Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use fs2::FileExt as _;
use iroh_db_core::AuthorId;
use iroh_db_security::{LocalCredentials, open_commit, verify_backup_signature};

use crate::{DbError, IrohDb, LatencyMetrics};

const BACKUP_FORMAT_VERSION: u16 = 2;
const CATALOG_FILE: &str = "BACKUP-CATALOG.v2";
const MAX_CATALOG_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CATALOG_ENTRIES: usize = 1_000_000;
const COPY_BUFFER_BYTES: usize = 64 * 1024;

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
    signer: AuthorId,
}

impl BackupReport {
    pub const fn files(self) -> usize {
        self.files
    }

    pub const fn bytes(self) -> u64 {
        self.bytes
    }

    /// Device identity that authenticated the canonical backup catalog.
    pub const fn signer(self) -> AuthorId {
        self.signer
    }
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
struct BackupCatalogContent {
    #[n(0)]
    version: u16,
    #[n(1)]
    entries: Vec<BackupCatalogEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
struct BackupCatalogEntry {
    #[n(0)]
    hash: [u8; 32],
    #[n(1)]
    size: u64,
    #[n(2)]
    path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
struct SignedBackupCatalog {
    #[n(0)]
    content: Vec<u8>,
    #[n(1)]
    signer: AuthorId,
    #[n(2)]
    signature: [u8; 64],
}

/// Evidence from immutable-object and derived-state verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    commits: usize,
    orphan_commits: usize,
    typed_rebuild_performed: bool,
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
    local_apply_latency: LatencyMetrics,
    query_latency: LatencyMetrics,
    index_records_scanned: u64,
    equivocation_quarantines: u64,
    schema_rebases: u64,
    sync_rounds: u64,
    sync_failures: u64,
    sync_commits_received: u64,
    sync_commits_sent: u64,
    snapshots_created: u64,
    snapshots_installed: u64,
    snapshot_age: Option<Duration>,
    repairs_succeeded: u64,
    repairs_failed: u64,
    last_repair_derived_consistent: Option<bool>,
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

    pub const fn local_apply_latency(self) -> LatencyMetrics {
        self.local_apply_latency
    }

    pub const fn query_latency(self) -> LatencyMetrics {
        self.query_latency
    }

    pub const fn index_records_scanned(self) -> u64 {
        self.index_records_scanned
    }

    pub const fn equivocation_quarantines(self) -> u64 {
        self.equivocation_quarantines
    }

    pub const fn schema_rebases(self) -> u64 {
        self.schema_rebases
    }

    pub const fn sync_rounds(self) -> u64 {
        self.sync_rounds
    }

    pub const fn sync_failures(self) -> u64 {
        self.sync_failures
    }

    pub const fn sync_commits_received(self) -> u64 {
        self.sync_commits_received
    }

    pub const fn sync_commits_sent(self) -> u64 {
        self.sync_commits_sent
    }

    pub const fn snapshots_created(self) -> u64 {
        self.snapshots_created
    }

    pub const fn snapshots_installed(self) -> u64 {
        self.snapshots_installed
    }

    pub const fn snapshot_age(self) -> Option<Duration> {
        self.snapshot_age
    }

    pub const fn repairs_succeeded(self) -> u64 {
        self.repairs_succeeded
    }

    pub const fn repairs_failed(self) -> u64 {
        self.repairs_failed
    }

    pub const fn last_repair_derived_consistent(self) -> Option<bool> {
        self.last_repair_derived_consistent
    }
}

impl VerificationReport {
    pub const fn commits(&self) -> usize {
        self.commits
    }

    pub const fn orphan_commits(&self) -> usize {
        self.orphan_commits
    }

    /// Returns whether registered Rust record adapters were sufficient for a full replay.
    pub const fn typed_rebuild_performed(&self) -> bool {
        self.typed_rebuild_performed
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
        let runtime = self.inner.telemetry.snapshot();
        let (active_migrations, staged_migration_records, frozen_migrations) =
            self.inner.store.migration_counts(self.domain_id())?;
        let snapshot_age = self
            .inner
            .store
            .snapshot_observed_at(self.domain_id())?
            .map(|observed| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    .saturating_sub(observed)
            })
            .map(Duration::from_secs);
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
            local_apply_latency: runtime.local_apply,
            query_latency: runtime.query,
            index_records_scanned: runtime.index_records_scanned,
            equivocation_quarantines: runtime.equivocation_quarantines,
            schema_rebases: runtime.schema_rebases,
            sync_rounds: runtime.sync_rounds,
            sync_failures: runtime.sync_failures,
            sync_commits_received: runtime.sync_received,
            sync_commits_sent: runtime.sync_sent,
            snapshots_created: runtime.snapshots_created,
            snapshots_installed: runtime.snapshots_installed,
            snapshot_age,
            repairs_succeeded: runtime.repairs_succeeded,
            repairs_failed: runtime.repairs_failed,
            last_repair_derived_consistent: runtime.last_repair_derived_consistent,
        })
    }

    /// Verifies content hashes, signatures, encryption, dependency presence, and rebuild equality.
    #[tracing::instrument(name = "iroh_db.verify", skip_all)]
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
        let adapters_available = self.inner.has_record_adapters();
        let no_replay_input = commit_ids.is_empty()
            && self
                .inner
                .store
                .snapshot_baseline(self.domain_id())?
                .is_none();
        let typed_rebuild_performed = adapters_available || no_replay_input;
        let derived_consistent = if typed_rebuild_performed {
            canonical_records(self.rebuild_mutations().await?)? == current
        } else {
            false
        };
        Ok(VerificationReport {
            commits: commit_ids.len(),
            orphan_commits: orphans.len(),
            typed_rebuild_performed,
            derived_consistent,
            state_root: self.state_root()?,
        })
    }

    /// Rebuilds typed materialized state in memory and swaps it in one metadata transaction.
    #[tracing::instrument(name = "iroh_db.repair", skip_all)]
    pub async fn repair(&self) -> Result<VerificationReport, DbError> {
        let result = self.repair_inner().await;
        self.inner.telemetry.record_repair(
            result
                .as_ref()
                .ok()
                .map(VerificationReport::derived_consistent),
        );
        result
    }

    async fn repair_inner(&self) -> Result<VerificationReport, DbError> {
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
    #[tracing::instrument(name = "iroh_db.repair_indexes", skip_all)]
    pub async fn repair_indexes(&self) -> Result<VerificationReport, DbError> {
        let result = self.repair_indexes_inner().await;
        self.inner.telemetry.record_repair(
            result
                .as_ref()
                .ok()
                .map(VerificationReport::derived_consistent),
        );
        result
    }

    async fn repair_indexes_inner(&self) -> Result<VerificationReport, DbError> {
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

/// Creates an authenticated backup from a closed database using its default file key provider.
#[tracing::instrument(name = "iroh_db.backup", skip_all)]
pub fn backup_closed(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    options: BackupOptions,
) -> Result<BackupReport, DbError> {
    let source = source.as_ref();
    let signer = LocalCredentials::load(source.join("keys"))?.signer();
    backup_closed_with_signer(source, destination, options, &signer)
}

/// Creates a closed-store backup authenticated by an application-managed key provider.
#[tracing::instrument(name = "iroh_db.backup", skip_all)]
pub fn backup_closed_with_signer(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    options: BackupOptions,
    signer: &iroh_db_security::IrohSigner,
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
    let mut files = Vec::new();
    collect_files(source, source, options, &mut files)?;
    files.sort();
    if files.len() > MAX_CATALOG_ENTRIES {
        return Err(operation_error("backup contains too many files"));
    }
    let staging = create_staging_directory(destination, "backup")?;
    let result = build_backup(source, &staging, &files, signer);
    let report = match result {
        Ok(report) => {
            publish_staging_directory(&staging, destination)?;
            report
        }
        Err(error) => {
            discard_staging_directory(&staging);
            return Err(error);
        }
    };
    drop(lock);
    Ok(report)
}

fn build_backup(
    source: &Path,
    staging: &Path,
    files: &[PathBuf],
    signer: &iroh_db_security::IrohSigner,
) -> Result<BackupReport, DbError> {
    let mut entries = Vec::with_capacity(files.len());
    let mut total = 0_u64;
    for relative in files {
        let target = staging.join(relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(io_operation)?;
        }
        let (hash, size) = copy_and_hash(&source.join(relative), &target)?;
        total = total
            .checked_add(size)
            .ok_or_else(|| operation_error("backup byte count overflow"))?;
        entries.push(BackupCatalogEntry {
            hash,
            size,
            path: canonical_relative(relative)?,
        });
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let content = BackupCatalogContent {
        version: BACKUP_FORMAT_VERSION,
        entries,
    };
    let content = minicbor::to_vec(content).map_err(backup_codec)?;
    if u64::try_from(content.len()).unwrap_or(u64::MAX) > MAX_CATALOG_BYTES {
        return Err(operation_error("backup catalog is too large"));
    }
    let catalog = SignedBackupCatalog {
        signature: signer.sign_backup_catalog(&content),
        signer: signer.author(),
        content,
    };
    let catalog = minicbor::to_vec(catalog).map_err(backup_codec)?;
    write_new_file(&staging.join(CATALOG_FILE), &catalog)?;
    Ok(BackupReport {
        files: files.len(),
        bytes: total,
        signer: signer.author(),
    })
}

/// Verifies the embedded self-signature and every file before publishing a restore directory.
///
/// Use [`restore_backup_from`] when the source device identity is part of the
/// trust decision; an unpinned self-signature proves integrity, not provenance.
#[tracing::instrument(name = "iroh_db.restore", skip_all)]
pub fn restore_backup(
    backup: impl AsRef<Path>,
    destination: impl AsRef<Path>,
) -> Result<BackupReport, DbError> {
    restore_backup_impl(backup.as_ref(), destination.as_ref(), None)
}

/// Restores only when the authenticated catalog signer matches the expected device.
#[tracing::instrument(name = "iroh_db.restore", skip_all)]
pub fn restore_backup_from(
    backup: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    expected_signer: AuthorId,
) -> Result<BackupReport, DbError> {
    restore_backup_impl(backup.as_ref(), destination.as_ref(), Some(expected_signer))
}

fn restore_backup_impl(
    backup: &Path,
    destination: &Path,
    expected_signer: Option<AuthorId>,
) -> Result<BackupReport, DbError> {
    if destination.exists() {
        return Err(operation_error("restore destination already exists"));
    }
    require_directory_without_symlink(backup)?;
    let catalog_bytes =
        read_bounded_regular_file(backup, Path::new(CATALOG_FILE), MAX_CATALOG_BYTES)?;
    let catalog: SignedBackupCatalog = decode_backup_canonical(&catalog_bytes)?;
    verify_backup_signature(catalog.signer, &catalog.content, &catalog.signature)?;
    if expected_signer.is_some_and(|expected| expected != catalog.signer) {
        return Err(operation_error(
            "backup signer does not match the expected device",
        ));
    }
    let content: BackupCatalogContent = decode_backup_canonical(&catalog.content)?;
    validate_catalog(&content)?;
    let mut total = 0_u64;
    for entry in &content.entries {
        let relative = Path::new(&entry.path);
        let (hash, size) = hash_backup_file(backup, relative)?;
        if size != entry.size || hash != entry.hash {
            return Err(operation_error("backup checksum mismatch"));
        }
        total = total
            .checked_add(size)
            .ok_or_else(|| operation_error("restore byte count overflow"))?;
    }
    let staging = create_staging_directory(destination, "restore")?;
    let result = restore_into_staging(backup, &staging, &content.entries);
    if let Err(error) = result {
        discard_staging_directory(&staging);
        return Err(error);
    }
    publish_staging_directory(&staging, destination)?;
    Ok(BackupReport {
        files: content.entries.len(),
        bytes: total,
        signer: catalog.signer,
    })
}

fn restore_into_staging(
    backup: &Path,
    staging: &Path,
    entries: &[BackupCatalogEntry],
) -> Result<(), DbError> {
    for entry in entries {
        let relative = Path::new(&entry.path);
        let target = staging.join(relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(io_operation)?;
        }
        let (hash, size) = copy_backup_file(backup, relative, &target)?;
        if size != entry.size || hash != entry.hash {
            return Err(operation_error("backup changed during restore"));
        }
        set_restored_permissions(relative, &target)?;
    }
    Ok(())
}

fn create_staging_directory(destination: &Path, purpose: &str) -> Result<PathBuf, DbError> {
    let parent = destination_parent(destination);
    if !parent.is_dir() {
        return Err(operation_error("destination parent is not a directory"));
    }
    let name = destination
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| operation_error("destination name must be valid UTF-8"))?;
    for _ in 0..16 {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|_| DbError::RandomnessUnavailable)?;
        let candidate = parent.join(format!(
            ".{name}.iroh-db-{purpose}-{}",
            blake3::hash(&random).to_hex()
        ));
        match std::fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(io_operation(error)),
        }
    }
    Err(operation_error("could not allocate a staging directory"))
}

fn publish_staging_directory(staging: &Path, destination: &Path) -> Result<(), DbError> {
    if destination.exists() {
        discard_staging_directory(staging);
        return Err(operation_error("destination appeared during publication"));
    }
    sync_tree_directories(staging)?;
    if let Err(error) = std::fs::rename(staging, destination) {
        discard_staging_directory(staging);
        return Err(io_operation(error));
    }
    sync_directory(destination_parent(destination))
}

fn destination_parent(destination: &Path) -> &Path {
    destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn sync_tree_directories(root: &Path) -> Result<(), DbError> {
    let mut directories = vec![root.to_path_buf()];
    collect_directories(root, &mut directories)?;
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        sync_directory(&directory)?;
    }
    Ok(())
}

fn collect_directories(directory: &Path, directories: &mut Vec<PathBuf>) -> Result<(), DbError> {
    for entry in std::fs::read_dir(directory).map_err(io_operation)? {
        let entry = entry.map_err(io_operation)?;
        if entry.file_type().map_err(io_operation)?.is_dir() {
            let path = entry.path();
            directories.push(path.clone());
            collect_directories(&path, directories)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<(), DbError> {
    std::fs::File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(io_operation)
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> Result<(), DbError> {
    Ok(())
}

fn discard_staging_directory(staging: &Path) {
    let _ignored = std::fs::remove_dir_all(staging);
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), DbError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(io_operation)?;
    file.write_all(bytes).map_err(io_operation)?;
    file.sync_all().map_err(io_operation)
}

fn copy_and_hash(source: &Path, target: &Path) -> Result<([u8; 32], u64), DbError> {
    let metadata = std::fs::symlink_metadata(source).map_err(io_operation)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(operation_error("backup source changed during collection"));
    }
    let mut reader = std::fs::File::open(source).map_err(io_operation)?;
    let mut writer = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)
        .map_err(io_operation)?;
    let result = copy_reader_and_hash(&mut reader, &mut writer)?;
    writer.sync_all().map_err(io_operation)?;
    Ok(result)
}

fn copy_backup_file(
    backup: &Path,
    relative: &Path,
    target: &Path,
) -> Result<([u8; 32], u64), DbError> {
    let mut reader = open_backup_file(backup, relative)?;
    let mut writer = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)
        .map_err(io_operation)?;
    let result = copy_reader_and_hash(&mut reader, &mut writer)?;
    writer.sync_all().map_err(io_operation)?;
    Ok(result)
}

fn copy_reader_and_hash(
    reader: &mut std::fs::File,
    writer: &mut std::fs::File,
) -> Result<([u8; 32], u64), DbError> {
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut hasher = blake3::Hasher::new();
    let mut size = 0_u64;
    loop {
        let read = reader.read(&mut buffer).map_err(io_operation)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        writer.write_all(&buffer[..read]).map_err(io_operation)?;
        size = size
            .checked_add(u64::try_from(read).unwrap_or(u64::MAX))
            .ok_or_else(|| operation_error("backup byte count overflow"))?;
    }
    Ok((*hasher.finalize().as_bytes(), size))
}

fn hash_backup_file(backup: &Path, relative: &Path) -> Result<([u8; 32], u64), DbError> {
    let mut reader = open_backup_file(backup, relative)?;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut hasher = blake3::Hasher::new();
    let mut size = 0_u64;
    loop {
        let read = reader.read(&mut buffer).map_err(io_operation)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        size = size
            .checked_add(u64::try_from(read).unwrap_or(u64::MAX))
            .ok_or_else(|| operation_error("restore byte count overflow"))?;
    }
    Ok((*hasher.finalize().as_bytes(), size))
}

fn open_backup_file(backup: &Path, relative: &Path) -> Result<std::fs::File, DbError> {
    validate_relative(relative)?;
    let components: Vec<_> = relative.components().collect();
    let mut current = backup.to_path_buf();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(component) = component else {
            return Err(operation_error("backup contains an unsafe path"));
        };
        current.push(component);
        let metadata = std::fs::symlink_metadata(&current).map_err(io_operation)?;
        if metadata.file_type().is_symlink()
            || (index + 1 < components.len() && !metadata.is_dir())
            || (index + 1 == components.len() && !metadata.is_file())
        {
            return Err(operation_error("backup contains a non-regular path"));
        }
    }
    std::fs::File::open(current).map_err(io_operation)
}

fn read_bounded_regular_file(
    root: &Path,
    relative: &Path,
    maximum: u64,
) -> Result<Vec<u8>, DbError> {
    let mut file = open_backup_file(root, relative)?;
    let length = file.metadata().map_err(io_operation)?.len();
    if length > maximum {
        return Err(operation_error("backup catalog is too large"));
    }
    let capacity = usize::try_from(length)
        .map_err(|_| operation_error("backup catalog exceeds platform limits"))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes).map_err(io_operation)?;
    Ok(bytes)
}

fn require_directory_without_symlink(path: &Path) -> Result<(), DbError> {
    let metadata = std::fs::symlink_metadata(path).map_err(io_operation)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(operation_error("backup root must be a regular directory"));
    }
    Ok(())
}

fn validate_catalog(content: &BackupCatalogContent) -> Result<(), DbError> {
    if content.version != BACKUP_FORMAT_VERSION {
        return Err(operation_error("unsupported backup format"));
    }
    if content.entries.len() > MAX_CATALOG_ENTRIES {
        return Err(operation_error("backup catalog contains too many files"));
    }
    let mut previous: Option<&str> = None;
    let mut total = 0_u64;
    let mut has_format = false;
    for entry in &content.entries {
        if entry.path.len() > 4096 || entry.path == CATALOG_FILE {
            return Err(operation_error("backup catalog contains an invalid path"));
        }
        let relative = Path::new(&entry.path);
        validate_relative(relative)?;
        if canonical_relative(relative)? != entry.path
            || previous.is_some_and(|value| value >= entry.path.as_str())
        {
            return Err(operation_error(
                "backup catalog paths are non-canonical or unordered",
            ));
        }
        previous = Some(&entry.path);
        has_format |= entry.path == "FORMAT";
        total = total
            .checked_add(entry.size)
            .ok_or_else(|| operation_error("backup catalog byte count overflow"))?;
    }
    if !has_format {
        return Err(operation_error("backup catalog does not contain FORMAT"));
    }
    Ok(())
}

fn canonical_relative(path: &Path) -> Result<String, DbError> {
    validate_relative(path)?;
    path.components()
        .map(|component| match component {
            Component::Normal(value) => value
                .to_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| operation_error("backup paths must be valid UTF-8")),
            _ => Err(operation_error("backup contains an unsafe path")),
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|components| components.join("/"))
}

fn decode_backup_canonical<T>(bytes: &[u8]) -> Result<T, DbError>
where
    T: minicbor::Encode<()> + for<'value> minicbor::Decode<'value, ()>,
{
    let mut decoder = minicbor::Decoder::new(bytes);
    let value = decoder.decode().map_err(backup_codec)?;
    if decoder.position() != bytes.len() || minicbor::to_vec(&value).map_err(backup_codec)? != bytes
    {
        return Err(operation_error("backup catalog is not canonical"));
    }
    Ok(value)
}

#[allow(clippy::needless_pass_by_value)]
fn backup_codec(error: impl std::fmt::Display) -> DbError {
    DbError::Operation(format!("invalid backup catalog: {error}"))
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

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use iroh_db_security::IrohSigner;

    use super::*;

    #[test]
    fn signed_backup_catalog_has_permanent_golden_bytes() {
        let content = minicbor::to_vec(BackupCatalogContent {
            version: BACKUP_FORMAT_VERSION,
            entries: vec![BackupCatalogEntry {
                hash: [1; 32],
                size: 3,
                path: "FORMAT".into(),
            }],
        })
        .unwrap();
        let signer = IrohSigner::from_secret_bytes([7; 32]);
        let catalog = minicbor::to_vec(SignedBackupCatalog {
            signature: signer.sign_backup_catalog(&content),
            signer: signer.author(),
            content,
        })
        .unwrap();
        let mut actual = String::with_capacity(catalog.len() * 2);
        for byte in catalog {
            write!(&mut actual, "{byte:02x}").expect("writing to a string cannot fail");
        }

        assert_eq!(
            actual,
            "83982e188202188118831898182001010101010101010101010101010101010101010101010101010101010101010318661846184f1852184d18411854982018ea184a186c186318e2189c18520a18be18f51850187b13182e18c518f918951847187618ae18be18be187b18921842181e18ea186914184618d2182c98401871188718a31826189e189a18b81873183e184218c118ea0618fa1852185918e0189c1823182b18b01832187a18241837182d18b6184b182718af18a618fd185a186f18d618741518f4184618dc1840189618331841182c18d51833185d121846186b18471881189a1018cc182b18dd1118501865186e189b04"
        );
    }
}
