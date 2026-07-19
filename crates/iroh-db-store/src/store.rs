use std::{
    fs::{File, OpenOptions},
    path::Path,
    sync::Arc,
};

use fs2::FileExt as _;
use iroh_db_core::{
    AuthorId, BlobHash, CapabilityId, CollectionId, CommitCodecError, CommitEnvelope, CommitId,
    DomainId, SchemaDescriptor, SchemaError,
};
use iroh_db_security::{CapabilityCertificate, ControlTransition, DomainDescriptor, Permission};
use redb::{Database, ReadableDatabase as _, ReadableTable as _, TableDefinition};

use crate::{BlobStore, BlobStoreError, IndexValue, MaterializedRecord, StoredRecord};

const FORMAT_CONTENTS: &str = "iroh-db 1.0\n";
const COMMIT_METADATA: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("commit_metadata_v1");
const SNAPSHOT_COVERAGE: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("snapshot_coverage_v1");
const AUTHOR_SEQUENCES: TableDefinition<'static, &[u8], u64> =
    TableDefinition::new("author_sequences_v1");
const AUTHOR_HEADS: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("author_heads_v1");
const FRONTIER: TableDefinition<'static, &[u8], u8> = TableDefinition::new("frontier_v1");
const QUARANTINED_COMMITS: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("quarantined_commits_v1");
const QUARANTINED_AUTHORS: TableDefinition<'static, &[u8], u64> =
    TableDefinition::new("quarantined_authors_v1");
const SCHEMAS: TableDefinition<'static, &[u8], &[u8]> = TableDefinition::new("schemas_v1");
const RECORDS: TableDefinition<'static, &[u8], &[u8]> = TableDefinition::new("records_v1");
const RECORD_INDEX_KEYS: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("record_index_keys_v1");
const SECONDARY_INDEX: TableDefinition<'static, &[u8], u8> =
    TableDefinition::new("secondary_index_v1");
const TRUSTED_AUTHORS: TableDefinition<'static, &[u8], u8> =
    TableDefinition::new("trusted_authors_v1");
const DOMAIN_DESCRIPTORS: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("domain_descriptors_v1");
const CAPABILITIES: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("capabilities_v1");
const ACTIVE_CAPABILITIES: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("active_capabilities_v1");
const REVOKED_CAPABILITIES: TableDefinition<'static, &[u8], u64> =
    TableDefinition::new("revoked_capabilities_v1");
const CONTROL_HEADS: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("control_heads_v1");
const DEVICE_GROUPS: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("device_groups_v1");
const CONSUMED_INVITATIONS: TableDefinition<'static, &[u8], u8> =
    TableDefinition::new("consumed_invitations_v1");

/// The result of durably recording an immutable commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// The commit blob and metadata became durable.
    Applied(CommitId),
    /// The exact commit was already durable; no metadata changed.
    Duplicate(CommitId),
}

enum CommitPreflight {
    Duplicate(CommitId),
    Ready {
        previous_author_head: Option<CommitId>,
    },
}

/// A local durable-store failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// A filesystem operation failed.
    #[error("store filesystem operation failed: {0}")]
    Io(String),
    /// The redb metadata operation failed.
    #[error("metadata database operation failed: {0}")]
    Database(String),
    /// The immutable blob repository failed.
    #[error(transparent)]
    Blob(#[from] BlobStoreError),
    /// The blob repository returned a hash other than the bytes' expected hash.
    #[error("blob store returned a mismatched content hash")]
    BlobHashMismatch,
    /// A commit skipped or repeated an author's required next sequence.
    #[error("author sequence gap: expected {expected}, got {actual}")]
    SequenceGap {
        /// The only sequence accepted next.
        expected: u64,
        /// The sequence supplied by the commit.
        actual: u64,
    },
    /// The next author sequence did not causally extend that author's accepted head.
    #[error("commit does not extend previous author commit {previous}")]
    AuthorChainMissing {
        /// The accepted author commit that must be in dependency ancestry.
        previous: CommitId,
    },
    /// A post-snapshot author commit did not extend the complete installed frontier.
    #[error("commit does not extend installed snapshot frontier commit {frontier}")]
    SnapshotBaselineMissing {
        /// A current frontier commit absent from incoming dependency ancestry.
        frontier: CommitId,
    },
    /// Two different immutable commits claim one author-local sequence.
    #[error(
        "author {author} equivocated at sequence {sequence}: conflicting commits {first} and {second}"
    )]
    AuthorEquivocation {
        /// The signing author that reused a sequence.
        author: AuthorId,
        /// The reused author-local sequence.
        sequence: u64,
        /// Lexicographically first conflicting commit ID.
        first: CommitId,
        /// Lexicographically second conflicting commit ID.
        second: CommitId,
    },
    /// A commit is immutable evidence in a quarantined equivocation branch.
    #[error("commit is quarantined: {0}")]
    QuarantinedCommit(CommitId),
    /// An author's signing key equivocated and cannot extend that branch.
    #[error("author {author} is quarantined from sequence {from_sequence}")]
    QuarantinedAuthor {
        /// The equivocated author identity.
        author: AuthorId,
        /// The first sequence no longer accepted from this author.
        from_sequence: u64,
    },
    /// A declared causal dependency is not accepted locally.
    #[error("commit dependency is missing: {0}")]
    MissingDependency(CommitId),
    /// The directory has an incompatible format marker.
    #[error("unsupported store directory format")]
    UnsupportedFormat,
    /// Another process already holds the exclusive writer lock.
    #[error("database is already open for writing")]
    AlreadyOpen,
    /// A stored commit blob was missing.
    #[error("commit blob is missing: {0}")]
    MissingCommitBlob(CommitId),
    /// Stored immutable bytes were not a canonical commit.
    #[error(transparent)]
    CommitCodec(#[from] CommitCodecError),
    /// A stored schema descriptor could not be decoded.
    #[error(transparent)]
    Schema(#[from] SchemaError),
    /// The same domain, collection and version was registered with different bytes.
    #[error("schema mismatch for collection {collection_id} version {version}")]
    SchemaMismatch {
        /// Stable collection identifier.
        collection_id: CollectionId,
        /// Application schema version.
        version: u32,
    },
    /// A supplied index was absent from the schema or was not declared indexed.
    #[error("field {field_id} is not an index in collection {collection_id}")]
    InvalidIndex {
        /// Stable collection identifier.
        collection_id: CollectionId,
        /// Stable field identifier.
        field_id: u32,
    },
    /// Stored derived metadata was structurally corrupt.
    #[error("derived metadata is corrupt: {0}")]
    CorruptDerivedMetadata(String),
    /// A signed domain authority object failed validation or conflicted with durable state.
    #[error("domain authority metadata is invalid: {0}")]
    InvalidAuthority(String),
}

/// Transactional metadata paired with an immutable content-addressed blob repository.
#[derive(Clone)]
pub struct Store {
    inner: Arc<StoreInner>,
}

struct StoreInner {
    database: Database,
    blobs: Arc<dyn BlobStore>,
    _lock: File,
}

impl Store {
    /// Opens or creates a local store directory and acquires its writer lock.
    pub fn open(root: impl AsRef<Path>, blobs: Arc<dyn BlobStore>) -> Result<Self, StoreError> {
        let root = root.as_ref();
        std::fs::create_dir_all(root).map_err(io_error)?;
        std::fs::create_dir_all(root.join("locks")).map_err(io_error)?;
        std::fs::create_dir_all(root.join("tmp")).map_err(io_error)?;

        let format_path = root.join("FORMAT");
        if format_path.exists() {
            let contents = std::fs::read_to_string(&format_path).map_err(io_error)?;
            if contents != FORMAT_CONTENTS {
                return Err(StoreError::UnsupportedFormat);
            }
        } else {
            std::fs::write(&format_path, FORMAT_CONTENTS).map_err(io_error)?;
        }

        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(root.join("locks/writer.lock"))
            .map_err(io_error)?;
        lock.try_lock_exclusive()
            .map_err(|_| StoreError::AlreadyOpen)?;

        let database = Database::create(root.join("meta.redb")).map_err(database_error)?;
        initialize_tables(&database)?;
        Ok(Self {
            inner: Arc::new(StoreInner {
                database,
                blobs,
                _lock: lock,
            }),
        })
    }

    /// Makes immutable bytes durable before atomically publishing their metadata.
    pub async fn persist_commit(
        &self,
        envelope: &CommitEnvelope,
    ) -> Result<ApplyOutcome, StoreError> {
        self.persist_commit_with_records(envelope, &[]).await
    }

    /// Makes a commit blob durable, then atomically publishes metadata and derived records.
    pub async fn persist_commit_with_records(
        &self,
        envelope: &CommitEnvelope,
        records: &[MaterializedRecord],
    ) -> Result<ApplyOutcome, StoreError> {
        let commit_id = envelope.commit_id();
        let previous_author_head = match self.commit_preflight(envelope).await? {
            CommitPreflight::Duplicate(commit_id) => {
                return Ok(ApplyOutcome::Duplicate(commit_id));
            }
            CommitPreflight::Ready {
                previous_author_head,
            } => previous_author_head,
        };
        let expected_blob_hash = BlobHash::from_bytes(commit_id.to_bytes());
        let actual_blob_hash = self.inner.blobs.put(envelope.encode_canonical()).await?;
        if actual_blob_hash != expected_blob_hash {
            return Err(StoreError::BlobHashMismatch);
        }

        self.publish_commit_with_records(envelope, records, previous_author_head)
    }

    fn publish_commit_with_records(
        &self,
        envelope: &CommitEnvelope,
        records: &[MaterializedRecord],
        previous_author_head: Option<CommitId>,
    ) -> Result<ApplyOutcome, StoreError> {
        let commit_id = envelope.commit_id();
        let write = self.inner.database.begin_write().map_err(database_error)?;
        {
            let mut commits = write.open_table(COMMIT_METADATA).map_err(database_error)?;
            let coverage = write
                .open_table(SNAPSHOT_COVERAGE)
                .map_err(database_error)?;
            if commits
                .get(commit_id.as_bytes().as_slice())
                .map_err(database_error)?
                .is_some()
            {
                return Ok(ApplyOutcome::Duplicate(commit_id));
            }

            for dependency in envelope.header().dependencies() {
                let stored = commits
                    .get(dependency.as_bytes().as_slice())
                    .map_err(database_error)?
                    .is_some();
                let snapshotted = coverage
                    .get(dependency.as_bytes().as_slice())
                    .map_err(database_error)?
                    .is_some();
                if !stored && !snapshotted {
                    return Err(StoreError::MissingDependency(*dependency));
                }
            }

            let author_key =
                author_sequence_key(envelope.header().domain_id(), envelope.header().author());
            let mut sequences = write.open_table(AUTHOR_SEQUENCES).map_err(database_error)?;
            let last_sequence = sequences
                .get(author_key.as_slice())
                .map_err(database_error)?
                .map(|value| value.value());
            let expected_sequence = match last_sequence {
                Some(sequence) => sequence.checked_add(1).ok_or(StoreError::SequenceGap {
                    expected: sequence,
                    actual: envelope.header().author_sequence(),
                })?,
                None => 0,
            };
            if envelope.header().author_sequence() != expected_sequence {
                return Err(StoreError::SequenceGap {
                    expected: expected_sequence,
                    actual: envelope.header().author_sequence(),
                });
            }

            let mut author_heads = write.open_table(AUTHOR_HEADS).map_err(database_error)?;
            let current_author_head = author_heads
                .get(author_key.as_slice())
                .map_err(database_error)?
                .map(|value| {
                    let bytes: [u8; 32] = value.value().try_into().map_err(|_| {
                        StoreError::CorruptDerivedMetadata(
                            "author head commit ID is invalid".into(),
                        )
                    })?;
                    Ok::<CommitId, StoreError>(CommitId::from_bytes(bytes))
                })
                .transpose()?;
            if current_author_head != previous_author_head {
                return Err(StoreError::SequenceGap {
                    expected: expected_sequence,
                    actual: envelope.header().author_sequence(),
                });
            }

            let metadata = encode_metadata(envelope);
            commits
                .insert(commit_id.as_bytes().as_slice(), metadata.as_slice())
                .map_err(database_error)?;
            sequences
                .insert(author_key.as_slice(), envelope.header().author_sequence())
                .map_err(database_error)?;
            author_heads
                .insert(author_key.as_slice(), commit_id.as_bytes().as_slice())
                .map_err(database_error)?;

            let mut frontier = write.open_table(FRONTIER).map_err(database_error)?;
            for dependency in envelope.header().dependencies() {
                let dependency_key = frontier_key(envelope.header().domain_id(), *dependency);
                frontier
                    .remove(dependency_key.as_slice())
                    .map_err(database_error)?;
            }
            let commit_key = frontier_key(envelope.header().domain_id(), commit_id);
            frontier
                .insert(commit_key.as_slice(), 0)
                .map_err(database_error)?;

            apply_materialized_records(&write, envelope.header().domain_id(), records)?;
        }
        write.commit().map_err(database_error)?;
        Ok(ApplyOutcome::Applied(commit_id))
    }

    async fn commit_preflight(
        &self,
        envelope: &CommitEnvelope,
    ) -> Result<CommitPreflight, StoreError> {
        let commit_id = envelope.commit_id();
        if self.is_commit_quarantined(commit_id)? {
            return Err(StoreError::QuarantinedCommit(commit_id));
        }
        if let Some(from_sequence) =
            self.author_quarantine(envelope.header().domain_id(), envelope.header().author())?
            && envelope.header().author_sequence() >= from_sequence
        {
            return Err(StoreError::QuarantinedAuthor {
                author: envelope.header().author(),
                from_sequence,
            });
        }
        if self.contains_commit(commit_id)? {
            return Ok(CommitPreflight::Duplicate(commit_id));
        }
        if let Some(existing) = self.accepted_author_commit(
            envelope.header().domain_id(),
            envelope.header().author(),
            envelope.header().author_sequence(),
        )? && existing != commit_id
        {
            let (first, second) = if existing < commit_id {
                (existing, commit_id)
            } else {
                (commit_id, existing)
            };
            return Err(StoreError::AuthorEquivocation {
                author: envelope.header().author(),
                sequence: envelope.header().author_sequence(),
                first,
                second,
            });
        }
        let previous_author_head =
            self.author_head(envelope.header().domain_id(), envelope.header().author())?;
        if let Some(previous) = previous_author_head
            && !self
                .dependencies_include_ancestor(envelope.header().dependencies(), previous)
                .await?
        {
            return Err(StoreError::AuthorChainMissing { previous });
        }
        if previous_author_head.is_none()
            && self
                .last_sequence(envelope.header().domain_id(), envelope.header().author())?
                .is_some()
        {
            for frontier in self.frontier(envelope.header().domain_id())? {
                if !self
                    .dependencies_include_ancestor(envelope.header().dependencies(), frontier)
                    .await?
                {
                    return Err(StoreError::SnapshotBaselineMissing { frontier });
                }
            }
        }
        Ok(CommitPreflight::Ready {
            previous_author_head,
        })
    }

    /// Returns whether commit metadata is accepted locally.
    pub fn contains_commit(&self, commit_id: CommitId) -> Result<bool, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let commits = read.open_table(COMMIT_METADATA).map_err(database_error)?;
        let coverage = read.open_table(SNAPSHOT_COVERAGE).map_err(database_error)?;
        let quarantined = read
            .open_table(QUARANTINED_COMMITS)
            .map_err(database_error)?;
        let stored = commits
            .get(commit_id.as_bytes().as_slice())
            .map_err(database_error)?
            .is_some()
            && quarantined
                .get(commit_id.as_bytes().as_slice())
                .map_err(database_error)?
                .is_none();
        let snapshotted = coverage
            .get(commit_id.as_bytes().as_slice())
            .map_err(database_error)?
            .is_some();
        Ok(stored || snapshotted)
    }

    /// Returns whether a commit ID is retained only as equivocation evidence.
    pub fn is_commit_quarantined(&self, commit_id: CommitId) -> Result<bool, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let quarantined = read
            .open_table(QUARANTINED_COMMITS)
            .map_err(database_error)?;
        Ok(quarantined
            .get(commit_id.as_bytes().as_slice())
            .map_err(database_error)?
            .is_some())
    }

    /// Returns the first rejected sequence for an equivocated author, if any.
    pub fn author_quarantine(
        &self,
        domain_id: DomainId,
        author: AuthorId,
    ) -> Result<Option<u64>, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let quarantined = read
            .open_table(QUARANTINED_AUTHORS)
            .map_err(database_error)?;
        let key = author_sequence_key(domain_id, author);
        Ok(quarantined
            .get(key.as_slice())
            .map_err(database_error)?
            .map(|value| value.value()))
    }

    /// Returns the latest accepted author sequence in a domain.
    pub fn last_sequence(
        &self,
        domain_id: DomainId,
        author: AuthorId,
    ) -> Result<Option<u64>, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let sequences = read.open_table(AUTHOR_SEQUENCES).map_err(database_error)?;
        let key = author_sequence_key(domain_id, author);
        Ok(sequences
            .get(key.as_slice())
            .map_err(database_error)?
            .map(|value| value.value()))
    }

    /// Returns the latest accepted immutable commit for an author in a domain.
    pub fn author_head(
        &self,
        domain_id: DomainId,
        author: AuthorId,
    ) -> Result<Option<CommitId>, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let heads = read.open_table(AUTHOR_HEADS).map_err(database_error)?;
        let key = author_sequence_key(domain_id, author);
        heads
            .get(key.as_slice())
            .map_err(database_error)?
            .map(|value| {
                let bytes: [u8; 32] = value.value().try_into().map_err(|_| {
                    StoreError::CorruptDerivedMetadata("author head commit ID is invalid".into())
                })?;
                Ok(CommitId::from_bytes(bytes))
            })
            .transpose()
    }

    /// Returns an accepted conflicting commit for the envelope's author sequence.
    pub fn conflicting_author_commit(
        &self,
        envelope: &CommitEnvelope,
    ) -> Result<Option<CommitId>, StoreError> {
        let commit_id = envelope.commit_id();
        Ok(self
            .accepted_author_commit(
                envelope.header().domain_id(),
                envelope.header().author(),
                envelope.header().author_sequence(),
            )?
            .filter(|existing| *existing != commit_id))
    }

    /// Atomically quarantines an equivocated branch and publishes rebuilt accepted state.
    pub async fn quarantine_equivocation(
        &self,
        evidence: &CommitEnvelope,
        invalid_commits: &[CommitId],
        accepted_frontier: &[CommitId],
        author_heads: &[(AuthorId, u64, CommitId)],
        records: &[MaterializedRecord],
    ) -> Result<(), StoreError> {
        let evidence_id = evidence.commit_id();
        let expected_hash = BlobHash::from_bytes(evidence_id.to_bytes());
        if self.inner.blobs.put(evidence.encode_canonical()).await? != expected_hash {
            return Err(StoreError::BlobHashMismatch);
        }
        let domain_id = evidence.header().domain_id();
        let write = self.inner.database.begin_write().map_err(database_error)?;
        clear_materialized_domain(&write, domain_id)?;
        apply_materialized_records(&write, domain_id, records)?;
        {
            let mut quarantined = write
                .open_table(QUARANTINED_COMMITS)
                .map_err(database_error)?;
            for commit_id in invalid_commits
                .iter()
                .copied()
                .chain(std::iter::once(evidence_id))
            {
                quarantined
                    .insert(
                        commit_id.as_bytes().as_slice(),
                        domain_id.as_bytes().as_slice(),
                    )
                    .map_err(database_error)?;
            }
        }
        {
            let mut authors = write
                .open_table(QUARANTINED_AUTHORS)
                .map_err(database_error)?;
            let key = author_sequence_key(domain_id, evidence.header().author());
            let existing = authors
                .get(key.as_slice())
                .map_err(database_error)?
                .map(|value| value.value());
            let from_sequence = existing.map_or(evidence.header().author_sequence(), |current| {
                current.min(evidence.header().author_sequence())
            });
            authors
                .insert(key.as_slice(), from_sequence)
                .map_err(database_error)?;
        }
        {
            let mut sequences = write.open_table(AUTHOR_SEQUENCES).map_err(database_error)?;
            let keys = table_u64_keys_with_prefix(&sequences, domain_id.as_bytes())?;
            for key in keys {
                sequences.remove(key.as_slice()).map_err(database_error)?;
            }
            let mut heads = write.open_table(AUTHOR_HEADS).map_err(database_error)?;
            let keys = table_keys_with_prefix(&heads, domain_id.as_bytes())?;
            for key in keys {
                heads.remove(key.as_slice()).map_err(database_error)?;
            }
            for (author, sequence, commit_id) in author_heads {
                let key = author_sequence_key(domain_id, *author);
                sequences
                    .insert(key.as_slice(), *sequence)
                    .map_err(database_error)?;
                heads
                    .insert(key.as_slice(), commit_id.as_bytes().as_slice())
                    .map_err(database_error)?;
            }
        }
        {
            let mut frontier = write.open_table(FRONTIER).map_err(database_error)?;
            let keys = table_u8_keys_with_prefix(&frontier, domain_id.as_bytes())?;
            for key in keys {
                frontier.remove(key.as_slice()).map_err(database_error)?;
            }
            for commit_id in accepted_frontier {
                let key = frontier_key(domain_id, *commit_id);
                frontier.insert(key.as_slice(), 0).map_err(database_error)?;
            }
        }
        write.commit().map_err(database_error)
    }

    fn accepted_author_commit(
        &self,
        domain_id: DomainId,
        author: AuthorId,
        sequence: u64,
    ) -> Result<Option<CommitId>, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let commits = read.open_table(COMMIT_METADATA).map_err(database_error)?;
        let quarantined = read
            .open_table(QUARANTINED_COMMITS)
            .map_err(database_error)?;
        for entry in commits.iter().map_err(database_error)? {
            let (key, value) = entry.map_err(database_error)?;
            if quarantined
                .get(key.value())
                .map_err(database_error)?
                .is_some()
            {
                continue;
            }
            let metadata = value.value();
            if metadata.len() != 112 {
                return Err(StoreError::CorruptDerivedMetadata(
                    "commit metadata length is invalid".into(),
                ));
            }
            if &metadata[..32] != domain_id.as_bytes()
                || &metadata[32..64] != author.as_bytes()
                || metadata[72..80] != sequence.to_be_bytes()
            {
                continue;
            }
            let bytes: [u8; 32] = key.value().try_into().map_err(|_| {
                StoreError::CorruptDerivedMetadata("commit ID length is invalid".into())
            })?;
            return Ok(Some(CommitId::from_bytes(bytes)));
        }
        Ok(None)
    }

    async fn dependencies_include_ancestor(
        &self,
        dependencies: &[CommitId],
        ancestor: CommitId,
    ) -> Result<bool, StoreError> {
        let mut pending = dependencies.to_vec();
        let mut visited = std::collections::BTreeSet::new();
        while let Some(commit_id) = pending.pop() {
            if commit_id == ancestor {
                return Ok(true);
            }
            if !visited.insert(commit_id) {
                continue;
            }
            match self.load_commit(commit_id).await {
                Ok(envelope) => pending.extend_from_slice(envelope.header().dependencies()),
                Err(StoreError::MissingCommitBlob(_)) if self.contains_commit(commit_id)? => {
                    // Snapshot-covered history is trusted as an opaque causal baseline.
                }
                Err(error) => return Err(error),
            }
        }
        Ok(false)
    }

    /// Returns the canonical sorted commit frontier for a domain.
    pub fn frontier(&self, domain_id: DomainId) -> Result<Vec<CommitId>, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let frontier = read.open_table(FRONTIER).map_err(database_error)?;
        let mut commits = Vec::new();
        for entry in frontier.iter().map_err(database_error)? {
            let (key, _) = entry.map_err(database_error)?;
            let key = key.value();
            if key.starts_with(domain_id.as_bytes()) {
                let bytes: [u8; 32] = key[32..]
                    .try_into()
                    .map_err(|_| StoreError::Database("invalid frontier key".into()))?;
                commits.push(CommitId::from_bytes(bytes));
            }
        }
        commits.sort_unstable();
        Ok(commits)
    }

    /// Loads one canonical materialized record state by primary key.
    pub fn get_record(
        &self,
        domain_id: DomainId,
        collection_id: CollectionId,
        record_id: &[u8],
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let records = read.open_table(RECORDS).map_err(database_error)?;
        let key = record_key(domain_id, collection_id, record_id);
        Ok(records
            .get(key.as_slice())
            .map_err(database_error)?
            .map(|value| value.value().to_vec()))
    }

    /// Lists canonical record IDs and states in stable primary-key order.
    pub fn list_records(
        &self,
        domain_id: DomainId,
        collection_id: CollectionId,
    ) -> Result<Vec<StoredRecord>, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let records = read.open_table(RECORDS).map_err(database_error)?;
        let prefix = record_prefix(domain_id, collection_id);
        let mut found = Vec::new();
        for entry in records.iter().map_err(database_error)? {
            let (key, value) = entry.map_err(database_error)?;
            let key = key.value();
            if key.starts_with(&prefix) {
                found.push(StoredRecord {
                    record_id: key[prefix.len()..].to_vec(),
                    state: value.value().to_vec(),
                });
            }
        }
        Ok(found)
    }

    /// Resolves an equality index to stable record IDs.
    pub fn lookup_equal(
        &self,
        domain_id: DomainId,
        collection_id: CollectionId,
        field_id: u32,
        value: &[u8],
    ) -> Result<Vec<Vec<u8>>, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let index = read.open_table(SECONDARY_INDEX).map_err(database_error)?;
        let prefix = index_value_prefix(domain_id, collection_id, field_id, value)?;
        let mut record_ids = Vec::new();
        for entry in index.iter().map_err(database_error)? {
            let (key, _) = entry.map_err(database_error)?;
            let key = key.value();
            if !key.starts_with(&prefix) {
                continue;
            }
            let suffix = &key[prefix.len()..];
            if suffix.len() < 4 {
                return Err(StoreError::CorruptDerivedMetadata(
                    "index record length is missing".into(),
                ));
            }
            let length = read_u32(&suffix[..4])?;
            if suffix.len() != 4 + length {
                return Err(StoreError::CorruptDerivedMetadata(
                    "index record length is invalid".into(),
                ));
            }
            record_ids.push(suffix[4..].to_vec());
        }
        record_ids.sort();
        Ok(record_ids)
    }

    /// Loads a registered schema version, if present.
    pub fn registered_schema(
        &self,
        domain_id: DomainId,
        collection_id: CollectionId,
        version: u32,
    ) -> Result<Option<SchemaDescriptor>, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let schemas = read.open_table(SCHEMAS).map_err(database_error)?;
        let key = schema_key(domain_id, collection_id, version);
        schemas
            .get(key.as_slice())
            .map_err(database_error)?
            .map(|value| {
                SchemaDescriptor::decode_canonical(value.value()).map_err(StoreError::from)
            })
            .transpose()
    }

    /// Lists accepted commit IDs, including snapshot-covered history, in deterministic order.
    pub fn list_commit_ids(&self, domain_id: DomainId) -> Result<Vec<CommitId>, StoreError> {
        let mut ids = self.list_stored_commit_ids(domain_id)?;
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let coverage = read.open_table(SNAPSHOT_COVERAGE).map_err(database_error)?;
        for entry in coverage.iter().map_err(database_error)? {
            let (key, value) = entry.map_err(database_error)?;
            if value.value() == domain_id.as_bytes() {
                let bytes: [u8; 32] = key.value().try_into().map_err(|_| {
                    StoreError::CorruptDerivedMetadata("coverage commit ID is invalid".into())
                })?;
                ids.push(CommitId::from_bytes(bytes));
            }
        }
        ids.sort_unstable();
        ids.dedup();
        Ok(ids)
    }

    /// Returns whether this domain relies on snapshot-covered commit history.
    pub fn has_snapshot_coverage(&self, domain_id: DomainId) -> Result<bool, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let coverage = read.open_table(SNAPSHOT_COVERAGE).map_err(database_error)?;
        for entry in coverage.iter().map_err(database_error)? {
            let (_, value) = entry.map_err(database_error)?;
            if value.value() == domain_id.as_bytes() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Lists commit IDs whose immutable envelope blobs are stored locally.
    pub fn list_stored_commit_ids(&self, domain_id: DomainId) -> Result<Vec<CommitId>, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let commits = read.open_table(COMMIT_METADATA).map_err(database_error)?;
        let quarantined = read
            .open_table(QUARANTINED_COMMITS)
            .map_err(database_error)?;
        let mut ids = Vec::new();
        for entry in commits.iter().map_err(database_error)? {
            let (key, value) = entry.map_err(database_error)?;
            if value.value().starts_with(domain_id.as_bytes())
                && quarantined
                    .get(key.value())
                    .map_err(database_error)?
                    .is_none()
            {
                let bytes: [u8; 32] = key.value().try_into().map_err(|_| {
                    StoreError::CorruptDerivedMetadata("commit ID length is invalid".into())
                })?;
                ids.push(CommitId::from_bytes(bytes));
            }
        }
        ids.sort_unstable();
        Ok(ids)
    }

    /// Exports durable per-author sequence baselines for a snapshot.
    pub fn author_sequences(
        &self,
        domain_id: DomainId,
    ) -> Result<Vec<(AuthorId, u64)>, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let sequences = read.open_table(AUTHOR_SEQUENCES).map_err(database_error)?;
        let mut values = Vec::new();
        for entry in sequences.iter().map_err(database_error)? {
            let (key, sequence) = entry.map_err(database_error)?;
            let key = key.value();
            if key.starts_with(domain_id.as_bytes()) {
                let author: [u8; 32] = key[32..].try_into().map_err(|_| {
                    StoreError::CorruptDerivedMetadata("author sequence key is invalid".into())
                })?;
                values.push((AuthorId::from_bytes(author), sequence.value()));
            }
        }
        values.sort_unstable_by_key(|(author, _)| *author);
        Ok(values)
    }

    /// Exports complete canonical derived state for snapshots and equivalence checks.
    pub fn export_materialized(
        &self,
        domain_id: DomainId,
    ) -> Result<Vec<MaterializedRecord>, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let schemas = read.open_table(SCHEMAS).map_err(database_error)?;
        let records = read.open_table(RECORDS).map_err(database_error)?;
        let record_indexes = read.open_table(RECORD_INDEX_KEYS).map_err(database_error)?;
        let mut schema_values = Vec::new();
        for entry in schemas.iter().map_err(database_error)? {
            let (key, value) = entry.map_err(database_error)?;
            if key.value().starts_with(domain_id.as_bytes()) {
                schema_values.push(SchemaDescriptor::decode_canonical(value.value())?);
            }
        }
        schema_values.sort_by_key(|schema| (schema.collection_id(), schema.version()));

        let mut exported = Vec::new();
        for schema in schema_values {
            let prefix = record_prefix(domain_id, schema.collection_id());
            for entry in records.iter().map_err(database_error)? {
                let (key, value) = entry.map_err(database_error)?;
                let record_key = key.value();
                if !record_key.starts_with(&prefix) {
                    continue;
                }
                let record_id = record_key[prefix.len()..].to_vec();
                let index_keys = record_indexes
                    .get(record_key)
                    .map_err(database_error)?
                    .map(|encoded| decode_key_list(encoded.value()))
                    .transpose()?
                    .unwrap_or_default();
                let indexes = index_keys
                    .iter()
                    .map(|key| {
                        decode_index_value(key, domain_id, schema.collection_id(), &record_id)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                exported.push(
                    MaterializedRecord::upsert(
                        schema.clone(),
                        record_id,
                        value.value().to_vec(),
                        indexes,
                    )
                    .map_err(|error| StoreError::CorruptDerivedMetadata(error.to_string()))?,
                );
            }
        }
        Ok(exported)
    }

    /// Atomically replaces all derived state for one domain.
    pub fn replace_materialized(
        &self,
        domain_id: DomainId,
        records: &[MaterializedRecord],
    ) -> Result<(), StoreError> {
        let write = self.inner.database.begin_write().map_err(database_error)?;
        clear_materialized_domain(&write, domain_id)?;
        apply_materialized_records(&write, domain_id, records)?;
        write.commit().map_err(database_error)
    }

    /// Atomically installs snapshot-derived state and its causal acceptance baseline.
    pub fn install_snapshot(
        &self,
        domain_id: DomainId,
        records: &[MaterializedRecord],
        covered_commits: &[CommitId],
        frontier_commits: &[CommitId],
        author_sequences: &[(AuthorId, u64)],
    ) -> Result<(), StoreError> {
        let write = self.inner.database.begin_write().map_err(database_error)?;
        clear_materialized_domain(&write, domain_id)?;
        clear_domain_snapshot_metadata(&write, domain_id)?;
        apply_materialized_records(&write, domain_id, records)?;
        {
            let commits = write.open_table(COMMIT_METADATA).map_err(database_error)?;
            let mut coverage = write
                .open_table(SNAPSHOT_COVERAGE)
                .map_err(database_error)?;
            for commit_id in covered_commits {
                if commits
                    .get(commit_id.as_bytes().as_slice())
                    .map_err(database_error)?
                    .is_some()
                {
                    continue;
                }
                coverage
                    .insert(
                        commit_id.as_bytes().as_slice(),
                        domain_id.as_bytes().as_slice(),
                    )
                    .map_err(database_error)?;
            }
        }
        {
            let mut frontier = write.open_table(FRONTIER).map_err(database_error)?;
            for commit_id in frontier_commits {
                let key = frontier_key(domain_id, *commit_id);
                frontier.insert(key.as_slice(), 0).map_err(database_error)?;
            }
        }
        {
            let mut sequences = write.open_table(AUTHOR_SEQUENCES).map_err(database_error)?;
            for (author, sequence) in author_sequences {
                let key = author_sequence_key(domain_id, *author);
                sequences
                    .insert(key.as_slice(), *sequence)
                    .map_err(database_error)?;
            }
        }
        write.commit().map_err(database_error)
    }

    /// Loads and strictly decodes an accepted immutable commit blob.
    pub async fn load_commit(&self, commit_id: CommitId) -> Result<CommitEnvelope, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let commits = read.open_table(COMMIT_METADATA).map_err(database_error)?;
        if commits
            .get(commit_id.as_bytes().as_slice())
            .map_err(database_error)?
            .is_none()
        {
            return Err(StoreError::MissingCommitBlob(commit_id));
        }
        drop(commits);
        drop(read);
        let hash = BlobHash::from_bytes(commit_id.to_bytes());
        let bytes = self
            .inner
            .blobs
            .get(hash)
            .await?
            .ok_or(StoreError::MissingCommitBlob(commit_id))?;
        let envelope = CommitEnvelope::decode_canonical(&bytes)?;
        if envelope.commit_id() != commit_id {
            return Err(StoreError::BlobHashMismatch);
        }
        Ok(envelope)
    }

    /// Finds canonical commit blobs left behind before their metadata transaction committed.
    ///
    /// Arbitrary application blobs are ignored. The returned IDs are deterministic and can be
    /// offered to a repair workflow; scanning never mutates durable state.
    pub async fn scan_commit_orphans(&self) -> Result<Vec<CommitId>, StoreError> {
        let mut orphans = Vec::new();
        for hash in self.inner.blobs.list().await? {
            let Some(bytes) = self.inner.blobs.get(hash).await? else {
                continue;
            };
            let Ok(envelope) = CommitEnvelope::decode_canonical(&bytes) else {
                continue;
            };
            let commit_id = envelope.commit_id();
            if commit_id.to_bytes() == hash.to_bytes() && !self.contains_commit(commit_id)? {
                orphans.push(commit_id);
            }
        }
        orphans.sort_unstable();
        orphans.dedup();
        Ok(orphans)
    }

    /// Atomically records a domain genesis descriptor and its owner capability.
    pub fn bootstrap_domain(
        &self,
        descriptor: &DomainDescriptor,
        root: &CapabilityCertificate,
    ) -> Result<(), StoreError> {
        descriptor.verify().map_err(authority_error)?;
        root.verify_signature().map_err(authority_error)?;
        if root.domain_id() != descriptor.domain_id()
            || root.subject() != descriptor.owner()
            || root.issuer_capability().is_some()
            || !root.permissions().contains(Permission::Admin)
        {
            return Err(StoreError::InvalidAuthority(
                "owner capability does not match descriptor".into(),
            ));
        }
        let descriptor_bytes = descriptor.encode_canonical().map_err(authority_error)?;
        let capability_bytes = root.encode_canonical().map_err(authority_error)?;
        let capability_id = root.id().map_err(authority_error)?;
        let write = self.inner.database.begin_write().map_err(database_error)?;
        {
            let mut descriptors = write
                .open_table(DOMAIN_DESCRIPTORS)
                .map_err(database_error)?;
            let existing = descriptors
                .get(descriptor.domain_id().as_bytes().as_slice())
                .map_err(database_error)?
                .map(|value| value.value().to_vec());
            if existing
                .as_deref()
                .is_some_and(|bytes| bytes != descriptor_bytes)
            {
                return Err(StoreError::InvalidAuthority(
                    "domain descriptor conflicts with genesis".into(),
                ));
            }
            descriptors
                .insert(
                    descriptor.domain_id().as_bytes().as_slice(),
                    descriptor_bytes.as_slice(),
                )
                .map_err(database_error)?;
        }
        insert_capability_tables(&write, root, capability_id, &capability_bytes)?;
        write.commit().map_err(database_error)
    }

    /// Installs a delegated capability after validating its durable issuer link.
    pub fn install_capability(
        &self,
        capability: &CapabilityCertificate,
    ) -> Result<CapabilityId, StoreError> {
        let issuer_id = capability.issuer_capability().ok_or_else(|| {
            StoreError::InvalidAuthority("delegated capability lacks issuer".into())
        })?;
        let issuer = self
            .capability(issuer_id)?
            .ok_or_else(|| StoreError::InvalidAuthority("capability issuer is missing".into()))?;
        capability
            .validate_delegation(&issuer)
            .map_err(authority_error)?;
        let capability_id = capability.id().map_err(authority_error)?;
        let bytes = capability.encode_canonical().map_err(authority_error)?;
        let write = self.inner.database.begin_write().map_err(database_error)?;
        insert_capability_tables(&write, capability, capability_id, &bytes)?;
        write.commit().map_err(database_error)?;
        Ok(capability_id)
    }

    /// Loads one verified capability certificate by content ID.
    pub fn capability(
        &self,
        capability_id: CapabilityId,
    ) -> Result<Option<CapabilityCertificate>, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let capabilities = read.open_table(CAPABILITIES).map_err(database_error)?;
        capabilities
            .get(capability_id.as_bytes().as_slice())
            .map_err(database_error)?
            .map(|value| {
                CapabilityCertificate::decode_canonical(value.value()).map_err(authority_error)
            })
            .transpose()
    }

    /// Resolves a bounded root-to-leaf capability chain.
    pub fn capability_chain(
        &self,
        leaf: CapabilityId,
    ) -> Result<Vec<CapabilityCertificate>, StoreError> {
        let mut reversed = Vec::new();
        let mut next = Some(leaf);
        while let Some(capability_id) = next {
            if reversed.len() >= 9 {
                return Err(StoreError::InvalidAuthority(
                    "capability chain exceeds depth bound".into(),
                ));
            }
            let capability = self.capability(capability_id)?.ok_or_else(|| {
                StoreError::InvalidAuthority("capability chain link is missing".into())
            })?;
            next = capability.issuer_capability();
            reversed.push(capability);
        }
        reversed.reverse();
        for pair in reversed.windows(2) {
            pair[1]
                .validate_delegation(&pair[0])
                .map_err(authority_error)?;
        }
        Ok(reversed)
    }

    /// Loads the immutable descriptor when this is a capability-controlled domain.
    pub fn domain_descriptor(
        &self,
        domain_id: DomainId,
    ) -> Result<Option<DomainDescriptor>, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let descriptors = read
            .open_table(DOMAIN_DESCRIPTORS)
            .map_err(database_error)?;
        descriptors
            .get(domain_id.as_bytes().as_slice())
            .map_err(database_error)?
            .map(|value| DomainDescriptor::decode_canonical(value.value()).map_err(authority_error))
            .transpose()
    }

    /// Returns the active capability selected for an endpoint in a domain.
    pub fn active_capability(
        &self,
        domain_id: DomainId,
        subject: AuthorId,
    ) -> Result<Option<CapabilityId>, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let active = read
            .open_table(ACTIVE_CAPABILITIES)
            .map_err(database_error)?;
        let key = active_capability_key(domain_id, subject);
        active
            .get(key.as_slice())
            .map_err(database_error)?
            .map(|value| {
                let bytes: [u8; 32] = value.value().try_into().map_err(|_| {
                    StoreError::CorruptDerivedMetadata("active capability ID is invalid".into())
                })?;
                Ok(CapabilityId::from_bytes(bytes))
            })
            .transpose()
    }

    /// Checks active, non-revoked, endpoint-bound permission at an epoch.
    pub fn authorize_capability(
        &self,
        domain_id: DomainId,
        subject: AuthorId,
        capability_id: CapabilityId,
        permission: Permission,
        epoch: u64,
    ) -> Result<bool, StoreError> {
        if self.active_capability(domain_id, subject)? != Some(capability_id) {
            return Ok(false);
        }
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let revoked = read
            .open_table(REVOKED_CAPABILITIES)
            .map_err(database_error)?;
        if revoked
            .get(capability_id.as_bytes().as_slice())
            .map_err(database_error)?
            .is_some()
        {
            return Ok(false);
        }
        let Some(capability) = self.capability(capability_id)? else {
            return Ok(false);
        };
        Ok(capability.domain_id() == domain_id
            && capability.subject() == subject
            && capability.permits(permission, epoch))
    }

    /// Loads and verifies the current single-successor control head.
    pub fn control_head(
        &self,
        domain_id: DomainId,
    ) -> Result<Option<ControlTransition>, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let heads = read.open_table(CONTROL_HEADS).map_err(database_error)?;
        heads
            .get(domain_id.as_bytes().as_slice())
            .map_err(database_error)?
            .map(|value| {
                ControlTransition::decode_canonical(value.value()).map_err(authority_error)
            })
            .transpose()
    }

    /// Returns the epoch authorized by the durable control chain.
    pub fn current_epoch(&self, domain_id: DomainId) -> Result<u64, StoreError> {
        Ok(self
            .control_head(domain_id)?
            .map_or(0, |head| head.new_epoch()))
    }

    /// Returns the currently designated single writer.
    pub fn current_writer(&self, domain_id: DomainId) -> Result<Option<AuthorId>, StoreError> {
        if let Some(head) = self.control_head(domain_id)? {
            return Ok(Some(head.writer()));
        }
        Ok(self
            .domain_descriptor(domain_id)?
            .map(|descriptor| descriptor.owner()))
    }

    /// Atomically advances authority, records the causal cut, and revokes endpoint access.
    pub fn apply_control(&self, control: &ControlTransition) -> Result<(), StoreError> {
        control.verify().map_err(authority_error)?;
        let current = self.control_head(control.domain_id())?;
        let (sequence, predecessor, epoch) = if let Some(head) = current.as_ref() {
            (
                head.sequence().checked_add(1).ok_or_else(|| {
                    StoreError::InvalidAuthority("control sequence exhausted".into())
                })?,
                Some(head.id().map_err(authority_error)?),
                head.new_epoch(),
            )
        } else {
            (1, None, 0)
        };
        let can_control = self.authorize_capability(
            control.domain_id(),
            control.author(),
            control.author_capability(),
            Permission::Revoke,
            epoch,
        )? || self.authorize_capability(
            control.domain_id(),
            control.author(),
            control.author_capability(),
            Permission::Admin,
            epoch,
        )?;
        if control.sequence() != sequence
            || control.predecessor() != predecessor
            || control.previous_epoch() != epoch
            || self.frontier(control.domain_id())? != control.cut()
            || !can_control
        {
            return Err(StoreError::InvalidAuthority(
                "control transition does not extend the active head".into(),
            ));
        }
        if control.revoked_subjects().contains(&control.author()) {
            return Err(StoreError::InvalidAuthority(
                "control author cannot revoke itself".into(),
            ));
        }
        let bytes = control.encode_canonical().map_err(authority_error)?;
        let write = self.inner.database.begin_write().map_err(database_error)?;
        {
            let mut heads = write.open_table(CONTROL_HEADS).map_err(database_error)?;
            heads
                .insert(control.domain_id().as_bytes().as_slice(), bytes.as_slice())
                .map_err(database_error)?;
        }
        for subject in control.revoked_subjects() {
            let active_key = active_capability_key(control.domain_id(), *subject);
            let capability_id = {
                let mut active = write
                    .open_table(ACTIVE_CAPABILITIES)
                    .map_err(database_error)?;
                let id = active
                    .get(active_key.as_slice())
                    .map_err(database_error)?
                    .map(|value| value.value().to_vec());
                active
                    .remove(active_key.as_slice())
                    .map_err(database_error)?;
                id
            };
            if let Some(capability_id) = capability_id {
                write
                    .open_table(REVOKED_CAPABILITIES)
                    .map_err(database_error)?
                    .insert(capability_id.as_slice(), control.sequence())
                    .map_err(database_error)?;
            }
            let trusted_key = trusted_author_key(control.domain_id(), *subject);
            write
                .open_table(TRUSTED_AUTHORS)
                .map_err(database_error)?
                .remove(trusted_key.as_slice())
                .map_err(database_error)?;
        }
        write.commit().map_err(database_error)
    }

    /// Adds a device to the local domain authorization set.
    pub fn trust_author(&self, domain_id: DomainId, author: AuthorId) -> Result<(), StoreError> {
        let write = self.inner.database.begin_write().map_err(database_error)?;
        {
            let mut trusted = write.open_table(TRUSTED_AUTHORS).map_err(database_error)?;
            let key = trusted_author_key(domain_id, author);
            trusted.insert(key.as_slice(), 0).map_err(database_error)?;
        }
        write.commit().map_err(database_error)
    }

    /// Returns whether a device is locally authorized for this domain.
    pub fn is_author_trusted(
        &self,
        domain_id: DomainId,
        author: AuthorId,
    ) -> Result<bool, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let trusted = read.open_table(TRUSTED_AUTHORS).map_err(database_error)?;
        let key = trusted_author_key(domain_id, author);
        Ok(trusted
            .get(key.as_slice())
            .map_err(database_error)?
            .is_some())
    }

    /// Lists locally authorized devices in canonical identity order.
    pub fn trusted_authors(&self, domain_id: DomainId) -> Result<Vec<AuthorId>, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let trusted = read.open_table(TRUSTED_AUTHORS).map_err(database_error)?;
        let mut authors = Vec::new();
        for entry in trusted.iter().map_err(database_error)? {
            let (key, _) = entry.map_err(database_error)?;
            let key = key.value();
            if key.starts_with(domain_id.as_bytes()) {
                let bytes: [u8; 32] = key[32..].try_into().map_err(|_| {
                    StoreError::CorruptDerivedMetadata("trusted author length is invalid".into())
                })?;
                authors.push(AuthorId::from_bytes(bytes));
            }
        }
        authors.sort_unstable();
        Ok(authors)
    }

    /// Replaces bounded application-facing group metadata without changing protocol identity.
    pub fn set_device_group(
        &self,
        domain_id: DomainId,
        label: &str,
        members: &[AuthorId],
    ) -> Result<(), StoreError> {
        if label.is_empty() || label.len() > 128 || members.len() > 256 {
            return Err(StoreError::InvalidAuthority(
                "device group exceeds label or member bounds".into(),
            ));
        }
        let mut canonical = members.to_vec();
        canonical.sort_unstable();
        canonical.dedup();
        let key = device_group_key(domain_id, label);
        let value: Vec<u8> = canonical
            .iter()
            .flat_map(|author| author.as_bytes().iter().copied())
            .collect();
        let write = self.inner.database.begin_write().map_err(database_error)?;
        write
            .open_table(DEVICE_GROUPS)
            .map_err(database_error)?
            .insert(key.as_slice(), value.as_slice())
            .map_err(database_error)?;
        write.commit().map_err(database_error)
    }

    /// Lists device groups for one domain in label order.
    pub fn device_groups(
        &self,
        domain_id: DomainId,
    ) -> Result<Vec<(String, Vec<AuthorId>)>, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let groups = read.open_table(DEVICE_GROUPS).map_err(database_error)?;
        let mut result = Vec::new();
        for entry in groups.iter().map_err(database_error)? {
            let (key, value) = entry.map_err(database_error)?;
            let key = key.value();
            if !key.starts_with(domain_id.as_bytes()) {
                continue;
            }
            let label = std::str::from_utf8(&key[32..])
                .map_err(|_| StoreError::CorruptDerivedMetadata("group label is invalid".into()))?
                .to_owned();
            let chunks = value.value().chunks_exact(32);
            if !chunks.remainder().is_empty() {
                return Err(StoreError::CorruptDerivedMetadata(
                    "group member data is invalid".into(),
                ));
            }
            let members = chunks
                .map(|chunk| {
                    let bytes: [u8; 32] = chunk.try_into().expect("exact chunk length");
                    AuthorId::from_bytes(bytes)
                })
                .collect();
            result.push((label, members));
        }
        result.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(result)
    }

    /// Atomically marks an offline invitation ticket consumed, returning false on replay.
    pub fn consume_invitation(&self, invitation_id: [u8; 32]) -> Result<bool, StoreError> {
        let write = self.inner.database.begin_write().map_err(database_error)?;
        let fresh = {
            let mut consumed = write
                .open_table(CONSUMED_INVITATIONS)
                .map_err(database_error)?;
            if consumed
                .get(invitation_id.as_slice())
                .map_err(database_error)?
                .is_some()
            {
                false
            } else {
                consumed
                    .insert(invitation_id.as_slice(), 0)
                    .map_err(database_error)?;
                true
            }
        };
        write.commit().map_err(database_error)?;
        Ok(fresh)
    }
}

fn initialize_tables(database: &Database) -> Result<(), StoreError> {
    let write = database.begin_write().map_err(database_error)?;
    write.open_table(COMMIT_METADATA).map_err(database_error)?;
    write
        .open_table(SNAPSHOT_COVERAGE)
        .map_err(database_error)?;
    write.open_table(AUTHOR_SEQUENCES).map_err(database_error)?;
    write.open_table(AUTHOR_HEADS).map_err(database_error)?;
    write.open_table(FRONTIER).map_err(database_error)?;
    write
        .open_table(QUARANTINED_COMMITS)
        .map_err(database_error)?;
    write
        .open_table(QUARANTINED_AUTHORS)
        .map_err(database_error)?;
    write.open_table(SCHEMAS).map_err(database_error)?;
    write.open_table(RECORDS).map_err(database_error)?;
    write
        .open_table(RECORD_INDEX_KEYS)
        .map_err(database_error)?;
    write.open_table(SECONDARY_INDEX).map_err(database_error)?;
    write.open_table(TRUSTED_AUTHORS).map_err(database_error)?;
    write
        .open_table(DOMAIN_DESCRIPTORS)
        .map_err(database_error)?;
    write.open_table(CAPABILITIES).map_err(database_error)?;
    write
        .open_table(ACTIVE_CAPABILITIES)
        .map_err(database_error)?;
    write
        .open_table(REVOKED_CAPABILITIES)
        .map_err(database_error)?;
    write.open_table(CONTROL_HEADS).map_err(database_error)?;
    write.open_table(DEVICE_GROUPS).map_err(database_error)?;
    write
        .open_table(CONSUMED_INVITATIONS)
        .map_err(database_error)?;
    write.commit().map_err(database_error)
}

fn trusted_author_key(domain_id: DomainId, author: AuthorId) -> [u8; 64] {
    let mut key = [0_u8; 64];
    key[..32].copy_from_slice(domain_id.as_bytes());
    key[32..].copy_from_slice(author.as_bytes());
    key
}

fn active_capability_key(domain_id: DomainId, subject: AuthorId) -> [u8; 64] {
    let mut key = [0_u8; 64];
    key[..32].copy_from_slice(domain_id.as_bytes());
    key[32..].copy_from_slice(subject.as_bytes());
    key
}

fn device_group_key(domain_id: DomainId, label: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(32 + label.len());
    key.extend_from_slice(domain_id.as_bytes());
    key.extend_from_slice(label.as_bytes());
    key
}

fn insert_capability_tables(
    write: &redb::WriteTransaction,
    capability: &CapabilityCertificate,
    capability_id: CapabilityId,
    bytes: &[u8],
) -> Result<(), StoreError> {
    {
        let mut capabilities = write.open_table(CAPABILITIES).map_err(database_error)?;
        let existing = capabilities
            .get(capability_id.as_bytes().as_slice())
            .map_err(database_error)?
            .map(|value| value.value().to_vec());
        if existing.as_deref().is_some_and(|stored| stored != bytes) {
            return Err(StoreError::InvalidAuthority(
                "capability ID collision".into(),
            ));
        }
        capabilities
            .insert(capability_id.as_bytes().as_slice(), bytes)
            .map_err(database_error)?;
    }
    {
        let mut active = write
            .open_table(ACTIVE_CAPABILITIES)
            .map_err(database_error)?;
        let key = active_capability_key(capability.domain_id(), capability.subject());
        active
            .insert(key.as_slice(), capability_id.as_bytes().as_slice())
            .map_err(database_error)?;
    }
    Ok(())
}

#[allow(clippy::needless_pass_by_value)]
fn authority_error(error: impl std::fmt::Display) -> StoreError {
    StoreError::InvalidAuthority(error.to_string())
}

fn apply_materialized_records(
    write: &redb::WriteTransaction,
    domain_id: DomainId,
    mutations: &[MaterializedRecord],
) -> Result<(), StoreError> {
    for mutation in mutations {
        let collection_id = mutation.schema.collection_id();
        let schema_key = schema_key(domain_id, collection_id, mutation.schema.version());
        let schema_bytes = mutation.schema.encode_canonical();
        {
            let mut schemas = write.open_table(SCHEMAS).map_err(database_error)?;
            let existing = schemas
                .get(schema_key.as_slice())
                .map_err(database_error)?
                .map(|value| value.value().to_vec());
            if let Some(existing) = existing {
                if existing != schema_bytes {
                    return Err(StoreError::SchemaMismatch {
                        collection_id,
                        version: mutation.schema.version(),
                    });
                }
            } else {
                schemas
                    .insert(schema_key.as_slice(), schema_bytes.as_slice())
                    .map_err(database_error)?;
            }
        }

        for index in &mutation.indexes {
            let declared = mutation
                .schema
                .fields()
                .iter()
                .any(|field| field.id() == index.field_id && field.is_indexed());
            if !declared {
                return Err(StoreError::InvalidIndex {
                    collection_id,
                    field_id: index.field_id,
                });
            }
        }

        let record_key = record_key(domain_id, collection_id, &mutation.record_id);
        remove_record_indexes(write, &record_key)?;
        let mut records = write.open_table(RECORDS).map_err(database_error)?;
        match &mutation.state {
            Some(state) => {
                records
                    .insert(record_key.as_slice(), state.as_slice())
                    .map_err(database_error)?;
                let index_keys = mutation
                    .indexes
                    .iter()
                    .map(|index| {
                        index_key(
                            domain_id,
                            collection_id,
                            index.field_id,
                            &index.value,
                            &mutation.record_id,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let mut secondary = write.open_table(SECONDARY_INDEX).map_err(database_error)?;
                for key in &index_keys {
                    secondary
                        .insert(key.as_slice(), 0)
                        .map_err(database_error)?;
                }
                let encoded_keys = encode_key_list(&index_keys)?;
                let mut record_indexes = write
                    .open_table(RECORD_INDEX_KEYS)
                    .map_err(database_error)?;
                record_indexes
                    .insert(record_key.as_slice(), encoded_keys.as_slice())
                    .map_err(database_error)?;
            }
            None => {
                records
                    .remove(record_key.as_slice())
                    .map_err(database_error)?;
            }
        }
    }
    Ok(())
}

fn remove_record_indexes(
    write: &redb::WriteTransaction,
    record_key: &[u8],
) -> Result<(), StoreError> {
    let old_keys = {
        let record_indexes = write
            .open_table(RECORD_INDEX_KEYS)
            .map_err(database_error)?;
        record_indexes
            .get(record_key)
            .map_err(database_error)?
            .map(|value| value.value().to_vec())
    };
    if let Some(old_keys) = old_keys {
        let old_keys = decode_key_list(&old_keys)?;
        let mut secondary = write.open_table(SECONDARY_INDEX).map_err(database_error)?;
        for key in old_keys {
            secondary.remove(key.as_slice()).map_err(database_error)?;
        }
        let mut record_indexes = write
            .open_table(RECORD_INDEX_KEYS)
            .map_err(database_error)?;
        record_indexes.remove(record_key).map_err(database_error)?;
    }
    Ok(())
}

fn clear_materialized_domain(
    write: &redb::WriteTransaction,
    domain_id: DomainId,
) -> Result<(), StoreError> {
    {
        let mut table = write.open_table(SCHEMAS).map_err(database_error)?;
        let keys = table_keys_with_prefix(&table, domain_id.as_bytes())?;
        for key in keys {
            table.remove(key.as_slice()).map_err(database_error)?;
        }
    }
    {
        let mut table = write.open_table(RECORDS).map_err(database_error)?;
        let keys = table_keys_with_prefix(&table, domain_id.as_bytes())?;
        for key in keys {
            table.remove(key.as_slice()).map_err(database_error)?;
        }
    }
    {
        let mut table = write
            .open_table(RECORD_INDEX_KEYS)
            .map_err(database_error)?;
        let keys = table_keys_with_prefix(&table, domain_id.as_bytes())?;
        for key in keys {
            table.remove(key.as_slice()).map_err(database_error)?;
        }
    }
    {
        let mut table = write.open_table(SECONDARY_INDEX).map_err(database_error)?;
        let mut keys = Vec::new();
        for entry in table.iter().map_err(database_error)? {
            let (key, _) = entry.map_err(database_error)?;
            if key.value().starts_with(domain_id.as_bytes()) {
                keys.push(key.value().to_vec());
            }
        }
        for key in keys {
            table.remove(key.as_slice()).map_err(database_error)?;
        }
    }
    Ok(())
}

fn clear_domain_snapshot_metadata(
    write: &redb::WriteTransaction,
    domain_id: DomainId,
) -> Result<(), StoreError> {
    {
        let mut coverage = write
            .open_table(SNAPSHOT_COVERAGE)
            .map_err(database_error)?;
        let mut keys = Vec::new();
        for entry in coverage.iter().map_err(database_error)? {
            let (key, value) = entry.map_err(database_error)?;
            if value.value() == domain_id.as_bytes() {
                keys.push(key.value().to_vec());
            }
        }
        for key in keys {
            coverage.remove(key.as_slice()).map_err(database_error)?;
        }
    }
    {
        let mut frontier = write.open_table(FRONTIER).map_err(database_error)?;
        let keys = table_u8_keys_with_prefix(&frontier, domain_id.as_bytes())?;
        for key in keys {
            frontier.remove(key.as_slice()).map_err(database_error)?;
        }
    }
    {
        let mut sequences = write.open_table(AUTHOR_SEQUENCES).map_err(database_error)?;
        let mut keys = Vec::new();
        for entry in sequences.iter().map_err(database_error)? {
            let (key, _) = entry.map_err(database_error)?;
            if key.value().starts_with(domain_id.as_bytes()) {
                keys.push(key.value().to_vec());
            }
        }
        for key in keys {
            sequences.remove(key.as_slice()).map_err(database_error)?;
        }
    }
    {
        let mut heads = write.open_table(AUTHOR_HEADS).map_err(database_error)?;
        let keys = table_keys_with_prefix(&heads, domain_id.as_bytes())?;
        for key in keys {
            heads.remove(key.as_slice()).map_err(database_error)?;
        }
    }
    Ok(())
}

fn table_keys_with_prefix(
    table: &impl redb::ReadableTable<&'static [u8], &'static [u8]>,
    prefix: &[u8],
) -> Result<Vec<Vec<u8>>, StoreError> {
    let mut keys = Vec::new();
    for entry in table.iter().map_err(database_error)? {
        let (key, _) = entry.map_err(database_error)?;
        if key.value().starts_with(prefix) {
            keys.push(key.value().to_vec());
        }
    }
    Ok(keys)
}

fn table_u8_keys_with_prefix(
    table: &impl redb::ReadableTable<&'static [u8], u8>,
    prefix: &[u8],
) -> Result<Vec<Vec<u8>>, StoreError> {
    let mut keys = Vec::new();
    for entry in table.iter().map_err(database_error)? {
        let (key, _) = entry.map_err(database_error)?;
        if key.value().starts_with(prefix) {
            keys.push(key.value().to_vec());
        }
    }
    Ok(keys)
}

fn table_u64_keys_with_prefix(
    table: &impl redb::ReadableTable<&'static [u8], u64>,
    prefix: &[u8],
) -> Result<Vec<Vec<u8>>, StoreError> {
    let mut keys = Vec::new();
    for entry in table.iter().map_err(database_error)? {
        let (key, _) = entry.map_err(database_error)?;
        if key.value().starts_with(prefix) {
            keys.push(key.value().to_vec());
        }
    }
    Ok(keys)
}

fn decode_index_value(
    key: &[u8],
    domain_id: DomainId,
    collection_id: CollectionId,
    record_id: &[u8],
) -> Result<IndexValue, StoreError> {
    if key.len() < 76
        || !key.starts_with(domain_id.as_bytes())
        || key[32..64] != *collection_id.as_bytes()
    {
        return Err(StoreError::CorruptDerivedMetadata(
            "secondary index prefix is invalid".into(),
        ));
    }
    let field_id = u32::from_be_bytes(
        key[64..68]
            .try_into()
            .map_err(|_| StoreError::CorruptDerivedMetadata("index field is invalid".into()))?,
    );
    let value_len = read_u32(&key[68..72])?;
    let value_end = 72_usize
        .checked_add(value_len)
        .ok_or_else(|| StoreError::CorruptDerivedMetadata("index value overflow".into()))?;
    if key.len() < value_end + 4 {
        return Err(StoreError::CorruptDerivedMetadata(
            "secondary index value is truncated".into(),
        ));
    }
    let record_len = read_u32(&key[value_end..value_end + 4])?;
    if key.len() != value_end + 4 + record_len || &key[value_end + 4..] != record_id {
        return Err(StoreError::CorruptDerivedMetadata(
            "secondary index record ID is invalid".into(),
        ));
    }
    Ok(IndexValue::new(field_id, key[72..value_end].to_vec()))
}

fn schema_key(domain_id: DomainId, collection_id: CollectionId, version: u32) -> [u8; 68] {
    let mut key = [0_u8; 68];
    key[..32].copy_from_slice(domain_id.as_bytes());
    key[32..64].copy_from_slice(collection_id.as_bytes());
    key[64..].copy_from_slice(&version.to_be_bytes());
    key
}

fn record_prefix(domain_id: DomainId, collection_id: CollectionId) -> [u8; 64] {
    let mut prefix = [0_u8; 64];
    prefix[..32].copy_from_slice(domain_id.as_bytes());
    prefix[32..].copy_from_slice(collection_id.as_bytes());
    prefix
}

fn record_key(domain_id: DomainId, collection_id: CollectionId, record_id: &[u8]) -> Vec<u8> {
    let prefix = record_prefix(domain_id, collection_id);
    let mut key = Vec::with_capacity(prefix.len() + record_id.len());
    key.extend_from_slice(&prefix);
    key.extend_from_slice(record_id);
    key
}

fn index_value_prefix(
    domain_id: DomainId,
    collection_id: CollectionId,
    field_id: u32,
    value: &[u8],
) -> Result<Vec<u8>, StoreError> {
    let value_len = u32::try_from(value.len())
        .map_err(|_| StoreError::CorruptDerivedMetadata("index value length exceeds u32".into()))?;
    let mut key = Vec::with_capacity(72 + value.len());
    key.extend_from_slice(domain_id.as_bytes());
    key.extend_from_slice(collection_id.as_bytes());
    key.extend_from_slice(&field_id.to_be_bytes());
    key.extend_from_slice(&value_len.to_be_bytes());
    key.extend_from_slice(value);
    Ok(key)
}

fn index_key(
    domain_id: DomainId,
    collection_id: CollectionId,
    field_id: u32,
    value: &[u8],
    record_id: &[u8],
) -> Result<Vec<u8>, StoreError> {
    let mut key = index_value_prefix(domain_id, collection_id, field_id, value)?;
    let record_len = u32::try_from(record_id.len())
        .map_err(|_| StoreError::CorruptDerivedMetadata("record ID length exceeds u32".into()))?;
    key.extend_from_slice(&record_len.to_be_bytes());
    key.extend_from_slice(record_id);
    Ok(key)
}

fn encode_key_list(keys: &[Vec<u8>]) -> Result<Vec<u8>, StoreError> {
    let count = u32::try_from(keys.len())
        .map_err(|_| StoreError::CorruptDerivedMetadata("too many index keys".into()))?;
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&count.to_be_bytes());
    for key in keys {
        let length = u32::try_from(key.len()).map_err(|_| {
            StoreError::CorruptDerivedMetadata("index key length exceeds u32".into())
        })?;
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend_from_slice(key);
    }
    Ok(encoded)
}

fn decode_key_list(bytes: &[u8]) -> Result<Vec<Vec<u8>>, StoreError> {
    if bytes.len() < 4 {
        return Err(StoreError::CorruptDerivedMetadata(
            "index key list count is missing".into(),
        ));
    }
    let count = read_u32(&bytes[..4])?;
    let mut offset = 4;
    let mut keys = Vec::with_capacity(count);
    for _ in 0..count {
        if bytes.len().saturating_sub(offset) < 4 {
            return Err(StoreError::CorruptDerivedMetadata(
                "index key length is missing".into(),
            ));
        }
        let length = read_u32(&bytes[offset..offset + 4])?;
        offset += 4;
        if bytes.len().saturating_sub(offset) < length {
            return Err(StoreError::CorruptDerivedMetadata(
                "index key bytes are truncated".into(),
            ));
        }
        keys.push(bytes[offset..offset + length].to_vec());
        offset += length;
    }
    if offset != bytes.len() {
        return Err(StoreError::CorruptDerivedMetadata(
            "index key list has trailing data".into(),
        ));
    }
    Ok(keys)
}

fn read_u32(bytes: &[u8]) -> Result<usize, StoreError> {
    let bytes: [u8; 4] = bytes
        .try_into()
        .map_err(|_| StoreError::CorruptDerivedMetadata("expected a four-byte length".into()))?;
    usize::try_from(u32::from_be_bytes(bytes)).map_err(|error| {
        StoreError::CorruptDerivedMetadata(format!("invalid platform length: {error}"))
    })
}

fn author_sequence_key(domain_id: DomainId, author: AuthorId) -> [u8; 64] {
    let mut key = [0_u8; 64];
    key[..32].copy_from_slice(domain_id.as_bytes());
    key[32..].copy_from_slice(author.as_bytes());
    key
}

fn frontier_key(domain_id: DomainId, commit_id: CommitId) -> [u8; 64] {
    let mut key = [0_u8; 64];
    key[..32].copy_from_slice(domain_id.as_bytes());
    key[32..].copy_from_slice(commit_id.as_bytes());
    key
}

fn encode_metadata(envelope: &CommitEnvelope) -> Vec<u8> {
    let mut metadata = Vec::with_capacity(112);
    metadata.extend_from_slice(envelope.header().domain_id().as_bytes());
    metadata.extend_from_slice(envelope.header().author().as_bytes());
    metadata.extend_from_slice(&envelope.header().epoch().to_be_bytes());
    metadata.extend_from_slice(&envelope.header().author_sequence().to_be_bytes());
    metadata.extend_from_slice(envelope.header().capability_id().as_bytes());
    metadata
}

// Error conversion consumes std's typed error while only retaining safe display text.
#[allow(clippy::needless_pass_by_value)]
fn io_error(error: std::io::Error) -> StoreError {
    StoreError::Io(error.to_string())
}

// Error conversion consumes redb's typed errors while only retaining safe display text.
#[allow(clippy::needless_pass_by_value)]
fn database_error(error: impl std::fmt::Display) -> StoreError {
    StoreError::Database(error.to_string())
}
