use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    path::Path,
    sync::{Arc, Mutex},
};

use fs2::FileExt as _;
use iroh_db_core::{
    AuthorId, BlobHash, CapabilityId, CollectionId, CommitCodecError, CommitEnvelope, CommitId,
    DomainId, MigrationCodecError, MigrationId, SchemaActivation, SchemaDescriptor, SchemaError,
    SchemaStage, VersionVector, staging_digest,
};
use iroh_db_security::{
    AuthorityCheckpoint, CapabilityCertificate, ControlTransition, DomainDescriptor, Invitation,
    Permission,
};
use redb::{Database, ReadableDatabase as _, ReadableTable as _, TableDefinition};

use crate::{BlobStore, BlobStoreError, IndexValue, MaterializedRecord, StoredRecord};

const FORMAT_V5: &str = "iroh-db 5.0\n";
const FORMAT_CONTENTS: &str = "iroh-db 6.0\n";
const SNAPSHOT_BASELINE_VERSION: u16 = 1;
const MAX_SNAPSHOT_BASELINE_BYTES: usize = 8 * 1024 * 1024;
const MAX_SNAPSHOT_BASELINE_ENTRIES: usize = 65_536;
const COMMIT_METADATA: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("commit_metadata_v1");
const COMMIT_CONTEXTS: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("commit_contexts_v1");
const RECORD_HEADS: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("record_heads_v1");
const RECONCILIATION_READY: TableDefinition<'static, &[u8], u8> =
    TableDefinition::new("reconciliation_ready_v1");
const SNAPSHOT_COVERAGE: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("snapshot_coverage_v1");
const SNAPSHOT_BASELINES: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("snapshot_baselines_v1");
const BLOB_OWNERSHIP: TableDefinition<'static, &[u8], u8> =
    TableDefinition::new("blob_ownership_v1");
const AUTHOR_SEQUENCES: TableDefinition<'static, &[u8], u64> =
    TableDefinition::new("author_sequences_v1");
const AUTHOR_COMMITS: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("author_commits_v1");
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
const SUBJECT_REVOCATIONS: TableDefinition<'static, &[u8], u64> =
    TableDefinition::new("subject_revocations_v1");
const AUTHORITY_CHECKPOINTS: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("authority_checkpoints_v1");
const CONTROL_HEADS: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("control_heads_v1");
const CONTROL_OBJECTS: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("control_objects_v1");
const CONTROL_SLOTS: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("control_slots_v1");
const CONTROL_FORKS: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("control_forks_v1");
const DEVICE_GROUPS: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("device_groups_v1");
const CONSUMED_INVITATIONS: TableDefinition<'static, &[u8], u8> =
    TableDefinition::new("consumed_invitations_v1");
const ACTIVE_SCHEMAS: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("active_schemas_v1");
const MIGRATION_STAGES: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("migration_stages_v1");
const MIGRATION_ACTIVATIONS: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("migration_activations_v1");
const MIGRATION_CHECKPOINTS: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("migration_checkpoints_v1");
const MIGRATION_FORKS: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("migration_forks_v1");
const OPERATIONAL_METADATA: TableDefinition<'static, &[u8], u64> =
    TableDefinition::new("operational_metadata_v1");
const SNAPSHOT_OBSERVED_AT_TAG: u8 = 1;

/// The result of durably recording an immutable commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// The commit blob and metadata became durable.
    Applied(CommitId),
    /// The exact commit was already durable; no metadata changed.
    Duplicate(CommitId),
}

/// One immutable operation that remains a causal head for a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordHead {
    commit_id: CommitId,
    author: AuthorId,
    sequence: u64,
    mutation: MaterializedRecord,
}

impl RecordHead {
    /// Constructs a durable record-head entry from an authenticated commit operation.
    pub fn new(
        commit_id: CommitId,
        author: AuthorId,
        sequence: u64,
        mutation: MaterializedRecord,
    ) -> Self {
        Self {
            commit_id,
            author,
            sequence,
            mutation,
        }
    }

    pub const fn commit_id(&self) -> CommitId {
        self.commit_id
    }

    pub const fn author(&self) -> AuthorId {
        self.author
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn mutation(&self) -> &MaterializedRecord {
        &self.mutation
    }
}

/// Complete replacement set for one record's rebuildable causal heads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordHeadSet {
    collection_id: CollectionId,
    record_id: Vec<u8>,
    heads: Vec<RecordHead>,
}

impl RecordHeadSet {
    pub fn new(
        collection_id: CollectionId,
        record_id: Vec<u8>,
        heads: Vec<RecordHead>,
    ) -> Result<Self, StoreError> {
        if heads.is_empty()
            || heads.iter().any(|head| {
                head.mutation.schema().collection_id() != collection_id
                    || head.mutation.record_id() != record_id
            })
        {
            return Err(StoreError::CorruptDerivedMetadata(
                "record head replacement has inconsistent targets".into(),
            ));
        }
        Ok(Self {
            collection_id,
            record_id,
            heads,
        })
    }

    pub const fn collection_id(&self) -> CollectionId {
        self.collection_id
    }

    pub fn record_id(&self) -> &[u8] {
        &self.record_id
    }

    pub fn heads(&self) -> &[RecordHead] {
        &self.heads
    }
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
    /// A canonical schema migration object was invalid.
    #[error(transparent)]
    Migration(#[from] MigrationCodecError),
    /// Migration-derived state did not match its immutable commit history.
    #[error("schema migration metadata is invalid: {0}")]
    InvalidMigration(String),
    /// Two activation commits attempted different successors for one schema.
    #[error("collection {collection_id} is frozen by incompatible schema activations")]
    SchemaMigrationFork { collection_id: CollectionId },
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
    /// A snapshot supplied a noncanonical or inconsistent causal baseline.
    #[error("snapshot metadata is invalid: {0}")]
    InvalidSnapshotMetadata(String),
    /// A signed domain authority object failed validation or conflicted with durable state.
    #[error("domain authority metadata is invalid: {0}")]
    InvalidAuthority(String),
    /// The designated controller signed two different successors for one control slot.
    #[error(
        "domain {domain} is frozen by conflicting control transitions {first:?} and {second:?}"
    )]
    ControlFork {
        /// Security domain whose controller equivocated.
        domain: DomainId,
        /// Lexicographically first transition ID.
        first: [u8; 32],
        /// Lexicographically second transition ID.
        second: [u8; 32],
    },
}

/// Canonical durable reference to the immutable signed snapshot used as a history baseline.
#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
pub struct SnapshotBaseline {
    #[n(0)]
    version: u16,
    #[n(1)]
    domain_id: DomainId,
    #[n(2)]
    epoch: u64,
    #[n(3)]
    manifest_hash: BlobHash,
    #[n(4)]
    state_root: [u8; 32],
    #[n(5)]
    frontier: Vec<CommitId>,
    #[n(6)]
    author_sequences: Vec<(AuthorId, u64)>,
}

impl SnapshotBaseline {
    pub fn new(
        domain_id: DomainId,
        epoch: u64,
        manifest_hash: BlobHash,
        state_root: [u8; 32],
        frontier: Vec<CommitId>,
        author_sequences: Vec<(AuthorId, u64)>,
    ) -> Result<Self, StoreError> {
        let baseline = Self {
            version: SNAPSHOT_BASELINE_VERSION,
            domain_id,
            epoch,
            manifest_hash,
            state_root,
            frontier,
            author_sequences,
        };
        baseline.validate()?;
        Ok(baseline)
    }

    pub const fn domain_id(&self) -> DomainId {
        self.domain_id
    }
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
    pub const fn manifest_hash(&self) -> BlobHash {
        self.manifest_hash
    }
    pub const fn state_root(&self) -> [u8; 32] {
        self.state_root
    }
    pub fn frontier(&self) -> &[CommitId] {
        &self.frontier
    }
    pub fn author_sequences(&self) -> &[(AuthorId, u64)] {
        &self.author_sequences
    }

    fn encode_canonical(&self) -> Result<Vec<u8>, StoreError> {
        minicbor::to_vec(self).map_err(|error| StoreError::Database(error.to_string()))
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() > MAX_SNAPSHOT_BASELINE_BYTES {
            return Err(StoreError::CorruptDerivedMetadata(
                "snapshot baseline exceeds encoded size limit".into(),
            ));
        }
        let mut decoder = minicbor::Decoder::new(bytes);
        let baseline: Self = decoder.decode().map_err(|error| {
            StoreError::CorruptDerivedMetadata(format!("snapshot baseline: {error}"))
        })?;
        baseline.validate()?;
        if decoder.position() != bytes.len() || baseline.encode_canonical()? != bytes {
            return Err(StoreError::CorruptDerivedMetadata(
                "snapshot baseline is not canonical".into(),
            ));
        }
        Ok(baseline)
    }

    fn validate(&self) -> Result<(), StoreError> {
        if self.version != SNAPSHOT_BASELINE_VERSION
            || self.frontier.len() > MAX_SNAPSHOT_BASELINE_ENTRIES
            || self.author_sequences.len() > MAX_SNAPSHOT_BASELINE_ENTRIES
            || !strictly_sorted(&self.frontier)
            || !self
                .author_sequences
                .windows(2)
                .all(|pair| pair[0].0 < pair[1].0)
            || self.frontier.is_empty() != self.author_sequences.is_empty()
        {
            return Err(StoreError::InvalidSnapshotMetadata(
                "snapshot recovery baseline is malformed".into(),
            ));
        }
        Ok(())
    }
}

/// Transactional metadata paired with an immutable content-addressed blob repository.
#[derive(Clone)]
pub struct Store {
    inner: Arc<StoreInner>,
}

struct StoreInner {
    database: Database,
    blobs: Arc<dyn BlobStore>,
    control_writer: Mutex<()>,
    _lock: File,
}

impl Store {
    /// Opens or creates a local store directory and acquires its writer lock.
    pub fn open(root: impl AsRef<Path>, blobs: Arc<dyn BlobStore>) -> Result<Self, StoreError> {
        let root = root.as_ref();
        std::fs::create_dir_all(root).map_err(io_error)?;
        std::fs::create_dir_all(root.join("locks")).map_err(io_error)?;
        std::fs::create_dir_all(root.join("tmp")).map_err(io_error)?;

        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(root.join("locks/writer.lock"))
            .map_err(io_error)?;
        lock.try_lock_exclusive()
            .map_err(|_| StoreError::AlreadyOpen)?;

        prepare_store_format(root)?;

        let database = Database::create(root.join("meta-v6.redb")).map_err(database_error)?;
        initialize_tables(&database)?;
        Ok(Self {
            inner: Arc::new(StoreInner {
                database,
                blobs,
                control_writer: Mutex::new(()),
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
        self.persist_commit_components(envelope, records, &[], None, None)
            .await
    }

    /// Persists a record commit and atomically advances its incremental causal index.
    pub async fn persist_commit_with_reconciliation(
        &self,
        envelope: &CommitEnvelope,
        records: &[MaterializedRecord],
        context: &VersionVector,
        record_heads: &[RecordHeadSet],
    ) -> Result<ApplyOutcome, StoreError> {
        self.persist_commit_components(envelope, records, &[], None, Some((context, record_heads)))
            .await
    }

    async fn persist_commit_components(
        &self,
        envelope: &CommitEnvelope,
        records: &[MaterializedRecord],
        stages: &[SchemaStage],
        activation: Option<&SchemaActivation>,
        reconciliation: Option<(&VersionVector, &[RecordHeadSet])>,
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

        self.publish_commit_components(
            envelope,
            records,
            stages,
            activation,
            previous_author_head,
            reconciliation,
        )
    }

    /// Persists an invisible bounded set of migration stages with its immutable commit.
    pub async fn persist_schema_stages(
        &self,
        envelope: &CommitEnvelope,
        stages: &[SchemaStage],
    ) -> Result<ApplyOutcome, StoreError> {
        if stages.is_empty() {
            return Err(StoreError::InvalidMigration(
                "a staging commit must contain at least one stage".into(),
            ));
        }
        let commit_id = envelope.commit_id();
        let previous_author_head = match self.commit_preflight(envelope).await? {
            CommitPreflight::Duplicate(commit_id) => return Ok(ApplyOutcome::Duplicate(commit_id)),
            CommitPreflight::Ready {
                previous_author_head,
            } => previous_author_head,
        };
        let expected = BlobHash::from_bytes(commit_id.to_bytes());
        if self.inner.blobs.put(envelope.encode_canonical()).await? != expected {
            return Err(StoreError::BlobHashMismatch);
        }
        self.publish_commit_components(envelope, &[], stages, None, previous_author_head, None)
    }

    /// Atomically publishes a completely staged schema transition with its commit.
    pub async fn persist_schema_activation(
        &self,
        envelope: &CommitEnvelope,
        activation: &SchemaActivation,
    ) -> Result<ApplyOutcome, StoreError> {
        let commit_id = envelope.commit_id();
        let previous_author_head = match self.commit_preflight(envelope).await? {
            CommitPreflight::Duplicate(commit_id) => return Ok(ApplyOutcome::Duplicate(commit_id)),
            CommitPreflight::Ready {
                previous_author_head,
            } => previous_author_head,
        };
        let expected = BlobHash::from_bytes(commit_id.to_bytes());
        if self.inner.blobs.put(envelope.encode_canonical()).await? != expected {
            return Err(StoreError::BlobHashMismatch);
        }
        self.publish_commit_components(
            envelope,
            &[],
            &[],
            Some(activation),
            previous_author_head,
            None,
        )
    }

    /// Persists schema stages while atomically advancing the causal commit index.
    pub async fn persist_schema_stages_with_context(
        &self,
        envelope: &CommitEnvelope,
        stages: &[SchemaStage],
        context: &VersionVector,
    ) -> Result<ApplyOutcome, StoreError> {
        if stages.is_empty() {
            return Err(StoreError::InvalidMigration(
                "a staging commit must contain at least one stage".into(),
            ));
        }
        self.persist_commit_components(envelope, &[], stages, None, Some((context, &[])))
            .await
    }

    /// Persists schema activation while atomically advancing the causal commit index.
    pub async fn persist_schema_activation_with_context(
        &self,
        envelope: &CommitEnvelope,
        activation: &SchemaActivation,
        context: &VersionVector,
    ) -> Result<ApplyOutcome, StoreError> {
        self.persist_commit_components(envelope, &[], &[], Some(activation), Some((context, &[])))
            .await
    }

    #[allow(clippy::too_many_lines)]
    fn publish_commit_components(
        &self,
        envelope: &CommitEnvelope,
        records: &[MaterializedRecord],
        stages: &[SchemaStage],
        activation: Option<&SchemaActivation>,
        previous_author_head: Option<CommitId>,
        reconciliation: Option<(&VersionVector, &[RecordHeadSet])>,
    ) -> Result<ApplyOutcome, StoreError> {
        let commit_id = envelope.commit_id();
        let write = self.inner.database.begin_write().map_err(database_error)?;
        let mut migration_fork: Option<CollectionId>;
        {
            let mut commits = write.open_table(COMMIT_METADATA).map_err(database_error)?;
            let coverage = write
                .open_table(SNAPSHOT_COVERAGE)
                .map_err(database_error)?;
            let quarantined = write
                .open_table(QUARANTINED_COMMITS)
                .map_err(database_error)?;
            if commits
                .get(commit_id.as_bytes().as_slice())
                .map_err(database_error)?
                .is_some()
            {
                return Ok(ApplyOutcome::Duplicate(commit_id));
            }

            for dependency in envelope.header().dependencies() {
                if !dependency_is_accepted(
                    &commits,
                    &coverage,
                    &quarantined,
                    envelope.header().domain_id(),
                    *dependency,
                )? {
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
            write
                .open_table(AUTHOR_COMMITS)
                .map_err(database_error)?
                .insert(
                    author_commit_key(
                        envelope.header().domain_id(),
                        envelope.header().author(),
                        envelope.header().author_sequence(),
                    )
                    .as_slice(),
                    commit_id.as_bytes().as_slice(),
                )
                .map_err(database_error)?;
            author_heads
                .insert(author_key.as_slice(), commit_id.as_bytes().as_slice())
                .map_err(database_error)?;

            publish_frontier(&write, envelope.header().domain_id(), envelope, commit_id)?;

            apply_materialized_records(&write, envelope.header().domain_id(), records)?;
            match reconciliation {
                Some((context, record_heads)) => {
                    apply_reconciliation_update(&write, envelope, context, record_heads)?;
                }
                None => mark_reconciliation_stale(&write, envelope.header().domain_id())?,
            }
            migration_fork = apply_schema_stages(&write, envelope.header().domain_id(), stages)?;
            if migration_fork.is_none()
                && let Some(activation) = activation
                && apply_schema_activation(&write, envelope.header().domain_id(), activation)?
            {
                migration_fork = Some(activation.to().collection_id());
            }
        }
        write.commit().map_err(database_error)?;
        if let Some(collection_id) = migration_fork {
            return Err(StoreError::SchemaMigrationFork { collection_id });
        }
        Ok(ApplyOutcome::Applied(commit_id))
    }

    /// Returns the active schema activation for a collection, if it has migrated.
    pub fn active_schema_activation(
        &self,
        domain_id: DomainId,
        collection_id: CollectionId,
    ) -> Result<Option<SchemaActivation>, StoreError> {
        if self.migration_frozen(domain_id, collection_id)? {
            return Err(StoreError::SchemaMigrationFork { collection_id });
        }
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let table = read.open_table(ACTIVE_SCHEMAS).map_err(database_error)?;
        table
            .get(active_schema_key(domain_id, collection_id).as_slice())
            .map_err(database_error)?
            .map(|value| {
                SchemaActivation::decode_canonical(value.value()).map_err(StoreError::from)
            })
            .transpose()
    }

    /// Lists active schema cuts for a domain in collection order.
    pub fn active_schema_activations(
        &self,
        domain_id: DomainId,
    ) -> Result<Vec<SchemaActivation>, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let forks = read.open_table(MIGRATION_FORKS).map_err(database_error)?;
        if !table_keys_with_prefix(&forks, domain_id.as_bytes())?.is_empty() {
            return Err(StoreError::InvalidMigration(
                "domain contains a frozen schema activation fork".into(),
            ));
        }
        let table = read.open_table(ACTIVE_SCHEMAS).map_err(database_error)?;
        let mut activations = Vec::new();
        for entry in table.iter().map_err(database_error)? {
            let (key, value) = entry.map_err(database_error)?;
            if key.value().starts_with(domain_id.as_bytes()) {
                activations.push(SchemaActivation::decode_canonical(value.value())?);
            }
        }
        activations.sort_unstable_by_key(|activation| activation.to().collection_id());
        Ok(activations)
    }

    /// Returns whether incompatible activation siblings froze a collection.
    pub fn migration_frozen(
        &self,
        domain_id: DomainId,
        collection_id: CollectionId,
    ) -> Result<bool, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let table = read.open_table(MIGRATION_FORKS).map_err(database_error)?;
        Ok(table
            .get(active_schema_key(domain_id, collection_id).as_slice())
            .map_err(database_error)?
            .is_some())
    }

    /// Returns low-cardinality active, staged-record, and frozen migration counts.
    pub fn migration_counts(
        &self,
        domain_id: DomainId,
    ) -> Result<(usize, usize, usize), StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let active = read.open_table(ACTIVE_SCHEMAS).map_err(database_error)?;
        let stages = read.open_table(MIGRATION_STAGES).map_err(database_error)?;
        let forks = read.open_table(MIGRATION_FORKS).map_err(database_error)?;
        Ok((
            table_keys_with_prefix(&active, domain_id.as_bytes())?.len(),
            table_keys_with_prefix(&stages, domain_id.as_bytes())?.len(),
            table_keys_with_prefix(&forks, domain_id.as_bytes())?.len(),
        ))
    }

    /// Records when this device last created or installed a verified snapshot.
    pub fn record_snapshot_observed_at(
        &self,
        domain_id: DomainId,
        unix_seconds: u64,
    ) -> Result<(), StoreError> {
        let write = self.inner.database.begin_write().map_err(database_error)?;
        {
            let mut table = write
                .open_table(OPERATIONAL_METADATA)
                .map_err(database_error)?;
            table
                .insert(
                    operational_metadata_key(domain_id, SNAPSHOT_OBSERVED_AT_TAG).as_slice(),
                    unix_seconds,
                )
                .map_err(database_error)?;
        }
        write.commit().map_err(database_error)
    }

    /// Returns the durable local observation time of the newest verified snapshot.
    pub fn snapshot_observed_at(&self, domain_id: DomainId) -> Result<Option<u64>, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let table = read
            .open_table(OPERATIONAL_METADATA)
            .map_err(database_error)?;
        Ok(table
            .get(operational_metadata_key(domain_id, SNAPSHOT_OBSERVED_AT_TAG).as_slice())
            .map_err(database_error)?
            .map(|value| value.value()))
    }

    /// Loads every durable stage for one migration in source-key order.
    pub fn schema_stages(
        &self,
        domain_id: DomainId,
        migration_id: MigrationId,
    ) -> Result<Vec<SchemaStage>, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let table = read.open_table(MIGRATION_STAGES).map_err(database_error)?;
        load_schema_stages(&table, domain_id, migration_id)
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
        if self.contains_commit(envelope.header().domain_id(), commit_id)? {
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
                .dependencies_include_ancestor(
                    envelope.header().domain_id(),
                    envelope.header().dependencies(),
                    previous,
                )
                .await?
        {
            return Err(StoreError::AuthorChainMissing { previous });
        }
        if let Some(baseline) = self.snapshot_baseline(envelope.header().domain_id())?
            && baseline
                .author_sequences()
                .iter()
                .any(|(author, _)| *author == envelope.header().author())
        {
            for &frontier in baseline.frontier() {
                if !self
                    .dependencies_include_ancestor(
                        envelope.header().domain_id(),
                        envelope.header().dependencies(),
                        frontier,
                    )
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
    pub fn contains_commit(
        &self,
        domain_id: DomainId,
        commit_id: CommitId,
    ) -> Result<bool, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let commits = read.open_table(COMMIT_METADATA).map_err(database_error)?;
        let coverage = read.open_table(SNAPSHOT_COVERAGE).map_err(database_error)?;
        let quarantined = read
            .open_table(QUARANTINED_COMMITS)
            .map_err(database_error)?;
        let stored = commits
            .get(commit_id.as_bytes().as_slice())
            .map_err(database_error)?
            .is_some_and(|metadata| metadata.value().starts_with(domain_id.as_bytes()))
            && quarantined
                .get(commit_id.as_bytes().as_slice())
                .map_err(database_error)?
                .is_none();
        let snapshotted = coverage
            .get(commit_id.as_bytes().as_slice())
            .map_err(database_error)?
            .is_some_and(|covered_domain| covered_domain.value() == domain_id.as_bytes());
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
        author_sequences: &[(AuthorId, u64)],
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
        clear_reconciliation_domain(&write, domain_id)?;
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
            for (author, sequence) in author_sequences {
                let key = author_sequence_key(domain_id, *author);
                sequences
                    .insert(key.as_slice(), *sequence)
                    .map_err(database_error)?;
            }
            for (author, _, commit_id) in author_heads {
                let key = author_sequence_key(domain_id, *author);
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
        if self
            .last_sequence(domain_id, author)?
            .is_none_or(|last| sequence > last)
        {
            return Ok(None);
        }
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let author_commits = read.open_table(AUTHOR_COMMITS).map_err(database_error)?;
        let author_key = author_commit_key(domain_id, author, sequence);
        if let Some(value) = author_commits
            .get(author_key.as_slice())
            .map_err(database_error)?
        {
            let bytes: [u8; 32] = value.value().try_into().map_err(|_| {
                StoreError::CorruptDerivedMetadata("author commit ID is invalid".into())
            })?;
            let commit_id = CommitId::from_bytes(bytes);
            return if self.is_commit_quarantined(commit_id)? {
                Ok(None)
            } else {
                Ok(Some(commit_id))
            };
        }
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
        domain_id: DomainId,
        dependencies: &[CommitId],
        ancestor: CommitId,
    ) -> Result<bool, StoreError> {
        if self.reconciliation_index_ready(domain_id)? {
            if dependencies.contains(&ancestor) {
                return Ok(true);
            }
            let read = self.inner.database.begin_read().map_err(database_error)?;
            let commits = read.open_table(COMMIT_METADATA).map_err(database_error)?;
            let Some(metadata) = commits
                .get(ancestor.as_bytes().as_slice())
                .map_err(database_error)?
            else {
                return Ok(false);
            };
            if metadata.value().len() != 112 || !metadata.value().starts_with(domain_id.as_bytes())
            {
                return Err(StoreError::CorruptDerivedMetadata(
                    "ancestor commit metadata is invalid".into(),
                ));
            }
            let author: [u8; 32] = metadata.value()[32..64].try_into().map_err(|_| {
                StoreError::CorruptDerivedMetadata("ancestor author is invalid".into())
            })?;
            let sequence =
                u64::from_be_bytes(metadata.value()[72..80].try_into().map_err(|_| {
                    StoreError::CorruptDerivedMetadata("ancestor sequence is invalid".into())
                })?);
            let dot = iroh_db_core::Dot::new(AuthorId::from_bytes(author), sequence, 0);
            drop(metadata);
            drop(commits);
            drop(read);
            let baseline = self.snapshot_baseline(domain_id)?;
            for dependency in dependencies {
                if self
                    .commit_context(domain_id, *dependency)?
                    .is_some_and(|context| context.covers(&dot))
                {
                    return Ok(true);
                }
                if self.contains_commit(domain_id, *dependency)?
                    && baseline.as_ref().is_some_and(|baseline| {
                        baseline
                            .author_sequences()
                            .iter()
                            .any(|(author, sequence)| {
                                *author == dot.author() && *sequence >= dot.sequence()
                            })
                    })
                {
                    return Ok(true);
                }
            }
            return Ok(false);
        }
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
                Ok(envelope) if envelope.header().domain_id() == domain_id => {
                    pending.extend_from_slice(envelope.header().dependencies());
                }
                Ok(_) => return Ok(false),
                Err(StoreError::MissingCommitBlob(_))
                    if self.contains_commit(domain_id, commit_id)? =>
                {
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

    /// Returns whether the rebuildable causal and record-head indexes are complete.
    pub fn reconciliation_index_ready(&self, domain_id: DomainId) -> Result<bool, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let ready = read
            .open_table(RECONCILIATION_READY)
            .map_err(database_error)?;
        Ok(ready
            .get(domain_id.as_bytes().as_slice())
            .map_err(database_error)?
            .is_some())
    }

    /// Loads the inclusive causal context cached for one accepted commit.
    pub fn commit_context(
        &self,
        domain_id: DomainId,
        commit_id: CommitId,
    ) -> Result<Option<VersionVector>, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let contexts = read.open_table(COMMIT_CONTEXTS).map_err(database_error)?;
        let key = commit_context_key(domain_id, commit_id);
        contexts
            .get(key.as_slice())
            .map_err(database_error)?
            .map(|value| decode_version_vector(value.value()))
            .transpose()
    }

    /// Loads only the current causal heads for one materialized record.
    pub fn record_heads(
        &self,
        domain_id: DomainId,
        collection_id: CollectionId,
        record_id: &[u8],
    ) -> Result<Vec<RecordHead>, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let heads = read.open_table(RECORD_HEADS).map_err(database_error)?;
        let prefix = record_head_prefix(domain_id, collection_id, record_id)?;
        let mut result = Vec::new();
        for entry in heads.range(prefix.as_slice()..).map_err(database_error)? {
            let (key, value) = entry.map_err(database_error)?;
            if !key.value().starts_with(&prefix) {
                break;
            }
            if key.value().len() != prefix.len() + 32 {
                return Err(StoreError::CorruptDerivedMetadata(
                    "record head key has an invalid commit ID".into(),
                ));
            }
            let commit: [u8; 32] = key.value()[prefix.len()..].try_into().map_err(|_| {
                StoreError::CorruptDerivedMetadata(
                    "record head commit ID has an invalid length".into(),
                )
            })?;
            result.push(decode_record_head(
                CommitId::from_bytes(commit),
                value.value(),
            )?);
        }
        result.sort_unstable_by_key(RecordHead::commit_id);
        Ok(result)
    }

    /// Atomically replaces the complete rebuildable reconciliation index for a domain.
    pub fn replace_reconciliation_index(
        &self,
        domain_id: DomainId,
        contexts: &[(CommitId, VersionVector)],
        heads: &[RecordHead],
    ) -> Result<(), StoreError> {
        let write = self.inner.database.begin_write().map_err(database_error)?;
        clear_reconciliation_domain(&write, domain_id)?;
        {
            let mut table = write.open_table(COMMIT_CONTEXTS).map_err(database_error)?;
            for (commit_id, context) in contexts {
                let key = commit_context_key(domain_id, *commit_id);
                let encoded = encode_version_vector(context)?;
                table
                    .insert(key.as_slice(), encoded.as_slice())
                    .map_err(database_error)?;
            }
        }
        {
            let mut table = write.open_table(RECORD_HEADS).map_err(database_error)?;
            for head in heads {
                let key = record_head_key(domain_id, head)?;
                let value = encode_record_head(head)?;
                table
                    .insert(key.as_slice(), value.as_slice())
                    .map_err(database_error)?;
            }
        }
        write
            .open_table(RECONCILIATION_READY)
            .map_err(database_error)?
            .insert(domain_id.as_bytes().as_slice(), 1)
            .map_err(database_error)?;
        write.commit().map_err(database_error)
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

    /// Loads the highest registered schema version for one collection.
    pub fn latest_registered_schema(
        &self,
        domain_id: DomainId,
        collection_id: CollectionId,
    ) -> Result<Option<SchemaDescriptor>, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let schemas = read.open_table(SCHEMAS).map_err(database_error)?;
        let mut prefix = [0_u8; 64];
        prefix[..32].copy_from_slice(domain_id.as_bytes());
        prefix[32..].copy_from_slice(collection_id.as_bytes());
        let mut latest: Option<SchemaDescriptor> = None;
        for entry in schemas.iter().map_err(database_error)? {
            let (key, value) = entry.map_err(database_error)?;
            if !key.value().starts_with(&prefix) {
                continue;
            }
            let schema = SchemaDescriptor::decode_canonical(value.value())?;
            if latest
                .as_ref()
                .is_none_or(|current| schema.version() > current.version())
            {
                latest = Some(schema);
            }
        }
        Ok(latest)
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
        Ok(!self.snapshot_coverage(domain_id)?.is_empty())
    }

    /// Lists the exact opaque commit IDs represented by the installed snapshot.
    pub fn snapshot_coverage(&self, domain_id: DomainId) -> Result<Vec<CommitId>, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let coverage = read.open_table(SNAPSHOT_COVERAGE).map_err(database_error)?;
        let mut commits = Vec::new();
        for entry in coverage.iter().map_err(database_error)? {
            let (key, value) = entry.map_err(database_error)?;
            if value.value() == domain_id.as_bytes() {
                let commit_id = key.value().try_into().map_err(|_| {
                    StoreError::CorruptDerivedMetadata("coverage commit ID is invalid".into())
                })?;
                commits.push(CommitId::from_bytes(commit_id));
            }
        }
        commits.sort_unstable();
        if commits.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(StoreError::CorruptDerivedMetadata(
                "snapshot coverage contains duplicate commits".into(),
            ));
        }
        Ok(commits)
    }

    /// Loads the immutable snapshot recovery baseline for a compacted domain.
    pub fn snapshot_baseline(
        &self,
        domain_id: DomainId,
    ) -> Result<Option<SnapshotBaseline>, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let baselines = read
            .open_table(SNAPSHOT_BASELINES)
            .map_err(database_error)?;
        let baseline = baselines
            .get(domain_id.as_bytes().as_slice())
            .map_err(database_error)?
            .map(|bytes| SnapshotBaseline::decode_canonical(bytes.value()))
            .transpose()?;
        if baseline
            .as_ref()
            .is_some_and(|baseline| baseline.domain_id() != domain_id)
        {
            return Err(StoreError::CorruptDerivedMetadata(
                "snapshot baseline crosses domains".into(),
            ));
        }
        Ok(baseline)
    }

    /// Idempotently records local ownership of an immutable blob by one security domain.
    pub fn claim_blob(&self, domain_id: DomainId, hash: BlobHash) -> Result<(), StoreError> {
        let write = self.inner.database.begin_write().map_err(database_error)?;
        write
            .open_table(BLOB_OWNERSHIP)
            .map_err(database_error)?
            .insert(blob_ownership_key(domain_id, hash).as_slice(), 0)
            .map_err(database_error)?;
        write.commit().map_err(database_error)
    }

    /// Returns whether an accepted commit or claimed immutable blob belongs to a domain.
    pub fn owns_blob(&self, domain_id: DomainId, hash: BlobHash) -> Result<bool, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let ownership = read.open_table(BLOB_OWNERSHIP).map_err(database_error)?;
        if ownership
            .get(blob_ownership_key(domain_id, hash).as_slice())
            .map_err(database_error)?
            .is_some()
        {
            return Ok(true);
        }
        let commits = read.open_table(COMMIT_METADATA).map_err(database_error)?;
        let quarantined = read
            .open_table(QUARANTINED_COMMITS)
            .map_err(database_error)?;
        Ok(commits
            .get(hash.as_bytes().as_slice())
            .map_err(database_error)?
            .is_some_and(|metadata| metadata.value().starts_with(domain_id.as_bytes()))
            && quarantined
                .get(hash.as_bytes().as_slice())
                .map_err(database_error)?
                .is_none())
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

    /// Lists locally stored accepted commits visible through an epoch.
    pub fn list_stored_commit_ids_through(
        &self,
        domain_id: DomainId,
        max_epoch: u64,
    ) -> Result<Vec<CommitId>, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let commits = read.open_table(COMMIT_METADATA).map_err(database_error)?;
        let quarantined = read
            .open_table(QUARANTINED_COMMITS)
            .map_err(database_error)?;
        let mut ids = Vec::new();
        for entry in commits.iter().map_err(database_error)? {
            let (key, value) = entry.map_err(database_error)?;
            let metadata = value.value();
            if metadata.len() != 112 || !metadata.starts_with(domain_id.as_bytes()) {
                continue;
            }
            let epoch = u64::from_be_bytes(metadata[64..72].try_into().map_err(|_| {
                StoreError::CorruptDerivedMetadata("commit epoch metadata is invalid".into())
            })?);
            if epoch <= max_epoch
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
        let mut schema_values = BTreeMap::<CollectionId, SchemaDescriptor>::new();
        for entry in schemas.iter().map_err(database_error)? {
            let (key, value) = entry.map_err(database_error)?;
            if key.value().starts_with(domain_id.as_bytes()) {
                let schema = SchemaDescriptor::decode_canonical(value.value())?;
                schema_values
                    .entry(schema.collection_id())
                    .and_modify(|current| {
                        if schema.version() > current.version() {
                            *current = schema.clone();
                        }
                    })
                    .or_insert(schema);
            }
        }

        let mut exported = Vec::new();
        for schema in schema_values.into_values() {
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
    #[allow(clippy::too_many_arguments)]
    pub fn install_snapshot(
        &self,
        domain_id: DomainId,
        records: &[MaterializedRecord],
        covered_commits: &[CommitId],
        frontier_commits: &[CommitId],
        author_sequences: &[(AuthorId, u64)],
        activations: &[SchemaActivation],
        observed_at_unix_seconds: u64,
        baseline: &SnapshotBaseline,
    ) -> Result<(), StoreError> {
        validate_snapshot_metadata(records, covered_commits, frontier_commits, author_sequences)?;
        if baseline.domain_id() != domain_id
            || baseline.frontier() != frontier_commits
            || baseline.author_sequences() != author_sequences
        {
            return Err(StoreError::InvalidSnapshotMetadata(
                "snapshot recovery baseline differs from signed metadata".into(),
            ));
        }
        let baseline_bytes = baseline.encode_canonical()?;
        let write = self.inner.database.begin_write().map_err(database_error)?;
        clear_reconciliation_domain(&write, domain_id)?;
        clear_materialized_domain(&write, domain_id)?;
        clear_domain_migration_metadata(&write, domain_id)?;
        clear_domain_snapshot_metadata(&write, domain_id)?;
        apply_materialized_records(&write, domain_id, records)?;
        install_snapshot_activations(&write, domain_id, records, activations)?;
        {
            write
                .open_table(SNAPSHOT_BASELINES)
                .map_err(database_error)?
                .insert(domain_id.as_bytes().as_slice(), baseline_bytes.as_slice())
                .map_err(database_error)?;
            let mut coverage = write
                .open_table(SNAPSHOT_COVERAGE)
                .map_err(database_error)?;
            for commit_id in covered_commits {
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
        write
            .open_table(OPERATIONAL_METADATA)
            .map_err(database_error)?
            .insert(
                operational_metadata_key(domain_id, SNAPSHOT_OBSERVED_AT_TAG).as_slice(),
                observed_at_unix_seconds,
            )
            .map_err(database_error)?;
        write
            .open_table(RECONCILIATION_READY)
            .map_err(database_error)?
            .insert(domain_id.as_bytes().as_slice(), 1)
            .map_err(database_error)?;
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
            if commit_id.to_bytes() == hash.to_bytes()
                && !self.contains_commit(envelope.header().domain_id(), commit_id)?
            {
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
        let _control_writer = self.inner.control_writer.lock().map_err(|_| {
            StoreError::InvalidAuthority("control writer lock is unavailable".into())
        })?;
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

    /// Atomically imports a descriptor, chain, active root/leaf, and trust set.
    pub fn import_domain_authority_atomic(
        &self,
        descriptor: &DomainDescriptor,
        chain: &[CapabilityCertificate],
    ) -> Result<CapabilityId, StoreError> {
        let _control_writer = self.inner.control_writer.lock().map_err(|_| {
            StoreError::InvalidAuthority("control writer lock is unavailable".into())
        })?;
        descriptor.verify().map_err(authority_error)?;
        if chain.is_empty() || chain.len() > 9 {
            return Err(StoreError::InvalidAuthority(
                "capability chain has invalid depth".into(),
            ));
        }
        let root = &chain[0];
        root.verify_signature().map_err(authority_error)?;
        if root.domain_id() != descriptor.domain_id()
            || root.subject() != descriptor.owner()
            || root.issuer_capability().is_some()
            || !root.permissions().contains(Permission::Admin)
        {
            return Err(StoreError::InvalidAuthority(
                "capability root does not match descriptor".into(),
            ));
        }
        for pair in chain.windows(2) {
            pair[1]
                .validate_delegation(&pair[0])
                .map_err(authority_error)?;
        }
        if let Some(existing) = self.domain_descriptor(descriptor.domain_id())?
            && existing != *descriptor
        {
            return Err(StoreError::InvalidAuthority(
                "domain descriptor conflicts with genesis".into(),
            ));
        }
        let mut validated = Vec::with_capacity(chain.len());
        for capability in chain {
            if capability.domain_id() != descriptor.domain_id() {
                return Err(StoreError::InvalidAuthority(
                    "capability chain crosses domains".into(),
                ));
            }
            let capability_id = capability.id().map_err(authority_error)?;
            let bytes = capability.encode_canonical().map_err(authority_error)?;
            if let Some(stored) = self.capability(capability_id)?
                && stored != *capability
            {
                return Err(StoreError::InvalidAuthority(
                    "capability ID collision".into(),
                ));
            }
            validated.push((capability.clone(), capability_id, bytes));
        }
        if !self.capability_anchors_are_current(descriptor.domain_id(), chain)? {
            return Err(StoreError::InvalidAuthority(
                "capability chain is revoked or has an invalid control anchor".into(),
            ));
        }

        let descriptor_bytes = descriptor.encode_canonical().map_err(authority_error)?;
        let (leaf, leaf_id, _) = validated
            .last()
            .ok_or_else(|| StoreError::InvalidAuthority("capability chain is empty".into()))?;
        let write = self.inner.database.begin_write().map_err(database_error)?;
        write
            .open_table(DOMAIN_DESCRIPTORS)
            .map_err(database_error)?
            .insert(
                descriptor.domain_id().as_bytes().as_slice(),
                descriptor_bytes.as_slice(),
            )
            .map_err(database_error)?;
        for (_, capability_id, bytes) in &validated {
            insert_capability_record(&write, *capability_id, bytes)?;
        }
        let (root, root_id, _) = validated
            .first()
            .ok_or_else(|| StoreError::InvalidAuthority("capability chain is empty".into()))?;
        set_active_capability(&write, root, *root_id)?;
        set_active_capability(&write, leaf, *leaf_id)?;
        {
            let mut trusted = write.open_table(TRUSTED_AUTHORS).map_err(database_error)?;
            for (capability, _, _) in &validated {
                let key = trusted_author_key(descriptor.domain_id(), capability.subject());
                trusted.insert(key.as_slice(), 1).map_err(database_error)?;
            }
        }
        write.commit().map_err(database_error)?;
        Ok(*leaf_id)
    }

    /// Atomically imports a signed current authority baseline from a targeted invitation.
    #[allow(clippy::too_many_lines)]
    pub fn import_authority_checkpoint_atomic(
        &self,
        invitation: &Invitation,
    ) -> Result<CapabilityId, StoreError> {
        let _control_writer = self.inner.control_writer.lock().map_err(|_| {
            StoreError::InvalidAuthority("control writer lock is unavailable".into())
        })?;
        let encoded_invitation = invitation.encode_canonical().map_err(authority_error)?;
        Invitation::decode_canonical(&encoded_invitation).map_err(authority_error)?;
        let descriptor = invitation.descriptor();
        if self.domain_descriptor(descriptor.domain_id())?.is_some()
            || self.control_head(descriptor.domain_id())?.is_some()
        {
            return Err(StoreError::InvalidAuthority(
                "authority checkpoint cannot replace existing domain authority".into(),
            ));
        }
        let checkpoint = invitation.authority_checkpoint();
        let mut evidence = BTreeMap::<CapabilityId, CapabilityCertificate>::new();
        for capability in invitation.authority_evidence() {
            let id = capability.id().map_err(authority_error)?;
            evidence.insert(id, capability.clone());
        }
        if evidence.keys().copied().collect::<Vec<_>>() != checkpoint.capability_ids() {
            return Err(StoreError::InvalidAuthority(
                "checkpoint capability evidence is incomplete".into(),
            ));
        }
        let leaf = invitation
            .capability_chain()
            .last()
            .ok_or_else(|| StoreError::InvalidAuthority("checkpoint leaf is missing".into()))?;
        let leaf_id = leaf.id().map_err(authority_error)?;
        let checkpoint_bytes = checkpoint.encode_canonical().map_err(authority_error)?;
        let descriptor_bytes = descriptor.encode_canonical().map_err(authority_error)?;
        let write = self.inner.database.begin_write().map_err(database_error)?;
        write
            .open_table(DOMAIN_DESCRIPTORS)
            .map_err(database_error)?
            .insert(
                descriptor.domain_id().as_bytes().as_slice(),
                descriptor_bytes.as_slice(),
            )
            .map_err(database_error)?;
        for (id, capability) in &evidence {
            let bytes = capability.encode_canonical().map_err(authority_error)?;
            insert_capability_record(&write, *id, &bytes)?;
        }
        for id in checkpoint.active_capability_ids() {
            let capability = evidence.get(id).ok_or_else(|| {
                StoreError::InvalidAuthority("checkpoint active capability is missing".into())
            })?;
            set_active_capability(&write, capability, *id)?;
        }
        write
            .open_table(AUTHORITY_CHECKPOINTS)
            .map_err(database_error)?
            .insert(
                descriptor.domain_id().as_bytes().as_slice(),
                checkpoint_bytes.as_slice(),
            )
            .map_err(database_error)?;
        for (subject, sequence) in checkpoint.subject_revocations() {
            let key = subject_revocation_key(descriptor.domain_id(), *subject);
            write
                .open_table(SUBJECT_REVOCATIONS)
                .map_err(database_error)?
                .insert(key.as_slice(), *sequence)
                .map_err(database_error)?;
        }
        if let Some(head) = checkpoint.head() {
            let control_id = head.id().map_err(authority_error)?;
            insert_control_observation(&write, head, control_id)?;
            let bytes = head.encode_canonical().map_err(authority_error)?;
            write
                .open_table(CONTROL_HEADS)
                .map_err(database_error)?
                .insert(
                    descriptor.domain_id().as_bytes().as_slice(),
                    bytes.as_slice(),
                )
                .map_err(database_error)?;
        }
        let mut trusted = write.open_table(TRUSTED_AUTHORS).map_err(database_error)?;
        for id in checkpoint.active_capability_ids() {
            let capability = evidence.get(id).ok_or_else(|| {
                StoreError::InvalidAuthority("checkpoint active capability is missing".into())
            })?;
            let key = trusted_author_key(descriptor.domain_id(), capability.subject());
            trusted.insert(key.as_slice(), 1).map_err(database_error)?;
        }
        drop(trusted);
        write.commit().map_err(database_error)?;
        Ok(leaf_id)
    }

    /// Installs a delegated capability after validating its durable issuer link.
    pub fn install_capability(
        &self,
        capability: &CapabilityCertificate,
    ) -> Result<CapabilityId, StoreError> {
        let _control_writer = self.inner.control_writer.lock().map_err(|_| {
            StoreError::InvalidAuthority("control writer lock is unavailable".into())
        })?;
        let issuer_id = capability.issuer_capability().ok_or_else(|| {
            StoreError::InvalidAuthority("delegated capability lacks issuer".into())
        })?;
        let capability_id = capability.id().map_err(authority_error)?;
        let mut chain = self.capability_chain(issuer_id)?;
        chain.push(capability.clone());
        let validated =
            self.validate_capability_chain_for_install(&chain, Some(capability_id), false)?;
        let write = self.inner.database.begin_write().map_err(database_error)?;
        for (_, id, bytes) in &validated {
            insert_capability_record(&write, *id, bytes)?;
        }
        set_active_capability(&write, capability, capability_id)?;
        write.commit().map_err(database_error)?;
        Ok(capability_id)
    }

    /// Atomically installs a validated root-to-leaf capability chain.
    ///
    /// Only the leaf becomes active. Intermediate certificates are retained as
    /// immutable delegation evidence and cannot replace another subject's
    /// active capability as a side effect of authenticating the leaf.
    pub fn install_capability_chain_atomic(
        &self,
        chain: &[CapabilityCertificate],
    ) -> Result<CapabilityId, StoreError> {
        let _control_writer = self.inner.control_writer.lock().map_err(|_| {
            StoreError::InvalidAuthority("control writer lock is unavailable".into())
        })?;
        let validated = self.validate_capability_chain_for_install(chain, None, false)?;
        let (leaf, leaf_id, _) = validated
            .last()
            .ok_or_else(|| StoreError::InvalidAuthority("capability chain is empty".into()))?;
        let write = self.inner.database.begin_write().map_err(database_error)?;
        for (_, capability_id, bytes) in &validated {
            insert_capability_record(&write, *capability_id, bytes)?;
        }
        set_active_capability(&write, leaf, *leaf_id)?;
        write.commit().map_err(database_error)?;
        Ok(*leaf_id)
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

    /// Lists exact active capability IDs for a domain in canonical order.
    pub fn active_capabilities(
        &self,
        domain_id: DomainId,
    ) -> Result<Vec<CapabilityId>, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let active = read
            .open_table(ACTIVE_CAPABILITIES)
            .map_err(database_error)?;
        let mut ids = Vec::new();
        for entry in active.iter().map_err(database_error)? {
            let (key, value) = entry.map_err(database_error)?;
            if !key.value().starts_with(domain_id.as_bytes()) {
                continue;
            }
            let bytes: [u8; 32] = value.value().try_into().map_err(|_| {
                StoreError::CorruptDerivedMetadata("active capability ID is invalid".into())
            })?;
            ids.push(CapabilityId::from_bytes(bytes));
        }
        ids.sort_unstable();
        ids.dedup();
        Ok(ids)
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
        self.ensure_control_not_forked(domain_id)?;
        if self.active_capability(domain_id, subject)? != Some(capability_id) {
            return Ok(false);
        }
        let chain = match self.capability_chain(capability_id) {
            Ok(chain) => chain,
            Err(StoreError::InvalidAuthority(_)) => return Ok(false),
            Err(error) => return Err(error),
        };
        if !self.capability_anchors_are_current(domain_id, &chain)? {
            return Ok(false);
        }
        let Some(capability) = chain.last() else {
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
        self.ensure_control_not_forked(domain_id)?;
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

    /// Returns the accepted control chain in ascending sequence order.
    pub fn accepted_control_chain(
        &self,
        domain_id: DomainId,
    ) -> Result<Vec<ControlTransition>, StoreError> {
        self.ensure_control_not_forked(domain_id)?;
        let baseline = self.authority_checkpoint(domain_id)?;
        let baseline_id = baseline
            .as_ref()
            .and_then(AuthorityCheckpoint::head)
            .map(ControlTransition::id)
            .transpose()
            .map_err(authority_error)?;
        let Some(mut current) = self.control_head(domain_id)? else {
            return Ok(Vec::new());
        };
        let mut reversed = Vec::new();
        loop {
            let current_id = current.id().map_err(authority_error)?;
            let predecessor = current.predecessor();
            reversed.push(current);
            if Some(current_id) == baseline_id {
                break;
            }
            let Some(predecessor) = predecessor else {
                break;
            };
            current = self
                .control_object(domain_id, predecessor)?
                .ok_or_else(|| {
                    StoreError::CorruptDerivedMetadata(
                        "accepted control predecessor is missing".into(),
                    )
                })?;
        }
        reversed.reverse();
        let first_sequence = baseline
            .as_ref()
            .and_then(AuthorityCheckpoint::head)
            .map_or(1, ControlTransition::sequence);
        for (index, control) in reversed.iter().enumerate() {
            let expected = u64::try_from(index)
                .map_err(|_| {
                    StoreError::CorruptDerivedMetadata("control chain is too long".into())
                })?
                .checked_add(first_sequence)
                .ok_or_else(|| {
                    StoreError::CorruptDerivedMetadata("control sequence overflow".into())
                })?;
            if control.domain_id() != domain_id || control.sequence() != expected {
                return Err(StoreError::CorruptDerivedMetadata(
                    "accepted control chain is not contiguous".into(),
                ));
            }
        }
        Ok(reversed)
    }

    /// Loads and verifies the optional history-compacting authority baseline.
    pub fn authority_checkpoint(
        &self,
        domain_id: DomainId,
    ) -> Result<Option<AuthorityCheckpoint>, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let table = read
            .open_table(AUTHORITY_CHECKPOINTS)
            .map_err(database_error)?;
        let checkpoint = table
            .get(domain_id.as_bytes().as_slice())
            .map_err(database_error)?
            .map(|value| {
                AuthorityCheckpoint::decode_canonical(value.value()).map_err(authority_error)
            })
            .transpose()?;
        if checkpoint
            .as_ref()
            .is_some_and(|checkpoint| checkpoint.domain_id() != domain_id)
        {
            return Err(StoreError::CorruptDerivedMetadata(
                "authority checkpoint crosses domains".into(),
            ));
        }
        Ok(checkpoint)
    }

    /// Checks persisted checkpoint evidence against immutable authority objects.
    pub fn authority_checkpoint_consistent(&self, domain_id: DomainId) -> Result<bool, StoreError> {
        let Some(checkpoint) = self.authority_checkpoint(domain_id)? else {
            return Ok(true);
        };
        if self.domain_descriptor(domain_id)?.is_none() {
            return Ok(false);
        }
        if let Some(head) = checkpoint.head() {
            let id = head.id().map_err(authority_error)?;
            if self.control_transition(domain_id, id)?.as_ref() != Some(head) {
                return Ok(false);
            }
        }
        for id in checkpoint.capability_ids() {
            if self
                .capability(*id)?
                .is_none_or(|capability| capability.domain_id() != domain_id)
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Loads one retained canonical control object by content ID.
    pub fn control_transition(
        &self,
        domain_id: DomainId,
        control_id: [u8; 32],
    ) -> Result<Option<ControlTransition>, StoreError> {
        self.control_object(domain_id, control_id)
    }

    /// Loads one retained accepted transition by its signed sequence.
    pub fn accepted_control_at_sequence(
        &self,
        domain_id: DomainId,
        sequence: u64,
    ) -> Result<Option<ControlTransition>, StoreError> {
        Ok(self
            .accepted_control_chain(domain_id)?
            .into_iter()
            .find(|control| control.sequence() == sequence))
    }

    /// Returns the epoch authorized by the durable control chain.
    pub fn current_epoch(&self, domain_id: DomainId) -> Result<u64, StoreError> {
        self.ensure_control_not_forked(domain_id)?;
        Ok(self
            .control_head(domain_id)?
            .map_or(0, |head| head.new_epoch()))
    }

    /// Returns the accepted domain-control sequence, or zero at genesis.
    pub fn current_control_sequence(&self, domain_id: DomainId) -> Result<u64, StoreError> {
        Ok(self
            .control_head(domain_id)?
            .as_ref()
            .map_or(0, ControlTransition::sequence))
    }

    /// Checks the rebuildable subject-revocation index against signed control.
    pub fn subject_revocations_consistent(&self, domain_id: DomainId) -> Result<bool, StoreError> {
        let expected = self.expected_subject_revocations(domain_id)?;
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let table = read
            .open_table(SUBJECT_REVOCATIONS)
            .map_err(database_error)?;
        let mut actual = BTreeMap::new();
        for entry in table.iter().map_err(database_error)? {
            let (key, value) = entry.map_err(database_error)?;
            let key = key.value();
            if key.len() != 64 || !key.starts_with(domain_id.as_bytes()) {
                continue;
            }
            let subject = AuthorId::from_bytes(key[32..].try_into().map_err(|_| {
                StoreError::CorruptDerivedMetadata("subject revocation endpoint is invalid".into())
            })?);
            actual.insert(subject, value.value());
        }
        Ok(actual == expected)
    }

    /// Returns the canonical revocation accumulator derived from signed authority.
    pub fn subject_revocations(
        &self,
        domain_id: DomainId,
    ) -> Result<Vec<(AuthorId, u64)>, StoreError> {
        Ok(self
            .expected_subject_revocations(domain_id)?
            .into_iter()
            .collect())
    }

    /// Atomically rebuilds subject revocations from the accepted signed chain.
    pub fn repair_subject_revocations(&self, domain_id: DomainId) -> Result<(), StoreError> {
        let _control_writer = self.inner.control_writer.lock().map_err(|_| {
            StoreError::InvalidAuthority("control writer lock is unavailable".into())
        })?;
        let expected = self.expected_subject_revocations(domain_id)?;
        let write = self.inner.database.begin_write().map_err(database_error)?;
        {
            let mut table = write
                .open_table(SUBJECT_REVOCATIONS)
                .map_err(database_error)?;
            table
                .retain(|key, _| !key.starts_with(domain_id.as_bytes()))
                .map_err(database_error)?;
            for (subject, sequence) in expected {
                let key = subject_revocation_key(domain_id, subject);
                table
                    .insert(key.as_slice(), sequence)
                    .map_err(database_error)?;
            }
        }
        write.commit().map_err(database_error)
    }

    /// Returns the endpoint exclusively authorized to sign the next control transition.
    pub fn current_controller(&self, domain_id: DomainId) -> Result<AuthorId, StoreError> {
        self.ensure_control_not_forked(domain_id)?;
        if let Some(head) = self.control_head(domain_id)? {
            return Ok(head.controller());
        }
        self.domain_descriptor(domain_id)?
            .map(|descriptor| descriptor.owner())
            .ok_or_else(|| StoreError::InvalidAuthority("domain descriptor is missing".into()))
    }

    /// Returns the currently designated single writer.
    pub fn current_writer(&self, domain_id: DomainId) -> Result<Option<AuthorId>, StoreError> {
        self.ensure_control_not_forked(domain_id)?;
        if let Some(head) = self.control_head(domain_id)? {
            return Ok(Some(head.writer()));
        }
        Ok(self
            .domain_descriptor(domain_id)?
            .map(|descriptor| descriptor.owner()))
    }

    /// Verifies and retains a control object before separately delivered key material is activated.
    pub fn observe_control(&self, control: &ControlTransition) -> Result<(), StoreError> {
        let _control_writer = self.inner.control_writer.lock().map_err(|_| {
            StoreError::InvalidAuthority("control writer lock is unavailable".into())
        })?;
        control.verify().map_err(authority_error)?;
        self.ensure_control_not_forked(control.domain_id())?;
        let current = self.control_head(control.domain_id())?;
        let control_id = control.id().map_err(authority_error)?;
        if current
            .as_ref()
            .map(ControlTransition::id)
            .transpose()
            .map_err(authority_error)?
            .is_some_and(|current_id| current_id == control_id)
        {
            return Ok(());
        }
        if self.control_slot_is_observed(control, control_id)? {
            return Ok(());
        }
        if let Some(head) = current.as_ref()
            && control.sequence() == head.sequence()
            && control.predecessor() == head.predecessor()
            && control.previous_epoch() == head.previous_epoch()
        {
            self.validate_control_sibling(control, head)?;
            return self.freeze_control_fork(head, control);
        }
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
        if control.sequence() != sequence
            || control.predecessor() != predecessor
            || control.previous_epoch() != epoch
            || self.frontier(control.domain_id())? != control.cut()
        {
            return Err(StoreError::InvalidAuthority(
                "control transition does not extend the active head".into(),
            ));
        }
        self.validate_control_authority(
            control,
            self.current_controller(control.domain_id())?,
            epoch,
            None,
        )?;
        let write = self.inner.database.begin_write().map_err(database_error)?;
        insert_control_observation(&write, control, control_id)?;
        write.commit().map_err(database_error)
    }

    /// Atomically advances authority, records the causal cut, and revokes endpoint access.
    pub fn apply_control(&self, control: &ControlTransition) -> Result<(), StoreError> {
        self.apply_control_bundle(control, &[])
    }

    /// Atomically installs successor capability evidence and advances authority.
    pub fn apply_control_bundle(
        &self,
        control: &ControlTransition,
        successor_chain: &[CapabilityCertificate],
    ) -> Result<(), StoreError> {
        let _control_writer = self.inner.control_writer.lock().map_err(|_| {
            StoreError::InvalidAuthority("control writer lock is unavailable".into())
        })?;
        control.verify().map_err(authority_error)?;
        self.ensure_control_not_forked(control.domain_id())?;
        let current = self.control_head(control.domain_id())?;
        let control_id = control.id().map_err(authority_error)?;
        if current
            .as_ref()
            .map(ControlTransition::id)
            .transpose()
            .map_err(authority_error)?
            .is_some_and(|current_id| current_id == control_id)
        {
            return Ok(());
        }
        self.control_slot_is_observed(control, control_id)?;
        if let Some(head) = current.as_ref()
            && control.sequence() == head.sequence()
            && control.predecessor() == head.predecessor()
            && control.previous_epoch() == head.previous_epoch()
        {
            self.validate_control_sibling(control, head)?;
            return self.freeze_control_fork(head, control);
        }
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
        if control.sequence() != sequence
            || control.predecessor() != predecessor
            || control.previous_epoch() != epoch
            || self.frontier(control.domain_id())? != control.cut()
        {
            return Err(StoreError::InvalidAuthority(
                "control transition does not extend the active head".into(),
            ));
        }
        let validated_successor = if successor_chain.is_empty() {
            Vec::new()
        } else {
            self.validate_capability_chain_for_install(
                successor_chain,
                Some(control.controller_capability()),
                true,
            )?
        };
        let candidate_successor_chain = validated_successor
            .iter()
            .map(|(capability, _, _)| capability.clone())
            .collect::<Vec<_>>();
        self.validate_control_authority(
            control,
            self.current_controller(control.domain_id())?,
            epoch,
            (!candidate_successor_chain.is_empty()).then_some(candidate_successor_chain.as_slice()),
        )?;
        if control.revoked_subjects().contains(&control.author()) {
            return Err(StoreError::InvalidAuthority(
                "control author cannot revoke itself".into(),
            ));
        }
        let bytes = control.encode_canonical().map_err(authority_error)?;
        let write = self.inner.database.begin_write().map_err(database_error)?;
        {
            for (_, capability_id, capability_bytes) in &validated_successor {
                insert_capability_record(&write, *capability_id, capability_bytes)?;
            }
            if let Some((leaf, leaf_id, _)) = validated_successor.last() {
                set_active_capability(&write, leaf, *leaf_id)?;
            }
            insert_control_observation(&write, control, control_id)?;
            let mut heads = write.open_table(CONTROL_HEADS).map_err(database_error)?;
            heads
                .insert(control.domain_id().as_bytes().as_slice(), bytes.as_slice())
                .map_err(database_error)?;
        }
        apply_control_revocations(&write, control)?;
        write.commit().map_err(database_error)
    }

    fn validate_control_authority(
        &self,
        control: &ControlTransition,
        expected_controller: AuthorId,
        epoch: u64,
        candidate_successor_chain: Option<&[CapabilityCertificate]>,
    ) -> Result<(), StoreError> {
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
        let next_chain = if let Some(candidate) = candidate_successor_chain {
            candidate.to_vec()
        } else {
            self.capability_chain(control.controller_capability())?
        };
        let next_capability = next_chain.last().ok_or_else(|| {
            StoreError::InvalidAuthority("successor capability chain is empty".into())
        })?;
        let next_can_admin = next_capability.id().map_err(authority_error)?
            == control.controller_capability()
            && self.capability_anchors_are_current_with_historical_nomination(
                control.domain_id(),
                &next_chain,
                candidate_successor_chain.is_some(),
            )?
            && !next_chain
                .iter()
                .any(|capability| control.revoked_subjects().contains(&capability.subject()))
            && {
                let capability = next_capability;
                capability.domain_id() == control.domain_id()
                    && capability.subject() == control.controller()
                    && capability.permits(Permission::Admin, control.new_epoch())
            };
        if control.author() != expected_controller || !can_control || !next_can_admin {
            return Err(StoreError::InvalidAuthority(
                "control transition lacks designated controller authority".into(),
            ));
        }
        Ok(())
    }

    fn validate_capability_chain_for_install(
        &self,
        chain: &[CapabilityCertificate],
        replace_leaf: Option<CapabilityId>,
        allow_historical_nomination: bool,
    ) -> Result<Vec<(CapabilityCertificate, CapabilityId, Vec<u8>)>, StoreError> {
        if chain.is_empty() || chain.len() > 9 {
            return Err(StoreError::InvalidAuthority(
                "capability chain has invalid depth".into(),
            ));
        }
        let root = &chain[0];
        let descriptor = self
            .domain_descriptor(root.domain_id())?
            .ok_or_else(|| StoreError::InvalidAuthority("domain descriptor is missing".into()))?;
        let root_id = root.id().map_err(authority_error)?;
        let stored_root = self
            .capability(root_id)?
            .ok_or_else(|| StoreError::InvalidAuthority("capability root is unknown".into()))?;
        if root.subject() != descriptor.owner()
            || root.issuer_capability().is_some()
            || stored_root != *root
        {
            return Err(StoreError::InvalidAuthority(
                "capability chain has an invalid root".into(),
            ));
        }
        for pair in chain.windows(2) {
            pair[1]
                .validate_delegation(&pair[0])
                .map_err(authority_error)?;
        }
        let mut validated = Vec::with_capacity(chain.len());
        for capability in chain {
            if capability.domain_id() != root.domain_id() {
                return Err(StoreError::InvalidAuthority(
                    "capability chain crosses domains".into(),
                ));
            }
            let capability_id = capability.id().map_err(authority_error)?;
            let bytes = capability.encode_canonical().map_err(authority_error)?;
            if let Some(stored) = self.capability(capability_id)?
                && stored != *capability
            {
                return Err(StoreError::InvalidAuthority(
                    "capability ID collision".into(),
                ));
            }
            validated.push((capability.clone(), capability_id, bytes));
        }
        let (leaf, leaf_id, _) = validated
            .last()
            .ok_or_else(|| StoreError::InvalidAuthority("capability chain is empty".into()))?;
        if replace_leaf.is_some_and(|expected| expected != *leaf_id) {
            return Err(StoreError::InvalidAuthority(
                "capability chain leaf does not match signed successor".into(),
            ));
        }
        if replace_leaf.is_none()
            && let Some(active) = self.active_capability(leaf.domain_id(), leaf.subject())?
            && active != *leaf_id
        {
            let current = self.capability(active)?.ok_or_else(|| {
                StoreError::CorruptDerivedMetadata("active capability record is missing".into())
            })?;
            if leaf.issued_control_sequence() <= current.issued_control_sequence() {
                return Err(StoreError::InvalidAuthority(
                    "capability chain would replace an active leaf without advancing control"
                        .into(),
                ));
            }
        }
        let capabilities = validated
            .iter()
            .map(|(capability, _, _)| capability.clone())
            .collect::<Vec<_>>();
        if !self.capability_anchors_are_current_with_historical_nomination(
            root.domain_id(),
            &capabilities,
            allow_historical_nomination,
        )? {
            return Err(StoreError::InvalidAuthority(
                "capability chain is revoked or has an invalid control anchor".into(),
            ));
        }
        Ok(validated)
    }

    fn capability_anchors_are_current(
        &self,
        domain_id: DomainId,
        chain: &[CapabilityCertificate],
    ) -> Result<bool, StoreError> {
        self.capability_anchors_are_current_with_historical_nomination(domain_id, chain, false)
    }

    fn capability_anchors_are_current_with_historical_nomination(
        &self,
        domain_id: DomainId,
        chain: &[CapabilityCertificate],
        allow_historical_nomination: bool,
    ) -> Result<bool, StoreError> {
        let controls = self.accepted_control_chain(domain_id)?;
        let checkpoint = self.authority_checkpoint(domain_id)?;
        let expected_revocations = self.expected_subject_revocations(domain_id)?;
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let revoked = read
            .open_table(REVOKED_CAPABILITIES)
            .map_err(database_error)?;
        let subject_revocations = read
            .open_table(SUBJECT_REVOCATIONS)
            .map_err(database_error)?;
        for capability in chain {
            if capability.domain_id() != domain_id {
                return Ok(false);
            }
            let capability_id = capability.id().map_err(authority_error)?;
            let baseline_sequence = checkpoint
                .as_ref()
                .and_then(AuthorityCheckpoint::head)
                .map(ControlTransition::sequence);
            let before_truncated_baseline = baseline_sequence
                .is_some_and(|sequence| capability.issued_control_sequence() < sequence);
            let checkpoint_allows = before_truncated_baseline
                && checkpoint
                    .as_ref()
                    .is_some_and(|checkpoint| checkpoint.capability_ids().contains(&capability_id));
            let anchor_is_accepted = if before_truncated_baseline {
                checkpoint_allows || allow_historical_nomination
            } else if capability.issued_control_sequence() == 0 {
                capability.issued_control_head().is_none()
            } else {
                controls
                    .iter()
                    .find(|control| control.sequence() == capability.issued_control_sequence())
                    .map(ControlTransition::id)
                    .transpose()
                    .map_err(authority_error)?
                    == capability.issued_control_head()
            };
            if !anchor_is_accepted {
                return Ok(false);
            }
            if revoked
                .get(capability_id.as_bytes().as_slice())
                .map_err(database_error)?
                .is_some()
            {
                return Ok(false);
            }
            let subject_key = subject_revocation_key(domain_id, capability.subject());
            let stored_revocation = subject_revocations
                .get(subject_key.as_slice())
                .map_err(database_error)?
                .map(|sequence| sequence.value());
            let expected_revocation = expected_revocations.get(&capability.subject()).copied();
            if stored_revocation != expected_revocation {
                return Err(StoreError::CorruptDerivedMetadata(
                    "subject revocation index differs from signed control".into(),
                ));
            }
            if expected_revocation
                .is_some_and(|sequence| sequence > capability.issued_control_sequence())
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn expected_subject_revocations(
        &self,
        domain_id: DomainId,
    ) -> Result<BTreeMap<AuthorId, u64>, StoreError> {
        let checkpoint = self.authority_checkpoint(domain_id)?;
        let mut revocations: BTreeMap<AuthorId, u64> = checkpoint
            .as_ref()
            .map(|checkpoint| checkpoint.subject_revocations().iter().copied().collect())
            .unwrap_or_default();
        let baseline_sequence = checkpoint
            .as_ref()
            .and_then(AuthorityCheckpoint::head)
            .map_or(0, ControlTransition::sequence);
        for control in self.accepted_control_chain(domain_id)? {
            if control.sequence() <= baseline_sequence {
                continue;
            }
            for subject in control.revoked_subjects() {
                revocations
                    .entry(*subject)
                    .and_modify(|sequence| *sequence = (*sequence).max(control.sequence()))
                    .or_insert(control.sequence());
            }
        }
        Ok(revocations)
    }

    fn validate_control_sibling(
        &self,
        conflicting: &ControlTransition,
        accepted: &ControlTransition,
    ) -> Result<(), StoreError> {
        if conflicting.author() != self.controller_before(accepted)? {
            return Err(StoreError::InvalidAuthority(
                "control sibling was not signed by the predecessor controller".into(),
            ));
        }
        Ok(())
    }

    fn controller_before(&self, control: &ControlTransition) -> Result<AuthorId, StoreError> {
        if let Some(checkpoint_head) = self
            .authority_checkpoint(control.domain_id())?
            .as_ref()
            .and_then(AuthorityCheckpoint::head)
            && checkpoint_head.id().map_err(authority_error)?
                == control.id().map_err(authority_error)?
        {
            return Ok(control.author());
        }
        let Some(predecessor) = control.predecessor() else {
            return self
                .domain_descriptor(control.domain_id())?
                .map(|descriptor| descriptor.owner())
                .ok_or_else(|| {
                    StoreError::InvalidAuthority("domain descriptor is missing".into())
                });
        };
        self.control_object(control.domain_id(), predecessor)?
            .map(|value| value.controller())
            .ok_or_else(|| {
                StoreError::InvalidAuthority("control predecessor object is missing".into())
            })
    }

    fn control_object(
        &self,
        domain_id: DomainId,
        control_id: [u8; 32],
    ) -> Result<Option<ControlTransition>, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let objects = read.open_table(CONTROL_OBJECTS).map_err(database_error)?;
        let key = control_object_key(domain_id, control_id);
        objects
            .get(key.as_slice())
            .map_err(database_error)?
            .map(|value| {
                ControlTransition::decode_canonical(value.value()).map_err(authority_error)
            })
            .transpose()
    }

    fn control_slot(&self, control: &ControlTransition) -> Result<Option<[u8; 32]>, StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let slots = read.open_table(CONTROL_SLOTS).map_err(database_error)?;
        slots
            .get(control_slot_key(control).as_slice())
            .map_err(database_error)?
            .map(|value| {
                value.value().try_into().map_err(|_| {
                    StoreError::CorruptDerivedMetadata("control slot ID is invalid".into())
                })
            })
            .transpose()
    }

    fn control_slot_is_observed(
        &self,
        control: &ControlTransition,
        control_id: [u8; 32],
    ) -> Result<bool, StoreError> {
        let Some(observed_id) = self.control_slot(control)? else {
            return Ok(false);
        };
        if observed_id == control_id {
            return Ok(true);
        }
        let observed = self
            .control_object(control.domain_id(), observed_id)?
            .ok_or_else(|| {
                StoreError::CorruptDerivedMetadata("observed control slot object is missing".into())
            })?;
        self.validate_control_sibling(control, &observed)?;
        self.freeze_control_fork(&observed, control)?;
        Ok(false)
    }

    fn freeze_control_fork(
        &self,
        accepted: &ControlTransition,
        conflicting: &ControlTransition,
    ) -> Result<(), StoreError> {
        let domain = accepted.domain_id();
        let accepted_id = accepted.id().map_err(authority_error)?;
        let conflicting_id = conflicting.id().map_err(authority_error)?;
        let (first, second) = if accepted_id < conflicting_id {
            (accepted_id, conflicting_id)
        } else {
            (conflicting_id, accepted_id)
        };
        let bytes = conflicting.encode_canonical().map_err(authority_error)?;
        let mut evidence = [0_u8; 64];
        evidence[..32].copy_from_slice(&first);
        evidence[32..].copy_from_slice(&second);
        let write = self.inner.database.begin_write().map_err(database_error)?;
        write
            .open_table(CONTROL_OBJECTS)
            .map_err(database_error)?
            .insert(
                control_object_key(domain, conflicting_id).as_slice(),
                bytes.as_slice(),
            )
            .map_err(database_error)?;
        write
            .open_table(CONTROL_FORKS)
            .map_err(database_error)?
            .insert(domain.as_bytes().as_slice(), evidence.as_slice())
            .map_err(database_error)?;
        write.commit().map_err(database_error)?;
        Err(StoreError::ControlFork {
            domain,
            first,
            second,
        })
    }

    fn ensure_control_not_forked(&self, domain: DomainId) -> Result<(), StoreError> {
        let read = self.inner.database.begin_read().map_err(database_error)?;
        let forks = read.open_table(CONTROL_FORKS).map_err(database_error)?;
        let Some(value) = forks
            .get(domain.as_bytes().as_slice())
            .map_err(database_error)?
        else {
            return Ok(());
        };
        let evidence: [u8; 64] = value.value().try_into().map_err(|_| {
            StoreError::CorruptDerivedMetadata("control fork evidence is invalid".into())
        })?;
        let first = evidence[..32].try_into().expect("exact evidence length");
        let second = evidence[32..].try_into().expect("exact evidence length");
        Err(StoreError::ControlFork {
            domain,
            first,
            second,
        })
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

fn dependency_is_accepted(
    commits: &impl redb::ReadableTable<&'static [u8], &'static [u8]>,
    coverage: &impl redb::ReadableTable<&'static [u8], &'static [u8]>,
    quarantined: &impl redb::ReadableTable<&'static [u8], &'static [u8]>,
    domain_id: DomainId,
    dependency: CommitId,
) -> Result<bool, StoreError> {
    let key = dependency.as_bytes().as_slice();
    let stored = commits
        .get(key)
        .map_err(database_error)?
        .is_some_and(|metadata| metadata.value().starts_with(domain_id.as_bytes()))
        && quarantined.get(key).map_err(database_error)?.is_none();
    let snapshotted = coverage
        .get(key)
        .map_err(database_error)?
        .is_some_and(|domain| domain.value() == domain_id.as_bytes());
    Ok(stored || snapshotted)
}

fn publish_frontier(
    write: &redb::WriteTransaction,
    domain_id: DomainId,
    envelope: &CommitEnvelope,
    commit_id: CommitId,
) -> Result<(), StoreError> {
    let mut frontier = write.open_table(FRONTIER).map_err(database_error)?;
    for dependency in envelope.header().dependencies() {
        let dependency_key = frontier_key(domain_id, *dependency);
        frontier
            .remove(dependency_key.as_slice())
            .map_err(database_error)?;
    }
    let commit_key = frontier_key(domain_id, commit_id);
    frontier
        .insert(commit_key.as_slice(), 0)
        .map_err(database_error)?;
    Ok(())
}

fn apply_reconciliation_update(
    write: &redb::WriteTransaction,
    envelope: &CommitEnvelope,
    context: &VersionVector,
    record_heads: &[RecordHeadSet],
) -> Result<(), StoreError> {
    let own_dot = iroh_db_core::Dot::new(
        envelope.header().author(),
        envelope.header().author_sequence(),
        0,
    );
    if !context.covers(&own_dot) {
        return Err(StoreError::CorruptDerivedMetadata(
            "commit context does not include its own author sequence".into(),
        ));
    }
    let domain_id = envelope.header().domain_id();
    {
        let key = commit_context_key(domain_id, envelope.commit_id());
        let encoded = encode_version_vector(context)?;
        write
            .open_table(COMMIT_CONTEXTS)
            .map_err(database_error)?
            .insert(key.as_slice(), encoded.as_slice())
            .map_err(database_error)?;
    }
    {
        let mut table = write.open_table(RECORD_HEADS).map_err(database_error)?;
        for replacement in record_heads {
            let prefix = record_head_prefix(
                domain_id,
                replacement.collection_id(),
                replacement.record_id(),
            )?;
            for key in table_keys_with_prefix(&table, &prefix)? {
                table.remove(key.as_slice()).map_err(database_error)?;
            }
            for head in replacement.heads() {
                let key = record_head_key(domain_id, head)?;
                let value = encode_record_head(head)?;
                table
                    .insert(key.as_slice(), value.as_slice())
                    .map_err(database_error)?;
            }
        }
    }
    write
        .open_table(RECONCILIATION_READY)
        .map_err(database_error)?
        .insert(domain_id.as_bytes().as_slice(), 1)
        .map_err(database_error)?;
    Ok(())
}

fn mark_reconciliation_stale(
    write: &redb::WriteTransaction,
    domain_id: DomainId,
) -> Result<(), StoreError> {
    write
        .open_table(RECONCILIATION_READY)
        .map_err(database_error)?
        .remove(domain_id.as_bytes().as_slice())
        .map_err(database_error)?;
    Ok(())
}

fn validate_snapshot_metadata(
    records: &[MaterializedRecord],
    covered_commits: &[CommitId],
    frontier_commits: &[CommitId],
    author_sequences: &[(AuthorId, u64)],
) -> Result<(), StoreError> {
    let records_are_ordered = records.windows(2).all(|pair| {
        (pair[0].schema().collection_id(), pair[0].record_id())
            < (pair[1].schema().collection_id(), pair[1].record_id())
    });
    if !records_are_ordered || records.iter().any(|record| record.state().is_none()) {
        return Err(StoreError::InvalidSnapshotMetadata(
            "materialized records are not unique canonical upserts".into(),
        ));
    }
    if !strictly_sorted(covered_commits) || !strictly_sorted(frontier_commits) {
        return Err(StoreError::InvalidSnapshotMetadata(
            "commit coverage and frontier must be strictly ordered".into(),
        ));
    }
    if !author_sequences
        .windows(2)
        .all(|pair| pair[0].0 < pair[1].0)
    {
        return Err(StoreError::InvalidSnapshotMetadata(
            "author sequence entries must be strictly ordered".into(),
        ));
    }
    if frontier_commits
        .iter()
        .any(|commit_id| covered_commits.binary_search(commit_id).is_err())
    {
        return Err(StoreError::InvalidSnapshotMetadata(
            "snapshot frontier is not covered by the snapshot".into(),
        ));
    }
    if covered_commits.is_empty() != frontier_commits.is_empty()
        || covered_commits.is_empty() != author_sequences.is_empty()
    {
        return Err(StoreError::InvalidSnapshotMetadata(
            "empty history must have an empty frontier and version vector".into(),
        ));
    }
    Ok(())
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn initialize_tables(database: &Database) -> Result<(), StoreError> {
    let write = database.begin_write().map_err(database_error)?;
    write.open_table(COMMIT_METADATA).map_err(database_error)?;
    write.open_table(COMMIT_CONTEXTS).map_err(database_error)?;
    write.open_table(RECORD_HEADS).map_err(database_error)?;
    write
        .open_table(RECONCILIATION_READY)
        .map_err(database_error)?;
    write
        .open_table(SNAPSHOT_COVERAGE)
        .map_err(database_error)?;
    write
        .open_table(SNAPSHOT_BASELINES)
        .map_err(database_error)?;
    write.open_table(BLOB_OWNERSHIP).map_err(database_error)?;
    write.open_table(AUTHOR_SEQUENCES).map_err(database_error)?;
    write.open_table(AUTHOR_COMMITS).map_err(database_error)?;
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
    write
        .open_table(SUBJECT_REVOCATIONS)
        .map_err(database_error)?;
    write
        .open_table(AUTHORITY_CHECKPOINTS)
        .map_err(database_error)?;
    write.open_table(CONTROL_HEADS).map_err(database_error)?;
    write.open_table(CONTROL_OBJECTS).map_err(database_error)?;
    write.open_table(CONTROL_SLOTS).map_err(database_error)?;
    write.open_table(CONTROL_FORKS).map_err(database_error)?;
    write.open_table(DEVICE_GROUPS).map_err(database_error)?;
    write
        .open_table(CONSUMED_INVITATIONS)
        .map_err(database_error)?;
    write.open_table(ACTIVE_SCHEMAS).map_err(database_error)?;
    write.open_table(MIGRATION_STAGES).map_err(database_error)?;
    write
        .open_table(MIGRATION_ACTIVATIONS)
        .map_err(database_error)?;
    write
        .open_table(MIGRATION_CHECKPOINTS)
        .map_err(database_error)?;
    write.open_table(MIGRATION_FORKS).map_err(database_error)?;
    write
        .open_table(OPERATIONAL_METADATA)
        .map_err(database_error)?;
    write.commit().map_err(database_error)
}

fn prepare_store_format(root: &Path) -> Result<(), StoreError> {
    let format_path = root.join("FORMAT");
    if !format_path.exists() {
        return write_format_marker(root, FORMAT_CONTENTS);
    }
    match std::fs::read_to_string(&format_path)
        .map_err(io_error)?
        .as_str()
    {
        FORMAT_CONTENTS => Ok(()),
        FORMAT_V5 => shadow_migrate_v5(root),
        _ => Err(StoreError::UnsupportedFormat),
    }
}

fn shadow_migrate_v5(root: &Path) -> Result<(), StoreError> {
    let legacy = root.join("meta.redb");
    let preserved = root.join("meta-v5.redb");
    let candidate = root.join("tmp/meta-v6.redb");
    let live = root.join("meta-v6.redb");
    if !preserved.exists() {
        if !legacy.is_file() {
            return Err(StoreError::Io("format v5 metadata file is missing".into()));
        }
        copy_and_sync(&legacy, &preserved)?;
    }
    if candidate.exists() {
        std::fs::remove_file(&candidate).map_err(io_error)?;
    }
    copy_and_sync(&preserved, &candidate)?;
    {
        let mut database = Database::create(&candidate).map_err(database_error)?;
        initialize_tables(&database)?;
        if !database.check_integrity().map_err(database_error)? {
            return Err(StoreError::Database(
                "v6 shadow metadata required integrity repair".into(),
            ));
        }
    }
    if live.exists() {
        std::fs::remove_file(&live).map_err(io_error)?;
    }
    std::fs::rename(&candidate, &live).map_err(io_error)?;
    sync_directory(root)?;
    write_format_marker(root, FORMAT_CONTENTS)
}

fn copy_and_sync(source: &Path, destination: &Path) -> Result<(), StoreError> {
    std::fs::copy(source, destination).map_err(io_error)?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(destination)
        .map_err(io_error)?
        .sync_all()
        .map_err(io_error)
}

fn write_format_marker(root: &Path, contents: &str) -> Result<(), StoreError> {
    let candidate = root.join("tmp/FORMAT.next");
    std::fs::write(&candidate, contents).map_err(io_error)?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(&candidate)
        .map_err(io_error)?
        .sync_all()
        .map_err(io_error)?;
    std::fs::rename(candidate, root.join("FORMAT")).map_err(io_error)?;
    sync_directory(root)
}

fn sync_directory(path: &Path) -> Result<(), StoreError> {
    File::open(path)
        .map_err(io_error)?
        .sync_all()
        .map_err(io_error)
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

fn subject_revocation_key(domain_id: DomainId, subject: AuthorId) -> [u8; 64] {
    active_capability_key(domain_id, subject)
}

fn control_object_key(domain_id: DomainId, control_id: [u8; 32]) -> [u8; 64] {
    let mut key = [0_u8; 64];
    key[..32].copy_from_slice(domain_id.as_bytes());
    key[32..].copy_from_slice(&control_id);
    key
}

fn control_slot_key(control: &ControlTransition) -> [u8; 81] {
    let mut key = [0_u8; 81];
    key[..32].copy_from_slice(control.domain_id().as_bytes());
    key[32..40].copy_from_slice(&control.sequence().to_be_bytes());
    if let Some(predecessor) = control.predecessor() {
        key[40] = 1;
        key[41..73].copy_from_slice(&predecessor);
    }
    key[73..].copy_from_slice(&control.previous_epoch().to_be_bytes());
    key
}

fn insert_control_observation(
    write: &redb::WriteTransaction,
    control: &ControlTransition,
    control_id: [u8; 32],
) -> Result<(), StoreError> {
    let bytes = control.encode_canonical().map_err(authority_error)?;
    write
        .open_table(CONTROL_OBJECTS)
        .map_err(database_error)?
        .insert(
            control_object_key(control.domain_id(), control_id).as_slice(),
            bytes.as_slice(),
        )
        .map_err(database_error)?;
    write
        .open_table(CONTROL_SLOTS)
        .map_err(database_error)?
        .insert(control_slot_key(control).as_slice(), control_id.as_slice())
        .map_err(database_error)?;
    Ok(())
}

fn apply_control_revocations(
    write: &redb::WriteTransaction,
    control: &ControlTransition,
) -> Result<(), StoreError> {
    for subject in control.revoked_subjects() {
        let subject_key = subject_revocation_key(control.domain_id(), *subject);
        write
            .open_table(SUBJECT_REVOCATIONS)
            .map_err(database_error)?
            .insert(subject_key.as_slice(), control.sequence())
            .map_err(database_error)?;
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
    Ok(())
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
    insert_capability_record(write, capability_id, bytes)?;
    set_active_capability(write, capability, capability_id)
}

fn insert_capability_record(
    write: &redb::WriteTransaction,
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
    Ok(())
}

fn set_active_capability(
    write: &redb::WriteTransaction,
    capability: &CapabilityCertificate,
    capability_id: CapabilityId,
) -> Result<(), StoreError> {
    let mut active = write
        .open_table(ACTIVE_CAPABILITIES)
        .map_err(database_error)?;
    let key = active_capability_key(capability.domain_id(), capability.subject());
    active
        .insert(key.as_slice(), capability_id.as_bytes().as_slice())
        .map_err(database_error)?;
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

fn apply_schema_stages(
    write: &redb::WriteTransaction,
    domain_id: DomainId,
    stages: &[SchemaStage],
) -> Result<Option<CollectionId>, StoreError> {
    if stages.is_empty() {
        return Ok(None);
    }
    staging_digest(stages)?;
    let mut table = write.open_table(MIGRATION_STAGES).map_err(database_error)?;
    for stage in stages {
        let target = MaterializedRecord::decode_canonical(stage.target_record())
            .map_err(|error| StoreError::InvalidMigration(error.to_string()))?;
        if target.state().is_none()
            || target.record_id() != stage.source_record_id()
            || target.schema().schema_id() != stage.to().schema_id()
        {
            return Err(StoreError::InvalidMigration(
                "stage target does not match its target schema and source key".into(),
            ));
        }
        let key = migration_stage_key(domain_id, stage.migration_id(), stage.source_record_id());
        let bytes = stage.encode_canonical();
        let existing = table
            .get(key.as_slice())
            .map_err(database_error)?
            .map(|value| value.value().to_vec());
        if let Some(existing) = existing.filter(|existing| existing != &bytes) {
            let evidence = minicbor::to_vec((existing, bytes.clone()))
                .map_err(|error| StoreError::InvalidMigration(error.to_string()))?;
            drop(table);
            write
                .open_table(MIGRATION_FORKS)
                .map_err(database_error)?
                .insert(
                    active_schema_key(domain_id, stage.to().collection_id()).as_slice(),
                    evidence.as_slice(),
                )
                .map_err(database_error)?;
            return Ok(Some(stage.to().collection_id()));
        }
        table
            .insert(key.as_slice(), bytes.as_slice())
            .map_err(database_error)?;
    }
    Ok(None)
}

fn apply_schema_activation(
    write: &redb::WriteTransaction,
    domain_id: DomainId,
    activation: &SchemaActivation,
) -> Result<bool, StoreError> {
    let collection_id = activation.to().collection_id();
    let history_key =
        migration_activation_key(domain_id, collection_id, activation.from().schema_id());
    let activation_bytes = activation.encode_canonical();
    let conflict = {
        let history = write
            .open_table(MIGRATION_ACTIVATIONS)
            .map_err(database_error)?;
        history
            .get(history_key.as_slice())
            .map_err(database_error)?
            .map(|existing| existing.value().to_vec())
            .filter(|existing| existing != &activation_bytes)
    };
    if let Some(existing) = conflict {
        let evidence = minicbor::to_vec((existing, activation_bytes.clone()))
            .map_err(|error| StoreError::InvalidMigration(error.to_string()))?;
        write
            .open_table(MIGRATION_FORKS)
            .map_err(database_error)?
            .insert(
                active_schema_key(domain_id, collection_id).as_slice(),
                evidence.as_slice(),
            )
            .map_err(database_error)?;
        return Ok(true);
    }

    let stages = {
        let table = write.open_table(MIGRATION_STAGES).map_err(database_error)?;
        load_schema_stages(&table, domain_id, activation.migration_id())?
    };
    if u64::try_from(stages.len()).ok() != Some(activation.staged_records())
        || staging_digest(&stages)? != activation.staging_digest()
        || stages.iter().any(|stage| {
            stage.from().schema_id() != activation.from().schema_id()
                || stage.to().schema_id() != activation.to().schema_id()
        })
    {
        return Err(StoreError::InvalidMigration(
            "activation does not commit to the complete durable staging set".into(),
        ));
    }

    let mut targets = Vec::with_capacity(stages.len());
    for stage in &stages {
        targets.push(
            MaterializedRecord::decode_canonical(stage.target_record())
                .map_err(|error| StoreError::InvalidMigration(error.to_string()))?,
        );
    }
    clear_materialized_collection(write, domain_id, collection_id)?;
    register_schema(write, domain_id, activation.from())?;
    register_schema(write, domain_id, activation.to())?;
    apply_materialized_records(write, domain_id, &targets)?;

    write
        .open_table(MIGRATION_ACTIVATIONS)
        .map_err(database_error)?
        .insert(history_key.as_slice(), activation_bytes.as_slice())
        .map_err(database_error)?;
    write
        .open_table(ACTIVE_SCHEMAS)
        .map_err(database_error)?
        .insert(
            active_schema_key(domain_id, collection_id).as_slice(),
            activation_bytes.as_slice(),
        )
        .map_err(database_error)?;
    Ok(false)
}

fn load_schema_stages(
    table: &impl redb::ReadableTable<&'static [u8], &'static [u8]>,
    domain_id: DomainId,
    migration_id: MigrationId,
) -> Result<Vec<SchemaStage>, StoreError> {
    let prefix = migration_stage_prefix(domain_id, migration_id);
    let mut stages = Vec::new();
    for entry in table.iter().map_err(database_error)? {
        let (key, value) = entry.map_err(database_error)?;
        if key.value().starts_with(&prefix) {
            stages.push(SchemaStage::decode_canonical(value.value())?);
        }
    }
    stages.sort_unstable_by(|left, right| left.source_record_id().cmp(right.source_record_id()));
    Ok(stages)
}

fn register_schema(
    write: &redb::WriteTransaction,
    domain_id: DomainId,
    schema: &SchemaDescriptor,
) -> Result<(), StoreError> {
    let key = schema_key(domain_id, schema.collection_id(), schema.version());
    let bytes = schema.encode_canonical();
    let mut schemas = write.open_table(SCHEMAS).map_err(database_error)?;
    if let Some(existing) = schemas.get(key.as_slice()).map_err(database_error)?
        && existing.value() != bytes
    {
        return Err(StoreError::SchemaMismatch {
            collection_id: schema.collection_id(),
            version: schema.version(),
        });
    }
    schemas
        .insert(key.as_slice(), bytes.as_slice())
        .map_err(database_error)?;
    Ok(())
}

fn clear_materialized_collection(
    write: &redb::WriteTransaction,
    domain_id: DomainId,
    collection_id: CollectionId,
) -> Result<(), StoreError> {
    let prefix = record_prefix(domain_id, collection_id);
    {
        let mut table = write.open_table(RECORDS).map_err(database_error)?;
        for key in table_keys_with_prefix(&table, &prefix)? {
            table.remove(key.as_slice()).map_err(database_error)?;
        }
    }
    {
        let mut table = write
            .open_table(RECORD_INDEX_KEYS)
            .map_err(database_error)?;
        for key in table_keys_with_prefix(&table, &prefix)? {
            table.remove(key.as_slice()).map_err(database_error)?;
        }
    }
    {
        let mut table = write.open_table(SECONDARY_INDEX).map_err(database_error)?;
        let mut keys = Vec::new();
        for entry in table.iter().map_err(database_error)? {
            let (key, _) = entry.map_err(database_error)?;
            if key.value().starts_with(&prefix) {
                keys.push(key.value().to_vec());
            }
        }
        for key in keys {
            table.remove(key.as_slice()).map_err(database_error)?;
        }
    }
    Ok(())
}

fn install_snapshot_activations(
    write: &redb::WriteTransaction,
    domain_id: DomainId,
    records: &[MaterializedRecord],
    activations: &[SchemaActivation],
) -> Result<(), StoreError> {
    if activations
        .windows(2)
        .any(|pair| pair[0].to().collection_id() >= pair[1].to().collection_id())
    {
        return Err(StoreError::InvalidSnapshotMetadata(
            "schema activations are not unique and ordered".into(),
        ));
    }
    for activation in activations {
        let collection_id = activation.to().collection_id();
        if records.iter().any(|record| {
            record.schema().collection_id() == collection_id
                && record.schema().schema_id() != activation.to().schema_id()
        }) {
            return Err(StoreError::InvalidSnapshotMetadata(
                "record schema disagrees with active migration".into(),
            ));
        }
        register_schema(write, domain_id, activation.from())?;
        register_schema(write, domain_id, activation.to())?;
        let bytes = activation.encode_canonical();
        write
            .open_table(ACTIVE_SCHEMAS)
            .map_err(database_error)?
            .insert(
                active_schema_key(domain_id, collection_id).as_slice(),
                bytes.as_slice(),
            )
            .map_err(database_error)?;
        write
            .open_table(MIGRATION_ACTIVATIONS)
            .map_err(database_error)?
            .insert(
                migration_activation_key(domain_id, collection_id, activation.from().schema_id())
                    .as_slice(),
                bytes.as_slice(),
            )
            .map_err(database_error)?;
    }
    Ok(())
}

fn clear_domain_migration_metadata(
    write: &redb::WriteTransaction,
    domain_id: DomainId,
) -> Result<(), StoreError> {
    for table_definition in [
        ACTIVE_SCHEMAS,
        MIGRATION_STAGES,
        MIGRATION_ACTIVATIONS,
        MIGRATION_FORKS,
    ] {
        let mut table = write.open_table(table_definition).map_err(database_error)?;
        for key in table_keys_with_prefix(&table, domain_id.as_bytes())? {
            table.remove(key.as_slice()).map_err(database_error)?;
        }
    }
    let mut checkpoints = write
        .open_table(MIGRATION_CHECKPOINTS)
        .map_err(database_error)?;
    for key in table_keys_with_prefix(&checkpoints, domain_id.as_bytes())? {
        checkpoints.remove(key.as_slice()).map_err(database_error)?;
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

fn clear_reconciliation_domain(
    write: &redb::WriteTransaction,
    domain_id: DomainId,
) -> Result<(), StoreError> {
    {
        let mut table = write.open_table(COMMIT_CONTEXTS).map_err(database_error)?;
        for key in table_keys_with_prefix(&table, domain_id.as_bytes())? {
            table.remove(key.as_slice()).map_err(database_error)?;
        }
    }
    {
        let mut table = write.open_table(RECORD_HEADS).map_err(database_error)?;
        for key in table_keys_with_prefix(&table, domain_id.as_bytes())? {
            table.remove(key.as_slice()).map_err(database_error)?;
        }
    }
    mark_reconciliation_stale(write, domain_id)
}

fn clear_domain_snapshot_metadata(
    write: &redb::WriteTransaction,
    domain_id: DomainId,
) -> Result<(), StoreError> {
    write
        .open_table(SNAPSHOT_BASELINES)
        .map_err(database_error)?
        .remove(domain_id.as_bytes().as_slice())
        .map_err(database_error)?;
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
    for entry in table.range(prefix..).map_err(database_error)? {
        let (key, _) = entry.map_err(database_error)?;
        if !key.value().starts_with(prefix) {
            break;
        }
        keys.push(key.value().to_vec());
    }
    Ok(keys)
}

fn table_u8_keys_with_prefix(
    table: &impl redb::ReadableTable<&'static [u8], u8>,
    prefix: &[u8],
) -> Result<Vec<Vec<u8>>, StoreError> {
    let mut keys = Vec::new();
    for entry in table.range(prefix..).map_err(database_error)? {
        let (key, _) = entry.map_err(database_error)?;
        if !key.value().starts_with(prefix) {
            break;
        }
        keys.push(key.value().to_vec());
    }
    Ok(keys)
}

fn table_u64_keys_with_prefix(
    table: &impl redb::ReadableTable<&'static [u8], u64>,
    prefix: &[u8],
) -> Result<Vec<Vec<u8>>, StoreError> {
    let mut keys = Vec::new();
    for entry in table.range(prefix..).map_err(database_error)? {
        let (key, _) = entry.map_err(database_error)?;
        if !key.value().starts_with(prefix) {
            break;
        }
        keys.push(key.value().to_vec());
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

fn active_schema_key(domain_id: DomainId, collection_id: CollectionId) -> [u8; 64] {
    let mut key = [0_u8; 64];
    key[..32].copy_from_slice(domain_id.as_bytes());
    key[32..].copy_from_slice(collection_id.as_bytes());
    key
}

fn operational_metadata_key(domain_id: DomainId, tag: u8) -> [u8; 33] {
    let mut key = [0_u8; 33];
    key[..32].copy_from_slice(domain_id.as_bytes());
    key[32] = tag;
    key
}

fn migration_stage_prefix(domain_id: DomainId, migration_id: MigrationId) -> [u8; 64] {
    let mut prefix = [0_u8; 64];
    prefix[..32].copy_from_slice(domain_id.as_bytes());
    prefix[32..].copy_from_slice(migration_id.as_bytes());
    prefix
}

fn migration_stage_key(
    domain_id: DomainId,
    migration_id: MigrationId,
    record_id: &[u8],
) -> Vec<u8> {
    let prefix = migration_stage_prefix(domain_id, migration_id);
    let mut key = Vec::with_capacity(prefix.len() + record_id.len());
    key.extend_from_slice(&prefix);
    key.extend_from_slice(record_id);
    key
}

fn migration_activation_key(
    domain_id: DomainId,
    collection_id: CollectionId,
    from_schema: iroh_db_core::SchemaId,
) -> [u8; 96] {
    let mut key = [0_u8; 96];
    key[..32].copy_from_slice(domain_id.as_bytes());
    key[32..64].copy_from_slice(collection_id.as_bytes());
    key[64..].copy_from_slice(from_schema.as_bytes());
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

fn author_commit_key(domain_id: DomainId, author: AuthorId, sequence: u64) -> [u8; 72] {
    let mut key = [0_u8; 72];
    key[..64].copy_from_slice(&author_sequence_key(domain_id, author));
    key[64..].copy_from_slice(&sequence.to_be_bytes());
    key
}

fn blob_ownership_key(domain_id: DomainId, hash: BlobHash) -> [u8; 64] {
    let mut key = [0_u8; 64];
    key[..32].copy_from_slice(domain_id.as_bytes());
    key[32..].copy_from_slice(hash.as_bytes());
    key
}

fn frontier_key(domain_id: DomainId, commit_id: CommitId) -> [u8; 64] {
    let mut key = [0_u8; 64];
    key[..32].copy_from_slice(domain_id.as_bytes());
    key[32..].copy_from_slice(commit_id.as_bytes());
    key
}

fn commit_context_key(domain_id: DomainId, commit_id: CommitId) -> [u8; 64] {
    frontier_key(domain_id, commit_id)
}

fn record_head_prefix(
    domain_id: DomainId,
    collection_id: CollectionId,
    record_id: &[u8],
) -> Result<Vec<u8>, StoreError> {
    let record_length = u32::try_from(record_id.len()).map_err(|_| {
        StoreError::CorruptDerivedMetadata("record head ID length exceeds u32".into())
    })?;
    let mut key = Vec::with_capacity(68 + record_id.len());
    key.extend_from_slice(domain_id.as_bytes());
    key.extend_from_slice(collection_id.as_bytes());
    key.extend_from_slice(&record_length.to_be_bytes());
    key.extend_from_slice(record_id);
    Ok(key)
}

fn record_head_key(domain_id: DomainId, head: &RecordHead) -> Result<Vec<u8>, StoreError> {
    let mut key = record_head_prefix(
        domain_id,
        head.mutation().schema().collection_id(),
        head.mutation().record_id(),
    )?;
    key.extend_from_slice(head.commit_id().as_bytes());
    Ok(key)
}

fn encode_version_vector(context: &VersionVector) -> Result<Vec<u8>, StoreError> {
    minicbor::to_vec(context).map_err(|error| {
        StoreError::CorruptDerivedMetadata(format!("commit context encoding failed: {error}"))
    })
}

fn decode_version_vector(bytes: &[u8]) -> Result<VersionVector, StoreError> {
    let mut decoder = minicbor::Decoder::new(bytes);
    let context: VersionVector = decoder.decode().map_err(|error| {
        StoreError::CorruptDerivedMetadata(format!("commit context is invalid: {error}"))
    })?;
    if decoder.position() != bytes.len() || encode_version_vector(&context)? != bytes {
        return Err(StoreError::CorruptDerivedMetadata(
            "commit context is not canonical".into(),
        ));
    }
    Ok(context)
}

fn encode_record_head(head: &RecordHead) -> Result<Vec<u8>, StoreError> {
    let mutation = head.mutation().encode_canonical().map_err(|error| {
        StoreError::CorruptDerivedMetadata(format!("record head mutation is invalid: {error}"))
    })?;
    let mut encoded = Vec::with_capacity(40 + mutation.len());
    encoded.extend_from_slice(head.author().as_bytes());
    encoded.extend_from_slice(&head.sequence().to_be_bytes());
    encoded.extend_from_slice(&mutation);
    Ok(encoded)
}

fn decode_record_head(commit_id: CommitId, bytes: &[u8]) -> Result<RecordHead, StoreError> {
    if bytes.len() < 40 {
        return Err(StoreError::CorruptDerivedMetadata(
            "record head value is truncated".into(),
        ));
    }
    let author: [u8; 32] = bytes[..32].try_into().expect("exact author length");
    let sequence: [u8; 8] = bytes[32..40].try_into().expect("exact sequence length");
    let mutation = MaterializedRecord::decode_canonical(&bytes[40..]).map_err(|error| {
        StoreError::CorruptDerivedMetadata(format!("record head mutation is invalid: {error}"))
    })?;
    Ok(RecordHead::new(
        commit_id,
        AuthorId::from_bytes(author),
        u64::from_be_bytes(sequence),
        mutation,
    ))
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
