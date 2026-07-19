use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
    path::Path,
    sync::{Arc, RwLock},
};

use iroh_db_blobs::{BlobEngine, BlobError, BlobRef, BlobStream, IrohBlobStore};
use iroh_db_core::{
    AuthorId, BlobHash, CapabilityId, CollectionId, CommitBody, CommitCodecError, CommitEnvelope,
    CommitHeader, CommitId, Dot, EqualityFilter, IrohRecord, Operation, OperationKind, RangeFilter,
    RecordError, RecordKey, SchemaId, TransactionId, TypedField, VersionVector,
};
use iroh_db_security::{
    AuthorityError, CapabilityCertificate, ConsistencyMode, ControlTransition, DomainDescriptor,
    DomainSeed, Invitation, InvitationError, InvitationSecret, InvitationTicket, LocalCredentials,
    Permission, PermissionSet, SecurityError, open_commit, seal_commit,
};
use iroh_db_store::{
    ApplyOutcome, BlobFuture, BlobStore, BlobStoreError, IndexValue, MaterializedError,
    MaterializedRecord, Store, StoreError,
};
use tokio::io::AsyncRead;
use tokio::sync::{Mutex, RwLock as AsyncRwLock, broadcast};

const CHANGE_CAPACITY: usize = 1_024;
const MAX_RECONCILE_COMMITS: usize = 65_536;

/// An embedded database operation failure.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// Durable metadata or blob storage failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// A typed record failed schema or codec validation.
    #[error(transparent)]
    Record(#[from] RecordError),
    /// A prepared materialization violated storage bounds.
    #[error(transparent)]
    Materialized(#[from] MaterializedError),
    /// Commit encryption, signing or key-provider access failed.
    #[error(transparent)]
    Security(#[from] SecurityError),
    /// A capability, invitation, or domain-control object failed validation.
    #[error(transparent)]
    Authority(#[from] AuthorityError),
    /// A targeted online or offline invitation failed validation or decryption.
    #[error(transparent)]
    Invitation(#[from] InvitationError),
    /// A bounded canonical commit object could not be constructed.
    #[error(transparent)]
    Commit(#[from] CommitCodecError),
    /// The operating-system cryptographic random source failed.
    #[error("cryptographic randomness is unavailable")]
    RandomnessUnavailable,
    /// The local author sequence exhausted its durable range.
    #[error("local author sequence is exhausted")]
    SequenceExhausted,
    /// A transaction without operations cannot create a commit.
    #[error("transaction contains no operations")]
    EmptyTransaction,
    /// Collection or transaction handles still reference the database during close.
    #[error("database cannot close while collection or transaction handles remain")]
    HandlesOpen,
    /// A query predicate could not encode its value.
    #[error("query predicate is invalid: {0}")]
    InvalidQuery(RecordError),
    /// An opaque pagination cursor was malformed, modified, stale, or used with another query.
    #[error("invalid pagination cursor: {0}")]
    InvalidCursor(String),
    /// Encrypted blob import, manifest validation or streaming setup failed.
    #[error(transparent)]
    Blob(#[from] BlobError),
    /// A snapshot failed canonical, signature, domain or state-root validation.
    #[error("snapshot validation failed: {0}")]
    InvalidSnapshot(String),
    /// A network-authenticated device is not authorized for this domain operation.
    #[error("device is not authorized for this domain")]
    UnauthorizedDevice,
    /// A commit authored behind a signed epoch cut must be explicitly rebased by the application.
    #[error("commit {0} was authored before the active epoch cut and requires rebase")]
    RebaseRequired(CommitId),
    /// A domain handle predates the durable control epoch and must be reopened.
    #[error("domain handle epoch {handle} is stale; active epoch is {active}")]
    StaleEpoch { handle: u64, active: u64 },
    /// A one-time offline invitation ticket was already imported by this device.
    #[error("offline invitation ticket was already consumed")]
    InvitationAlreadyUsed,
    /// A remote commit targets a typed collection not registered by this process.
    #[error("record schema is not registered for collection {0}")]
    UnknownRecordSchema(CollectionId),
    /// A remote commit header, operation, or materialization disagreed about its target.
    #[error("remote commit operation is inconsistent: {0}")]
    InvalidRemoteCommit(String),
    /// Endpoint, QUIC, control-frame, or immutable transfer failed.
    #[error("synchronization failed: {0}")]
    Network(String),
    /// Verification, repair, backup, or restore failed without overwriting a good copy.
    #[error("operation failed: {0}")]
    Operation(String),
}

/// A committed materialized-record change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    collection_id: CollectionId,
    record_id: Vec<u8>,
    kind: ChangeKind,
}

impl Change {
    /// Returns the affected collection.
    pub const fn collection_id(&self) -> CollectionId {
        self.collection_id
    }

    /// Returns the canonical application record ID.
    pub fn record_id(&self) -> &[u8] {
        &self.record_id
    }

    /// Returns whether the record was replaced or removed.
    pub const fn kind(&self) -> ChangeKind {
        self.kind
    }
}

/// The visible effect of a committed record mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    /// A record became present or received new materialized state.
    Upserted,
    /// A record was removed.
    Deleted,
}

/// One atomic post-commit subscription event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeBatch {
    commit_id: CommitId,
    sequence: u64,
    changes: Vec<Change>,
}

impl ChangeBatch {
    /// Returns the immutable source commit.
    pub const fn commit_id(&self) -> CommitId {
        self.commit_id
    }

    /// Returns the monotonically increasing local-author sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns all record effects published atomically by the commit.
    pub fn changes(&self) -> &[Change] {
        &self.changes
    }
}

/// Subscription receive failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SubscriptionError {
    /// The database closed the subscription channel.
    #[error("subscription is closed")]
    Closed,
    /// The bounded channel dropped events; the caller must re-query.
    #[error("subscription lagged by {0} commit batches; re-query required")]
    Lagged(u64),
}

/// A local-first embedded database with one default private domain.
#[derive(Clone)]
pub struct IrohDb {
    pub(crate) inner: Arc<DbInner>,
    pub(crate) domain: Arc<RwLock<DomainSeed>>,
}

pub(crate) struct DbInner {
    pub(crate) store: Store,
    pub(crate) blobs: Arc<IrohBlobStore>,
    pub(crate) credentials: LocalCredentials,
    pub(crate) writer: Mutex<()>,
    pub(crate) control_gate: AsyncRwLock<()>,
    domains: RwLock<BTreeMap<iroh_db_core::DomainId, Arc<RwLock<DomainSeed>>>>,
    changes: RwLock<BTreeMap<iroh_db_core::DomainId, broadcast::Sender<ChangeBatch>>>,
    adapters: RwLock<BTreeMap<CollectionId, RecordAdapter>>,
}

#[derive(Clone)]
struct DomainBlobStore {
    blobs: Arc<IrohBlobStore>,
    metadata: Store,
    domain_id: iroh_db_core::DomainId,
}

impl BlobStore for DomainBlobStore {
    fn put(&self, bytes: Vec<u8>) -> BlobFuture<'_, BlobHash> {
        Box::pin(async move {
            let hash = self.blobs.put(bytes).await?;
            self.metadata
                .claim_blob(self.domain_id, hash)
                .map_err(blob_metadata_error)?;
            Ok(hash)
        })
    }

    fn get(&self, hash: BlobHash) -> BlobFuture<'_, Option<Vec<u8>>> {
        self.blobs.get(hash)
    }

    fn list(&self) -> BlobFuture<'_, Vec<BlobHash>> {
        Box::pin(async move {
            let mut owned = Vec::new();
            for hash in self.blobs.list().await? {
                if self
                    .metadata
                    .owns_blob(self.domain_id, hash)
                    .map_err(blob_metadata_error)?
                {
                    owned.push(hash);
                }
            }
            Ok(owned)
        })
    }

    fn claim(&self, hash: BlobHash) -> BlobFuture<'_, ()> {
        Box::pin(async move {
            self.metadata
                .claim_blob(self.domain_id, hash)
                .map_err(blob_metadata_error)
        })
    }
}

#[derive(Clone, Copy)]
struct RecordAdapter {
    schema_id: SchemaId,
    merge: fn(Option<&[u8]>, &MaterializedRecord) -> Result<MaterializedRecord, DbError>,
    canonicalize: fn(
        &MaterializedRecord,
        AuthorId,
        u64,
        &VersionVector,
        &mut u32,
    ) -> Result<MaterializedRecord, DbError>,
}

/// Result of feeding one authenticated immutable commit into the local apply kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteApply {
    /// The commit and its merged materialization became durable.
    Applied(CommitId),
    /// The exact commit was already accepted.
    Duplicate(CommitId),
    /// Conflicting author-sequence branches were removed from accepted history.
    Quarantined {
        /// The author whose signing key produced conflicting commits.
        author: AuthorId,
        /// The first equivocated author-local sequence.
        sequence: u64,
    },
}

/// Application-facing label that groups device endpoints without changing protocol identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceGroup {
    label: String,
    members: Vec<AuthorId>,
}

impl DeviceGroup {
    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn members(&self) -> &[AuthorId] {
        &self.members
    }
}

/// Result of copying an explicit current-state projection into independent domain history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectionReport {
    selected: usize,
    commit: Option<CommitId>,
}

impl ProjectionReport {
    pub const fn selected(&self) -> usize {
        self.selected
    }

    pub const fn commit(&self) -> Option<CommitId> {
        self.commit
    }
}

impl IrohDb {
    /// Opens or creates an offline embedded database. No endpoint is started.
    pub async fn open(root: impl AsRef<Path>) -> Result<Self, DbError> {
        let root = root.as_ref();
        std::fs::create_dir_all(root).map_err(|error| StoreError::Io(error.to_string()))?;
        let credentials = LocalCredentials::load_or_create(root.join("keys"))?;
        let blobs = Arc::new(
            IrohBlobStore::load(root.join("blobs"))
                .await
                .map_err(StoreError::from)?,
        );
        let store = Store::open(root, blobs.clone())?;
        reconcile_domain_epochs(&credentials, &store)?;
        store.trust_author(credentials.domain_id(), credentials.signer().author())?;
        let domain = credentials.domain_seed();
        credentials.store_domain(&domain)?;
        let domain = Arc::new(RwLock::new(domain));
        let (changes, _) = broadcast::channel(CHANGE_CAPACITY);
        let mut domain_changes = BTreeMap::new();
        domain_changes.insert(
            domain
                .read()
                .expect("domain seed lock is not poisoned")
                .domain_id(),
            changes,
        );
        let mut domains = BTreeMap::new();
        domains.insert(
            domain
                .read()
                .expect("domain seed lock is not poisoned")
                .domain_id(),
            domain.clone(),
        );
        Ok(Self {
            inner: Arc::new(DbInner {
                store,
                blobs,
                credentials,
                writer: Mutex::new(()),
                control_gate: AsyncRwLock::new(()),
                domains: RwLock::new(domains),
                changes: RwLock::new(domain_changes),
                adapters: RwLock::new(BTreeMap::new()),
            }),
            domain,
        })
    }

    /// Creates a new per-device identity inside an existing encrypted domain.
    pub async fn create_in_domain(
        root: impl AsRef<Path>,
        seed: &DomainSeed,
    ) -> Result<Self, DbError> {
        let root = root.as_ref();
        std::fs::create_dir_all(root).map_err(|error| StoreError::Io(error.to_string()))?;
        LocalCredentials::create_for_domain(root.join("keys"), seed)?;
        Self::open(root).await
    }

    /// Opens a strongly typed collection in the default private domain.
    pub fn collection<Record: IrohRecord>(&self) -> Collection<Record> {
        let schema = Record::schema().expect("a record schema is statically valid");
        self.inner
            .adapters
            .write()
            .expect("record adapter lock is not poisoned")
            .insert(
                schema.collection_id(),
                RecordAdapter {
                    schema_id: schema.schema_id(),
                    merge: merge_materialized::<Record>,
                    canonicalize: canonicalize_materialized::<Record>,
                },
            );
        Collection {
            db: self.clone(),
            marker: PhantomData,
        }
    }

    /// Starts an atomic transaction in the default private domain.
    pub fn transaction(&self) -> Transaction {
        Transaction {
            db: self.clone(),
            prepared: Vec::new(),
        }
    }

    /// Returns the encrypted first-class blob API for the default domain.
    pub fn blobs(&self) -> Blobs {
        Blobs { db: self.clone() }
    }

    /// Returns this device's authenticated endpoint identity.
    pub fn author_id(&self) -> AuthorId {
        self.inner.credentials.signer().author()
    }

    /// Exports sensitive domain bootstrap material for a trusted device-add workflow.
    pub fn domain_seed(&self) -> DomainSeed {
        self.domain
            .read()
            .expect("domain seed lock is not poisoned")
            .clone()
    }

    /// Returns this handle's isolated security and replication domain.
    pub fn domain_id(&self) -> iroh_db_core::DomainId {
        self.domain
            .read()
            .expect("domain seed lock is not poisoned")
            .domain_id()
    }

    /// Attaches an independently encrypted domain to this device and returns its handle.
    pub fn attach_domain(&self, seed: &DomainSeed) -> Result<Self, DbError> {
        self.inner.credentials.store_domain(seed)?;
        self.inner
            .store
            .trust_author(seed.domain_id(), self.author_id())?;
        self.ensure_change_channel(seed.domain_id());
        self.domain(seed.domain_id())
    }

    /// Creates a capability-controlled domain owned by this device.
    pub fn create_domain(&self, mode: ConsistencyMode) -> Result<Self, DbError> {
        let seed = DomainSeed::generate()?;
        let domain = self.attach_domain(&seed)?;
        let mut descriptor_nonce = [0_u8; 32];
        let mut capability_nonce = [0_u8; 32];
        getrandom::fill(&mut descriptor_nonce).map_err(|_| DbError::RandomnessUnavailable)?;
        getrandom::fill(&mut capability_nonce).map_err(|_| DbError::RandomnessUnavailable)?;
        let signer = self.inner.credentials.signer();
        let descriptor =
            DomainDescriptor::issue(seed.domain_id(), mode, &signer, descriptor_nonce)?;
        let root = CapabilityCertificate::issue_root(
            seed.domain_id(),
            PermissionSet::all(),
            &signer,
            capability_nonce,
        )?;
        self.inner.store.bootstrap_domain(&descriptor, &root)?;
        Ok(domain)
    }

    /// Returns the signed genesis descriptor for a controlled domain.
    pub fn domain_descriptor(&self) -> Result<Option<DomainDescriptor>, DbError> {
        self.inner
            .store
            .domain_descriptor(self.domain_id())
            .map_err(DbError::from)
    }

    /// Advances the domain epoch at its current causal frontier and revokes endpoints.
    pub fn rotate_epoch(
        &self,
        revoked_subjects: &[AuthorId],
    ) -> Result<(Self, ControlTransition), DbError> {
        let controller = self.inner.store.current_controller(self.domain_id())?;
        self.rotate_epoch_with_controller(revoked_subjects, controller)
    }

    /// Advances the epoch and designates the endpoint that must sign the following transition.
    pub fn rotate_epoch_with_controller(
        &self,
        revoked_subjects: &[AuthorId],
        next_controller: AuthorId,
    ) -> Result<(Self, ControlTransition), DbError> {
        let _control_writer = self
            .inner
            .control_gate
            .try_write()
            .map_err(|_| DbError::Operation("control plane is busy".into()))?;
        let active_epoch = self.inner.store.current_epoch(self.domain_id())?;
        if self.epoch() != active_epoch {
            return Err(DbError::StaleEpoch {
                handle: self.epoch(),
                active: active_epoch,
            });
        }
        let author_capability = self
            .inner
            .store
            .active_capability(self.domain_id(), self.author_id())?
            .ok_or(DbError::UnauthorizedDevice)?;
        if self.inner.store.current_controller(self.domain_id())? != self.author_id() {
            return Err(DbError::UnauthorizedDevice);
        }
        let head = self.inner.store.control_head(self.domain_id())?;
        let sequence = head.as_ref().map_or(Ok(1), |value| {
            value
                .sequence()
                .checked_add(1)
                .ok_or(DbError::SequenceExhausted)
        })?;
        let predecessor = head.as_ref().map(ControlTransition::id).transpose()?;
        let next_seed = self.domain_seed().next_epoch()?;
        let writer = self
            .inner
            .store
            .current_writer(self.domain_id())?
            .ok_or(DbError::UnauthorizedDevice)?;
        let next_controller_capability = self
            .inner
            .store
            .active_capability(self.domain_id(), next_controller)?
            .ok_or(DbError::UnauthorizedDevice)?;
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| DbError::RandomnessUnavailable)?;
        let control = ControlTransition::issue(
            self.domain_id(),
            sequence,
            predecessor,
            active_epoch,
            self.inner.store.frontier(self.domain_id())?,
            revoked_subjects.to_vec(),
            writer,
            next_controller,
            next_controller_capability,
            next_seed.distribution_digest(),
            author_capability,
            nonce,
            &self.inner.credentials.signer(),
        )?;
        self.inner.store.observe_control(&control)?;
        self.inner.credentials.stage_domain(&next_seed)?;
        if let Err(error) = self.inner.store.apply_control(&control) {
            return Err(DbError::Store(error));
        }
        self.inner.credentials.activate_domain(&next_seed)?;
        self.set_domain_seed(&next_seed);
        Ok((self.domain(self.domain_id())?, control))
    }

    /// Applies signed control and its separately delivered endpoint-targeted epoch key.
    pub fn apply_epoch_rotation(
        &self,
        control: &ControlTransition,
        next_seed: &DomainSeed,
    ) -> Result<Self, DbError> {
        self.apply_epoch_rotation_with_capabilities(control, next_seed, &[])
    }

    pub(crate) fn apply_epoch_rotation_with_capabilities(
        &self,
        control: &ControlTransition,
        next_seed: &DomainSeed,
        successor_chain: &[CapabilityCertificate],
    ) -> Result<Self, DbError> {
        let _control_writer = self
            .inner
            .control_gate
            .try_write()
            .map_err(|_| DbError::Operation("control plane is busy".into()))?;
        if control.domain_id() != self.domain_id()
            || next_seed.domain_id() != self.domain_id()
            || next_seed.epoch() != control.new_epoch()
            || next_seed.distribution_digest() != control.key_distribution_digest()
            || control.revoked_subjects().contains(&self.author_id())
        {
            return Err(DbError::UnauthorizedDevice);
        }
        if successor_chain.is_empty() {
            self.inner.store.observe_control(control)?;
        }
        self.inner.credentials.stage_domain(next_seed)?;
        let apply_result = if successor_chain.is_empty() {
            self.inner.store.apply_control(control)
        } else {
            self.inner
                .store
                .apply_control_bundle(control, successor_chain)
        };
        if let Err(error) = apply_result {
            return Err(DbError::Store(error));
        }
        self.inner.credentials.activate_domain(next_seed)?;
        self.set_domain_seed(next_seed);
        self.domain(self.domain_id())
    }

    /// Issues and installs a narrowed endpoint capability from this device's active grant.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_capability(
        &self,
        subject: AuthorId,
        permissions: PermissionSet,
        delegation_permissions: PermissionSet,
        valid_from_epoch: u64,
        valid_through_epoch: Option<u64>,
    ) -> Result<CapabilityCertificate, DbError> {
        let _control_writer = self
            .inner
            .control_gate
            .try_write()
            .map_err(|_| DbError::Operation("control plane is busy".into()))?;
        self.issue_capability_guarded(
            subject,
            permissions,
            delegation_permissions,
            valid_from_epoch,
            valid_through_epoch,
        )
    }

    fn issue_capability_guarded(
        &self,
        subject: AuthorId,
        permissions: PermissionSet,
        delegation_permissions: PermissionSet,
        valid_from_epoch: u64,
        valid_through_epoch: Option<u64>,
    ) -> Result<CapabilityCertificate, DbError> {
        let active_epoch = self.inner.store.current_epoch(self.domain_id())?;
        if self.epoch() != active_epoch {
            return Err(DbError::StaleEpoch {
                handle: self.epoch(),
                active: active_epoch,
            });
        }
        let issuer_id = self
            .inner
            .store
            .active_capability(self.domain_id(), self.author_id())?
            .ok_or(DbError::UnauthorizedDevice)?;
        if !self.inner.store.authorize_capability(
            self.domain_id(),
            self.author_id(),
            issuer_id,
            Permission::Invite,
            active_epoch,
        )? {
            return Err(DbError::UnauthorizedDevice);
        }
        let issuer = self
            .inner
            .store
            .capability(issuer_id)?
            .ok_or(DbError::UnauthorizedDevice)?;
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| DbError::RandomnessUnavailable)?;
        let capability = issuer.delegate(
            &self.inner.credentials.signer(),
            subject,
            permissions,
            delegation_permissions,
            valid_from_epoch,
            valid_through_epoch,
            nonce,
        )?;
        self.inner.store.install_capability(&capability)?;
        self.inner.store.trust_author(self.domain_id(), subject)?;
        Ok(capability)
    }

    /// Returns this device's active capability in the selected domain.
    pub fn active_capability(&self) -> Result<Option<CapabilityCertificate>, DbError> {
        self.inner
            .store
            .active_capability(self.domain_id(), self.author_id())?
            .map(|id| self.inner.store.capability(id))
            .transpose()
            .map(Option::flatten)
            .map_err(DbError::from)
    }

    pub(crate) fn capability_for_permission(
        &self,
        subject: AuthorId,
        permission: Permission,
        epoch: u64,
    ) -> Result<CapabilityId, DbError> {
        if !self
            .inner
            .store
            .is_author_trusted(self.domain_id(), subject)?
        {
            return Err(DbError::UnauthorizedDevice);
        }
        if self
            .inner
            .store
            .domain_descriptor(self.domain_id())?
            .is_none()
        {
            return Ok(private_capability(self.domain_id()));
        }
        let capability_id = self
            .inner
            .store
            .active_capability(self.domain_id(), subject)?
            .ok_or(DbError::UnauthorizedDevice)?;
        if !self.inner.store.authorize_capability(
            self.domain_id(),
            subject,
            capability_id,
            permission,
            epoch,
        )? {
            return Err(DbError::UnauthorizedDevice);
        }
        Ok(capability_id)
    }

    pub(crate) fn blob_engine(&self) -> BlobEngine {
        BlobEngine::new_at_epoch(
            Arc::new(DomainBlobStore {
                blobs: self.inner.blobs.clone(),
                metadata: self.inner.store.clone(),
                domain_id: self.domain_id(),
            }),
            self.domain_id(),
            self.epoch(),
            self.domain_key(),
        )
    }

    pub(crate) fn blob_engine_for_epoch(&self, epoch: u64) -> Result<BlobEngine, DbError> {
        Ok(BlobEngine::new_at_epoch(
            Arc::new(DomainBlobStore {
                blobs: self.inner.blobs.clone(),
                metadata: self.inner.store.clone(),
                domain_id: self.domain_id(),
            }),
            self.domain_id(),
            epoch,
            self.domain_key_for(epoch)?,
        ))
    }

    /// Issues a targeted signed invitation carrying the current epoch key and capability chain.
    pub fn invite(
        &self,
        subject: AuthorId,
        permissions: PermissionSet,
        delegation_permissions: PermissionSet,
        valid_through_epoch: Option<u64>,
    ) -> Result<Invitation, DbError> {
        let _control_writer = self
            .inner
            .control_gate
            .try_write()
            .map_err(|_| DbError::Operation("control plane is busy".into()))?;
        let capability = self.issue_capability_guarded(
            subject,
            permissions,
            delegation_permissions,
            self.epoch(),
            valid_through_epoch,
        )?;
        let descriptor = self
            .domain_descriptor()?
            .ok_or(DbError::UnauthorizedDevice)?;
        let chain = self.inner.store.capability_chain(capability.id()?)?;
        Invitation::issue(
            descriptor,
            chain,
            self.domain_seed(),
            subject,
            &self.inner.credentials.signer(),
        )
        .map_err(DbError::from)
    }

    /// Imports a validated invitation only when it names this device endpoint.
    pub fn import_invitation(&self, invitation: &Invitation) -> Result<Self, DbError> {
        let _control_writer = self
            .inner
            .control_gate
            .try_write()
            .map_err(|_| DbError::Operation("control plane is busy".into()))?;
        self.import_invitation_guarded(invitation)
    }

    fn import_invitation_guarded(&self, invitation: &Invitation) -> Result<Self, DbError> {
        if invitation.subject() != self.author_id() {
            return Err(DbError::UnauthorizedDevice);
        }
        if self
            .inner
            .store
            .domain_descriptor(invitation.descriptor().domain_id())?
            .is_some()
        {
            self.inner
                .store
                .current_epoch(invitation.descriptor().domain_id())?;
        }
        let chain = invitation.capability_chain();
        self.inner
            .store
            .import_domain_authority_atomic(invitation.descriptor(), chain)?;
        self.inner
            .credentials
            .store_domain(&invitation.domain_seed())?;
        self.domain(invitation.descriptor().domain_id())
    }

    /// Decrypts an offline ticket for this endpoint and imports its domain authority.
    pub fn import_ticket(
        &self,
        ticket: &InvitationTicket,
        secret: &InvitationSecret,
    ) -> Result<Self, DbError> {
        let invitation = ticket.open(secret, self.author_id())?;
        let _control_writer = self
            .inner
            .control_gate
            .try_write()
            .map_err(|_| DbError::Operation("control plane is busy".into()))?;
        if !self.inner.store.consume_invitation(ticket.id()?)? {
            return Err(DbError::InvitationAlreadyUsed);
        }
        self.import_invitation_guarded(&invitation)
    }

    /// Opens a previously attached domain under the same device identity and local store.
    pub fn domain(&self, domain_id: iroh_db_core::DomainId) -> Result<Self, DbError> {
        let seed = self.inner.credentials.load_domain(domain_id)?;
        self.ensure_change_channel(domain_id);
        let domain = self
            .inner
            .domains
            .write()
            .expect("domain context lock is not poisoned")
            .entry(domain_id)
            .or_insert_with(|| Arc::new(RwLock::new(seed)))
            .clone();
        Ok(Self {
            inner: self.inner.clone(),
            domain,
        })
    }

    /// Lists domains whose encrypted keys are available to this device.
    pub fn domains(&self) -> Result<Vec<iroh_db_core::DomainId>, DbError> {
        self.inner.credentials.domains().map_err(DbError::from)
    }

    /// Replaces a bounded local UX group; authorization remains endpoint-specific.
    pub fn set_device_group(&self, label: &str, members: &[AuthorId]) -> Result<(), DbError> {
        self.inner
            .store
            .set_device_group(self.domain_id(), label, members)
            .map_err(DbError::from)
    }

    /// Lists durable application-facing device groups for this domain.
    pub fn device_groups(&self) -> Result<Vec<DeviceGroup>, DbError> {
        Ok(self
            .inner
            .store
            .device_groups(self.domain_id())?
            .into_iter()
            .map(|(label, members)| DeviceGroup { label, members })
            .collect())
    }

    /// Copies selected current typed records into one independent destination commit.
    pub async fn project<Record, PredicateFn>(
        &self,
        destination: &IrohDb,
        mut include: PredicateFn,
    ) -> Result<ProjectionReport, DbError>
    where
        Record: IrohRecord,
        PredicateFn: FnMut(&Record) -> bool,
    {
        if self.domain_id() == destination.domain_id() {
            return Err(DbError::InvalidRemoteCommit(
                "projection destination must be another domain".into(),
            ));
        }
        let records = self.collection::<Record>().query().fetch().await?;
        let _destination_collection = destination.collection::<Record>();
        let selected: Vec<_> = records
            .into_iter()
            .filter(|record| include(record))
            .collect();
        if selected.is_empty() {
            return Ok(ProjectionReport {
                selected: 0,
                commit: None,
            });
        }
        let selected_count = selected.len();
        let mut transaction = destination.transaction();
        for record in selected {
            transaction.put(record)?;
        }
        let batch = transaction.commit().await?;
        Ok(ProjectionReport {
            selected: selected_count,
            commit: Some(batch.commit_id()),
        })
    }

    /// Adds a device identity to the local authorization set.
    pub fn trust_device(&self, author: AuthorId) -> Result<(), DbError> {
        self.inner.store.trust_author(self.domain_id(), author)?;
        Ok(())
    }

    /// Loads accepted immutable commit envelopes in deterministic content-hash order.
    pub async fn commit_envelopes(&self) -> Result<Vec<CommitEnvelope>, DbError> {
        let domain = self.domain_id();
        let mut commits = Vec::new();
        for commit_id in self.inner.store.list_stored_commit_ids(domain)? {
            commits.push(self.inner.store.load_commit(commit_id).await?);
        }
        Ok(commits)
    }

    /// Validates, CRDT-merges, and atomically accepts one commit from an authenticated endpoint.
    pub async fn accept_remote_commit(
        &self,
        authenticated_peer: AuthorId,
        envelope: CommitEnvelope,
    ) -> Result<RemoteApply, DbError> {
        let _writer = self.inner.writer.lock().await;
        let header = envelope.header();
        let domain_id = self.domain_id();
        let commit_id = envelope.commit_id();
        if header.domain_id() != domain_id {
            return Err(DbError::UnauthorizedDevice);
        }
        if let Some(outcome) = self.quarantined_remote_apply(header, commit_id)? {
            return Ok(outcome);
        }
        if self.inner.store.contains_commit(commit_id)? {
            return Ok(RemoteApply::Duplicate(commit_id));
        }
        let active_epoch = self.inner.store.current_epoch(domain_id)?;
        if header.epoch() < active_epoch {
            return Err(DbError::RebaseRequired(commit_id));
        }
        if header.epoch() != active_epoch {
            return Err(DbError::UnauthorizedDevice);
        }
        if !self
            .inner
            .store
            .is_author_trusted(domain_id, authenticated_peer)?
            || !self
                .inner
                .store
                .is_author_trusted(domain_id, header.author())?
        {
            return Err(DbError::UnauthorizedDevice);
        }
        if self.inner.store.domain_descriptor(domain_id)?.is_some()
            && !self.inner.store.authorize_capability(
                domain_id,
                header.author(),
                header.capability_id(),
                Permission::Write,
                header.epoch(),
            )?
        {
            return Err(DbError::UnauthorizedDevice);
        }
        let body = open_commit(&envelope, &self.domain_key_for(header.epoch())?)?;
        if let Some(existing) = self.inner.store.conflicting_author_commit(&envelope)? {
            return self.quarantine_equivocation(envelope, existing).await;
        }
        self.validate_consistency(header.author(), &body)?;

        let adapters = self
            .inner
            .adapters
            .read()
            .expect("record adapter lock is not poisoned")
            .clone();
        let mutations = self
            .converged_mutations(&envelope, &body, &adapters)
            .await?;
        let changes = mutations
            .iter()
            .map(|mutation| Change {
                collection_id: mutation.schema().collection_id(),
                record_id: mutation.record_id().to_vec(),
                kind: if mutation.state().is_some() {
                    ChangeKind::Upserted
                } else {
                    ChangeKind::Deleted
                },
            })
            .collect();
        match self
            .inner
            .store
            .persist_commit_with_records(&envelope, &mutations)
            .await?
        {
            ApplyOutcome::Duplicate(id) => Ok(RemoteApply::Duplicate(id)),
            ApplyOutcome::Applied(id) => {
                let batch = ChangeBatch {
                    commit_id: id,
                    sequence: header.author_sequence(),
                    changes,
                };
                let _no_subscribers = self.changes().send(batch);
                Ok(RemoteApply::Applied(id))
            }
        }
    }

    fn quarantined_remote_apply(
        &self,
        header: &CommitHeader,
        commit_id: CommitId,
    ) -> Result<Option<RemoteApply>, DbError> {
        let commit_quarantined = self.inner.store.is_commit_quarantined(commit_id)?;
        let author_quarantined = self
            .inner
            .store
            .author_quarantine(header.domain_id(), header.author())?
            .is_some_and(|from_sequence| header.author_sequence() >= from_sequence);
        Ok(
            (commit_quarantined || author_quarantined).then_some(RemoteApply::Quarantined {
                author: header.author(),
                sequence: header.author_sequence(),
            }),
        )
    }

    async fn quarantine_equivocation(
        &self,
        evidence: CommitEnvelope,
        existing: CommitId,
    ) -> Result<RemoteApply, DbError> {
        let author = evidence.header().author();
        let sequence = evidence.header().author_sequence();
        let commit_ids = self.inner.store.list_stored_commit_ids(self.domain_id())?;
        let mut graph = BTreeMap::<CommitId, Vec<CommitId>>::new();
        let mut headers = BTreeMap::<CommitId, (AuthorId, u64)>::new();
        for commit_id in &commit_ids {
            let envelope = self.inner.store.load_commit(*commit_id).await?;
            graph.insert(*commit_id, envelope.header().dependencies().to_vec());
            headers.insert(
                *commit_id,
                (
                    envelope.header().author(),
                    envelope.header().author_sequence(),
                ),
            );
        }
        let mut invalid = BTreeSet::from([existing]);
        loop {
            let mut changed = false;
            for (commit_id, dependencies) in &graph {
                if !invalid.contains(commit_id)
                    && dependencies
                        .iter()
                        .any(|dependency| invalid.contains(dependency))
                {
                    changed |= invalid.insert(*commit_id);
                }
            }
            if !changed {
                break;
            }
        }
        let accepted: Vec<_> = commit_ids
            .into_iter()
            .filter(|commit_id| !invalid.contains(commit_id))
            .collect();
        let adapters = self
            .inner
            .adapters
            .read()
            .expect("record adapter lock is not poisoned")
            .clone();
        let mutations = self.materialize_commit_ids(&accepted, &adapters).await?;
        let accepted_set: BTreeSet<_> = accepted.iter().copied().collect();
        let referenced: BTreeSet<_> = accepted
            .iter()
            .flat_map(|commit_id| graph[commit_id].iter().copied())
            .filter(|dependency| accepted_set.contains(dependency))
            .collect();
        let frontier: Vec<_> = accepted
            .iter()
            .copied()
            .filter(|commit_id| !referenced.contains(commit_id))
            .collect();
        let mut author_heads = BTreeMap::<AuthorId, (u64, CommitId)>::new();
        for commit_id in &accepted {
            let (commit_author, commit_sequence) = headers[commit_id];
            author_heads
                .entry(commit_author)
                .and_modify(|current| {
                    if commit_sequence > current.0 {
                        *current = (commit_sequence, *commit_id);
                    }
                })
                .or_insert((commit_sequence, *commit_id));
        }
        let author_heads: Vec<_> = author_heads
            .into_iter()
            .map(|(head_author, (head_sequence, commit_id))| {
                (head_author, head_sequence, commit_id)
            })
            .collect();
        let invalid: Vec<_> = invalid.into_iter().collect();
        let previous_records = self.inner.store.export_materialized(self.domain_id())?;
        self.inner
            .store
            .quarantine_equivocation(&evidence, &invalid, &frontier, &author_heads, &mutations)
            .await?;
        let changes = materialization_changes(&previous_records, &mutations);
        if !changes.is_empty() {
            let _no_subscribers = self.changes().send(ChangeBatch {
                commit_id: evidence.commit_id(),
                sequence,
                changes,
            });
        }
        Ok(RemoteApply::Quarantined { author, sequence })
    }

    async fn converged_mutations(
        &self,
        incoming: &CommitEnvelope,
        incoming_body: &CommitBody,
        adapters: &BTreeMap<CollectionId, RecordAdapter>,
    ) -> Result<Vec<MaterializedRecord>, DbError> {
        let domain = self.domain_id();
        let existing_ids = self.inner.store.list_stored_commit_ids(domain)?;
        if existing_ids.len() >= MAX_RECONCILE_COMMITS {
            return Err(DbError::InvalidRemoteCommit(
                "reconciliation commit budget exceeded".into(),
            ));
        }
        for dependency in incoming.header().dependencies() {
            if !self.inner.store.contains_commit(*dependency)? {
                return Err(DbError::InvalidRemoteCommit(
                    "commit dependency is missing".into(),
                ));
            }
        }

        let dependency_context = self
            .dependency_context(incoming.header().dependencies())
            .await?;
        let affected =
            validate_incoming_operations(incoming, incoming_body, adapters, &dependency_context)?;
        let mut graph = BTreeMap::<CommitId, Vec<CommitId>>::new();
        let mut candidates =
            BTreeMap::<(CollectionId, Vec<u8>), Vec<(CommitId, MaterializedRecord)>>::new();
        for commit_id in existing_ids {
            let envelope = self.inner.store.load_commit(commit_id).await?;
            graph.insert(commit_id, envelope.header().dependencies().to_vec());
            let body = open_commit(&envelope, &self.domain_key_for(envelope.header().epoch())?)?;
            collect_affected_operations(commit_id, &body, &affected, &mut candidates)?;
        }
        let incoming_id = incoming.commit_id();
        graph.insert(incoming_id, incoming.header().dependencies().to_vec());
        collect_affected_operations(incoming_id, incoming_body, &affected, &mut candidates)?;

        let mut mutations = Vec::with_capacity(affected.len());
        for (key, adapter) in affected {
            let entries = candidates
                .remove(&key)
                .ok_or_else(|| DbError::InvalidRemoteCommit("missing record operation".into()))?;
            mutations.push(resolve_record_heads(&key, adapter, &entries, &graph)?);
        }
        Ok(mutations)
    }

    async fn dependency_context(
        &self,
        dependencies: &[CommitId],
    ) -> Result<VersionVector, DbError> {
        let mut context = VersionVector::new();
        let mut pending = dependencies.to_vec();
        let mut visited = BTreeSet::new();
        while let Some(commit_id) = pending.pop() {
            if !visited.insert(commit_id) {
                continue;
            }
            match self.inner.store.load_commit(commit_id).await {
                Ok(envelope) => {
                    if envelope.header().domain_id() != self.domain_id() {
                        return Err(DbError::InvalidRemoteCommit(
                            "dependency belongs to another domain".into(),
                        ));
                    }
                    context.observe(Dot::new(
                        envelope.header().author(),
                        envelope.header().author_sequence(),
                        0,
                    ));
                    pending.extend_from_slice(envelope.header().dependencies());
                }
                Err(StoreError::MissingCommitBlob(_))
                    if self.inner.store.contains_commit(commit_id)? =>
                {
                    for (author, sequence) in self.inner.store.author_sequences(self.domain_id())? {
                        context.observe(Dot::new(author, sequence, 0));
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(context)
    }

    pub(crate) async fn rebuild_mutations(&self) -> Result<Vec<MaterializedRecord>, DbError> {
        let domain = self.domain_id();
        if self.inner.store.has_snapshot_coverage(domain)? {
            return Err(DbError::InvalidSnapshot(
                "full replay requires the installed base snapshot".into(),
            ));
        }
        let commit_ids = self.inner.store.list_stored_commit_ids(domain)?;
        if commit_ids.len() > MAX_RECONCILE_COMMITS {
            return Err(DbError::InvalidSnapshot(
                "rebuild commit budget exceeded".into(),
            ));
        }
        let adapters = self
            .inner
            .adapters
            .read()
            .expect("record adapter lock is not poisoned")
            .clone();
        self.materialize_commit_ids(&commit_ids, &adapters).await
    }

    async fn materialize_commit_ids(
        &self,
        commit_ids: &[CommitId],
        adapters: &BTreeMap<CollectionId, RecordAdapter>,
    ) -> Result<Vec<MaterializedRecord>, DbError> {
        let mut graph = BTreeMap::<CommitId, Vec<CommitId>>::new();
        let mut candidates = RecordCandidates::new();
        for &commit_id in commit_ids {
            let envelope = self.inner.store.load_commit(commit_id).await?;
            graph.insert(commit_id, envelope.header().dependencies().to_vec());
            let body = open_commit(&envelope, &self.domain_key_for(envelope.header().epoch())?)?;
            let dependency_context = self
                .dependency_context(envelope.header().dependencies())
                .await?;
            let affected =
                validate_incoming_operations(&envelope, &body, adapters, &dependency_context)?;
            collect_affected_operations(commit_id, &body, &affected, &mut candidates)?;
        }
        let mut mutations = Vec::with_capacity(candidates.len());
        for (key, entries) in candidates {
            let adapter = *adapters
                .get(&key.0)
                .ok_or(DbError::UnknownRecordSchema(key.0))?;
            mutations.push(resolve_record_heads(&key, adapter, &entries, &graph)?);
        }
        Ok(mutations)
    }

    /// Flushes and shuts down the local blob actor for a clean same-process reopen.
    pub async fn close(self) -> Result<(), DbError> {
        let inner = Arc::try_unwrap(self.inner).map_err(|_| DbError::HandlesOpen)?;
        let DbInner { store, blobs, .. } = inner;
        drop(store);
        blobs
            .shutdown()
            .await
            .map_err(StoreError::from)
            .map_err(DbError::from)
    }

    pub(crate) fn domain_key(&self) -> iroh_db_security::DomainKey {
        self.domain_seed().domain_key()
    }

    fn domain_key_for(&self, epoch: u64) -> Result<iroh_db_security::DomainKey, DbError> {
        self.inner
            .credentials
            .load_domain_epoch(self.domain_id(), epoch)
            .map(|seed| seed.domain_key())
            .map_err(DbError::from)
    }

    pub(crate) fn epoch(&self) -> u64 {
        self.domain
            .read()
            .expect("domain seed lock is not poisoned")
            .epoch()
    }

    fn set_domain_seed(&self, seed: &DomainSeed) {
        *self
            .domain
            .write()
            .expect("domain seed lock is not poisoned") = seed.clone();
    }

    fn ensure_change_channel(&self, domain_id: iroh_db_core::DomainId) {
        let mut changes = self
            .inner
            .changes
            .write()
            .expect("change channel lock is not poisoned");
        changes.entry(domain_id).or_insert_with(|| {
            let (sender, _) = broadcast::channel(CHANGE_CAPACITY);
            sender
        });
    }

    fn changes(&self) -> broadcast::Sender<ChangeBatch> {
        self.ensure_change_channel(self.domain_id());
        self.inner
            .changes
            .read()
            .expect("change channel lock is not poisoned")
            .get(&self.domain_id())
            .expect("domain change channel exists")
            .clone()
    }

    async fn apply(&self, prepared: Vec<PreparedRecord>) -> Result<ChangeBatch, DbError> {
        if prepared.is_empty() {
            return Err(DbError::EmptyTransaction);
        }
        validate_prepared_targets(&prepared)?;
        let _writer = self.inner.writer.lock().await;
        let domain_id = self.domain_id();
        let active_epoch = self.inner.store.current_epoch(domain_id)?;
        if self.epoch() != active_epoch {
            return Err(DbError::StaleEpoch {
                handle: self.epoch(),
                active: active_epoch,
            });
        }
        let signer = self.inner.credentials.signer();
        let sequence = self
            .inner
            .store
            .last_sequence(domain_id, signer.author())?
            .map_or(Ok(0), |value| {
                value.checked_add(1).ok_or(DbError::SequenceExhausted)
            })?;
        let dependencies = self.inner.store.frontier(domain_id)?;
        let dependency_context = self.dependency_context(&dependencies).await?;
        let mut nonce = [0_u8; 24];
        let mut transaction_id = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| DbError::RandomnessUnavailable)?;
        getrandom::fill(&mut transaction_id).map_err(|_| DbError::RandomnessUnavailable)?;

        let adapters = self
            .inner
            .adapters
            .read()
            .expect("record adapter lock is not poisoned")
            .clone();
        let operations = canonical_operations(
            &prepared,
            &adapters,
            signer.author(),
            sequence,
            &dependency_context,
        )?;
        let schemas: Vec<SchemaId> = prepared.iter().map(|entry| entry.schema_id).collect();
        let body = CommitBody::new(TransactionId::from_bytes(transaction_id), operations)?;
        self.validate_consistency(signer.author(), &body)?;
        let capability_id = match self
            .inner
            .store
            .active_capability(domain_id, signer.author())?
        {
            Some(capability_id)
                if self.inner.store.authorize_capability(
                    domain_id,
                    signer.author(),
                    capability_id,
                    Permission::Write,
                    self.epoch(),
                )? =>
            {
                capability_id
            }
            Some(_) | None if self.inner.store.domain_descriptor(domain_id)?.is_some() => {
                return Err(DbError::UnauthorizedDevice);
            }
            None => private_capability(domain_id),
            Some(_) => return Err(DbError::UnauthorizedDevice),
        };
        let header = CommitHeader::new(
            domain_id,
            self.epoch(),
            signer.author(),
            sequence,
            dependencies,
            capability_id,
            schemas,
            nonce,
        )?;
        let envelope = seal_commit(header, &body, &self.domain_key(), &signer)?;
        let mutations = self
            .converged_mutations(&envelope, &body, &adapters)
            .await?;
        self.inner
            .store
            .persist_commit_with_records(&envelope, &mutations)
            .await?;
        let batch = ChangeBatch {
            commit_id: envelope.commit_id(),
            sequence,
            changes: prepared.into_iter().map(|entry| entry.change).collect(),
        };
        let _no_subscribers = self.changes().send(batch.clone());
        Ok(batch)
    }

    fn validate_consistency(&self, author: AuthorId, body: &CommitBody) -> Result<(), DbError> {
        let Some(descriptor) = self.inner.store.domain_descriptor(self.domain_id())? else {
            return Ok(());
        };
        match descriptor.mode() {
            ConsistencyMode::MultiWriter => Ok(()),
            ConsistencyMode::SingleWriter
                if self.inner.store.current_writer(self.domain_id())? == Some(author) =>
            {
                Ok(())
            }
            ConsistencyMode::SingleWriter => Err(DbError::UnauthorizedDevice),
            ConsistencyMode::AppendOnly => {
                for operation in body.operations() {
                    if operation.kind() != OperationKind::FieldStateMerge
                        || self
                            .inner
                            .store
                            .get_record(
                                self.domain_id(),
                                operation.collection_id(),
                                operation.record_id(),
                            )?
                            .is_some()
                    {
                        return Err(DbError::InvalidRemoteCommit(
                            "append-only domains reject updates and deletes".into(),
                        ));
                    }
                    let mutation = MaterializedRecord::decode_canonical(operation.payload())?;
                    if mutation
                        .schema()
                        .fields()
                        .iter()
                        .filter(|field| !field.is_record_id())
                        .any(|field| field.crdt() != iroh_db_core::CrdtKind::Immutable)
                    {
                        return Err(DbError::InvalidRemoteCommit(
                            "append-only records require immutable fields".into(),
                        ));
                    }
                }
                Ok(())
            }
        }
    }
}

/// Encrypted blob import and lazy streaming handle.
pub struct Blobs {
    db: IrohDb,
}

impl Blobs {
    /// Encrypts and persists bytes as independently verified chunks plus a manifest.
    pub async fn import_bytes(
        &self,
        bytes: Vec<u8>,
        media_type: Option<String>,
    ) -> Result<BlobRef, DbError> {
        self.engine()
            .import_bytes(bytes, media_type)
            .await
            .map_err(DbError::from)
    }

    /// Incrementally encrypts and persists an asynchronous plaintext stream.
    pub async fn import_reader(
        &self,
        reader: impl AsyncRead + Unpin,
        media_type: Option<String>,
    ) -> Result<BlobRef, DbError> {
        self.engine()
            .import_reader(reader, media_type)
            .await
            .map_err(DbError::from)
    }

    /// Authenticates a manifest and opens a lazy seekable plaintext stream.
    pub async fn open(&self, reference: &BlobRef) -> Result<BlobStream, DbError> {
        self.engine().open(reference).await.map_err(DbError::from)
    }

    fn engine(&self) -> BlobEngine {
        self.db.blob_engine()
    }
}

/// A handle to one strongly typed collection.
pub struct Collection<Record> {
    db: IrohDb,
    marker: PhantomData<fn() -> Record>,
}

impl<Record: IrohRecord> Collection<Record> {
    /// Atomically creates or replaces one materialized CRDT record.
    pub async fn put(&self, record: Record) -> Result<ChangeBatch, DbError> {
        self.db.apply(vec![prepare_upsert(&record)?]).await
    }

    /// Reads one record entirely from local materialized state.
    #[allow(clippy::unused_async)]
    pub async fn get(&self, id: &Record::Id) -> Result<Option<Record>, DbError> {
        let schema = Record::schema()?;
        self.db
            .inner
            .store
            .get_record(
                self.db.domain_id(),
                schema.collection_id(),
                &id.encode_key()?,
            )?
            .map(|bytes| Record::decode_record(&bytes).map_err(DbError::from))
            .transpose()
    }

    /// Atomically deletes one record if present.
    pub async fn delete(&self, id: &Record::Id) -> Result<ChangeBatch, DbError> {
        self.db.apply(vec![prepare_delete::<Record>(id)?]).await
    }

    /// Starts a typed local query.
    pub fn query(&self) -> Query<Record> {
        Query {
            db: self.db.clone(),
            filter: None,
            order: None,
            limit: None,
            after: None,
            marker: PhantomData,
        }
    }

    /// Subscribes to future atomic changes for this collection.
    pub fn subscribe(&self) -> Result<Subscription<Record>, DbError> {
        let schema = Record::schema()?;
        let receiver = self.db.changes().subscribe();
        let initial = self
            .db
            .inner
            .store
            .list_records(self.db.domain_id(), schema.collection_id())?
            .into_iter()
            .map(|entry| Record::decode_record(entry.state()).map_err(DbError::from))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Subscription {
            collection_id: schema.collection_id(),
            initial: Some(initial),
            receiver,
        })
    }
}

/// A type-checked local collection query.
pub struct Query<Record> {
    db: IrohDb,
    filter: Option<Predicate<Record>>,
    order: Option<OrderClause<Record>>,
    limit: Option<usize>,
    after: Option<Cursor>,
    marker: PhantomData<fn() -> Record>,
}

/// A typed query predicate.
#[derive(Debug)]
pub enum Predicate<Record> {
    /// Exact visible-value equality.
    Equal(EqualityFilter<Record>),
    /// Ordered visible-value comparison.
    Range(RangeFilter<Record>),
}

impl<Record> From<EqualityFilter<Record>> for Predicate<Record> {
    fn from(value: EqualityFilter<Record>) -> Self {
        Self::Equal(value)
    }
}

impl<Record> From<RangeFilter<Record>> for Predicate<Record> {
    fn from(value: RangeFilter<Record>) -> Self {
        Self::Range(value)
    }
}

/// Query result order for a typed field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderDirection {
    /// Smallest values first.
    Ascending,
    /// Largest values first.
    Descending,
}

type ValueComparator =
    dyn Fn(&[Vec<u8>], &[Vec<u8>]) -> Result<Ordering, RecordError> + Send + Sync;
type EncodedCandidate = (Vec<u8>, Vec<u8>);

struct OrderClause<Record> {
    field_id: u32,
    direction: OrderDirection,
    compare: Arc<ValueComparator>,
    marker: PhantomData<fn() -> Record>,
}

/// An opaque, authenticated continuation position.
#[derive(Clone, PartialEq, Eq)]
pub struct Cursor(Vec<u8>);

impl Cursor {
    /// Reconstructs a cursor received from durable application state or a client.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the opaque encoded cursor.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Cursor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Cursor([opaque])")
    }
}

/// One stable page and an optional continuation cursor.
#[derive(Debug)]
pub struct Page<Record> {
    items: Vec<Record>,
    next_cursor: Option<Cursor>,
}

impl<Record> Page<Record> {
    /// Returns the page records in requested order.
    pub fn items(&self) -> &[Record] {
        &self.items
    }

    /// Consumes this page and returns its records.
    pub fn into_items(self) -> Vec<Record> {
        self.items
    }

    /// Returns a cursor when more matching records existed at execution time.
    pub const fn next_cursor(&self) -> Option<&Cursor> {
        self.next_cursor.as_ref()
    }
}

impl<Record: IrohRecord> Query<Record> {
    /// Adds an equality predicate. V1 accepts one predicate per query.
    #[must_use]
    pub fn filter(mut self, filter: impl Into<Predicate<Record>>) -> Self {
        self.filter = Some(filter.into());
        self
    }

    /// Orders by the smallest visible value of a typed ordered field, then primary key.
    #[must_use]
    pub fn order_by<Value>(
        mut self,
        field: TypedField<Record, Value>,
        direction: OrderDirection,
    ) -> Self
    where
        Value: RecordKey + Ord + Send + Sync + 'static,
    {
        self.order = Some(OrderClause {
            field_id: field.field_id(),
            direction,
            compare: Arc::new(compare_visible::<Value>),
            marker: PhantomData,
        });
        self
    }

    /// Bounds the number of records returned.
    #[must_use]
    pub const fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Continues after a cursor produced by the exact same query shape.
    #[must_use]
    pub fn after(mut self, cursor: Cursor) -> Self {
        self.after = Some(cursor);
        self
    }

    /// Executes against one local redb read snapshot.
    #[allow(clippy::unused_async)]
    pub async fn fetch(self) -> Result<Vec<Record>, DbError> {
        Ok(self.fetch_page().await?.into_items())
    }

    /// Executes a stable page against one local redb read snapshot.
    #[allow(clippy::unused_async)]
    pub async fn fetch_page(self) -> Result<Page<Record>, DbError> {
        let schema = Record::schema()?;
        let domain = self.db.domain_id();
        let fingerprint = self.fingerprint(schema.collection_id())?;
        let candidates = self.candidates(domain, schema.collection_id(), &schema)?;
        let mut records = Vec::new();
        for (record_id, bytes) in candidates {
            let record = Record::decode_record(&bytes)?;
            if self.matches(&record)? {
                records.push(QueryRecord { record_id, record });
            }
        }
        if let Some(order) = &self.order {
            let mut sort_error = None;
            records.sort_by(|left, right| {
                let result = compare_records(left, right, order);
                match result {
                    Ok(value) => value,
                    Err(error) => {
                        sort_error.get_or_insert(error);
                        Ordering::Equal
                    }
                }
            });
            if let Some(error) = sort_error {
                return Err(error);
            }
        }

        let start = match &self.after {
            Some(cursor) => {
                let last_id = self.decode_cursor(cursor, schema.collection_id(), fingerprint)?;
                records
                    .iter()
                    .position(|entry| entry.record_id == last_id)
                    .map(|position| position + 1)
                    .ok_or_else(|| DbError::InvalidCursor("cursor position is stale".into()))?
            }
            None => 0,
        };
        let limit = self.limit.unwrap_or(usize::MAX);
        let end = start.saturating_add(limit).min(records.len());
        let has_more = end < records.len();
        let selected = &records[start..end];
        let next_cursor = if has_more {
            selected
                .last()
                .map(|entry| {
                    self.encode_cursor(schema.collection_id(), fingerprint, &entry.record_id)
                })
                .transpose()?
        } else {
            None
        };
        let items = records
            .drain(start..end)
            .map(|entry| entry.record)
            .collect();
        Ok(Page { items, next_cursor })
    }

    fn candidates(
        &self,
        domain: iroh_db_core::DomainId,
        collection: CollectionId,
        schema: &iroh_db_core::SchemaDescriptor,
    ) -> Result<Vec<EncodedCandidate>, DbError> {
        if let Some(Predicate::Equal(filter)) = &self.filter {
            let value = filter
                .encoded_value()
                .map_err(|error| DbError::InvalidQuery(error.clone()))?;
            let indexed = schema
                .fields()
                .iter()
                .any(|field| field.id() == filter.field_id() && field.is_indexed());
            if indexed {
                return self
                    .db
                    .inner
                    .store
                    .lookup_equal(domain, collection, filter.field_id(), value)?
                    .into_iter()
                    .filter_map(|id| {
                        self.db
                            .inner
                            .store
                            .get_record(domain, collection, &id)
                            .transpose()
                            .map(|result| result.map(|state| (id, state)))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(DbError::from);
            }
        }
        Ok(self
            .db
            .inner
            .store
            .list_records(domain, collection)?
            .into_iter()
            .map(|entry| (entry.record_id().to_vec(), entry.state().to_vec()))
            .collect())
    }

    fn matches(&self, record: &Record) -> Result<bool, DbError> {
        match &self.filter {
            Some(Predicate::Equal(filter)) => {
                let expected = filter
                    .encoded_value()
                    .map_err(|error| DbError::InvalidQuery(error.clone()))?;
                Ok(record
                    .field_values(filter.field_id())?
                    .iter()
                    .any(|value| value == expected))
            }
            Some(Predicate::Range(filter)) => filter
                .matches(&record.field_values(filter.field_id())?)
                .map_err(DbError::InvalidQuery),
            None => Ok(true),
        }
    }

    fn fingerprint(&self, collection: CollectionId) -> Result<[u8; 32], DbError> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"iroh-db/query/v1");
        hasher.update(collection.as_bytes());
        match &self.filter {
            None => {
                hasher.update(&[0]);
            }
            Some(Predicate::Equal(filter)) => {
                hasher.update(&[1]);
                hasher.update(&filter.field_id().to_be_bytes());
                hasher.update(
                    filter
                        .encoded_value()
                        .map_err(|error| DbError::InvalidQuery(error.clone()))?,
                );
            }
            Some(Predicate::Range(filter)) => {
                hasher.update(&[2, filter.operator() as u8]);
                hasher.update(&filter.field_id().to_be_bytes());
                hasher.update(
                    filter
                        .encoded_bound()
                        .map_err(|error| DbError::InvalidQuery(error.clone()))?,
                );
            }
        }
        if let Some(order) = &self.order {
            hasher.update(&[1, order.direction as u8]);
            hasher.update(&order.field_id.to_be_bytes());
        } else {
            hasher.update(&[0]);
        }
        Ok(*hasher.finalize().as_bytes())
    }

    fn encode_cursor(
        &self,
        collection: CollectionId,
        fingerprint: [u8; 32],
        record_id: &[u8],
    ) -> Result<Cursor, DbError> {
        let domain = self.db.domain_id();
        let length = u32::try_from(record_id.len())
            .map_err(|_| DbError::InvalidCursor("record ID is too large".into()))?;
        let mut bytes = Vec::with_capacity(108 + record_id.len());
        bytes.extend_from_slice(b"IDBCUR01");
        bytes.extend_from_slice(domain.as_bytes());
        bytes.extend_from_slice(collection.as_bytes());
        bytes.extend_from_slice(&fingerprint);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(record_id);
        let key = self
            .db
            .inner
            .credentials
            .domain_key()
            .derive_subkey(domain.as_bytes(), b"iroh-db/query-cursor/v1")?;
        bytes.extend_from_slice(blake3::keyed_hash(&key, &bytes).as_bytes());
        Ok(Cursor(bytes))
    }

    fn decode_cursor(
        &self,
        cursor: &Cursor,
        collection: CollectionId,
        fingerprint: [u8; 32],
    ) -> Result<Vec<u8>, DbError> {
        let bytes = cursor.as_bytes();
        if bytes.len() < 140 || &bytes[..8] != b"IDBCUR01" {
            return Err(DbError::InvalidCursor("malformed cursor".into()));
        }
        let length = u32::from_be_bytes(
            bytes[104..108]
                .try_into()
                .map_err(|_| DbError::InvalidCursor("malformed cursor".into()))?,
        ) as usize;
        if bytes.len() != 140 + length {
            return Err(DbError::InvalidCursor("malformed cursor".into()));
        }
        let domain = self.db.domain_id();
        if &bytes[8..40] != domain.as_bytes()
            || &bytes[40..72] != collection.as_bytes()
            || bytes[72..104] != fingerprint
        {
            return Err(DbError::InvalidCursor(
                "cursor belongs to another query".into(),
            ));
        }
        let signed_len = bytes.len() - 32;
        let key = self
            .db
            .inner
            .credentials
            .domain_key()
            .derive_subkey(domain.as_bytes(), b"iroh-db/query-cursor/v1")?;
        let expected = blake3::keyed_hash(&key, &bytes[..signed_len]);
        if !constant_time_equal(expected.as_bytes(), &bytes[signed_len..]) {
            return Err(DbError::InvalidCursor(
                "cursor authentication failed".into(),
            ));
        }
        Ok(bytes[108..signed_len].to_vec())
    }
}

struct QueryRecord<Record> {
    record_id: Vec<u8>,
    record: Record,
}

fn compare_records<Record: IrohRecord>(
    left: &QueryRecord<Record>,
    right: &QueryRecord<Record>,
    order: &OrderClause<Record>,
) -> Result<Ordering, DbError> {
    let left_values = left.record.field_values(order.field_id)?;
    let right_values = right.record.field_values(order.field_id)?;
    let value_order = (order.compare)(&left_values, &right_values)?;
    let value_order = match order.direction {
        OrderDirection::Ascending => value_order,
        OrderDirection::Descending => value_order.reverse(),
    };
    Ok(value_order.then_with(|| left.record_id.cmp(&right.record_id)))
}

fn compare_visible<Value: RecordKey + Ord>(
    left: &[Vec<u8>],
    right: &[Vec<u8>],
) -> Result<Ordering, RecordError> {
    let left = left
        .iter()
        .map(|value| Value::decode_key(value))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .min();
    let right = right
        .iter()
        .map(|value| Value::decode_key(value))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .min();
    Ok(left.cmp(&right))
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

/// One ordered subscription event.
#[derive(Debug)]
pub enum SubscriptionEvent<Record> {
    /// A local record snapshot captured when the receiver was registered.
    Initial(Vec<Record>),
    /// One later atomic commit batch affecting the collection.
    Changes(ChangeBatch),
}

/// A bounded typed collection change stream.
pub struct Subscription<Record> {
    collection_id: CollectionId,
    initial: Option<Vec<Record>>,
    receiver: broadcast::Receiver<ChangeBatch>,
}

impl<Record> Subscription<Record> {
    /// Receives the initial local snapshot, then later batches affecting this collection.
    pub async fn recv(&mut self) -> Result<SubscriptionEvent<Record>, SubscriptionError> {
        if let Some(initial) = self.initial.take() {
            return Ok(SubscriptionEvent::Initial(initial));
        }
        loop {
            let batch = self.receiver.recv().await.map_err(|error| match error {
                broadcast::error::RecvError::Closed => SubscriptionError::Closed,
                broadcast::error::RecvError::Lagged(count) => SubscriptionError::Lagged(count),
            })?;
            let changes: Vec<_> = batch
                .changes
                .iter()
                .filter(|change| change.collection_id == self.collection_id)
                .cloned()
                .collect();
            if !changes.is_empty() {
                return Ok(SubscriptionEvent::Changes(ChangeBatch { changes, ..batch }));
            }
        }
    }
}

/// An atomic builder restricted to the database's default domain.
pub struct Transaction {
    db: IrohDb,
    prepared: Vec<PreparedRecord>,
}

impl Transaction {
    /// Adds a typed record replacement to this transaction.
    #[allow(clippy::needless_pass_by_value)]
    pub fn put<Record: IrohRecord>(&mut self, record: Record) -> Result<(), DbError> {
        self.prepared.push(prepare_upsert(&record)?);
        Ok(())
    }

    /// Adds a typed record deletion to this transaction.
    pub fn delete<Record: IrohRecord>(&mut self, id: &Record::Id) -> Result<(), DbError> {
        self.prepared.push(prepare_delete::<Record>(id)?);
        Ok(())
    }

    /// Creates one encrypted commit and publishes every prepared record atomically.
    pub async fn commit(self) -> Result<ChangeBatch, DbError> {
        self.db.apply(self.prepared).await
    }
}

struct PreparedRecord {
    materialized: MaterializedRecord,
    schema_id: SchemaId,
    change: Change,
}

fn validate_prepared_targets(prepared: &[PreparedRecord]) -> Result<(), DbError> {
    let mut targets = BTreeSet::new();
    for entry in prepared {
        let target = (entry.change.collection_id, entry.change.record_id.clone());
        if !targets.insert(target) {
            return Err(DbError::InvalidRemoteCommit(
                "a commit mutates one record more than once".into(),
            ));
        }
    }
    Ok(())
}

fn canonical_operations(
    prepared: &[PreparedRecord],
    adapters: &BTreeMap<CollectionId, RecordAdapter>,
    author: AuthorId,
    sequence: u64,
    dependency_context: &VersionVector,
) -> Result<Vec<Operation>, DbError> {
    let mut next_operation = 0;
    let mut operations = Vec::with_capacity(prepared.len());
    for entry in prepared {
        let mutation = if entry.materialized.state().is_some() {
            let adapter = adapters
                .get(&entry.change.collection_id)
                .ok_or(DbError::UnknownRecordSchema(entry.change.collection_id))?;
            (adapter.canonicalize)(
                &entry.materialized,
                author,
                sequence,
                dependency_context,
                &mut next_operation,
            )?
        } else {
            entry.materialized.clone()
        };
        operations.push(Operation::new(
            mutation.schema().collection_id(),
            mutation.record_id().to_vec(),
            0,
            if mutation.state().is_some() {
                OperationKind::FieldStateMerge
            } else {
                OperationKind::RecordDelete
            },
            mutation.encode_canonical()?,
        )?);
    }
    Ok(operations)
}

fn prepare_upsert<Record: IrohRecord>(record: &Record) -> Result<PreparedRecord, DbError> {
    let schema = Record::schema()?;
    let record_id = record.record_id()?;
    let state = record.encode_record()?;
    let mut indexes = Vec::new();
    for field in schema.fields().iter().filter(|field| field.is_indexed()) {
        for value in record.field_values(field.id())? {
            indexes.push(IndexValue::new(field.id(), value));
        }
    }
    let materialized =
        MaterializedRecord::upsert(schema.clone(), record_id.clone(), state, indexes)?;
    Ok(PreparedRecord {
        materialized,
        schema_id: schema.schema_id(),
        change: Change {
            collection_id: schema.collection_id(),
            record_id,
            kind: ChangeKind::Upserted,
        },
    })
}

fn prepare_delete<Record: IrohRecord>(id: &Record::Id) -> Result<PreparedRecord, DbError> {
    let schema = Record::schema()?;
    let record_id = id.encode_key()?;
    let materialized = MaterializedRecord::delete(schema.clone(), record_id.clone())?;
    Ok(PreparedRecord {
        materialized,
        schema_id: schema.schema_id(),
        change: Change {
            collection_id: schema.collection_id(),
            record_id,
            kind: ChangeKind::Deleted,
        },
    })
}

type RecordTarget = (CollectionId, Vec<u8>);
type RecordCandidates = BTreeMap<RecordTarget, Vec<(CommitId, MaterializedRecord)>>;

fn materialization_changes(
    before: &[MaterializedRecord],
    after: &[MaterializedRecord],
) -> Vec<Change> {
    let before = present_records(before);
    let after = present_records(after);
    before
        .keys()
        .chain(after.keys())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|target| before.get(target) != after.get(target))
        .map(|(collection_id, record_id)| Change {
            collection_id,
            kind: if after.contains_key(&(collection_id, record_id.clone())) {
                ChangeKind::Upserted
            } else {
                ChangeKind::Deleted
            },
            record_id,
        })
        .collect()
}

fn present_records(values: &[MaterializedRecord]) -> BTreeMap<RecordTarget, &MaterializedRecord> {
    values
        .iter()
        .filter(|record| record.state().is_some())
        .map(|record| {
            (
                (record.schema().collection_id(), record.record_id().to_vec()),
                record,
            )
        })
        .collect()
}

fn validate_incoming_operations(
    envelope: &CommitEnvelope,
    body: &CommitBody,
    adapters: &BTreeMap<CollectionId, RecordAdapter>,
    dependency_context: &VersionVector,
) -> Result<BTreeMap<RecordTarget, RecordAdapter>, DbError> {
    let mut affected = BTreeMap::new();
    let mut next_operation = 0;
    for operation in body.operations() {
        if !matches!(
            operation.kind(),
            OperationKind::FieldStateMerge | OperationKind::RecordDelete
        ) {
            return Err(DbError::InvalidRemoteCommit(
                "unsupported operation kind".into(),
            ));
        }
        let mutation = MaterializedRecord::decode_canonical(operation.payload())?;
        if mutation.schema().collection_id() != operation.collection_id()
            || mutation.record_id() != operation.record_id()
            || !envelope
                .header()
                .schema_ids()
                .contains(&mutation.schema().schema_id())
        {
            return Err(DbError::InvalidRemoteCommit(
                "schema or record target mismatch".into(),
            ));
        }
        let adapter = *adapters
            .get(&operation.collection_id())
            .ok_or(DbError::UnknownRecordSchema(operation.collection_id()))?;
        if adapter.schema_id != mutation.schema().schema_id() {
            return Err(DbError::InvalidRemoteCommit("schema ID mismatch".into()));
        }
        if mutation.state().is_some() {
            let canonical = (adapter.canonicalize)(
                &mutation,
                envelope.header().author(),
                envelope.header().author_sequence(),
                dependency_context,
                &mut next_operation,
            )?;
            if canonical != mutation {
                return Err(DbError::InvalidRemoteCommit(
                    "record contains causal metadata not issued by its commit".into(),
                ));
            }
        }
        let key = (operation.collection_id(), operation.record_id().to_vec());
        if affected.insert(key, adapter).is_some() {
            return Err(DbError::InvalidRemoteCommit(
                "a commit mutates one record more than once".into(),
            ));
        }
    }
    Ok(affected)
}

fn collect_affected_operations(
    commit_id: CommitId,
    body: &CommitBody,
    affected: &BTreeMap<RecordTarget, RecordAdapter>,
    candidates: &mut RecordCandidates,
) -> Result<(), DbError> {
    for operation in body.operations() {
        let key = (operation.collection_id(), operation.record_id().to_vec());
        if !affected.contains_key(&key) {
            continue;
        }
        let mutation = MaterializedRecord::decode_canonical(operation.payload())?;
        if mutation.schema().collection_id() != operation.collection_id()
            || mutation.record_id() != operation.record_id()
        {
            return Err(DbError::InvalidRemoteCommit(
                "accepted operation target is inconsistent".into(),
            ));
        }
        candidates
            .entry(key)
            .or_default()
            .push((commit_id, mutation));
    }
    Ok(())
}

fn resolve_record_heads(
    key: &RecordTarget,
    adapter: RecordAdapter,
    entries: &[(CommitId, MaterializedRecord)],
    graph: &BTreeMap<CommitId, Vec<CommitId>>,
) -> Result<MaterializedRecord, DbError> {
    let mut heads: Vec<_> = entries
        .iter()
        .filter(|(candidate, _)| {
            !entries
                .iter()
                .any(|(other, _)| candidate != other && is_ancestor(*candidate, *other, graph))
        })
        .collect();
    heads.sort_unstable_by_key(|(commit_id, _)| *commit_id);
    if heads.iter().any(|(_, mutation)| mutation.state().is_some()) {
        let mut merged: Option<MaterializedRecord> = None;
        for (_, mutation) in heads
            .into_iter()
            .filter(|(_, mutation)| mutation.state().is_some())
        {
            merged = Some((adapter.merge)(
                merged.as_ref().and_then(MaterializedRecord::state),
                mutation,
            )?);
        }
        return merged
            .ok_or_else(|| DbError::InvalidRemoteCommit("record head resolution failed".into()));
    }
    let (_, deletion) = heads
        .first()
        .ok_or_else(|| DbError::InvalidRemoteCommit("record has no causal head".into()))?;
    MaterializedRecord::delete(deletion.schema().clone(), key.1.clone()).map_err(DbError::from)
}

fn is_ancestor(
    ancestor: CommitId,
    descendant: CommitId,
    graph: &BTreeMap<CommitId, Vec<CommitId>>,
) -> bool {
    let mut pending = vec![descendant];
    let mut visited = BTreeSet::new();
    while let Some(commit_id) = pending.pop() {
        if !visited.insert(commit_id) {
            continue;
        }
        let Some(dependencies) = graph.get(&commit_id) else {
            continue;
        };
        if dependencies.contains(&ancestor) {
            return true;
        }
        pending.extend(dependencies);
    }
    false
}

fn merge_materialized<Record: IrohRecord>(
    existing: Option<&[u8]>,
    incoming: &MaterializedRecord,
) -> Result<MaterializedRecord, DbError> {
    let schema = Record::schema()?;
    if schema.schema_id() != incoming.schema().schema_id() {
        return Err(DbError::InvalidRemoteCommit(
            "registered schema mismatch".into(),
        ));
    }
    let Some(incoming_state) = incoming.state() else {
        return MaterializedRecord::delete(schema, incoming.record_id().to_vec())
            .map_err(DbError::from);
    };
    let mut record = Record::decode_record(incoming_state)?;
    if record.record_id()? != incoming.record_id() {
        return Err(DbError::InvalidRemoteCommit(
            "encoded record ID mismatch".into(),
        ));
    }
    if let Some(existing) = existing {
        let existing = Record::decode_record(existing)?;
        record.merge_record(&existing)?;
    }
    let mut indexes = Vec::new();
    for field in schema.fields().iter().filter(|field| field.is_indexed()) {
        for value in record.field_values(field.id())? {
            indexes.push(IndexValue::new(field.id(), value));
        }
    }
    MaterializedRecord::upsert(
        schema,
        incoming.record_id().to_vec(),
        record.encode_record()?,
        indexes,
    )
    .map_err(DbError::from)
}

fn canonicalize_materialized<Record: IrohRecord>(
    incoming: &MaterializedRecord,
    author: AuthorId,
    sequence: u64,
    context: &VersionVector,
    next_operation: &mut u32,
) -> Result<MaterializedRecord, DbError> {
    let schema = Record::schema()?;
    if schema.schema_id() != incoming.schema().schema_id() {
        return Err(DbError::InvalidRemoteCommit(
            "registered schema mismatch".into(),
        ));
    }
    let Some(state) = incoming.state() else {
        return MaterializedRecord::delete(schema, incoming.record_id().to_vec())
            .map_err(DbError::from);
    };
    let mut record = Record::decode_record(state)?;
    if record.record_id()? != incoming.record_id() {
        return Err(DbError::InvalidRemoteCommit(
            "encoded record ID mismatch".into(),
        ));
    }
    record.canonicalize_causality(author, sequence, context, next_operation)?;
    let mut indexes = Vec::new();
    for field in schema.fields().iter().filter(|field| field.is_indexed()) {
        for value in record.field_values(field.id())? {
            indexes.push(IndexValue::new(field.id(), value));
        }
    }
    MaterializedRecord::upsert(
        schema,
        incoming.record_id().to_vec(),
        record.encode_record()?,
        indexes,
    )
    .map_err(DbError::from)
}

fn reconcile_domain_epochs(credentials: &LocalCredentials, store: &Store) -> Result<(), DbError> {
    for domain_id in credentials.domains()? {
        if store.domain_descriptor(domain_id)?.is_none() {
            continue;
        }
        let active_epoch = match store.current_epoch(domain_id) {
            Ok(epoch) => epoch,
            Err(StoreError::ControlFork { .. }) => continue,
            Err(error) => return Err(DbError::Store(error)),
        };
        let current = credentials.load_domain(domain_id)?;
        if current.epoch() == active_epoch {
            continue;
        }
        let distance = current.epoch().abs_diff(active_epoch);
        if distance != 1 {
            return Err(DbError::Operation(format!(
                "domain {domain_id} key epoch differs from control by {distance}"
            )));
        }
        let authoritative = credentials.load_domain_epoch(domain_id, active_epoch)?;
        if active_epoch > 0 {
            let head = store.control_head(domain_id)?.ok_or_else(|| {
                DbError::Operation("active epoch has no control transition".into())
            })?;
            if head.new_epoch() != active_epoch
                || head.key_distribution_digest() != authoritative.distribution_digest()
            {
                return Err(DbError::Operation(
                    "staged epoch key does not match the active control transition".into(),
                ));
            }
        }
        credentials.activate_domain(&authoritative)?;
    }
    Ok(())
}

pub(crate) fn private_capability(domain_id: iroh_db_core::DomainId) -> CapabilityId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"iroh-db/private-capability/v1");
    hasher.update(domain_id.as_bytes());
    CapabilityId::from_bytes(*hasher.finalize().as_bytes())
}

#[allow(clippy::needless_pass_by_value)]
fn blob_metadata_error(error: impl std::fmt::Display) -> BlobStoreError {
    BlobStoreError::new(error.to_string())
}

#[cfg(test)]
mod control_recovery_tests {
    use super::*;

    #[tokio::test]
    async fn open_activates_the_staged_key_selected_by_durable_control() {
        let directory = tempfile::tempdir().unwrap();
        let device = IrohDb::open(directory.path()).await.unwrap();
        let domain = device.create_domain(ConsistencyMode::MultiWriter).unwrap();
        let domain_id = domain.domain_id();
        let old_seed = domain.domain_seed();
        let (next, _) = domain.rotate_epoch(&[]).unwrap();
        assert_eq!(next.domain_seed().epoch(), 1);

        device.inner.credentials.activate_domain(&old_seed).unwrap();
        assert_eq!(
            device
                .inner
                .credentials
                .load_domain(domain_id)
                .unwrap()
                .epoch(),
            0
        );
        drop(domain);
        drop(next);
        device.close().await.unwrap();

        let reopened = IrohDb::open(directory.path()).await.unwrap();
        let recovered = reopened.domain(domain_id).unwrap();
        assert_eq!(recovered.domain_seed().epoch(), 1);
        drop(recovered);
        reopened.close().await.unwrap();
    }

    #[tokio::test]
    async fn control_mutation_fails_while_a_disclosure_read_permit_is_held() {
        let directory = tempfile::tempdir().unwrap();
        let device = IrohDb::open(directory.path()).await.unwrap();
        let domain = device.create_domain(ConsistencyMode::MultiWriter).unwrap();
        let disclosure = device.inner.control_gate.read().await;
        assert!(matches!(
            domain.rotate_epoch(&[]),
            Err(DbError::Operation(message)) if message == "control plane is busy"
        ));
        assert!(matches!(
            domain.invite(
                AuthorId::from_bytes([91; 32]),
                PermissionSet::from_permissions(&[Permission::Read]),
                PermissionSet::empty(),
                None,
            ),
            Err(DbError::Operation(message)) if message == "control plane is busy"
        ));
        assert!(domain.domain_descriptor().unwrap().is_some());
        drop(disclosure);
        let (rotated, _) = domain.rotate_epoch(&[]).unwrap();
        assert_eq!(rotated.domain_seed().epoch(), 1);
        drop(domain);
        drop(rotated);
        device.close().await.unwrap();
    }

    #[tokio::test]
    async fn rotation_updates_every_live_handle_for_the_domain() {
        let directory = tempfile::tempdir().unwrap();
        let device = IrohDb::open(directory.path()).await.unwrap();
        let domain = device.create_domain(ConsistencyMode::MultiWriter).unwrap();
        let clone = domain.clone();
        let (rotated, _) = domain.rotate_epoch(&[]).unwrap();

        assert_eq!(clone.epoch(), 1);
        assert_eq!(clone.domain_seed().epoch(), 1);
        assert_eq!(rotated.epoch(), 1);

        drop(domain);
        drop(clone);
        drop(rotated);
        device.close().await.unwrap();
    }
}
