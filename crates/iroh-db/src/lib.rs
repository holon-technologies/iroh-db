//! Rust-native, local-first distributed database built on iroh.
//!
//! Local-first typed storage plus authenticated iroh synchronization.

#![forbid(unsafe_code)]

mod db;
mod network;
mod operations;
mod snapshot;
mod telemetry;

pub use db::{
    Blobs, Change, ChangeBatch, ChangeKind, Collection, Cursor, DbError, DeviceGroup, IrohDb,
    IrohDbBuilder, MigrationError, MigrationReport, OrderDirection, Page, Predicate,
    ProjectionReport, Query, RemoteApply, Subscription, SubscriptionError, SubscriptionEvent,
    Transaction,
};
pub use iroh_db_blobs::{
    BlobError, BlobPriority, BlobRef, BlobStream, FetchMetrics, FetchOptions, FetchScheduler,
    ProviderMetrics,
};
pub use iroh_db_core::{
    AuthorId, BlobHash, CapabilityId, CollectionId, CommitBody, CommitEnvelope, CommitHeader,
    CommitId, CrdtError, CrdtKind, DomainId, Dot, EqualityFilter, FieldDescriptor, FieldState,
    GrowOnlySet, Immutable, IrohRecord, Lww, Merge, MigrationId, MultiValue, Operation,
    OperationKind, OrSet, OrderedList, PnCounter, RangeFilter, RangeOperator, RecordError,
    RecordKey, SchemaActivation, SchemaDescriptor, SchemaId, SchemaStage, SnapshotId,
    TransactionId, TypedField, VersionVector, staging_digest,
};
pub use iroh_db_derive::IrohRecord;
pub use iroh_db_security::{
    CapabilityCertificate, ConsistencyMode, ControlTransition, DomainDescriptor, DomainSeed,
    Invitation, InvitationSecret, InvitationTicket, IrohSigner, KeyProvider, Permission,
    PermissionSet,
};
pub use network::{GossipSession, SYNC_ALPN, SyncNode, SyncReport};
pub use operations::{
    BackupOptions, BackupReport, OperationalMetrics, VerificationReport, backup_closed,
    backup_closed_with_signer, restore_backup, restore_backup_from,
};
pub use snapshot::Snapshot;
pub use telemetry::LatencyMetrics;

/// Implementation details referenced by generated code; not a stable API.
#[doc(hidden)]
pub mod __private {
    pub use iroh_db_core as core;
}
