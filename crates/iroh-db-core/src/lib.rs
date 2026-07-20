//! Deterministic identifiers, schemas, commits, and CRDT semantics for iroh-db.

#![forbid(unsafe_code)]

mod causality;
mod commit;
mod crdt;
mod id;
mod migration;
mod record;
mod schema;

pub use causality::{CausalRelation, Dot, VersionVector};
pub use commit::{
    CommitBody, CommitCodecError, CommitEnvelope, CommitHeader, CommitSignature, Operation,
    OperationKind,
};
pub use crdt::{
    CrdtError, GrowOnlySet, Immutable, Lww, Merge, MultiValue, OrSet, OrderedList, PnCounter,
};
pub use id::{
    AuthorId, BlobHash, CapabilityId, CollectionId, CommitId, DomainId, FixedIdError, MigrationId,
    SchemaId, SnapshotId, TransactionId,
};
pub use migration::{MigrationCodecError, SchemaActivation, SchemaStage, staging_digest};
pub use record::{
    EqualityFilter, FieldState, IrohRecord, RangeFilter, RangeOperator, RecordError, RecordFields,
    RecordKey, TypedField, decode_record_fields, encode_record_fields,
};
pub use schema::{CrdtKind, FieldDescriptor, SchemaDescriptor, SchemaError};
