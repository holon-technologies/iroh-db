//! Transactional, rebuildable local metadata storage for iroh-db.

#![forbid(unsafe_code)]

mod blob;
mod materialized;
mod store;

pub use blob::{BlobFuture, BlobStore, BlobStoreError};
pub use materialized::{IndexValue, MaterializedError, MaterializedRecord, StoredRecord};
pub use store::{ApplyOutcome, RecordHead, RecordHeadSet, SnapshotBaseline, Store, StoreError};
