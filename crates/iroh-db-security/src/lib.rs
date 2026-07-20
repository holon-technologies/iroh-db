//! Domain encryption, signatures, epochs, and capability validation for iroh-db.

#![forbid(unsafe_code)]

mod authority;
mod backup;
mod checkpoint;
mod commit;
mod credentials;
mod gossip;
mod invitation;
mod key;
mod snapshot;

pub use authority::{
    AuthorityError, CapabilityCertificate, ConsistencyMode, ControlTransition, DomainDescriptor,
    Permission, PermissionSet,
};
pub use backup::verify_backup_signature;
pub use checkpoint::{AuthorityCheckpoint, CheckpointError};
pub use commit::{SecurityError, open_commit, seal_commit};
pub use credentials::{DomainSeed, KeyProvider, LocalCredentials};
pub use gossip::verify_gossip_signature;
pub use invitation::{Invitation, InvitationError, InvitationSecret, InvitationTicket};
pub use key::{DomainKey, IrohSigner};
pub use snapshot::verify_snapshot_signature;
