//! Encrypted content-addressed blob manifests and streams for iroh-db.

#![forbid(unsafe_code)]

mod engine;
mod local;
mod model;
mod stream;

pub use engine::{BlobEngine, BlobPriority, FetchMetrics, FetchOptions};
pub use local::{BlobProtocol, IrohBlobStore};
pub use model::BlobRef;
pub use stream::BlobStream;

/// Encrypted manifest, chunk, streaming or storage failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BlobError {
    /// The immutable blob repository failed.
    #[error("blob repository failed: {0}")]
    Store(String),
    /// A referenced immutable object was absent locally.
    #[error("blob is not available locally: {0}")]
    MissingBlob(iroh_db_core::BlobHash),
    /// Bytes did not match their content address.
    #[error("blob content hash mismatch")]
    HashMismatch,
    /// The reference belongs to another domain or epoch.
    #[error("blob reference belongs to another domain or epoch")]
    WrongDomainOrEpoch,
    /// An encrypted object failed AEAD authentication.
    #[error("blob authentication failed")]
    AuthenticationFailed,
    /// Encryption failed.
    #[error("blob encryption failed")]
    EncryptionFailed,
    /// A domain-separated object key could not be derived.
    #[error("blob key derivation failed")]
    KeyDerivationFailed,
    /// A manifest violated canonical format or structural invariants.
    #[error("blob manifest is invalid")]
    InvalidManifest,
    /// A canonical blob object could not be encoded or decoded.
    #[error("blob codec failed: {0}")]
    Codec(String),
    /// Configured chunks were outside the supported range.
    #[error("chunk size must be between 64 KiB and 8 MiB, got {0}")]
    InvalidChunkSize(usize),
    /// Platform or manifest bounds cannot represent this blob.
    #[error("blob is too large")]
    BlobTooLarge,
    /// Reading a plaintext import stream failed.
    #[error("blob import stream failed: {0}")]
    Read(String),
    /// The operating-system cryptographic random source failed.
    #[error("cryptographic randomness is unavailable")]
    RandomnessUnavailable,
    /// A remote stream was opened without any usable provider.
    #[error("no blob providers are available")]
    NoProviders,
}
