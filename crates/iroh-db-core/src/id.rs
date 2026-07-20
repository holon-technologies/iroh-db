use std::{fmt, str::FromStr};

/// Number of bytes in every protocol identifier.
pub const ID_LEN: usize = 32;

/// An error returned when parsing a fixed-size protocol identifier.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FixedIdError {
    /// The decoded identifier did not contain exactly 32 bytes.
    #[error("identifier must be {ID_LEN} bytes, got {0}")]
    InvalidLength(usize),
    /// The identifier was not valid hexadecimal.
    #[error("identifier is not valid hexadecimal: {0}")]
    InvalidHex(String),
}

macro_rules! fixed_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(
            Clone,
            Copy,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            minicbor::Encode,
            minicbor::Decode,
        )]
        #[cbor(transparent)]
        pub struct $name(#[n(0)] [u8; ID_LEN]);

        impl $name {
            /// Constructs an identifier from its exact protocol bytes.
            pub const fn from_bytes(bytes: [u8; ID_LEN]) -> Self {
                Self(bytes)
            }

            /// Returns the exact protocol bytes.
            pub const fn as_bytes(&self) -> &[u8; ID_LEN] {
                &self.0
            }

            /// Consumes this identifier and returns its exact protocol bytes.
            pub const fn to_bytes(self) -> [u8; ID_LEN] {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&hex::encode(self.0))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{}({self})", stringify!($name))
            }
        }

        impl FromStr for $name {
            type Err = FixedIdError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                let bytes = hex::decode(value)
                    .map_err(|error| FixedIdError::InvalidHex(error.to_string()))?;
                let actual = bytes.len();
                let bytes = bytes
                    .try_into()
                    .map_err(|_: Vec<u8>| FixedIdError::InvalidLength(actual))?;
                Ok(Self(bytes))
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
    };
}

fixed_id!(
    /// A cryptographic device identity, represented independently from the iroh adapter.
    AuthorId
);
fixed_id!(
    /// An isolated authorization, encryption, replication, and transaction boundary.
    DomainId
);
fixed_id!(
    /// The stable identifier of a typed collection.
    CollectionId
);
fixed_id!(
    /// The content hash of an immutable commit blob.
    CommitId
);
fixed_id!(
    /// The BLAKE3 content hash of any immutable iroh blob.
    BlobHash
);
fixed_id!(
    /// The content hash of an immutable snapshot blob.
    SnapshotId
);
fixed_id!(
    /// The stable hash of a canonical record schema.
    SchemaId
);
fixed_id!(
    /// The stable hash of a canonical capability certificate.
    CapabilityId
);
fixed_id!(
    /// A unique identifier for one domain-local transaction.
    TransactionId
);
fixed_id!(
    /// A stable identifier for one domain-local schema migration attempt.
    MigrationId
);

impl CollectionId {
    /// Derives the stable collection identifier for a declared collection name.
    pub fn for_name(name: &str) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"iroh-db/collection/v1");
        hasher.update(name.as_bytes());
        Self::from_bytes(*hasher.finalize().as_bytes())
    }
}
