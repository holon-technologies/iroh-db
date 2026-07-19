use iroh_db_core::{BlobHash, DomainId, FieldState, RecordError};

/// A domain-bound reference to an encrypted immutable blob manifest.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, minicbor::Encode, minicbor::Decode,
)]
#[cbor(array)]
pub struct BlobRef {
    #[n(0)]
    domain_id: DomainId,
    #[n(1)]
    epoch: u64,
    #[n(2)]
    manifest_hash: BlobHash,
}

impl BlobRef {
    /// Constructs a reference from a validated domain, epoch and manifest hash.
    pub const fn new(domain_id: DomainId, epoch: u64, manifest_hash: BlobHash) -> Self {
        Self {
            domain_id,
            epoch,
            manifest_hash,
        }
    }

    /// Returns the owning security domain.
    pub const fn domain_id(self) -> DomainId {
        self.domain_id
    }

    /// Returns the encryption epoch.
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Returns the encrypted manifest's content hash.
    pub const fn manifest_hash(self) -> BlobHash {
        self.manifest_hash
    }
}

impl FieldState for BlobRef {
    type Value = Self;

    const CRDT_KIND: iroh_db_core::CrdtKind = iroh_db_core::CrdtKind::Immutable;

    fn encode_state(&self) -> Result<Vec<u8>, RecordError> {
        minicbor::to_vec(self).map_err(|error| RecordError::Encode(error.to_string()))
    }

    fn decode_state(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut decoder = minicbor::Decoder::new(bytes);
        let value = decoder
            .decode::<Self>()
            .map_err(|error| RecordError::Decode(error.to_string()))?;
        if decoder.position() != bytes.len() {
            return Err(RecordError::TrailingData);
        }
        if value.encode_state()? != bytes {
            return Err(RecordError::NonCanonicalEncoding);
        }
        Ok(value)
    }

    fn visible_values(&self) -> Result<Vec<Vec<u8>>, RecordError> {
        Ok(vec![self.encode_state()?])
    }

    fn merge_state(&mut self, other: &Self) -> Result<(), RecordError> {
        if self == other {
            Ok(())
        } else {
            Err(iroh_db_core::CrdtError::ImmutableAlreadySet.into())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
pub(crate) struct ManifestEnvelope {
    #[n(0)]
    pub(crate) version: u16,
    #[n(1)]
    pub(crate) domain_id: DomainId,
    #[n(2)]
    pub(crate) epoch: u64,
    #[n(3)]
    pub(crate) salt: [u8; 32],
    #[n(4)]
    pub(crate) nonce: [u8; 24],
    #[n(5)]
    pub(crate) ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
pub(crate) struct ManifestBody {
    #[n(0)]
    pub(crate) plaintext_len: u64,
    #[n(1)]
    pub(crate) plaintext_hash: [u8; 32],
    #[n(2)]
    pub(crate) chunk_size: u32,
    #[n(3)]
    pub(crate) chunks: Vec<ChunkDescriptor>,
    #[n(4)]
    pub(crate) media_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
pub(crate) struct ChunkDescriptor {
    #[n(0)]
    pub(crate) index: u32,
    #[n(1)]
    pub(crate) plaintext_len: u32,
    #[n(2)]
    pub(crate) ciphertext_hash: BlobHash,
    #[n(3)]
    pub(crate) nonce: [u8; 24],
}
