use iroh_db_core::{AuthorId, CapabilityId, DomainId};

use crate::{ControlTransition, IrohSigner, key::authority_checkpoint_signature_message};

const CHECKPOINT_VERSION: u16 = 1;
const MAX_CHECKPOINT_BYTES: usize = 1024 * 1024;
const MAX_CHECKPOINT_CAPABILITIES: usize = 1024;
const MAX_CHECKPOINT_REVOCATIONS: usize = 16_384;

/// A signed, history-compacting authority baseline for a targeted invitation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityCheckpoint {
    domain_id: DomainId,
    epoch: u64,
    head: Option<ControlTransition>,
    capability_ids: Vec<CapabilityId>,
    active_capability_ids: Vec<CapabilityId>,
    subject_revocations: Vec<(AuthorId, u64)>,
    issuer: AuthorId,
    issuer_capability: CapabilityId,
    subject: AuthorId,
    signature: [u8; 64],
}

impl AuthorityCheckpoint {
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        domain_id: DomainId,
        epoch: u64,
        head: Option<ControlTransition>,
        mut capability_ids: Vec<CapabilityId>,
        mut active_capability_ids: Vec<CapabilityId>,
        mut subject_revocations: Vec<(AuthorId, u64)>,
        issuer_capability: CapabilityId,
        subject: AuthorId,
        signer: &IrohSigner,
    ) -> Result<Self, CheckpointError> {
        capability_ids.sort_unstable();
        capability_ids.dedup();
        active_capability_ids.sort_unstable();
        active_capability_ids.dedup();
        subject_revocations.sort_unstable_by_key(|entry| entry.0);
        if subject_revocations
            .windows(2)
            .any(|pair| pair[0].0 == pair[1].0)
        {
            return Err(CheckpointError::InvalidShape);
        }
        let mut checkpoint = Self {
            domain_id,
            epoch,
            head,
            capability_ids,
            active_capability_ids,
            subject_revocations,
            issuer: signer.author(),
            issuer_capability,
            subject,
            signature: [0; 64],
        };
        checkpoint.validate_shape()?;
        checkpoint.signature = signer.sign_authority_checkpoint(&checkpoint.signing_bytes()?);
        Ok(checkpoint)
    }

    pub const fn domain_id(&self) -> DomainId {
        self.domain_id
    }
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
    pub const fn head(&self) -> Option<&ControlTransition> {
        self.head.as_ref()
    }
    pub fn capability_ids(&self) -> &[CapabilityId] {
        &self.capability_ids
    }
    pub fn active_capability_ids(&self) -> &[CapabilityId] {
        &self.active_capability_ids
    }
    pub fn subject_revocations(&self) -> &[(AuthorId, u64)] {
        &self.subject_revocations
    }
    pub const fn issuer(&self) -> AuthorId {
        self.issuer
    }
    pub const fn issuer_capability(&self) -> CapabilityId {
        self.issuer_capability
    }
    pub const fn subject(&self) -> AuthorId {
        self.subject
    }

    pub fn encode_canonical(&self) -> Result<Vec<u8>, CheckpointError> {
        let bytes = minicbor::to_vec(CheckpointWire {
            content: self.signing_bytes()?,
            signature: self.signature,
        })
        .map_err(codec_error)?;
        if bytes.len() > MAX_CHECKPOINT_BYTES {
            return Err(CheckpointError::TooLarge(bytes.len()));
        }
        Ok(bytes)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, CheckpointError> {
        if bytes.len() > MAX_CHECKPOINT_BYTES {
            return Err(CheckpointError::TooLarge(bytes.len()));
        }
        let wire: CheckpointWire = decode_exact(bytes)?;
        let content: CheckpointContent = decode_exact(&wire.content)?;
        if content.version != CHECKPOINT_VERSION {
            return Err(CheckpointError::UnsupportedVersion(content.version));
        }
        let head = content
            .head
            .map(|bytes| ControlTransition::decode_canonical(&bytes))
            .transpose()
            .map_err(authority_error)?;
        let checkpoint = Self {
            domain_id: content.domain_id,
            epoch: content.epoch,
            head,
            capability_ids: content.capability_ids,
            active_capability_ids: content.active_capability_ids,
            subject_revocations: content.subject_revocations,
            issuer: content.issuer,
            issuer_capability: content.issuer_capability,
            subject: content.subject,
            signature: wire.signature,
        };
        checkpoint.validate_shape()?;
        checkpoint.verify()?;
        if checkpoint.signing_bytes()? != wire.content || checkpoint.encode_canonical()? != bytes {
            return Err(CheckpointError::NonCanonical);
        }
        Ok(checkpoint)
    }

    pub fn verify(&self) -> Result<(), CheckpointError> {
        let public = iroh_base::PublicKey::try_from(self.issuer.as_bytes())
            .map_err(|_| CheckpointError::InvalidAuthor)?;
        public
            .verify(
                &authority_checkpoint_signature_message(&self.signing_bytes()?),
                &iroh_base::Signature::from_bytes(&self.signature),
            )
            .map_err(|_| CheckpointError::InvalidSignature)
    }

    fn validate_shape(&self) -> Result<(), CheckpointError> {
        if self.capability_ids.is_empty()
            || self.capability_ids.len() > MAX_CHECKPOINT_CAPABILITIES
            || self.active_capability_ids.is_empty()
            || self.active_capability_ids.len() > self.capability_ids.len()
            || self.subject_revocations.len() > MAX_CHECKPOINT_REVOCATIONS
            || !strictly_sorted(&self.capability_ids)
            || !strictly_sorted(&self.active_capability_ids)
            || self
                .active_capability_ids
                .iter()
                .any(|id| !self.capability_ids.contains(id))
            || !self
                .subject_revocations
                .windows(2)
                .all(|pair| pair[0].0 < pair[1].0)
            || !self.capability_ids.contains(&self.issuer_capability)
        {
            return Err(CheckpointError::InvalidShape);
        }
        match self.head.as_ref() {
            None if self.epoch == 0 => {}
            Some(head) if head.domain_id() == self.domain_id && head.new_epoch() == self.epoch => {}
            _ => return Err(CheckpointError::InvalidShape),
        }
        if self.subject_revocations.iter().any(|(_, sequence)| {
            *sequence == 0
                || self
                    .head
                    .as_ref()
                    .is_none_or(|head| *sequence > head.sequence())
        }) {
            return Err(CheckpointError::InvalidShape);
        }
        Ok(())
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, CheckpointError> {
        minicbor::to_vec(CheckpointContent {
            version: CHECKPOINT_VERSION,
            domain_id: self.domain_id,
            epoch: self.epoch,
            head: self
                .head
                .as_ref()
                .map(ControlTransition::encode_canonical)
                .transpose()
                .map_err(authority_error)?,
            capability_ids: self.capability_ids.clone(),
            active_capability_ids: self.active_capability_ids.clone(),
            subject_revocations: self.subject_revocations.clone(),
            issuer: self.issuer,
            issuer_capability: self.issuer_capability,
            subject: self.subject,
        })
        .map_err(codec_error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CheckpointError {
    #[error("authority checkpoint codec failed: {0}")]
    Codec(String),
    #[error("authority checkpoint is not canonical")]
    NonCanonical,
    #[error("unsupported authority checkpoint version: {0}")]
    UnsupportedVersion(u16),
    #[error("authority checkpoint has invalid shape")]
    InvalidShape,
    #[error("authority checkpoint signature is invalid")]
    InvalidSignature,
    #[error("authority checkpoint endpoint is invalid")]
    InvalidAuthor,
    #[error("authority checkpoint exceeds its bound: {0}")]
    TooLarge(usize),
    #[error("authority checkpoint evidence is invalid: {0}")]
    Authority(String),
}

#[derive(minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
struct CheckpointContent {
    #[n(0)]
    version: u16,
    #[n(1)]
    domain_id: DomainId,
    #[n(2)]
    epoch: u64,
    #[n(3)]
    head: Option<Vec<u8>>,
    #[n(4)]
    capability_ids: Vec<CapabilityId>,
    #[n(5)]
    subject_revocations: Vec<(AuthorId, u64)>,
    #[n(6)]
    issuer: AuthorId,
    #[n(7)]
    issuer_capability: CapabilityId,
    #[n(8)]
    subject: AuthorId,
    #[n(9)]
    active_capability_ids: Vec<CapabilityId>,
}

#[derive(minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
struct CheckpointWire {
    #[n(0)]
    content: Vec<u8>,
    #[n(1)]
    signature: [u8; 64],
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}
fn decode_exact<T: for<'a> minicbor::Decode<'a, ()>>(bytes: &[u8]) -> Result<T, CheckpointError> {
    let mut decoder = minicbor::Decoder::new(bytes);
    let value = decoder.decode().map_err(codec_error)?;
    if decoder.position() != bytes.len() {
        return Err(CheckpointError::NonCanonical);
    }
    Ok(value)
}
fn codec_error(error: impl std::fmt::Display) -> CheckpointError {
    CheckpointError::Codec(error.to_string())
}
fn authority_error(error: impl std::fmt::Display) -> CheckpointError {
    CheckpointError::Authority(error.to_string())
}
