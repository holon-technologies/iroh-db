use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead as _, KeyInit as _, Payload},
};
use iroh_db_core::{AuthorId, DomainId};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    CapabilityCertificate, DomainDescriptor, DomainKey, DomainSeed, IrohSigner, Permission,
    key::invitation_signature_message,
};

const INVITATION_VERSION: u16 = 1;
const MAX_INVITATION_BYTES: usize = 64 * 1024;
const TICKET_AAD: &[u8] = b"iroh-db/offline-invitation-ticket/v1";

/// A signed endpoint-targeted domain bootstrap payload.
#[derive(Clone)]
pub struct Invitation {
    descriptor: DomainDescriptor,
    chain: Vec<CapabilityCertificate>,
    seed: DomainSeed,
    subject: AuthorId,
    issuer: AuthorId,
    nonce: [u8; 32],
    signature: [u8; 64],
}

impl Invitation {
    /// Issues a signed invitation containing a validated least-privilege chain and epoch key.
    pub fn issue(
        descriptor: DomainDescriptor,
        chain: Vec<CapabilityCertificate>,
        seed: DomainSeed,
        subject: AuthorId,
        issuer: &IrohSigner,
    ) -> Result<Self, InvitationError> {
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| InvitationError::RandomnessUnavailable)?;
        let mut invitation = Self {
            descriptor,
            chain,
            seed,
            subject,
            issuer: issuer.author(),
            nonce,
            signature: [0; 64],
        };
        invitation.validate_chain()?;
        invitation.signature = issuer.sign_invitation(&invitation.signing_bytes()?);
        Ok(invitation)
    }

    /// Returns the target endpoint that alone may import this invitation.
    pub const fn subject(&self) -> AuthorId {
        self.subject
    }

    /// Returns the signed immutable domain descriptor.
    pub const fn descriptor(&self) -> &DomainDescriptor {
        &self.descriptor
    }

    /// Returns the validated root-to-leaf capability chain.
    pub fn capability_chain(&self) -> &[CapabilityCertificate] {
        &self.chain
    }

    /// Exports the sensitive current epoch seed for the targeted key-vault import path.
    pub fn domain_seed(&self) -> DomainSeed {
        self.seed.clone()
    }

    /// Strictly encodes the signed online invitation payload.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, InvitationError> {
        let bytes = minicbor::to_vec(InvitationWire {
            content: self.signing_bytes()?,
            issuer: self.issuer,
            signature: self.signature,
        })
        .map_err(codec_error)?;
        if bytes.len() > MAX_INVITATION_BYTES {
            return Err(InvitationError::TooLarge(bytes.len()));
        }
        Ok(bytes)
    }

    /// Strictly decodes and validates a signed invitation.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, InvitationError> {
        if bytes.len() > MAX_INVITATION_BYTES {
            return Err(InvitationError::TooLarge(bytes.len()));
        }
        let wire: InvitationWire = decode_exact(bytes)?;
        let content: InvitationContent = decode_exact(&wire.content)?;
        if content.version != INVITATION_VERSION {
            return Err(InvitationError::UnsupportedVersion(content.version));
        }
        let descriptor =
            DomainDescriptor::decode_canonical(&content.descriptor).map_err(authority_error)?;
        let chain = content
            .capability_chain
            .iter()
            .map(|bytes| CapabilityCertificate::decode_canonical(bytes).map_err(authority_error))
            .collect::<Result<Vec<_>, _>>()?;
        let invitation = Self {
            descriptor,
            chain,
            seed: DomainSeed::from_parts(
                content.domain_id,
                content.epoch,
                DomainKey::from_bytes(content.domain_key),
            ),
            subject: content.subject,
            issuer: wire.issuer,
            nonce: content.nonce,
            signature: wire.signature,
        };
        invitation.validate_chain()?;
        verify_signature(
            invitation.issuer,
            &invitation_signature_message(&wire.content),
            &invitation.signature,
        )?;
        if invitation.signing_bytes()? != wire.content || invitation.encode_canonical()? != bytes {
            return Err(InvitationError::NonCanonical);
        }
        Ok(invitation)
    }

    /// Encrypts this invitation into an offline ticket and returns its one-time bearer secret.
    pub fn seal_offline(&self) -> Result<(InvitationTicket, InvitationSecret), InvitationError> {
        let mut secret = [0_u8; 32];
        let mut nonce = [0_u8; 24];
        getrandom::fill(&mut secret).map_err(|_| InvitationError::RandomnessUnavailable)?;
        getrandom::fill(&mut nonce).map_err(|_| InvitationError::RandomnessUnavailable)?;
        let ciphertext = XChaCha20Poly1305::new((&secret).into())
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &self.encode_canonical()?,
                    aad: TICKET_AAD,
                },
            )
            .map_err(|_| InvitationError::EncryptionFailed)?;
        Ok((
            InvitationTicket { nonce, ciphertext },
            InvitationSecret(secret),
        ))
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, InvitationError> {
        let capability_chain = self
            .chain
            .iter()
            .map(|capability| capability.encode_canonical().map_err(authority_error))
            .collect::<Result<Vec<_>, _>>()?;
        minicbor::to_vec(InvitationContent {
            version: INVITATION_VERSION,
            descriptor: self
                .descriptor
                .encode_canonical()
                .map_err(authority_error)?,
            capability_chain,
            domain_id: self.seed.domain_id(),
            epoch: self.seed.epoch(),
            domain_key: *self.seed.domain_key().as_bytes(),
            subject: self.subject,
            nonce: self.nonce,
        })
        .map_err(codec_error)
    }

    fn validate_chain(&self) -> Result<(), InvitationError> {
        self.descriptor.verify().map_err(authority_error)?;
        let root = self.chain.first().ok_or(InvitationError::InvalidChain)?;
        if self.chain.len() > 9
            || root.issuer_capability().is_some()
            || root.domain_id() != self.descriptor.domain_id()
            || root.subject() != self.descriptor.owner()
            || self.seed.domain_id() != self.descriptor.domain_id()
        {
            return Err(InvitationError::InvalidChain);
        }
        for pair in self.chain.windows(2) {
            pair[1]
                .validate_delegation(&pair[0])
                .map_err(authority_error)?;
        }
        let leaf = self.chain.last().ok_or(InvitationError::InvalidChain)?;
        if leaf.subject() != self.subject
            || !leaf.permits(Permission::Read, self.seed.epoch())
            || leaf.issuer_endpoint() != self.issuer
        {
            return Err(InvitationError::InvalidChain);
        }
        Ok(())
    }
}

impl std::fmt::Debug for Invitation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Invitation([redacted])")
    }
}

/// An encrypted offline invitation envelope safe to store without its bearer secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitationTicket {
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

impl InvitationTicket {
    /// Decrypts and validates a ticket for exactly the local endpoint identity.
    pub fn open(
        &self,
        secret: &InvitationSecret,
        local_subject: AuthorId,
    ) -> Result<Invitation, InvitationError> {
        let plaintext = XChaCha20Poly1305::new((&secret.0).into())
            .decrypt(
                &XNonce::from(self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: TICKET_AAD,
                },
            )
            .map_err(|_| InvitationError::DecryptionFailed)?;
        let invitation = Invitation::decode_canonical(&plaintext)?;
        if invitation.subject != local_subject {
            return Err(InvitationError::WrongSubject);
        }
        Ok(invitation)
    }

    /// Strictly encodes the opaque ticket.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, InvitationError> {
        minicbor::to_vec(TicketWire {
            version: INVITATION_VERSION,
            nonce: self.nonce,
            ciphertext: self.ciphertext.clone(),
        })
        .map_err(codec_error)
    }

    /// Returns the content identifier used for durable one-time import consumption.
    pub fn id(&self) -> Result<[u8; 32], InvitationError> {
        Ok(*blake3::hash(&self.encode_canonical()?).as_bytes())
    }

    /// Strictly decodes an opaque ticket without attempting decryption.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, InvitationError> {
        let wire: TicketWire = decode_exact(bytes)?;
        if wire.version != INVITATION_VERSION {
            return Err(InvitationError::UnsupportedVersion(wire.version));
        }
        let ticket = Self {
            nonce: wire.nonce,
            ciphertext: wire.ciphertext,
        };
        if ticket.encode_canonical()? != bytes {
            return Err(InvitationError::NonCanonical);
        }
        Ok(ticket)
    }
}

/// A one-time offline invitation bearer secret.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct InvitationSecret([u8; 32]);

impl std::fmt::Debug for InvitationSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("InvitationSecret([redacted])")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvitationError {
    #[error("invitation codec failed: {0}")]
    Codec(String),
    #[error("invitation is not canonical")]
    NonCanonical,
    #[error("unsupported invitation version: {0}")]
    UnsupportedVersion(u16),
    #[error("invitation capability chain is invalid")]
    InvalidChain,
    #[error("invitation signature is invalid")]
    InvalidSignature,
    #[error("invitation endpoint key is invalid")]
    InvalidAuthor,
    #[error("invitation targets another endpoint")]
    WrongSubject,
    #[error("invitation encryption failed")]
    EncryptionFailed,
    #[error("invitation ticket decryption failed")]
    DecryptionFailed,
    #[error("cryptographic randomness is unavailable")]
    RandomnessUnavailable,
    #[error("invitation exceeds its bound: {0}")]
    TooLarge(usize),
    #[error("authority validation failed: {0}")]
    Authority(String),
}

#[derive(minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
struct InvitationContent {
    #[n(0)]
    version: u16,
    #[n(1)]
    descriptor: Vec<u8>,
    #[n(2)]
    capability_chain: Vec<Vec<u8>>,
    #[n(3)]
    domain_id: DomainId,
    #[n(4)]
    epoch: u64,
    #[n(5)]
    domain_key: [u8; 32],
    #[n(6)]
    subject: AuthorId,
    #[n(7)]
    nonce: [u8; 32],
}

#[derive(minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
struct InvitationWire {
    #[n(0)]
    content: Vec<u8>,
    #[n(1)]
    issuer: AuthorId,
    #[n(2)]
    signature: [u8; 64],
}

#[derive(minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
struct TicketWire {
    #[n(0)]
    version: u16,
    #[n(1)]
    nonce: [u8; 24],
    #[n(2)]
    ciphertext: Vec<u8>,
}

fn verify_signature(
    author: AuthorId,
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), InvitationError> {
    let public_key = iroh_base::PublicKey::try_from(author.as_bytes())
        .map_err(|_| InvitationError::InvalidAuthor)?;
    public_key
        .verify(message, &iroh_base::Signature::from_bytes(signature))
        .map_err(|_| InvitationError::InvalidSignature)
}

fn decode_exact<T>(bytes: &[u8]) -> Result<T, InvitationError>
where
    T: for<'bytes> minicbor::Decode<'bytes, ()>,
{
    let mut decoder = minicbor::Decoder::new(bytes);
    let value = decoder.decode().map_err(codec_error)?;
    if decoder.position() != bytes.len() {
        return Err(InvitationError::NonCanonical);
    }
    Ok(value)
}

#[allow(clippy::needless_pass_by_value)]
fn codec_error(error: impl std::fmt::Display) -> InvitationError {
    InvitationError::Codec(error.to_string())
}

#[allow(clippy::needless_pass_by_value)]
fn authority_error(error: impl std::fmt::Display) -> InvitationError {
    InvitationError::Authority(error.to_string())
}
