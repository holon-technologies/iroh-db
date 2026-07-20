use std::fmt;

use iroh_db_core::AuthorId;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::SecurityError;

/// A random symmetric key for one domain epoch.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DomainKey([u8; 32]);

impl DomainKey {
    /// Generates a key from the operating system's cryptographic random source.
    pub fn generate() -> Result<Self, SecurityError> {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| SecurityError::RandomnessUnavailable)?;
        Ok(Self(bytes))
    }

    /// Imports exact key bytes from a trusted key provider.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derives a domain-separated object key without exposing the epoch key.
    pub fn derive_subkey(
        &self,
        salt: &[u8],
        context: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, SecurityError> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hkdf = Hkdf::<Sha256>::new(Some(salt), &self.0);
        let mut output = Zeroizing::new([0_u8; 32]);
        hkdf.expand(context, &mut *output)
            .map_err(|_| SecurityError::KeyDerivationFailed)?;
        Ok(output)
    }
}

impl fmt::Debug for DomainKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DomainKey([redacted])")
    }
}

/// The iroh endpoint signing identity used by the database protocol.
#[derive(Clone)]
pub struct IrohSigner {
    secret_key: iroh_base::SecretKey,
}

impl IrohSigner {
    /// Generates a new iroh endpoint identity.
    pub fn generate() -> Self {
        Self {
            secret_key: iroh_base::SecretKey::generate(),
        }
    }

    /// Imports deterministic endpoint secret bytes from a trusted key provider.
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        Self {
            secret_key: iroh_base::SecretKey::from_bytes(&bytes),
        }
    }

    /// Wraps the same iroh secret key used by an endpoint.
    pub const fn new(secret_key: iroh_base::SecretKey) -> Self {
        Self { secret_key }
    }

    /// Returns the authenticated iroh endpoint identity.
    pub fn author(&self) -> AuthorId {
        AuthorId::from_bytes(*self.secret_key.public().as_bytes())
    }

    /// Signs canonical commit bytes under the commit-specific context.
    pub fn sign(&self, canonical_commit_bytes: &[u8]) -> [u8; 64] {
        self.secret_key
            .sign(&commit_signature_message(canonical_commit_bytes))
            .to_bytes()
    }

    /// Signs canonical snapshot bytes under a snapshot-specific context.
    pub fn sign_snapshot(&self, canonical_snapshot_bytes: &[u8]) -> [u8; 64] {
        self.secret_key
            .sign(&snapshot_signature_message(canonical_snapshot_bytes))
            .to_bytes()
    }

    /// Signs a canonical backup catalog under a backup-specific context.
    pub fn sign_backup_catalog(&self, canonical_catalog_bytes: &[u8]) -> [u8; 64] {
        self.secret_key
            .sign(&backup_signature_message(canonical_catalog_bytes))
            .to_bytes()
    }

    /// Signs a bounded gossip hint under a gossip-specific protocol context.
    pub fn sign_gossip(&self, canonical_hint_bytes: &[u8]) -> [u8; 64] {
        self.secret_key
            .sign(&gossip_signature_message(canonical_hint_bytes))
            .to_bytes()
    }

    /// Signs canonical domain-authority bytes under a capability-specific context.
    pub fn sign_capability(&self, canonical_authority_bytes: &[u8]) -> [u8; 64] {
        self.secret_key
            .sign(&capability_signature_message(canonical_authority_bytes))
            .to_bytes()
    }

    /// Signs canonical genesis bytes under a descriptor-specific context.
    pub fn sign_domain_descriptor(&self, canonical_descriptor_bytes: &[u8]) -> [u8; 64] {
        self.secret_key
            .sign(&domain_descriptor_signature_message(
                canonical_descriptor_bytes,
            ))
            .to_bytes()
    }

    /// Signs a targeted invitation under an invitation-specific context.
    pub fn sign_invitation(&self, canonical_invitation_bytes: &[u8]) -> [u8; 64] {
        self.secret_key
            .sign(&invitation_signature_message(canonical_invitation_bytes))
            .to_bytes()
    }

    /// Signs a history-compacting authority checkpoint.
    pub fn sign_authority_checkpoint(&self, canonical_bytes: &[u8]) -> [u8; 64] {
        self.secret_key
            .sign(&authority_checkpoint_signature_message(canonical_bytes))
            .to_bytes()
    }

    /// Signs a domain control transition under a control-specific context.
    pub fn sign_control(&self, canonical_control_bytes: &[u8]) -> [u8; 64] {
        self.secret_key
            .sign(&control_signature_message(canonical_control_bytes))
            .to_bytes()
    }

    pub(crate) fn secret_bytes(&self) -> [u8; 32] {
        self.secret_key.to_bytes()
    }
}

impl fmt::Debug for IrohSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IrohSigner([redacted])")
    }
}

pub(crate) fn commit_signature_message(canonical_commit_bytes: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(27 + canonical_commit_bytes.len());
    message.extend_from_slice(b"iroh-db/commit-signature/v1");
    message.extend_from_slice(canonical_commit_bytes);
    message
}

pub(crate) fn snapshot_signature_message(canonical_snapshot_bytes: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(29 + canonical_snapshot_bytes.len());
    message.extend_from_slice(b"iroh-db/snapshot-signature/v1");
    message.extend_from_slice(canonical_snapshot_bytes);
    message
}

pub(crate) fn backup_signature_message(canonical_catalog_bytes: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(27 + canonical_catalog_bytes.len());
    message.extend_from_slice(b"iroh-db/backup-signature/v1");
    message.extend_from_slice(canonical_catalog_bytes);
    message
}

pub(crate) fn gossip_signature_message(canonical_hint_bytes: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(27 + canonical_hint_bytes.len());
    message.extend_from_slice(b"iroh-db/gossip-signature/v1");
    message.extend_from_slice(canonical_hint_bytes);
    message
}

pub(crate) fn capability_signature_message(canonical_authority_bytes: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(31 + canonical_authority_bytes.len());
    message.extend_from_slice(b"iroh-db/capability-signature/v1");
    message.extend_from_slice(canonical_authority_bytes);
    message
}

pub(crate) fn domain_descriptor_signature_message(canonical_bytes: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(38 + canonical_bytes.len());
    message.extend_from_slice(b"iroh-db/domain-descriptor-signature/v1");
    message.extend_from_slice(canonical_bytes);
    message
}

pub(crate) fn invitation_signature_message(canonical_bytes: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(31 + canonical_bytes.len());
    message.extend_from_slice(b"iroh-db/invitation-signature/v1");
    message.extend_from_slice(canonical_bytes);
    message
}

pub(crate) fn authority_checkpoint_signature_message(canonical_bytes: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(41 + canonical_bytes.len());
    message.extend_from_slice(b"iroh-db/authority-checkpoint-signature/v1");
    message.extend_from_slice(canonical_bytes);
    message
}

pub(crate) fn control_signature_message(canonical_bytes: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(28 + canonical_bytes.len());
    message.extend_from_slice(b"iroh-db/control-signature/v1");
    message.extend_from_slice(canonical_bytes);
    message
}
