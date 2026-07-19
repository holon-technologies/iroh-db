use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use iroh_db_core::{CommitBody, CommitCodecError, CommitEnvelope, CommitHeader, CommitSignature};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{DomainKey, IrohSigner, key::commit_signature_message};

/// Cryptographic validation or commit protection failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecurityError {
    /// The header author did not match the supplied endpoint signer.
    #[error("commit author does not match the endpoint signer")]
    AuthorMismatch,
    /// The encoded endpoint public key was invalid.
    #[error("commit author is not a valid iroh endpoint id")]
    InvalidAuthor,
    /// The commit signature was invalid.
    #[error("commit signature validation failed")]
    InvalidSignature,
    /// Authenticated encryption could not be completed.
    #[error("commit encryption failed")]
    EncryptionFailed,
    /// Ciphertext authentication or decryption failed.
    #[error("commit decryption failed")]
    DecryptionFailed,
    /// The commit sub-key could not be derived.
    #[error("commit key derivation failed")]
    KeyDerivationFailed,
    /// The operating system random source was unavailable.
    #[error("cryptographic randomness is unavailable")]
    RandomnessUnavailable,
    /// Local key-provider I/O failed without exposing key material.
    #[error("local key provider I/O failed: {0}")]
    KeyProviderIo(String),
    /// Local key-provider bytes failed format or authentication checks.
    #[error("local key provider data is invalid")]
    InvalidKeyProviderData,
    /// Secret key files were accessible by group or other users.
    #[error("local key provider file permissions are not owner-only")]
    InsecureKeyPermissions,
    /// The canonical commit representation was invalid.
    #[error(transparent)]
    CommitCodec(#[from] CommitCodecError),
}

/// Encrypts and signs one canonical atomic commit.
pub fn seal_commit(
    header: CommitHeader,
    body: &CommitBody,
    domain_key: &DomainKey,
    signer: &IrohSigner,
) -> Result<CommitEnvelope, SecurityError> {
    if header.author() != signer.author() {
        return Err(SecurityError::AuthorMismatch);
    }

    let key = derive_commit_key(domain_key, &header)?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let associated_data = CommitEnvelope::signing_bytes_for(&header, &[])?;
    let nonce = XNonce::from(*header.nonce());
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &body.encode_canonical(),
                aad: &associated_data,
            },
        )
        .map_err(|_| SecurityError::EncryptionFailed)?;
    let signing_bytes = CommitEnvelope::signing_bytes_for(&header, &ciphertext)?;
    let signature = CommitSignature::from_bytes(signer.sign(&signing_bytes));
    Ok(CommitEnvelope::new(header, ciphertext, signature)?)
}

/// Verifies, authenticates, decrypts, and strictly decodes a commit.
pub fn open_commit(
    envelope: &CommitEnvelope,
    domain_key: &DomainKey,
) -> Result<CommitBody, SecurityError> {
    verify_signature(envelope)?;

    let key = derive_commit_key(domain_key, envelope.header())?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let associated_data = CommitEnvelope::signing_bytes_for(envelope.header(), &[])?;
    let nonce = XNonce::from(*envelope.header().nonce());
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: envelope.ciphertext(),
                aad: &associated_data,
            },
        )
        .map_err(|_| SecurityError::DecryptionFailed)?;
    Ok(CommitBody::decode_canonical(&plaintext)?)
}

fn verify_signature(envelope: &CommitEnvelope) -> Result<(), SecurityError> {
    let public_key = iroh_base::PublicKey::try_from(envelope.header().author().as_bytes())
        .map_err(|_| SecurityError::InvalidAuthor)?;
    let signature = iroh_base::Signature::from_bytes(envelope.signature().as_bytes());
    public_key
        .verify(
            &commit_signature_message(&envelope.signing_bytes()),
            &signature,
        )
        .map_err(|_| SecurityError::InvalidSignature)
}

fn derive_commit_key(
    domain_key: &DomainKey,
    header: &CommitHeader,
) -> Result<Zeroizing<[u8; 32]>, SecurityError> {
    let hkdf = Hkdf::<Sha256>::new(Some(header.domain_id().as_bytes()), domain_key.as_bytes());
    let mut info = Vec::with_capacity(25 + size_of::<u64>());
    info.extend_from_slice(b"iroh-db/commit-key/v1");
    info.extend_from_slice(&header.epoch().to_be_bytes());
    let mut output = Zeroizing::new([0_u8; 32]);
    hkdf.expand(&info, &mut *output)
        .map_err(|_| SecurityError::KeyDerivationFailed)?;
    Ok(output)
}
