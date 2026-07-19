use iroh_db_core::AuthorId;

use crate::{SecurityError, key::gossip_signature_message};

/// Verifies a gossip hint signature under its distinct protocol context.
pub fn verify_gossip_signature(
    author: AuthorId,
    canonical_hint_bytes: &[u8],
    signature: &[u8; 64],
) -> Result<(), SecurityError> {
    let public_key = iroh_base::PublicKey::try_from(author.as_bytes())
        .map_err(|_| SecurityError::InvalidAuthor)?;
    let signature = iroh_base::Signature::from_bytes(signature);
    public_key
        .verify(&gossip_signature_message(canonical_hint_bytes), &signature)
        .map_err(|_| SecurityError::InvalidSignature)
}
