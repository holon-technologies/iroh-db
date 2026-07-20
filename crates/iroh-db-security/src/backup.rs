use iroh_db_core::AuthorId;

use crate::{SecurityError, key::backup_signature_message};

/// Verifies a backup catalog signature under its distinct protocol context.
pub fn verify_backup_signature(
    author: AuthorId,
    canonical_catalog_bytes: &[u8],
    signature: &[u8; 64],
) -> Result<(), SecurityError> {
    let public_key = iroh_base::PublicKey::try_from(author.as_bytes())
        .map_err(|_| SecurityError::InvalidAuthor)?;
    let signature = iroh_base::Signature::from_bytes(signature);
    public_key
        .verify(
            &backup_signature_message(canonical_catalog_bytes),
            &signature,
        )
        .map_err(|_| SecurityError::InvalidSignature)
}
