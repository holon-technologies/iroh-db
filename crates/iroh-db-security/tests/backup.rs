use iroh_db_security::{IrohSigner, verify_backup_signature};

#[test]
fn backup_signatures_are_device_bound_tamper_evident_and_domain_separated() {
    let signer = IrohSigner::from_secret_bytes([7; 32]);
    let other = IrohSigner::from_secret_bytes([8; 32]);
    let catalog = b"canonical backup catalog";
    let signature = signer.sign_backup_catalog(catalog);

    verify_backup_signature(signer.author(), catalog, &signature).unwrap();
    assert!(verify_backup_signature(other.author(), catalog, &signature).is_err());
    assert!(verify_backup_signature(signer.author(), b"changed", &signature).is_err());

    let snapshot_signature = signer.sign_snapshot(catalog);
    assert!(verify_backup_signature(signer.author(), catalog, &snapshot_signature).is_err());
}
