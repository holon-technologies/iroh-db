use iroh_db_core::{
    CapabilityId, CollectionId, CommitBody, CommitEnvelope, CommitHeader, CommitId,
    CommitSignature, DomainId, Operation, OperationKind, SchemaId, TransactionId,
};
use iroh_db_security::{DomainKey, IrohSigner, SecurityError, open_commit, seal_commit};

fn id(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn body() -> CommitBody {
    CommitBody::new(
        TransactionId::from_bytes(id(9)),
        vec![
            Operation::new(
                CollectionId::for_name("tracks"),
                vec![1],
                2,
                OperationKind::LwwAssign,
                b"Teardrop".to_vec(),
            )
            .unwrap(),
        ],
    )
    .unwrap()
}

fn header(signer: &IrohSigner, domain: DomainId) -> CommitHeader {
    CommitHeader::new(
        domain,
        1,
        signer.author(),
        0,
        vec![CommitId::from_bytes(id(3))],
        CapabilityId::from_bytes(id(4)),
        vec![SchemaId::from_bytes(id(5))],
        [6; 24],
    )
    .unwrap()
}

#[test]
fn commit_is_signed_encrypted_and_round_trips() {
    let signer = IrohSigner::from_secret_bytes(id(7));
    let domain = DomainId::from_bytes(id(1));
    let key = DomainKey::from_bytes(id(8));
    let envelope = seal_commit(header(&signer, domain), &body(), &key, &signer).unwrap();

    assert_eq!(
        envelope.commit_id().to_string(),
        "3050675ef817a06110d268bf9f0d88c60a65d0ffa1409b02e1842d7408217f04"
    );
    assert_eq!(open_commit(&envelope, &key).unwrap(), body());
    assert!(
        !envelope
            .ciphertext()
            .windows(8)
            .any(|bytes| bytes == b"Teardrop")
    );
    assert_eq!(envelope.header().author(), signer.author());
}

#[test]
fn commit_verification_fails_closed_for_tampering_and_wrong_keys() {
    let signer = IrohSigner::from_secret_bytes(id(7));
    let domain = DomainId::from_bytes(id(1));
    let key = DomainKey::from_bytes(id(8));
    let envelope = seal_commit(header(&signer, domain), &body(), &key, &signer).unwrap();

    assert_eq!(
        open_commit(&envelope, &DomainKey::from_bytes(id(9))),
        Err(SecurityError::DecryptionFailed)
    );

    let mut ciphertext = envelope.ciphertext().to_vec();
    ciphertext[0] ^= 1;
    let tampered =
        CommitEnvelope::new(envelope.header().clone(), ciphertext, envelope.signature()).unwrap();
    assert_eq!(
        open_commit(&tampered, &key),
        Err(SecurityError::InvalidSignature)
    );

    let changed_domain = CommitHeader::new(
        DomainId::from_bytes(id(2)),
        envelope.header().epoch(),
        envelope.header().author(),
        envelope.header().author_sequence(),
        envelope.header().dependencies().to_vec(),
        envelope.header().capability_id(),
        envelope.header().schema_ids().to_vec(),
        *envelope.header().nonce(),
    )
    .unwrap();
    let tampered_header = CommitEnvelope::new(
        changed_domain,
        envelope.ciphertext().to_vec(),
        envelope.signature(),
    )
    .unwrap();
    assert_eq!(
        open_commit(&tampered_header, &key),
        Err(SecurityError::InvalidSignature)
    );
}

#[test]
fn a_valid_signature_does_not_bypass_aead_authentication() {
    let signer = IrohSigner::from_secret_bytes(id(7));
    let key = DomainKey::from_bytes(id(8));
    let header = header(&signer, DomainId::from_bytes(id(1)));
    let corrupted_ciphertext = vec![0; 32];
    let signing_bytes = CommitEnvelope::signing_bytes_for(&header, &corrupted_ciphertext).unwrap();
    let signature = CommitSignature::from_bytes(signer.sign(&signing_bytes));
    let forged = CommitEnvelope::new(header, corrupted_ciphertext, signature).unwrap();

    assert_eq!(
        open_commit(&forged, &key),
        Err(SecurityError::DecryptionFailed)
    );
}

#[test]
fn secrets_are_redacted_and_author_mismatch_is_rejected() {
    let signer = IrohSigner::from_secret_bytes(id(7));
    let other = IrohSigner::from_secret_bytes(id(10));
    let domain = DomainId::from_bytes(id(1));
    let key = DomainKey::from_bytes(id(8));

    assert_eq!(format!("{key:?}"), "DomainKey([redacted])");
    assert_eq!(format!("{signer:?}"), "IrohSigner([redacted])");
    assert_eq!(
        seal_commit(header(&other, domain), &body(), &key, &signer),
        Err(SecurityError::AuthorMismatch)
    );
}
