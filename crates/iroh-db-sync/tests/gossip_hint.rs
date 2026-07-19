use iroh_db_core::{CommitId, DomainId};
use iroh_db_security::{IrohSigner, verify_gossip_signature};
use iroh_db_sync::{GossipHint, SyncFrameError};

#[test]
fn signed_hint_is_canonical_bounded_and_contains_no_private_domain_data() {
    let signer = IrohSigner::generate();
    let commit = CommitId::from_bytes([0x42; 32]);
    let frontier = [0x24; 32];
    let unsigned = GossipHint::new(signer.author(), commit, frontier, 7, [0; 64]);
    let signature = signer.sign_gossip(&unsigned.signing_bytes().unwrap());
    let hint = GossipHint::new(signer.author(), commit, frontier, 7, signature);

    let encoded = hint.encode_canonical().unwrap();
    let decoded = GossipHint::decode_canonical(&encoded).unwrap();
    assert_eq!(decoded, hint);
    verify_gossip_signature(
        decoded.author(),
        &decoded.signing_bytes().unwrap(),
        decoded.signature(),
    )
    .unwrap();

    let domain = DomainId::from_bytes([0xa5; 32]);
    assert!(
        !encoded
            .windows(domain.as_bytes().len())
            .any(|window| window == domain.as_bytes())
    );
    assert!(
        !encoded
            .windows(b"private-record-id".len())
            .any(|window| window == b"private-record-id")
    );
    assert!(
        !encoded
            .windows(b"private-collection".len())
            .any(|window| window == b"private-collection")
    );
}

#[test]
fn malformed_or_trailing_hint_is_rejected() {
    let signer = IrohSigner::generate();
    let unsigned = GossipHint::new(
        signer.author(),
        CommitId::from_bytes([1; 32]),
        [2; 32],
        1,
        [0; 64],
    );
    let signature = signer.sign_gossip(&unsigned.signing_bytes().unwrap());
    let hint = GossipHint::new(
        signer.author(),
        CommitId::from_bytes([1; 32]),
        [2; 32],
        1,
        signature,
    );
    let mut bytes = hint.encode_canonical().unwrap();
    bytes.push(0);
    assert!(matches!(
        GossipHint::decode_canonical(&bytes),
        Err(SyncFrameError::NonCanonical)
    ));
}
