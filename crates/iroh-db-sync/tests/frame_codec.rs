use iroh_db_core::{CommitId, DomainId};
use iroh_db_sync::{
    MAX_CONTROL_FRAME, MAX_PROTOCOL_VERSION, MIN_PROTOCOL_VERSION, SyncFrame, SyncFrameError,
    missing_commits, negotiate_protocol,
};

#[test]
fn hello_has_stable_canonical_bytes() {
    let frame = SyncFrame::Hello {
        nonce: [0; 32],
        max_frame: u32::try_from(MAX_CONTROL_FRAME).unwrap(),
        min_protocol: MIN_PROTOCOL_VERSION,
        max_protocol: MAX_PROTOCOL_VERSION,
    };
    let bytes = frame.encode_canonical().unwrap();
    assert_eq!(
        hex::encode(&bytes),
        concat!(
            "900400f65820",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "801a00100000f6f6f6f6f6f680f60404"
        )
    );
    assert_eq!(SyncFrame::decode_canonical(&bytes).unwrap(), frame);
}

#[test]
fn protocol_ranges_choose_the_highest_overlap_and_fail_closed() {
    assert_eq!(negotiate_protocol(2, 4, 3, 5).unwrap(), 4);
    assert_eq!(
        negotiate_protocol(1, 2, 3, 4),
        Err(SyncFrameError::NoCommonProtocol {
            local_min: 1,
            local_max: 2,
            remote_min: 3,
            remote_max: 4,
        })
    );
    assert_eq!(
        negotiate_protocol(4, 3, 3, 4),
        Err(SyncFrameError::InvalidProtocolRange { min: 4, max: 3 })
    );
}

#[test]
fn frames_reject_trailing_oversized_and_excessive_refs() {
    let frame = SyncFrame::DomainRequest {
        domain_id: DomainId::from_bytes([1; 32]),
        epoch: 0,
        proof: [2; 32],
        capability_chain: Vec::new(),
    };
    let mut trailing = frame.encode_canonical().unwrap();
    trailing.push(0);
    assert_eq!(
        SyncFrame::decode_canonical(&trailing),
        Err(SyncFrameError::NonCanonical)
    );
    assert_eq!(
        SyncFrame::decode_canonical(&vec![0; MAX_CONTROL_FRAME + 1]),
        Err(SyncFrameError::FrameTooLarge(MAX_CONTROL_FRAME + 1))
    );
    assert!(matches!(
        SyncFrame::Refs {
            commits: vec![CommitId::from_bytes([3; 32]); 4_097]
        }
        .encode_canonical(),
        Err(SyncFrameError::TooManyReferences(4_097))
    ));
}

#[test]
fn frontier_difference_is_sorted_unique_and_bounded() {
    let one = CommitId::from_bytes([1; 32]);
    let two = CommitId::from_bytes([2; 32]);
    let three = CommitId::from_bytes([3; 32]);
    assert_eq!(
        missing_commits(&[one, three], &[three, two, one, two]).unwrap(),
        vec![two]
    );
}

#[test]
fn authority_frames_are_strict_bounded_and_canonical() {
    let state = SyncFrame::AuthorityState {
        epoch: 7,
        sequence: 7,
        head: Some([9; 32]),
    };
    let state_bytes = state.encode_canonical().unwrap();
    assert_eq!(SyncFrame::decode_canonical(&state_bytes).unwrap(), state);

    let request = SyncFrame::DomainRequest {
        domain_id: DomainId::from_bytes([1; 32]),
        epoch: 6,
        proof: [2; 32],
        capability_chain: vec![vec![3; 64]],
    };
    let request_bytes = request.encode_canonical().unwrap();
    assert_eq!(
        SyncFrame::decode_canonical(&request_bytes).unwrap(),
        request
    );

    let grant = SyncFrame::ControlGrant {
        transition: vec![4; 128],
        epoch_key: [5; 32],
        capability_chain: vec![vec![6; 256]],
    };
    let grant_bytes = grant.encode_canonical().unwrap();
    assert_eq!(SyncFrame::decode_canonical(&grant_bytes).unwrap(), grant);
    let debug = format!("{grant:?}");
    assert!(debug.contains("[redacted]"));
    assert!(!debug.contains(&format!("{:?}", [5_u8; 32])));

    let evidence = SyncFrame::ControlEvidence {
        transition: vec![7; 128],
    };
    let evidence_bytes = evidence.encode_canonical().unwrap();
    assert_eq!(
        SyncFrame::decode_canonical(&evidence_bytes).unwrap(),
        evidence
    );

    assert!(
        SyncFrame::ControlGrant {
            transition: vec![0; MAX_CONTROL_FRAME],
            epoch_key: [0; 32],
            capability_chain: Vec::new(),
        }
        .encode_canonical()
        .is_err()
    );
}
