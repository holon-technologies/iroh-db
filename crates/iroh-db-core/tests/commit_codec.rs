use iroh_db_core::{
    AuthorId, CapabilityId, CollectionId, CommitBody, CommitCodecError, CommitEnvelope,
    CommitHeader, CommitId, CommitSignature, DomainId, Operation, OperationKind, SchemaId,
    TransactionId,
};

fn id(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn sample_envelope() -> CommitEnvelope {
    let header = CommitHeader::new(
        DomainId::from_bytes(id(1)),
        3,
        AuthorId::from_bytes(id(2)),
        7,
        vec![CommitId::from_bytes(id(4)), CommitId::from_bytes(id(3))],
        CapabilityId::from_bytes(id(5)),
        vec![SchemaId::from_bytes(id(7)), SchemaId::from_bytes(id(6))],
        [8; 24],
    )
    .unwrap();
    CommitEnvelope::new(
        header,
        vec![9, 10, 11],
        CommitSignature::from_bytes([12; 64]),
    )
    .unwrap()
}

#[test]
fn commit_envelope_encoding_is_canonical_and_round_trips() {
    let envelope = sample_envelope();
    let encoded = envelope.encode_canonical();
    let decoded = CommitEnvelope::decode_canonical(&encoded).unwrap();

    assert_eq!(decoded, envelope);
    assert_eq!(
        decoded.header().dependencies()[0],
        CommitId::from_bytes(id(3))
    );
    assert_eq!(
        decoded.header().schema_ids()[0],
        SchemaId::from_bytes(id(6))
    );
    assert_eq!(decoded.commit_id(), envelope.commit_id());
    assert_ne!(decoded.signing_bytes(), encoded);
}

#[test]
fn commit_body_encoding_is_canonical_and_bounded() {
    let body = CommitBody::new(
        TransactionId::from_bytes(id(13)),
        vec![
            Operation::new(
                CollectionId::for_name("tracks"),
                vec![1, 2, 3],
                2,
                OperationKind::LwwAssign,
                b"Mezzanine".to_vec(),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let encoded = body.encode_canonical();

    assert_eq!(CommitBody::decode_canonical(&encoded).unwrap(), body);

    let oversized_record_id = Operation::new(
        CollectionId::for_name("tracks"),
        vec![0; 1_025],
        2,
        OperationKind::LwwAssign,
        Vec::new(),
    );
    assert_eq!(
        oversized_record_id,
        Err(CommitCodecError::RecordIdTooLarge(1_025))
    );
}

#[test]
fn commit_decoders_reject_truncation_and_trailing_data() {
    let encoded = sample_envelope().encode_canonical();
    for length in 0..encoded.len() {
        assert!(CommitEnvelope::decode_canonical(&encoded[..length]).is_err());
    }

    let mut trailing = encoded;
    trailing.push(0);
    assert!(CommitEnvelope::decode_canonical(&trailing).is_err());
}
