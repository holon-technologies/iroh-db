use iroh_db_core::{
    BlobHash, CollectionId, CrdtKind, FieldDescriptor, MigrationCodecError, MigrationId,
    OperationKind, SchemaActivation, SchemaDescriptor, SchemaStage, staging_digest,
};

fn schema(version: u32) -> SchemaDescriptor {
    let mut fields = vec![
        FieldDescriptor::new(1, "id", CrdtKind::Immutable, "TrackId").record_id(),
        FieldDescriptor::new(2, "title", CrdtKind::Lww, "String"),
    ];
    if version >= 2 {
        fields.push(FieldDescriptor::new(3, "genre", CrdtKind::Lww, "String"));
    }
    SchemaDescriptor::new("migration-tracks", version, fields).unwrap()
}

fn stage() -> SchemaStage {
    SchemaStage::new(
        MigrationId::from_bytes([1; 32]),
        schema(1),
        schema(2),
        b"teardrop".to_vec(),
        BlobHash::from_bytes([2; 32]),
        vec![3, 4, 5],
    )
    .unwrap()
}

#[test]
fn stage_and_activation_are_canonical_and_strict() {
    let stage = stage();
    let encoded = stage.encode_canonical();
    assert_eq!(
        hex::encode(&encoded),
        "aa006769726f682d64620101020003040458200101010101010101010101010101010101010101010101010101010101010101055877a8006769726f682d646201010200030104706d6967726174696f6e2d747261636b73055820548a18b071561aff421481c5e6b3974148cad8746911c2007f45ce3188ebae9c06010782a600010162696402060367547261636b496404f405f5a6000201657469746c6502010366537472696e6704f405f406588fa8006769726f682d646201010200030104706d6967726174696f6e2d747261636b73055820548a18b071561aff421481c5e6b3974148cad8746911c2007f45ce3188ebae9c06020783a600010162696402060367547261636b496404f405f5a6000201657469746c6502010366537472696e6704f405f4a60003016567656e726502010366537472696e6704f405f407487465617264726f7008582002020202020202020202020202020202020202020202020202020202020202020943030405"
    );
    assert_eq!(SchemaStage::decode_canonical(&encoded).unwrap(), stage);

    for length in 0..encoded.len() {
        assert!(SchemaStage::decode_canonical(&encoded[..length]).is_err());
    }
    let mut trailing = encoded;
    trailing.push(0);
    assert!(SchemaStage::decode_canonical(&trailing).is_err());

    let activation = SchemaActivation::new(
        MigrationId::from_bytes([1; 32]),
        schema(1),
        schema(2),
        1,
        BlobHash::from_bytes([6; 32]),
    )
    .unwrap();
    let encoded = activation.encode_canonical();
    assert_eq!(
        hex::encode(&encoded),
        "a9006769726f682d64620101020003050458200101010101010101010101010101010101010101010101010101010101010101055877a8006769726f682d646201010200030104706d6967726174696f6e2d747261636b73055820548a18b071561aff421481c5e6b3974148cad8746911c2007f45ce3188ebae9c06010782a600010162696402060367547261636b496404f405f5a6000201657469746c6502010366537472696e6704f405f406588fa8006769726f682d646201010200030104706d6967726174696f6e2d747261636b73055820548a18b071561aff421481c5e6b3974148cad8746911c2007f45ce3188ebae9c06020783a600010162696402060367547261636b496404f405f5a6000201657469746c6502010366537472696e6704f405f4a60003016567656e726502010366537472696e6704f405f407010858200606060606060606060606060606060606060606060606060606060606060606"
    );
    assert_eq!(
        SchemaActivation::decode_canonical(&encoded).unwrap(),
        activation
    );
    for length in 0..encoded.len() {
        assert!(SchemaActivation::decode_canonical(&encoded[..length]).is_err());
    }
    let mut trailing = encoded;
    trailing.push(0);
    assert!(SchemaActivation::decode_canonical(&trailing).is_err());
}

#[test]
fn migration_objects_reject_ambiguous_transitions_and_oversized_values() {
    assert!(matches!(
        SchemaStage::new(
            MigrationId::from_bytes([1; 32]),
            schema(1),
            schema(1),
            vec![],
            BlobHash::from_bytes([2; 32]),
            vec![],
        ),
        Err(MigrationCodecError::NonAdjacentVersion { from: 1, to: 1 })
    ));

    let other = SchemaDescriptor::new(
        "other",
        2,
        vec![FieldDescriptor::new(1, "id", CrdtKind::Immutable, "TrackId").record_id()],
    )
    .unwrap();
    assert!(matches!(
        SchemaActivation::new(
            MigrationId::from_bytes([1; 32]),
            schema(1),
            other,
            0,
            BlobHash::from_bytes([6; 32]),
        ),
        Err(MigrationCodecError::CollectionMismatch)
    ));

    assert!(matches!(
        SchemaStage::new(
            MigrationId::from_bytes([1; 32]),
            schema(1),
            schema(2),
            vec![0; 1_025],
            BlobHash::from_bytes([2; 32]),
            vec![],
        ),
        Err(MigrationCodecError::RecordIdTooLarge(1_025))
    ));
}

#[test]
fn migration_operation_kinds_are_stable() {
    assert_eq!(
        OperationKind::try_from(14).unwrap(),
        OperationKind::SchemaStage
    );
    assert_eq!(
        OperationKind::try_from(15).unwrap(),
        OperationKind::SchemaActivate
    );
    assert_eq!(OperationKind::SchemaStage as u8, 14);
    assert_eq!(OperationKind::SchemaActivate as u8, 15);
    assert_eq!(
        schema(1).collection_id(),
        CollectionId::for_name("migration-tracks")
    );
}

#[test]
fn staging_digest_is_order_independent_but_rejects_ambiguous_sets() {
    let first = stage();
    let second = SchemaStage::new(
        first.migration_id(),
        first.from().clone(),
        first.to().clone(),
        b"angel".to_vec(),
        BlobHash::from_bytes([7; 32]),
        vec![8, 9],
    )
    .unwrap();
    assert_eq!(
        staging_digest(&[first.clone(), second.clone()]).unwrap(),
        staging_digest(&[second, first.clone()]).unwrap()
    );
    assert_eq!(
        staging_digest(&[first.clone(), first]),
        Err(MigrationCodecError::DuplicateSourceRecord)
    );
}
