use iroh_db_core::{CrdtKind, FieldDescriptor, SchemaDescriptor, SchemaError};

fn track_schema() -> SchemaDescriptor {
    SchemaDescriptor::new(
        "tracks",
        1,
        vec![
            FieldDescriptor::new(1, "id", CrdtKind::Immutable, "TrackId").record_id(),
            FieldDescriptor::new(2, "title", CrdtKind::Lww, "String").indexed(),
            FieldDescriptor::new(3, "tags", CrdtKind::OrSet, "String"),
        ],
    )
    .expect("valid schema")
}

#[test]
fn schema_encoding_is_canonical_and_round_trips() {
    let schema = track_schema();
    let encoded = schema.encode_canonical();

    assert_eq!(
        hex::encode(&encoded),
        "a8006769726f682d64620101020003010466747261636b730558203d7d9e0d9969ffe4dfd2e91de8b39c482c0eceb1b3a6ab549e862b831f3b15db06010783a600010162696402060367547261636b496404f405f5a6000201657469746c6502010366537472696e6704f505f4a6000301647461677302020366537472696e6704f405f4"
    );
    assert_eq!(schema.encode_canonical(), encoded);
    assert_eq!(
        SchemaDescriptor::decode_canonical(&encoded).expect("canonical schema"),
        schema
    );
    assert_eq!(schema.schema_id(), track_schema().schema_id());
    assert_eq!(schema.collection_id(), track_schema().collection_id());
}

#[test]
fn schema_decoder_rejects_truncation_and_trailing_data() {
    let encoded = track_schema().encode_canonical();

    for length in 0..encoded.len() {
        assert!(
            SchemaDescriptor::decode_canonical(&encoded[..length]).is_err(),
            "accepted truncated schema at {length} bytes"
        );
    }

    let mut trailing = encoded;
    trailing.push(0);
    assert!(SchemaDescriptor::decode_canonical(&trailing).is_err());
}

#[test]
fn schema_validation_rejects_ambiguous_field_contracts() {
    let duplicate = SchemaDescriptor::new(
        "tracks",
        1,
        vec![
            FieldDescriptor::new(1, "id", CrdtKind::Immutable, "TrackId").record_id(),
            FieldDescriptor::new(1, "title", CrdtKind::Lww, "String"),
        ],
    );
    assert_eq!(duplicate, Err(SchemaError::DuplicateFieldId(1)));

    let missing_id = SchemaDescriptor::new(
        "tracks",
        1,
        vec![FieldDescriptor::new(2, "title", CrdtKind::Lww, "String")],
    );
    assert_eq!(missing_id, Err(SchemaError::MissingRecordId));

    let multiple_ids = SchemaDescriptor::new(
        "tracks",
        1,
        vec![
            FieldDescriptor::new(1, "id", CrdtKind::Immutable, "TrackId").record_id(),
            FieldDescriptor::new(2, "other_id", CrdtKind::Immutable, "TrackId").record_id(),
        ],
    );
    assert_eq!(multiple_ids, Err(SchemaError::MultipleRecordIds));
}
