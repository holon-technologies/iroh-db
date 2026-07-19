use iroh_db_core::{
    AuthorId, CollectionId, CrdtKind, Dot, FieldDescriptor, FieldState, IrohRecord, Lww,
    RecordError, RecordKey, SchemaDescriptor, VersionVector, decode_record_fields,
    encode_record_fields,
};

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(transparent)]
struct TrackId(#[n(0)] String);

#[derive(Debug, Clone, PartialEq, Eq)]
struct Track {
    id: TrackId,
    title: Lww<String>,
}

impl IrohRecord for Track {
    type Id = TrackId;

    fn schema() -> Result<SchemaDescriptor, RecordError> {
        Ok(SchemaDescriptor::new(
            "tracks",
            1,
            vec![
                FieldDescriptor::new(1, "id", CrdtKind::Immutable, "TrackId").record_id(),
                FieldDescriptor::new(2, "title", CrdtKind::Lww, "String").indexed(),
            ],
        )?)
    }

    fn id(&self) -> &Self::Id {
        &self.id
    }

    fn encode_record(&self) -> Result<Vec<u8>, RecordError> {
        encode_record_fields([(1, self.id.encode_key()?), (2, self.title.encode_state()?)])
    }

    fn decode_record(bytes: &[u8]) -> Result<Self, RecordError> {
        let fields = decode_record_fields(bytes)?;
        Ok(Self {
            id: TrackId::decode_key(fields.required(1)?)?,
            title: Lww::decode_state(fields.required(2)?)?,
        })
    }

    fn field_values(&self, field_id: u32) -> Result<Vec<Vec<u8>>, RecordError> {
        match field_id {
            1 => Ok(vec![self.id.encode_key()?]),
            2 => self.title.visible_values(),
            _ => Ok(Vec::new()),
        }
    }
}

#[test]
fn a_hand_written_record_has_a_stable_schema_key_and_canonical_codec() {
    let mut title = Lww::new();
    title
        .assign(
            "Teardrop".to_owned(),
            Dot::new(AuthorId::from_bytes([7; 32]), 0, 0),
            VersionVector::new(),
        )
        .unwrap();
    let track = Track {
        id: TrackId("track-1".to_owned()),
        title,
    };

    let schema = Track::schema().unwrap();
    assert_eq!(schema.collection_id(), CollectionId::for_name("tracks"));
    assert_eq!(track.record_id().unwrap(), track.id.encode_key().unwrap());

    let bytes = track.encode_record().unwrap();
    assert_eq!(Track::decode_record(&bytes).unwrap(), track);
    assert_eq!(track.field_values(2).unwrap().len(), 1);
    assert!(track.field_values(999).unwrap().is_empty());
    assert_eq!(
        Track::decode_record(&[bytes, vec![0]].concat()),
        Err(RecordError::TrailingData)
    );
}
