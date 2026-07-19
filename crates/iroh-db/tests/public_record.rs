use iroh_db::{AuthorId, BlobHash, BlobRef, DomainId, Dot, IrohRecord, Lww, OrSet, VersionVector};

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(transparent)]
struct TrackId(#[n(0)] String);

#[derive(Debug, Clone, PartialEq, Eq, IrohRecord)]
#[iroh_db(collection = "tracks", version = 1)]
struct Track {
    #[iroh_db(id, field_id = 1)]
    id: TrackId,
    #[iroh_db(field_id = 2, index)]
    title: Lww<String>,
    #[iroh_db(field_id = 3)]
    tags: OrSet<String>,
    #[iroh_db(field_id = 4)]
    audio: BlobRef,
}

#[test]
fn facade_only_record_api_compiles_and_round_trips() {
    let track = Track {
        id: TrackId("one".into()),
        title: Lww::new(),
        tags: OrSet::new(),
        audio: BlobRef::new(
            DomainId::from_bytes([1; 32]),
            0,
            BlobHash::from_bytes([2; 32]),
        ),
    };
    let encoded = track.encode_record().unwrap();
    assert_eq!(Track::decode_record(&encoded).unwrap(), track);
    assert_eq!(Track::title.field_id(), 2);
}

#[test]
fn derived_record_merge_is_fieldwise_and_convergent() {
    let audio = BlobRef::new(
        DomainId::from_bytes([1; 32]),
        0,
        BlobHash::from_bytes([2; 32]),
    );
    let mut left_title = Lww::new();
    left_title
        .assign(
            "left".into(),
            Dot::new(AuthorId::from_bytes([3; 32]), 0, 0),
            VersionVector::new(),
        )
        .unwrap();
    let mut right_title = Lww::new();
    right_title
        .assign(
            "right".into(),
            Dot::new(AuthorId::from_bytes([4; 32]), 0, 0),
            VersionVector::new(),
        )
        .unwrap();
    let mut left = Track {
        id: TrackId("one".into()),
        title: left_title,
        tags: OrSet::new(),
        audio,
    };
    let mut right = Track {
        id: TrackId("one".into()),
        title: right_title,
        tags: OrSet::new(),
        audio,
    };

    left.merge_record(&right).unwrap();
    right.merge_record(&left).unwrap();
    assert_eq!(
        left.encode_record().unwrap(),
        right.encode_record().unwrap()
    );
}
