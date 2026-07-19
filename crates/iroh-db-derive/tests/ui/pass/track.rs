use iroh_db_core::{FieldState as _, IrohRecord as _, Lww, OrSet};
use iroh_db_derive::IrohRecord;

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
}

fn main() {
    let schema = Track::schema().unwrap();
    assert_eq!(schema.collection_name(), "tracks");
    assert_eq!(Track::title.field_id(), 2);
    assert!(Track::title.is_indexed());

    let track = Track {
        id: TrackId("one".into()),
        title: Lww::new(),
        tags: OrSet::new(),
    };
    let bytes = track.encode_record().unwrap();
    assert_eq!(Track::decode_record(&bytes).unwrap(), track);
    assert!(track.title.encode_state().is_ok());
}
