use iroh_db::{AuthorId, Dot, IrohDb, IrohRecord, Lww, OrSet, VersionVector};

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(transparent)]
struct TrackId(#[n(0)] String);

#[derive(Debug, Clone, PartialEq, Eq, IrohRecord)]
#[iroh_db(collection = "tracks", version = 1)]
struct Track {
    #[iroh_db(id, field_id = 1)]
    id: TrackId,
    #[iroh_db(field_id = 2)]
    title: Lww<String>,
    #[iroh_db(field_id = 3, index)]
    artist: Lww<String>,
    #[iroh_db(field_id = 4)]
    tags: OrSet<String>,
}

fn register(value: &str, author: AuthorId, operation: u32) -> Lww<String> {
    let mut field = Lww::new();
    field
        .assign(
            value.to_owned(),
            Dot::new(author, 0, operation),
            VersionVector::new(),
        )
        .expect("fresh register assignment is valid");
    field
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "./music.irohdb".into());
    let db = IrohDb::open(path).await?;
    let tracks = db.collection::<Track>();
    let author = AuthorId::from_bytes([7; 32]);
    tracks
        .put(Track {
            id: TrackId("teardrop".into()),
            title: register("Teardrop", author, 0),
            artist: register("Massive Attack", author, 1),
            tags: OrSet::new(),
        })
        .await?;

    let results = tracks
        .query()
        .filter(Track::artist.eq("Massive Attack"))
        .fetch()
        .await?;
    println!("found {} track(s)", results.len());

    drop(tracks);
    db.close().await?;
    Ok(())
}
