use iroh_db::{
    AuthorId, ChangeKind, Cursor, DbError, Dot, IrohDb, IrohRecord, Lww, OrderDirection,
    SubscriptionEvent, VersionVector,
};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};

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
}

fn track(id: &str, title: &str, artist: &str) -> Track {
    let author = AuthorId::from_bytes([9; 32]);
    let mut title_field = Lww::new();
    title_field
        .assign(
            title.to_owned(),
            Dot::new(author, 0, 0),
            VersionVector::new(),
        )
        .unwrap();
    let mut artist_field = Lww::new();
    artist_field
        .assign(
            artist.to_owned(),
            Dot::new(author, 0, 1),
            VersionVector::new(),
        )
        .unwrap();
    Track {
        id: TrackId(id.to_owned()),
        title: title_field,
        artist: artist_field,
    }
}

#[tokio::test]
async fn typed_put_get_query_subscription_transaction_and_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let db = IrohDb::open(directory.path()).await.unwrap();
    let tracks = db.collection::<Track>();
    let mut changes = tracks.subscribe().unwrap();
    assert!(matches!(
        changes.recv().await.unwrap(),
        SubscriptionEvent::Initial(records) if records.is_empty()
    ));

    let teardrop = track("one", "Teardrop", "Massive Attack");
    tracks.put(teardrop.clone()).await.unwrap();
    let SubscriptionEvent::Changes(batch) = changes.recv().await.unwrap() else {
        panic!("initial event was already delivered")
    };
    assert_eq!(batch.changes().len(), 1);
    assert_eq!(batch.changes()[0].kind(), ChangeKind::Upserted);
    let stored_teardrop = tracks.get(&TrackId("one".into())).await.unwrap().unwrap();
    assert_eq!(stored_teardrop.id, teardrop.id);
    assert_eq!(stored_teardrop.title.get(), teardrop.title.get());
    assert_eq!(stored_teardrop.artist.get(), teardrop.artist.get());

    let results = tracks
        .query()
        .filter(Track::artist.eq("Massive Attack"))
        .fetch()
        .await
        .unwrap();
    assert_eq!(results, vec![stored_teardrop]);

    let mut transaction = db.transaction();
    transaction
        .put(track("two", "Angel", "Massive Attack"))
        .unwrap();
    transaction
        .put(track("three", "Roads", "Portishead"))
        .unwrap();
    let committed = transaction.commit().await.unwrap();
    assert_eq!(committed.changes().len(), 2);
    assert_eq!(tracks.query().fetch().await.unwrap().len(), 3);

    let audio = db
        .blobs()
        .import_bytes(
            b"seekable encrypted audio".to_vec(),
            Some("audio/test".into()),
        )
        .await
        .unwrap();
    let mut stream = db.blobs().open(&audio).await.unwrap();
    stream.seek(std::io::SeekFrom::Start(19)).await.unwrap();
    let mut suffix = Vec::new();
    stream.read_to_end(&mut suffix).await.unwrap();
    assert_eq!(suffix, b"audio");
    drop(stream);

    drop(changes);
    drop(tracks);
    db.close().await.unwrap();

    let reopened = IrohDb::open(directory.path()).await.unwrap();
    assert_eq!(
        reopened
            .collection::<Track>()
            .query()
            .fetch()
            .await
            .unwrap()
            .len(),
        3
    );
    let mut reopened_stream = reopened.blobs().open(&audio).await.unwrap();
    let mut bytes = Vec::new();
    reopened_stream.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, b"seekable encrypted audio");
    drop(reopened_stream);
    reopened.close().await.unwrap();
}

#[tokio::test]
async fn local_transaction_rejects_multiple_mutations_of_one_record() {
    let directory = tempfile::tempdir().unwrap();
    let db = IrohDb::open(directory.path()).await.unwrap();
    let tracks = db.collection::<Track>();
    let root_before = db.state_root().unwrap();

    let mut transaction = db.transaction();
    transaction.put(track("same", "First", "One")).unwrap();
    transaction.put(track("same", "Second", "Two")).unwrap();

    assert!(matches!(
        transaction.commit().await,
        Err(DbError::InvalidRemoteCommit(message))
            if message == "a commit mutates one record more than once"
    ));
    assert_eq!(db.state_root().unwrap(), root_before);
    assert!(tracks.get(&TrackId("same".into())).await.unwrap().is_none());
    assert!(db.commit_envelopes().await.unwrap().is_empty());

    drop(tracks);
    db.close().await.unwrap();
}

#[tokio::test]
async fn local_put_reissues_causal_metadata_from_the_signed_commit() {
    let directory = tempfile::tempdir().unwrap();
    let db = IrohDb::open(directory.path()).await.unwrap();
    let tracks = db.collection::<Track>();
    let supplied = track("owned", "Canonical", "Database");
    assert_ne!(supplied.title.dot().unwrap().author(), db.author_id());

    tracks.put(supplied).await.unwrap();
    let stored = tracks.get(&TrackId("owned".into())).await.unwrap().unwrap();

    assert_eq!(stored.title.get().map(String::as_str), Some("Canonical"));
    assert_eq!(stored.title.dot().unwrap().author(), db.author_id());
    assert_eq!(stored.title.dot().unwrap().sequence(), 0);
    assert_eq!(stored.artist.dot().unwrap().author(), db.author_id());
    assert_eq!(stored.artist.dot().unwrap().sequence(), 0);
    assert_ne!(stored.title.dot(), stored.artist.dot());

    drop(tracks);
    db.close().await.unwrap();
}

#[tokio::test]
async fn range_order_and_mac_bound_cursor_pagination_are_stable() {
    let directory = tempfile::tempdir().unwrap();
    let db = IrohDb::open(directory.path()).await.unwrap();
    let tracks = db.collection::<Track>();
    for value in [
        track("4", "Four", "D"),
        track("2", "Two", "B"),
        track("3", "Three", "C"),
        track("1", "One", "A"),
    ] {
        tracks.put(value).await.unwrap();
    }

    let first = tracks
        .query()
        .filter(Track::artist.ge("B"))
        .order_by(Track::artist, OrderDirection::Descending)
        .limit(2)
        .fetch_page()
        .await
        .unwrap();
    assert_eq!(
        first
            .items()
            .iter()
            .map(|item| item.id.0.as_str())
            .collect::<Vec<_>>(),
        vec!["4", "3"]
    );
    let cursor = first.next_cursor().unwrap().clone();
    let second = tracks
        .query()
        .filter(Track::artist.ge("B"))
        .order_by(Track::artist, OrderDirection::Descending)
        .limit(2)
        .after(cursor.clone())
        .fetch_page()
        .await
        .unwrap();
    assert_eq!(
        second
            .items()
            .iter()
            .map(|item| item.id.0.as_str())
            .collect::<Vec<_>>(),
        vec!["2"]
    );

    let wrong_query = tracks
        .query()
        .filter(Track::artist.gt("B"))
        .after(cursor)
        .fetch_page()
        .await;
    assert!(matches!(wrong_query, Err(DbError::InvalidCursor(_))));

    let mut tampered = first.next_cursor().unwrap().as_bytes().to_vec();
    *tampered.last_mut().unwrap() ^= 1;
    let result = tracks
        .query()
        .filter(Track::artist.ge("B"))
        .order_by(Track::artist, OrderDirection::Descending)
        .after(Cursor::from_bytes(tampered))
        .fetch_page()
        .await;
    assert!(matches!(result, Err(DbError::InvalidCursor(_))));

    drop(tracks);
    db.close().await.unwrap();
}
