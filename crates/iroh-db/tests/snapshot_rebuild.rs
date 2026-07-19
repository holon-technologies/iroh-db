use iroh_db::{AuthorId, Dot, IrohDb, IrohRecord, Lww, VersionVector};

#[derive(Debug, Clone, PartialEq, Eq, IrohRecord)]
#[iroh_db(collection = "notes", version = 1)]
struct Note {
    #[iroh_db(id, field_id = 1)]
    id: String,
    #[iroh_db(field_id = 2, index)]
    text: Lww<String>,
}

fn note(id: &str, text: &str, operation: u32) -> Note {
    let mut value = Lww::new();
    value
        .assign(
            text.to_owned(),
            Dot::new(AuthorId::from_bytes([8; 32]), 0, operation),
            VersionVector::new(),
        )
        .unwrap();
    Note {
        id: id.into(),
        text: value,
    }
}

#[tokio::test]
async fn snapshot_install_and_full_commit_rebuild_are_equivalent() {
    let directory = tempfile::tempdir().unwrap();
    let db = IrohDb::open(directory.path()).await.unwrap();
    let notes = db.collection::<Note>();
    notes.put(note("one", "offline", 0)).await.unwrap();
    let snapshot = db.snapshot().await.unwrap();
    let snapshot_root = db.state_root().unwrap();
    assert_eq!(snapshot.state_root(), snapshot_root);

    notes.put(note("two", "rebuildable", 1)).await.unwrap();
    let full_root = db.state_root().unwrap();
    assert_ne!(full_root, snapshot_root);
    assert_eq!(notes.query().fetch().await.unwrap().len(), 2);

    db.install_snapshot(snapshot).await.unwrap();
    assert_eq!(notes.query().fetch().await.unwrap().len(), 1);
    assert_eq!(db.state_root().unwrap(), snapshot_root);

    assert_eq!(db.rebuild().await.unwrap(), full_root);
    assert_eq!(notes.query().fetch().await.unwrap().len(), 2);

    drop(notes);
    db.close().await.unwrap();
}

#[tokio::test]
async fn rejected_snapshot_does_not_mutate_active_state() {
    let first_directory = tempfile::tempdir().unwrap();
    let second_directory = tempfile::tempdir().unwrap();
    let first = IrohDb::open(first_directory.path()).await.unwrap();
    let second = IrohDb::open(second_directory.path()).await.unwrap();
    first
        .collection::<Note>()
        .put(note("one", "preserved", 0))
        .await
        .unwrap();
    second
        .collection::<Note>()
        .put(note("other", "foreign", 0))
        .await
        .unwrap();
    let foreign = second.snapshot().await.unwrap();
    let root = first.state_root().unwrap();

    assert!(first.install_snapshot(foreign).await.is_err());
    assert_eq!(first.state_root().unwrap(), root);
    assert_eq!(
        first
            .collection::<Note>()
            .query()
            .fetch()
            .await
            .unwrap()
            .len(),
        1
    );

    first.close().await.unwrap();
    second.close().await.unwrap();
}
