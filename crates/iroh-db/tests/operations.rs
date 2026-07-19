use iroh_db::{
    AuthorId, BackupOptions, Dot, IrohDb, IrohRecord, Lww, VersionVector, backup_closed,
    restore_backup,
};

#[derive(Debug, Clone, PartialEq, Eq, IrohRecord)]
#[iroh_db(collection = "operations-notes", version = 1)]
struct Note {
    #[iroh_db(id, field_id = 1)]
    id: String,
    #[iroh_db(field_id = 2)]
    text: Lww<String>,
}

fn note(author: AuthorId) -> Note {
    let mut text = Lww::new();
    text.assign(
        "survives".into(),
        Dot::new(author, 0, 0),
        VersionVector::new(),
    )
    .unwrap();
    Note {
        id: "backup".into(),
        text,
    }
}

#[tokio::test]
async fn verify_repair_backup_and_restore_preserve_state_root() {
    let source = tempfile::tempdir().unwrap();
    let backup_parent = tempfile::tempdir().unwrap();
    let restore_parent = tempfile::tempdir().unwrap();
    let backup = backup_parent.path().join("backup");
    let restored = restore_parent.path().join("restored");
    let database = IrohDb::open(source.path()).await.unwrap();
    let notes = database.collection::<Note>();
    notes.put(note(database.author_id())).await.unwrap();
    let before = database.verify().await.unwrap();
    assert!(before.derived_consistent());
    let repaired = database.repair().await.unwrap();
    assert_eq!(repaired.state_root(), before.state_root());
    drop(notes);
    database.close().await.unwrap();

    let backup_report =
        backup_closed(source.path(), &backup, BackupOptions { include_keys: true }).unwrap();
    assert!(backup_report.files() > 3);
    restore_backup(&backup, &restored).unwrap();
    let restored_database = IrohDb::open(&restored).await.unwrap();
    let restored_notes = restored_database.collection::<Note>();
    assert!(
        restored_notes
            .get(&"backup".to_owned())
            .await
            .unwrap()
            .is_some()
    );
    let after = restored_database.verify().await.unwrap();
    assert_eq!(after.state_root(), before.state_root());
    drop(restored_notes);
    restored_database.close().await.unwrap();
}

#[test]
fn restore_rejects_tampered_backup_before_creating_destination() {
    let source = tempfile::tempdir().unwrap();
    std::fs::write(source.path().join("FORMAT"), "iroh-db 1.0\n").unwrap();
    std::fs::create_dir(source.path().join("locks")).unwrap();
    std::fs::write(source.path().join("locks/writer.lock"), b"").unwrap();
    std::fs::write(source.path().join("payload"), b"original").unwrap();
    let parent = tempfile::tempdir().unwrap();
    let backup = parent.path().join("backup");
    let restored = parent.path().join("restored");
    backup_closed(source.path(), &backup, BackupOptions::default()).unwrap();
    std::fs::write(backup.join("payload"), b"tampered").unwrap();
    assert!(restore_backup(&backup, &restored).is_err());
    assert!(!restored.exists());
}
