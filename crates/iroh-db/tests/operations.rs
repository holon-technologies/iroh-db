use iroh_db::{
    AuthorId, BackupOptions, ConsistencyMode, DomainId, Dot, IrohDb, IrohRecord, Lww, Permission,
    PermissionSet, VersionVector, backup_closed, restore_backup,
};
use redb::{ReadableTable as _, TableDefinition};

const RECORDS: TableDefinition<'static, &[u8], &[u8]> = TableDefinition::new("records_v1");
const SNAPSHOT_COVERAGE: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("snapshot_coverage_v1");
const SNAPSHOT_BASELINES: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("snapshot_baselines_v1");

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

fn corrupt_first_record(path: &std::path::Path) {
    let database = redb::Database::create(path.join("meta-v6.redb")).unwrap();
    let write = database.begin_write().unwrap();
    {
        let mut records = write.open_table(RECORDS).unwrap();
        let key = records
            .iter()
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .0
            .value()
            .to_vec();
        let corrupted = Note {
            id: "base".into(),
            text: note(AuthorId::from_bytes([199; 32])).text,
        }
        .encode_record()
        .unwrap();
        records
            .insert(key.as_slice(), corrupted.as_slice())
            .unwrap();
    }
    write.commit().unwrap();
}

fn mutate_snapshot_metadata(path: &std::path::Path, domain_id: DomainId, remove_baseline: bool) {
    let database = redb::Database::create(path.join("meta-v6.redb")).unwrap();
    let write = database.begin_write().unwrap();
    if remove_baseline {
        write
            .open_table(SNAPSHOT_COVERAGE)
            .unwrap()
            .remove([201; 32].as_slice())
            .unwrap();
        write
            .open_table(SNAPSHOT_BASELINES)
            .unwrap()
            .remove(domain_id.as_bytes().as_slice())
            .unwrap();
    } else {
        write
            .open_table(SNAPSHOT_COVERAGE)
            .unwrap()
            .insert([201; 32].as_slice(), domain_id.as_bytes().as_slice())
            .unwrap();
    }
    write.commit().unwrap();
}

async fn assert_snapshot_verification_fails(path: &std::path::Path, domain_id: DomainId) {
    let device = IrohDb::open(path).await.unwrap();
    let domain = device.domain(domain_id).unwrap();
    domain.collection::<Note>();
    assert!(domain.verify().await.is_err());
    drop(domain);
    device.close().await.unwrap();
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
    std::fs::write(source.path().join("FORMAT"), "iroh-db 4.0\n").unwrap();
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

#[tokio::test]
async fn verify_and_repair_reconstruct_snapshot_baseline_plus_tail() {
    let source_dir = tempfile::tempdir().unwrap();
    let target_dir = tempfile::tempdir().unwrap();
    let source_device = IrohDb::open(source_dir.path()).await.unwrap();
    let target_device = IrohDb::open(target_dir.path()).await.unwrap();
    let source = source_device
        .create_domain(ConsistencyMode::MultiWriter)
        .unwrap();
    let invitation = source
        .invite(
            target_device.author_id(),
            PermissionSet::from_permissions(&[Permission::Read, Permission::FetchBlobs]),
            PermissionSet::empty(),
            None,
        )
        .unwrap();
    let target = target_device.import_invitation(&invitation).unwrap();
    let domain_id = invitation.descriptor().domain_id();
    let source_notes = source.collection::<Note>();
    let target_notes = target.collection::<Note>();
    source_notes
        .put(Note {
            id: "base".into(),
            text: note(source.author_id()).text,
        })
        .await
        .unwrap();
    let snapshot = source.snapshot().await.unwrap();
    let source_node = source.start_sync().await.unwrap();
    let target_node = target.start_sync().await.unwrap();
    target_node
        .bootstrap_from(source_node.addr(), snapshot)
        .await
        .unwrap();
    source_notes
        .put(Note {
            id: "tail".into(),
            text: note(source.author_id()).text,
        })
        .await
        .unwrap();
    target_node.sync_with(source_node.addr()).await.unwrap();
    let expected_root = source.state_root().unwrap();
    source_node.shutdown().await.unwrap();
    target_node.shutdown().await.unwrap();
    drop(source_notes);
    drop(target_notes);
    drop(source);
    drop(target);
    source_device.close().await.unwrap();
    target_device.close().await.unwrap();

    corrupt_first_record(target_dir.path());

    let reopened_device = IrohDb::open(target_dir.path()).await.unwrap();
    let reopened = reopened_device.domain(domain_id).unwrap();
    let reopened_notes = reopened.collection::<Note>();
    let verification = reopened.verify().await.unwrap();
    assert!(!verification.derived_consistent());
    let repaired = reopened.repair().await.unwrap();
    assert!(repaired.derived_consistent());
    assert_eq!(repaired.state_root(), expected_root);
    assert!(
        reopened_notes
            .get(&"base".to_owned())
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        reopened_notes
            .get(&"tail".to_owned())
            .await
            .unwrap()
            .is_some()
    );
    drop(reopened_notes);
    drop(reopened);
    reopened_device.close().await.unwrap();

    mutate_snapshot_metadata(target_dir.path(), domain_id, false);
    assert_snapshot_verification_fails(target_dir.path(), domain_id).await;
    mutate_snapshot_metadata(target_dir.path(), domain_id, true);
    assert_snapshot_verification_fails(target_dir.path(), domain_id).await;
}
