use iroh_db::{
    AuthorId, ConsistencyMode, DbError, Dot, IrohDb, IrohRecord, Lww, Permission, PermissionSet,
    VersionVector,
};

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

#[tokio::test]
async fn controlled_domain_requires_explicit_snapshot_permission() {
    let owner_directory = tempfile::tempdir().unwrap();
    let member_directory = tempfile::tempdir().unwrap();
    let owner_device = IrohDb::open(owner_directory.path()).await.unwrap();
    let member_device = IrohDb::open(member_directory.path()).await.unwrap();
    let owner = owner_device
        .create_domain(ConsistencyMode::MultiWriter)
        .unwrap();
    let invitation = owner
        .invite(
            member_device.author_id(),
            PermissionSet::from_permissions(&[Permission::Read, Permission::Write]),
            PermissionSet::empty(),
            None,
        )
        .unwrap();
    let member = member_device.import_invitation(&invitation).unwrap();

    assert!(matches!(
        member.snapshot().await,
        Err(DbError::UnauthorizedDevice)
    ));
    assert!(owner.snapshot().await.is_ok());

    drop(owner);
    drop(member);
    owner_device.close().await.unwrap();
    member_device.close().await.unwrap();
}

#[tokio::test]
async fn snapshot_captured_before_control_rotation_is_rejected_atomically() {
    let directory = tempfile::tempdir().unwrap();
    let device = IrohDb::open(directory.path()).await.unwrap();
    let domain = device.create_domain(ConsistencyMode::MultiWriter).unwrap();
    domain
        .collection::<Note>()
        .put(note("base", "snapshotted", 0))
        .await
        .unwrap();
    let snapshot = domain.snapshot().await.unwrap();
    let (rotated, _) = domain.rotate_epoch(&[]).unwrap();
    rotated
        .collection::<Note>()
        .put(note("tail", "must survive", 1))
        .await
        .unwrap();
    let active_root = rotated.state_root().unwrap();

    assert!(matches!(
        domain.install_snapshot(snapshot).await,
        Err(DbError::InvalidSnapshot(_) | DbError::StaleEpoch { .. })
    ));
    assert_eq!(rotated.state_root().unwrap(), active_root);
    assert!(
        rotated
            .collection::<Note>()
            .get(&"tail".to_owned())
            .await
            .unwrap()
            .is_some()
    );

    drop(domain);
    drop(rotated);
    device.close().await.unwrap();
}

#[tokio::test]
async fn snapshot_bound_to_replaced_capability_is_rejected_atomically() {
    let directory = tempfile::tempdir().unwrap();
    let device = IrohDb::open(directory.path()).await.unwrap();
    let domain = device.create_domain(ConsistencyMode::MultiWriter).unwrap();
    let notes = domain.collection::<Note>();
    notes.put(note("base", "snapshotted", 0)).await.unwrap();
    let snapshot = domain.snapshot().await.unwrap();
    notes.put(note("tail", "must survive", 1)).await.unwrap();
    let active_root = domain.state_root().unwrap();
    domain
        .issue_capability(
            domain.author_id(),
            PermissionSet::from_permissions(&[Permission::Snapshot]),
            PermissionSet::empty(),
            domain.domain_seed().epoch(),
            None,
        )
        .unwrap();

    assert!(matches!(
        domain.install_snapshot(snapshot).await,
        Err(DbError::UnauthorizedDevice)
    ));
    assert_eq!(domain.state_root().unwrap(), active_root);
    assert!(notes.get(&"tail".to_owned()).await.unwrap().is_some());

    drop(notes);
    drop(domain);
    device.close().await.unwrap();
}
