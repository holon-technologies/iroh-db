use iroh_db::{
    AuthorId, ConsistencyMode, Dot, IrohDb, IrohRecord, Lww, Permission, PermissionSet,
    VersionVector,
};

#[derive(Debug, Clone, PartialEq, Eq, IrohRecord)]
#[iroh_db(collection = "shared-capability-notes", version = 1)]
struct Note {
    #[iroh_db(id, field_id = 1)]
    id: String,
    #[iroh_db(field_id = 2)]
    text: Lww<String>,
}

fn note(id: &str, text: &str, author: AuthorId) -> Note {
    let mut field = Lww::new();
    field
        .assign(text.into(), Dot::new(author, 0, 0), VersionVector::new())
        .unwrap();
    Note {
        id: id.into(),
        text: field,
    }
}

#[tokio::test]
async fn targeted_capability_invitation_enables_least_privilege_sync() {
    let owner_dir = tempfile::tempdir().unwrap();
    let member_dir = tempfile::tempdir().unwrap();
    let owner_device = IrohDb::open(owner_dir.path()).await.unwrap();
    let member_device = IrohDb::open(member_dir.path()).await.unwrap();
    let owner = owner_device
        .create_domain(ConsistencyMode::MultiWriter)
        .unwrap();
    let read_write = PermissionSet::from_permissions(&[
        Permission::Read,
        Permission::Write,
        Permission::FetchBlobs,
    ]);
    let invitation = owner
        .invite(
            member_device.author_id(),
            read_write,
            PermissionSet::empty(),
            None,
        )
        .unwrap();
    let member = member_device.import_invitation(&invitation).unwrap();
    let owner_notes = owner.collection::<Note>();
    let member_notes = member.collection::<Note>();
    owner_notes
        .put(note("owner", "first", owner.author_id()))
        .await
        .unwrap();

    let owner_node = owner.start_sync().await.unwrap();
    let member_node = member.start_sync().await.unwrap();
    member_node.sync_with(owner_node.addr()).await.unwrap();
    member_notes
        .put(note("member", "second", member.author_id()))
        .await
        .unwrap();
    owner_node.sync_with(member_node.addr()).await.unwrap();

    assert_eq!(owner.state_root().unwrap(), member.state_root().unwrap());
    assert!(
        owner_notes
            .get(&"member".to_owned())
            .await
            .unwrap()
            .is_some()
    );

    owner_node.shutdown().await.unwrap();
    member_node.shutdown().await.unwrap();
    drop(owner_notes);
    drop(member_notes);
    drop(owner);
    drop(member);
    owner_device.close().await.unwrap();
    member_device.close().await.unwrap();
}

#[tokio::test]
async fn read_only_offline_ticket_import_cannot_author_commits() {
    let owner_dir = tempfile::tempdir().unwrap();
    let reader_dir = tempfile::tempdir().unwrap();
    let owner_device = IrohDb::open(owner_dir.path()).await.unwrap();
    let reader_device = IrohDb::open(reader_dir.path()).await.unwrap();
    let owner = owner_device
        .create_domain(ConsistencyMode::MultiWriter)
        .unwrap();
    let invitation = owner
        .invite(
            reader_device.author_id(),
            PermissionSet::from_permissions(&[Permission::Read, Permission::FetchBlobs]),
            PermissionSet::empty(),
            None,
        )
        .unwrap();
    let (ticket, secret) = invitation.seal_offline().unwrap();
    let reader = reader_device.import_ticket(&ticket, &secret).unwrap();
    assert!(reader_device.import_ticket(&ticket, &secret).is_err());

    assert!(
        reader
            .collection::<Note>()
            .put(note("blocked", "write", reader.author_id()))
            .await
            .is_err()
    );
    assert!(reader.commit_envelopes().await.unwrap().is_empty());

    drop(owner);
    drop(reader);
    owner_device.close().await.unwrap();
    reader_device.close().await.unwrap();
}

#[tokio::test]
async fn online_invitation_is_released_only_to_its_authenticated_subject() {
    let owner_dir = tempfile::tempdir().unwrap();
    let member_dir = tempfile::tempdir().unwrap();
    let attacker_dir = tempfile::tempdir().unwrap();
    let owner_device = IrohDb::open(owner_dir.path()).await.unwrap();
    let member_device = IrohDb::open(member_dir.path()).await.unwrap();
    let attacker_device = IrohDb::open(attacker_dir.path()).await.unwrap();
    let owner = owner_device
        .create_domain(ConsistencyMode::MultiWriter)
        .unwrap();
    let invitation = owner
        .invite(
            member_device.author_id(),
            PermissionSet::from_permissions(&[
                Permission::Read,
                Permission::Write,
                Permission::FetchBlobs,
            ]),
            PermissionSet::empty(),
            None,
        )
        .unwrap();

    let owner_node = owner.start_sync().await.unwrap();
    owner_node.offer_invitation(&invitation).unwrap();
    let attacker_node = attacker_device.start_sync().await.unwrap();
    assert!(
        attacker_node
            .request_invitation(owner_node.addr())
            .await
            .is_err()
    );
    attacker_node.shutdown().await.unwrap();

    let member_bootstrap_node = member_device.start_sync().await.unwrap();
    let member = member_bootstrap_node
        .request_invitation(owner_node.addr())
        .await
        .unwrap();
    member_bootstrap_node.shutdown().await.unwrap();
    let member_node = member.start_sync().await.unwrap();
    let owner_notes = owner.collection::<Note>();
    let member_notes = member.collection::<Note>();

    owner_notes
        .put(note("online", "delivered", owner.author_id()))
        .await
        .unwrap();
    member_node.sync_with(owner_node.addr()).await.unwrap();
    assert!(
        member_notes
            .get(&"online".to_owned())
            .await
            .unwrap()
            .is_some()
    );

    owner_node.shutdown().await.unwrap();
    member_node.shutdown().await.unwrap();
    drop(owner_notes);
    drop(member_notes);
    drop(owner);
    drop(member);
    owner_device.close().await.unwrap();
    member_device.close().await.unwrap();
    attacker_device.close().await.unwrap();
}
