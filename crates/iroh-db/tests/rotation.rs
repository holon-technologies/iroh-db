use iroh_db::{
    AuthorId, ConsistencyMode, DbError, Dot, IrohDb, IrohRecord, Lww, Permission, PermissionSet,
    VersionVector,
};

#[derive(Debug, Clone, PartialEq, Eq, IrohRecord)]
#[iroh_db(collection = "rotation-notes", version = 1)]
struct Note {
    #[iroh_db(id, field_id = 1)]
    id: String,
    #[iroh_db(field_id = 2)]
    text: Lww<String>,
}

fn note(id: &str, text: &str, author: AuthorId) -> Note {
    let mut value = Lww::new();
    value
        .assign(text.into(), Dot::new(author, 0, 0), VersionVector::new())
        .unwrap();
    Note {
        id: id.into(),
        text: value,
    }
}

fn writer_permissions() -> PermissionSet {
    PermissionSet::from_permissions(&[Permission::Read, Permission::Write, Permission::FetchBlobs])
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn rotation_converges_remaining_member_and_surfaces_revoked_offline_write() {
    let owner_dir = tempfile::tempdir().unwrap();
    let member_dir = tempfile::tempdir().unwrap();
    let revoked_dir = tempfile::tempdir().unwrap();
    let owner_device = IrohDb::open(owner_dir.path()).await.unwrap();
    let member_device = IrohDb::open(member_dir.path()).await.unwrap();
    let revoked_device = IrohDb::open(revoked_dir.path()).await.unwrap();
    let owner = owner_device
        .create_domain(ConsistencyMode::MultiWriter)
        .unwrap();
    let member_invitation = owner
        .invite(
            member_device.author_id(),
            writer_permissions(),
            PermissionSet::empty(),
            None,
        )
        .unwrap();
    let revoked_invitation = owner
        .invite(
            revoked_device.author_id(),
            writer_permissions(),
            PermissionSet::empty(),
            None,
        )
        .unwrap();
    let member = member_device.import_invitation(&member_invitation).unwrap();
    let revoked = revoked_device
        .import_invitation(&revoked_invitation)
        .unwrap();
    let owner_notes = owner.collection::<Note>();
    let member_notes = member.collection::<Note>();
    let revoked_notes = revoked.collection::<Note>();
    owner_notes
        .put(note("before", "epoch zero", owner.author_id()))
        .await
        .unwrap();

    let owner_node = owner.start_sync().await.unwrap();
    let member_node = member.start_sync().await.unwrap();
    let revoked_node = revoked.start_sync().await.unwrap();
    member_node.sync_with(owner_node.addr()).await.unwrap();
    revoked_node.sync_with(owner_node.addr()).await.unwrap();
    owner_node.shutdown().await.unwrap();
    member_node.shutdown().await.unwrap();
    revoked_node.shutdown().await.unwrap();

    let (owner_epoch_one, control) = owner.rotate_epoch(&[revoked.author_id()]).unwrap();
    let epoch_one_invitation = owner_epoch_one
        .invite(
            member.author_id(),
            writer_permissions(),
            PermissionSet::empty(),
            None,
        )
        .unwrap();
    let member_epoch_one = member
        .apply_epoch_rotation(&control, &epoch_one_invitation.domain_seed())
        .unwrap()
        .import_invitation(&epoch_one_invitation)
        .unwrap();
    assert!(
        revoked
            .apply_epoch_rotation(&control, &epoch_one_invitation.domain_seed())
            .is_err()
    );

    revoked_notes
        .put(note("offline", "old epoch fork", revoked.author_id()))
        .await
        .unwrap();
    let offline = revoked
        .commit_envelopes()
        .await
        .unwrap()
        .into_iter()
        .find(|commit| commit.header().author() == revoked.author_id())
        .unwrap();
    assert!(matches!(
        owner_epoch_one
            .accept_remote_commit(revoked.author_id(), offline)
            .await,
        Err(DbError::RebaseRequired(_))
    ));

    let owner_epoch_one_notes = owner_epoch_one.collection::<Note>();
    let member_epoch_one_notes = member_epoch_one.collection::<Note>();
    owner_epoch_one_notes
        .put(note("after", "epoch one", owner_epoch_one.author_id()))
        .await
        .unwrap();
    let owner_node = owner_epoch_one.start_sync().await.unwrap();
    let member_node = member_epoch_one.start_sync().await.unwrap();
    member_node.sync_with(owner_node.addr()).await.unwrap();
    assert!(
        member_epoch_one_notes
            .get(&"before".to_owned())
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        member_epoch_one_notes
            .get(&"after".to_owned())
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        owner_epoch_one.state_root().unwrap(),
        member_epoch_one.state_root().unwrap()
    );

    owner_node.shutdown().await.unwrap();
    member_node.shutdown().await.unwrap();
    drop(owner_notes);
    drop(member_notes);
    drop(revoked_notes);
    drop(owner_epoch_one_notes);
    drop(member_epoch_one_notes);
    drop(owner);
    drop(member);
    drop(revoked);
    drop(owner_epoch_one);
    drop(member_epoch_one);
    owner_device.close().await.unwrap();
    member_device.close().await.unwrap();
    revoked_device.close().await.unwrap();
}
