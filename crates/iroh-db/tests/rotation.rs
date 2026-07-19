use iroh_db::{
    AuthorId, ConsistencyMode, DbError, Dot, IrohDb, IrohRecord, Lww, Permission, PermissionSet,
    VersionVector,
};

fn copy_directory(source: &std::path::Path, destination: &std::path::Path) {
    for entry in std::fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            std::fs::create_dir_all(&target).unwrap();
            copy_directory(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

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
    assert_eq!(
        epoch_one_invitation
            .capability_chain()
            .last()
            .unwrap()
            .issued_control_sequence(),
        1
    );
    assert_eq!(
        epoch_one_invitation
            .capability_chain()
            .last()
            .unwrap()
            .issued_control_head(),
        Some(control.id().unwrap())
    );
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

#[tokio::test]
async fn cloned_controller_equivocation_freezes_facade_writes() {
    let original_dir = tempfile::tempdir().unwrap();
    let left_dir = tempfile::tempdir().unwrap();
    let right_dir = tempfile::tempdir().unwrap();
    let invitee_dir = tempfile::tempdir().unwrap();
    let original_device = IrohDb::open(original_dir.path()).await.unwrap();
    let invitee_device = IrohDb::open(invitee_dir.path()).await.unwrap();
    let original = original_device
        .create_domain(ConsistencyMode::MultiWriter)
        .unwrap();
    let pending_invitation = original
        .invite(
            invitee_device.author_id(),
            PermissionSet::from_permissions(&[Permission::Read]),
            PermissionSet::empty(),
            None,
        )
        .unwrap();
    let domain_id = original.domain_id();
    drop(original);
    original_device.close().await.unwrap();
    copy_directory(original_dir.path(), left_dir.path());
    copy_directory(original_dir.path(), right_dir.path());

    let left_device = IrohDb::open(left_dir.path()).await.unwrap();
    let right_device = IrohDb::open(right_dir.path()).await.unwrap();
    let left = left_device.domain(domain_id).unwrap();
    let right = right_device.domain(domain_id).unwrap();
    let queued_node = left.start_sync().await.unwrap();
    queued_node.offer_invitation(&pending_invitation).unwrap();
    let (left_epoch_one, left_control) = left.rotate_epoch(&[]).unwrap();
    let (right_epoch_one, right_control) = right.rotate_epoch(&[]).unwrap();
    let left_seed = left_epoch_one.domain_seed();
    let right_seed = right_epoch_one.domain_seed();

    assert!(matches!(
        left_epoch_one.apply_epoch_rotation(&right_control, &right_seed),
        Err(DbError::Store(_))
    ));
    assert!(matches!(
        right_epoch_one.apply_epoch_rotation(&left_control, &left_seed),
        Err(DbError::Store(_))
    ));
    assert!(matches!(
        left_epoch_one
            .collection::<Note>()
            .put(note("blocked", "forked", left_epoch_one.author_id()))
            .await,
        Err(DbError::Store(_))
    ));
    assert!(matches!(
        right_epoch_one
            .collection::<Note>()
            .put(note("blocked", "forked", right_epoch_one.author_id()))
            .await,
        Err(DbError::Store(_))
    ));
    assert!(matches!(
        left_epoch_one.issue_capability(
            AuthorId::from_bytes([77; 32]),
            PermissionSet::from_permissions(&[Permission::Read]),
            PermissionSet::empty(),
            1,
            None,
        ),
        Err(DbError::Store(_))
    ));
    let frozen_node = left_epoch_one.start_sync().await.unwrap();
    assert!(matches!(
        frozen_node.offer_invitation(&pending_invitation),
        Err(DbError::Store(_))
    ));
    let requester_node = invitee_device.start_sync().await.unwrap();
    assert!(
        requester_node
            .request_invitation(queued_node.addr())
            .await
            .is_err()
    );
    requester_node.shutdown().await.unwrap();
    queued_node.shutdown().await.unwrap();
    frozen_node.shutdown().await.unwrap();

    drop(left);
    drop(right);
    drop(left_epoch_one);
    drop(right_epoch_one);
    left_device.close().await.unwrap();
    right_device.close().await.unwrap();
    invitee_device.close().await.unwrap();
}

#[tokio::test]
async fn controller_transfer_authorizes_only_the_successor() {
    let owner_dir = tempfile::tempdir().unwrap();
    let successor_dir = tempfile::tempdir().unwrap();
    let owner_device = IrohDb::open(owner_dir.path()).await.unwrap();
    let successor_device = IrohDb::open(successor_dir.path()).await.unwrap();
    let owner = owner_device
        .create_domain(ConsistencyMode::MultiWriter)
        .unwrap();
    let invitation = owner
        .invite(
            successor_device.author_id(),
            PermissionSet::from_permissions(&[
                Permission::Read,
                Permission::Write,
                Permission::Revoke,
                Permission::FetchBlobs,
                Permission::Admin,
            ]),
            PermissionSet::empty(),
            None,
        )
        .unwrap();
    let successor = successor_device.import_invitation(&invitation).unwrap();
    let (owner_epoch_one, transfer) = owner
        .rotate_epoch_with_controller(&[], successor.author_id())
        .unwrap();
    let successor_epoch_one = successor
        .apply_epoch_rotation(&transfer, &owner_epoch_one.domain_seed())
        .unwrap();

    assert!(matches!(
        owner_epoch_one.rotate_epoch(&[]),
        Err(DbError::UnauthorizedDevice)
    ));
    let (successor_epoch_two, _) = successor_epoch_one.rotate_epoch(&[]).unwrap();
    assert_eq!(successor_epoch_two.domain_seed().epoch(), 2);

    drop(owner);
    drop(successor);
    drop(owner_epoch_one);
    drop(successor_epoch_one);
    drop(successor_epoch_two);
    owner_device.close().await.unwrap();
    successor_device.close().await.unwrap();
}
