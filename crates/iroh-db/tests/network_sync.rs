use iroh_db::{
    AuthorId, ConsistencyMode, DomainSeed, Dot, IrohDb, IrohRecord, Lww, Permission, PermissionSet,
    VersionVector,
};

#[derive(Debug, Clone, PartialEq, Eq, IrohRecord)]
#[iroh_db(collection = "network-notes", version = 1)]
struct Note {
    #[iroh_db(id, field_id = 1)]
    id: String,
    #[iroh_db(field_id = 2, index)]
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

#[tokio::test]
async fn one_real_iroh_session_reconciles_both_offline_peers_via_blobs() {
    let seed = DomainSeed::generate().unwrap();
    let left_dir = tempfile::tempdir().unwrap();
    let right_dir = tempfile::tempdir().unwrap();
    let left = IrohDb::create_in_domain(left_dir.path(), &seed)
        .await
        .unwrap();
    let right = IrohDb::create_in_domain(right_dir.path(), &seed)
        .await
        .unwrap();
    left.trust_device(right.author_id()).unwrap();
    right.trust_device(left.author_id()).unwrap();
    let left_notes = left.collection::<Note>();
    let right_notes = right.collection::<Note>();
    left_notes
        .put(note("same", "left", left.author_id()))
        .await
        .unwrap();
    right_notes
        .put(note("same", "right", right.author_id()))
        .await
        .unwrap();

    let left_node = left.start_sync().await.unwrap();
    let right_node = right.start_sync().await.unwrap();
    let report = left_node.sync_with(right_node.addr()).await.unwrap();
    assert_eq!(report.received(), 1);
    assert_eq!(report.sent(), 1);
    assert_eq!(left.state_root().unwrap(), right.state_root().unwrap());
    assert_eq!(
        left_notes.get(&"same".to_owned()).await.unwrap(),
        right_notes.get(&"same".to_owned()).await.unwrap()
    );

    left_node.shutdown().await.unwrap();
    right_node.shutdown().await.unwrap();
    drop(left_notes);
    drop(right_notes);
    left.close().await.unwrap();
    right.close().await.unwrap();
}

#[tokio::test]
async fn valid_gossip_hint_triggers_ordinary_authenticated_sync() {
    let seed = DomainSeed::generate().unwrap();
    let left_dir = tempfile::tempdir().unwrap();
    let right_dir = tempfile::tempdir().unwrap();
    let left = IrohDb::create_in_domain(left_dir.path(), &seed)
        .await
        .unwrap();
    let right = IrohDb::create_in_domain(right_dir.path(), &seed)
        .await
        .unwrap();
    left.trust_device(right.author_id()).unwrap();
    right.trust_device(left.author_id()).unwrap();
    let left_notes = left.collection::<Note>();
    let right_notes = right.collection::<Note>();
    left_notes
        .put(note("announced", "available", left.author_id()))
        .await
        .unwrap();

    let left_node = left.start_sync().await.unwrap();
    let right_node = right.start_sync().await.unwrap();
    let left_gossip = left_node.join_gossip(Vec::new()).await.unwrap();
    let mut right_gossip = right_node
        .join_gossip(vec![left_node.addr()])
        .await
        .unwrap();
    left_gossip.announce().await.unwrap();
    let report = tokio::time::timeout(std::time::Duration::from_secs(10), right_gossip.sync_next())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(report.received(), 1);
    assert!(
        right_notes
            .get(&"announced".to_owned())
            .await
            .unwrap()
            .is_some()
    );

    drop(left_gossip);
    drop(right_gossip);
    left_node.shutdown().await.unwrap();
    right_node.shutdown().await.unwrap();
    drop(left_notes);
    drop(right_notes);
    left.close().await.unwrap();
    right.close().await.unwrap();
}

#[tokio::test]
async fn encrypted_snapshot_bootstrap_fetches_only_the_commit_tail() {
    let seed = DomainSeed::generate().unwrap();
    let source_dir = tempfile::tempdir().unwrap();
    let target_dir = tempfile::tempdir().unwrap();
    let source = IrohDb::create_in_domain(source_dir.path(), &seed)
        .await
        .unwrap();
    let target = IrohDb::create_in_domain(target_dir.path(), &seed)
        .await
        .unwrap();
    source.trust_device(target.author_id()).unwrap();
    target.trust_device(source.author_id()).unwrap();
    let source_notes = source.collection::<Note>();
    let target_notes = target.collection::<Note>();
    for index in 0..3 {
        source_notes
            .put(note(
                &format!("base-{index}"),
                "snapshotted",
                source.author_id(),
            ))
            .await
            .unwrap();
    }
    let snapshot = source.snapshot().await.unwrap();
    source_notes
        .put(note("tail", "recent", source.author_id()))
        .await
        .unwrap();

    let source_node = source.start_sync().await.unwrap();
    let target_node = target.start_sync().await.unwrap();
    target_node
        .bootstrap_from(source_node.addr(), snapshot)
        .await
        .unwrap();
    assert_eq!(target.state_root().unwrap(), snapshot.state_root());

    let report = target_node.sync_with(source_node.addr()).await.unwrap();
    assert_eq!(report.received(), 1);
    assert_eq!(target.state_root().unwrap(), source.state_root().unwrap());
    assert!(
        target_notes
            .get(&"tail".to_owned())
            .await
            .unwrap()
            .is_some()
    );

    source_node.shutdown().await.unwrap();
    target_node.shutdown().await.unwrap();
    drop(source_notes);
    drop(target_notes);
    source.close().await.unwrap();
    target.close().await.unwrap();
}

#[tokio::test]
async fn controlled_domain_accepts_snapshot_from_explicit_authority() {
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
    source
        .collection::<Note>()
        .put(note("base", "authorized", source.author_id()))
        .await
        .unwrap();
    let snapshot = source.snapshot().await.unwrap();

    let source_node = source.start_sync().await.unwrap();
    let target_node = target.start_sync().await.unwrap();
    target_node
        .bootstrap_from(source_node.addr(), snapshot)
        .await
        .unwrap();
    assert_eq!(target.state_root().unwrap(), source.state_root().unwrap());

    source_node.shutdown().await.unwrap();
    target_node.shutdown().await.unwrap();
    drop(source);
    drop(target);
    source_device.close().await.unwrap();
    target_device.close().await.unwrap();
}

#[tokio::test]
async fn rotated_new_member_bootstraps_snapshot_tail_and_next_control_after_restart() {
    let owner_dir = tempfile::tempdir().unwrap();
    let newcomer_dir = tempfile::tempdir().unwrap();
    let owner_device = IrohDb::open(owner_dir.path()).await.unwrap();
    let newcomer_device = IrohDb::open(newcomer_dir.path()).await.unwrap();
    let owner = owner_device
        .create_domain(ConsistencyMode::MultiWriter)
        .unwrap();
    let notes = owner.collection::<Note>();
    notes
        .put(note("base", "checkpointed", owner.author_id()))
        .await
        .unwrap();
    let (epoch_one, _) = owner.rotate_epoch(&[]).unwrap();
    let snapshot = epoch_one.snapshot().await.unwrap();
    let invitation = epoch_one
        .invite(
            newcomer_device.author_id(),
            PermissionSet::from_permissions(&[
                Permission::Read,
                Permission::Write,
                Permission::FetchBlobs,
            ]),
            PermissionSet::empty(),
            None,
        )
        .unwrap();
    let newcomer = newcomer_device.import_invitation(&invitation).unwrap();
    let newcomer_notes = newcomer.collection::<Note>();
    notes
        .put(note("tail", "recent", owner.author_id()))
        .await
        .unwrap();

    let owner_node = epoch_one.start_sync().await.unwrap();
    let newcomer_node = newcomer.start_sync().await.unwrap();
    newcomer_node
        .bootstrap_from(owner_node.addr(), snapshot)
        .await
        .unwrap();
    let report = newcomer_node.sync_with(owner_node.addr()).await.unwrap();
    assert_eq!(report.received(), 1);
    assert_eq!(
        newcomer.state_root().unwrap(),
        epoch_one.state_root().unwrap()
    );
    newcomer_node.shutdown().await.unwrap();
    drop(newcomer_notes);
    drop(newcomer);
    newcomer_device.close().await.unwrap();

    let reopened_device = IrohDb::open(newcomer_dir.path()).await.unwrap();
    let reopened = reopened_device.domain(epoch_one.domain_id()).unwrap();
    let reopened_notes = reopened.collection::<Note>();
    let reopened_node = reopened.start_sync().await.unwrap();
    let (epoch_two, _) = epoch_one.rotate_epoch(&[]).unwrap();
    reopened_node.sync_with(owner_node.addr()).await.unwrap();
    assert_eq!(reopened.domain_seed().epoch(), 2);
    assert_eq!(
        reopened.state_root().unwrap(),
        epoch_two.state_root().unwrap()
    );
    assert!(reopened.verify().await.unwrap().derived_consistent());

    reopened_node.shutdown().await.unwrap();
    owner_node.shutdown().await.unwrap();
    drop(notes);
    drop(owner);
    drop(epoch_one);
    drop(epoch_two);
    drop(reopened);
    drop(reopened_notes);
    owner_device.close().await.unwrap();
    reopened_device.close().await.unwrap();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn checkpoint_verifies_snapshot_signer_with_truncated_capability_anchor() {
    let owner_dir = tempfile::tempdir().unwrap();
    let signer_dir = tempfile::tempdir().unwrap();
    let newcomer_dir = tempfile::tempdir().unwrap();
    let owner_device = IrohDb::open(owner_dir.path()).await.unwrap();
    let signer_device = IrohDb::open(signer_dir.path()).await.unwrap();
    let newcomer_device = IrohDb::open(newcomer_dir.path()).await.unwrap();
    let owner = owner_device
        .create_domain(ConsistencyMode::MultiWriter)
        .unwrap();
    let (epoch_one, _) = owner.rotate_epoch(&[]).unwrap();
    let signer_invitation = epoch_one
        .invite(
            signer_device.author_id(),
            PermissionSet::from_permissions(&[
                Permission::Read,
                Permission::Write,
                Permission::FetchBlobs,
                Permission::Snapshot,
            ]),
            PermissionSet::empty(),
            None,
        )
        .unwrap();
    assert_eq!(
        signer_invitation
            .capability_chain()
            .last()
            .unwrap()
            .issued_control_sequence(),
        1
    );
    let signer = signer_device.import_invitation(&signer_invitation).unwrap();
    let owner_node = epoch_one.start_sync().await.unwrap();
    let signer_node = signer.start_sync().await.unwrap();
    signer_node.sync_with(owner_node.addr()).await.unwrap();

    let (epoch_two, _) = epoch_one.rotate_epoch(&[]).unwrap();
    signer_node.sync_with(owner_node.addr()).await.unwrap();
    let signer_notes = signer.collection::<Note>();
    signer_notes
        .put(note(
            "checkpoint-snapshot",
            "historical-anchor",
            signer.author_id(),
        ))
        .await
        .unwrap();
    let snapshot = signer.snapshot().await.unwrap();
    signer_node.shutdown().await.unwrap();
    let signer_node = signer.start_sync().await.unwrap();
    owner_node
        .fetch_blob_from(signer_node.addr(), &snapshot.blob_ref())
        .await
        .unwrap();
    let newcomer_invitation = epoch_two
        .invite(
            newcomer_device.author_id(),
            PermissionSet::from_permissions(&[Permission::Read, Permission::FetchBlobs]),
            PermissionSet::empty(),
            None,
        )
        .unwrap();
    let newcomer = newcomer_device
        .import_invitation(&newcomer_invitation)
        .unwrap();
    let newcomer_notes = newcomer.collection::<Note>();
    let newcomer_node = newcomer.start_sync().await.unwrap();
    newcomer_node
        .bootstrap_from(owner_node.addr(), snapshot)
        .await
        .unwrap();
    assert!(newcomer.verify().await.unwrap().derived_consistent());

    newcomer_node.shutdown().await.unwrap();
    signer_node.shutdown().await.unwrap();
    owner_node.shutdown().await.unwrap();
    drop(newcomer_notes);
    drop(signer_notes);
    drop(newcomer);
    drop(signer);
    drop(owner);
    drop(epoch_one);
    drop(epoch_two);
    owner_device.close().await.unwrap();
    signer_device.close().await.unwrap();
    newcomer_device.close().await.unwrap();

    let reopened_device = IrohDb::open(newcomer_dir.path()).await.unwrap();
    let reopened = reopened_device
        .domain(newcomer_invitation.descriptor().domain_id())
        .unwrap();
    let reopened_notes = reopened.collection::<Note>();
    assert!(reopened.verify().await.unwrap().derived_consistent());
    assert!(
        reopened_notes
            .get(&"checkpoint-snapshot".to_owned())
            .await
            .unwrap()
            .is_some()
    );
    drop(reopened_notes);
    drop(reopened);
    reopened_device.close().await.unwrap();
}

#[tokio::test]
async fn rotated_checkpoint_carries_omitted_writer_evidence_for_snapshot_tail() {
    let owner_dir = tempfile::tempdir().unwrap();
    let writer_dir = tempfile::tempdir().unwrap();
    let newcomer_dir = tempfile::tempdir().unwrap();
    let owner_device = IrohDb::open(owner_dir.path()).await.unwrap();
    let writer_device = IrohDb::open(writer_dir.path()).await.unwrap();
    let newcomer_device = IrohDb::open(newcomer_dir.path()).await.unwrap();
    let owner = owner_device
        .create_domain(ConsistencyMode::MultiWriter)
        .unwrap();
    let writer_invitation = owner
        .invite(
            writer_device.author_id(),
            PermissionSet::from_permissions(&[
                Permission::Read,
                Permission::Write,
                Permission::FetchBlobs,
            ]),
            PermissionSet::empty(),
            None,
        )
        .unwrap();
    let writer = writer_device.import_invitation(&writer_invitation).unwrap();
    let owner_notes = owner.collection::<Note>();
    let writer_notes = writer.collection::<Note>();
    owner_notes
        .put(note("base", "checkpointed", owner.author_id()))
        .await
        .unwrap();
    let owner_node = owner.start_sync().await.unwrap();
    let writer_node = writer.start_sync().await.unwrap();
    writer_node.sync_with(owner_node.addr()).await.unwrap();
    let (epoch_one, _) = owner.rotate_epoch(&[]).unwrap();
    writer_node.sync_with(owner_node.addr()).await.unwrap();
    let snapshot = epoch_one.snapshot().await.unwrap();
    let newcomer_invitation = epoch_one
        .invite(
            newcomer_device.author_id(),
            PermissionSet::from_permissions(&[Permission::Read, Permission::FetchBlobs]),
            PermissionSet::empty(),
            None,
        )
        .unwrap();
    assert!(
        !newcomer_invitation
            .capability_chain()
            .iter()
            .chain(newcomer_invitation.controller_chain())
            .any(|capability| capability.subject() == writer.author_id())
    );
    assert!(
        newcomer_invitation
            .authority_evidence()
            .iter()
            .any(|capability| capability.subject() == writer.author_id())
    );
    let newcomer = newcomer_device
        .import_invitation(&newcomer_invitation)
        .unwrap();
    let newcomer_notes = newcomer.collection::<Note>();
    let newcomer_node = newcomer.start_sync().await.unwrap();
    newcomer_node
        .bootstrap_from(owner_node.addr(), snapshot)
        .await
        .unwrap();
    writer_notes
        .put(note("tail", "writer-authored", writer.author_id()))
        .await
        .unwrap();
    owner_node.sync_with(writer_node.addr()).await.unwrap();

    let report = newcomer_node.sync_with(owner_node.addr()).await.unwrap();
    assert_eq!(report.received(), 1);
    assert_eq!(newcomer.state_root().unwrap(), writer.state_root().unwrap());

    newcomer_node.shutdown().await.unwrap();
    writer_node.shutdown().await.unwrap();
    owner_node.shutdown().await.unwrap();
    drop(newcomer_notes);
    drop(writer_notes);
    drop(owner_notes);
    drop(newcomer);
    drop(writer);
    drop(owner);
    drop(epoch_one);
    owner_device.close().await.unwrap();
    writer_device.close().await.unwrap();
    newcomer_device.close().await.unwrap();
}

#[tokio::test]
async fn sync_automatically_installs_a_non_revoked_members_next_epoch() {
    let owner_dir = tempfile::tempdir().unwrap();
    let member_dir = tempfile::tempdir().unwrap();
    let owner_device = IrohDb::open(owner_dir.path()).await.unwrap();
    let member_device = IrohDb::open(member_dir.path()).await.unwrap();
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
    let member = member_device.import_invitation(&invitation).unwrap();
    let owner_node = owner.start_sync().await.unwrap();
    let member_node = member.start_sync().await.unwrap();
    member_node.sync_with(owner_node.addr()).await.unwrap();

    let (rotated_owner, _) = owner.rotate_epoch(&[]).unwrap();
    member_node.sync_with(owner_node.addr()).await.unwrap();

    assert_eq!(rotated_owner.domain_seed().epoch(), 1);
    assert_eq!(member.domain_seed().epoch(), 1);
    assert_eq!(
        rotated_owner.domain_seed().distribution_digest(),
        member.domain_seed().distribution_digest()
    );

    owner_node.shutdown().await.unwrap();
    member_node.shutdown().await.unwrap();
    drop(owner);
    drop(rotated_owner);
    drop(member);
    owner_device.close().await.unwrap();
    member_device.close().await.unwrap();
}

#[tokio::test]
async fn lagging_peer_reconciles_before_accepting_an_ahead_active_capability() {
    let owner_dir = tempfile::tempdir().unwrap();
    let member_dir = tempfile::tempdir().unwrap();
    let owner_device = IrohDb::open(owner_dir.path()).await.unwrap();
    let member_device = IrohDb::open(member_dir.path()).await.unwrap();
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
    let member = member_device.import_invitation(&invitation).unwrap();
    let owner_node = owner.start_sync().await.unwrap();
    let member_node = member.start_sync().await.unwrap();
    member_node.sync_with(owner_node.addr()).await.unwrap();

    let (rotated_owner, _) = owner.rotate_epoch(&[]).unwrap();
    let refreshed_owner = rotated_owner
        .issue_capability(
            rotated_owner.author_id(),
            PermissionSet::all(),
            PermissionSet::all(),
            1,
            None,
        )
        .unwrap();
    assert_eq!(refreshed_owner.issued_control_sequence(), 1);

    member_node.sync_with(owner_node.addr()).await.unwrap();
    assert_eq!(member.domain_seed().epoch(), 1);

    owner_node.shutdown().await.unwrap();
    member_node.shutdown().await.unwrap();
    drop(owner);
    drop(rotated_owner);
    drop(member);
    owner_device.close().await.unwrap();
    member_device.close().await.unwrap();
}

#[tokio::test]
async fn sync_catches_up_multiple_epochs_at_their_causal_cuts() {
    let owner_dir = tempfile::tempdir().unwrap();
    let member_dir = tempfile::tempdir().unwrap();
    let owner_device = IrohDb::open(owner_dir.path()).await.unwrap();
    let member_device = IrohDb::open(member_dir.path()).await.unwrap();
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
    let member = member_device.import_invitation(&invitation).unwrap();
    let owner_notes = owner.collection::<Note>();
    let member_notes = member.collection::<Note>();
    let owner_node = owner.start_sync().await.unwrap();
    let member_node = member.start_sync().await.unwrap();
    member_node.sync_with(owner_node.addr()).await.unwrap();

    let (epoch_one, _) = owner.rotate_epoch(&[]).unwrap();
    owner_notes
        .put(note("between", "epoch one", owner.author_id()))
        .await
        .unwrap();
    let (epoch_two, _) = epoch_one.rotate_epoch(&[]).unwrap();
    member_node.sync_with(owner_node.addr()).await.unwrap();

    assert_eq!(member.domain_seed().epoch(), 2);
    assert_eq!(epoch_two.domain_seed().epoch(), 2);
    assert!(
        member_notes
            .get(&"between".to_owned())
            .await
            .unwrap()
            .is_some()
    );

    owner_node.shutdown().await.unwrap();
    member_node.shutdown().await.unwrap();
    drop(owner_notes);
    drop(member_notes);
    drop(owner);
    drop(epoch_one);
    drop(epoch_two);
    drop(member);
    owner_device.close().await.unwrap();
    member_device.close().await.unwrap();
}

#[tokio::test]
async fn sync_never_delivers_a_rotated_key_to_a_revoked_member() {
    let owner_dir = tempfile::tempdir().unwrap();
    let member_dir = tempfile::tempdir().unwrap();
    let owner_device = IrohDb::open(owner_dir.path()).await.unwrap();
    let member_device = IrohDb::open(member_dir.path()).await.unwrap();
    let owner = owner_device
        .create_domain(ConsistencyMode::MultiWriter)
        .unwrap();
    let invitation = owner
        .invite(
            member_device.author_id(),
            PermissionSet::from_permissions(&[Permission::Read, Permission::FetchBlobs]),
            PermissionSet::empty(),
            None,
        )
        .unwrap();
    let member = member_device.import_invitation(&invitation).unwrap();
    let owner_node = owner.start_sync().await.unwrap();
    let member_node = member.start_sync().await.unwrap();
    member_node.sync_with(owner_node.addr()).await.unwrap();

    let (rotated, _) = owner.rotate_epoch(&[member.author_id()]).unwrap();
    assert!(member_node.sync_with(owner_node.addr()).await.is_err());
    assert_eq!(member.domain_seed().epoch(), 0);

    owner_node.shutdown().await.unwrap();
    member_node.shutdown().await.unwrap();
    drop(owner);
    drop(rotated);
    drop(member);
    owner_device.close().await.unwrap();
    member_device.close().await.unwrap();
}

#[tokio::test]
async fn controller_transfer_propagates_authority_for_peer_mesh_sync() {
    let owner_dir = tempfile::tempdir().unwrap();
    let successor_dir = tempfile::tempdir().unwrap();
    let observer_dir = tempfile::tempdir().unwrap();
    let owner_device = IrohDb::open(owner_dir.path()).await.unwrap();
    let successor_device = IrohDb::open(successor_dir.path()).await.unwrap();
    let observer_device = IrohDb::open(observer_dir.path()).await.unwrap();
    let owner = owner_device
        .create_domain(ConsistencyMode::MultiWriter)
        .unwrap();
    let successor_invitation = owner
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
    let observer_invitation = owner
        .invite(
            observer_device.author_id(),
            PermissionSet::from_permissions(&[Permission::Read, Permission::FetchBlobs]),
            PermissionSet::empty(),
            None,
        )
        .unwrap();
    let successor = successor_device
        .import_invitation(&successor_invitation)
        .unwrap();
    let observer = observer_device
        .import_invitation(&observer_invitation)
        .unwrap();
    let owner_node = owner.start_sync().await.unwrap();
    let successor_node = successor.start_sync().await.unwrap();
    let observer_node = observer.start_sync().await.unwrap();

    let (owner_epoch_one, _) = owner
        .rotate_epoch_with_controller(&[], successor.author_id())
        .unwrap();
    successor_node.sync_with(owner_node.addr()).await.unwrap();
    observer_node.sync_with(owner_node.addr()).await.unwrap();
    let (successor_epoch_two, _) = successor.rotate_epoch(&[]).unwrap();
    observer_node
        .sync_with(successor_node.addr())
        .await
        .unwrap();

    assert_eq!(observer.domain_seed().epoch(), 2);
    assert_eq!(successor_epoch_two.domain_seed().epoch(), 2);

    owner_node.shutdown().await.unwrap();
    successor_node.shutdown().await.unwrap();
    observer_node.shutdown().await.unwrap();
    drop(owner);
    drop(owner_epoch_one);
    drop(successor);
    drop(successor_epoch_two);
    drop(observer);
    owner_device.close().await.unwrap();
    successor_device.close().await.unwrap();
    observer_device.close().await.unwrap();
}

#[tokio::test]
async fn blob_provider_requires_explicit_fetch_permission() {
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
            PermissionSet::from_permissions(&[Permission::Read]),
            PermissionSet::empty(),
            None,
        )
        .unwrap();
    let target = target_device.import_invitation(&invitation).unwrap();
    let secret = source
        .blobs()
        .import_bytes(b"capability protected".to_vec(), None)
        .await
        .unwrap();
    let source_node = source.start_sync().await.unwrap();
    let target_node = target.start_sync().await.unwrap();

    assert!(
        target_node
            .fetch_blob_from(source_node.addr(), &secret)
            .await
            .is_err()
    );
    assert!(target.blobs().open(&secret).await.is_err());

    source_node.shutdown().await.unwrap();
    target_node.shutdown().await.unwrap();
    drop(source);
    drop(target);
    source_device.close().await.unwrap();
    target_device.close().await.unwrap();
}

#[tokio::test]
async fn blob_provider_does_not_cross_shared_store_domain_boundary() {
    let source_dir = tempfile::tempdir().unwrap();
    let target_dir = tempfile::tempdir().unwrap();
    let source_device = IrohDb::open(source_dir.path()).await.unwrap();
    let target_device = IrohDb::open(target_dir.path()).await.unwrap();
    let source_a = source_device
        .create_domain(ConsistencyMode::MultiWriter)
        .unwrap();
    let source_b = source_device
        .create_domain(ConsistencyMode::MultiWriter)
        .unwrap();
    let fetch = PermissionSet::from_permissions(&[Permission::Read, Permission::FetchBlobs]);
    let invitation_a = source_a
        .invite(
            target_device.author_id(),
            fetch,
            PermissionSet::empty(),
            None,
        )
        .unwrap();
    let invitation_b = source_b
        .invite(
            target_device.author_id(),
            fetch,
            PermissionSet::empty(),
            None,
        )
        .unwrap();
    let target_a = target_device.import_invitation(&invitation_a).unwrap();
    let target_b = target_device.import_invitation(&invitation_b).unwrap();
    let secret_b = source_b
        .blobs()
        .import_bytes(b"domain b only".to_vec(), None)
        .await
        .unwrap();
    let source_a_node = source_a.start_sync().await.unwrap();
    let target_b_node = target_b.start_sync().await.unwrap();

    assert!(
        target_b_node
            .fetch_blob_from(source_a_node.addr(), &secret_b)
            .await
            .is_err()
    );
    assert!(target_b.blobs().open(&secret_b).await.is_err());

    source_a_node.shutdown().await.unwrap();
    target_b_node.shutdown().await.unwrap();
    drop(source_a);
    drop(source_b);
    drop(target_a);
    drop(target_b);
    source_device.close().await.unwrap();
    target_device.close().await.unwrap();
}

#[tokio::test]
async fn sync_requires_explicit_read_permission() {
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
    source
        .issue_capability(
            target.author_id(),
            PermissionSet::from_permissions(&[Permission::FetchBlobs]),
            PermissionSet::empty(),
            source.domain_seed().epoch(),
            None,
        )
        .unwrap();
    source
        .collection::<Note>()
        .put(note("private", "not readable", source.author_id()))
        .await
        .unwrap();
    let source_node = source.start_sync().await.unwrap();
    let target_node = target.start_sync().await.unwrap();

    assert!(target_node.sync_with(source_node.addr()).await.is_err());
    assert!(
        target
            .collection::<Note>()
            .get(&"private".to_owned())
            .await
            .unwrap()
            .is_none()
    );

    source_node.shutdown().await.unwrap();
    target_node.shutdown().await.unwrap();
    drop(source);
    drop(target);
    source_device.close().await.unwrap();
    target_device.close().await.unwrap();
}

#[tokio::test]
async fn snapshot_bootstrap_requires_receiver_read_permission() {
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
    source
        .issue_capability(
            target.author_id(),
            PermissionSet::from_permissions(&[Permission::FetchBlobs]),
            PermissionSet::empty(),
            source.domain_seed().epoch(),
            None,
        )
        .unwrap();
    source
        .collection::<Note>()
        .put(note("private", "not bootstrapped", source.author_id()))
        .await
        .unwrap();
    let snapshot = source.snapshot().await.unwrap();
    let source_node = source.start_sync().await.unwrap();
    let target_node = target.start_sync().await.unwrap();

    assert!(
        target_node
            .bootstrap_from(source_node.addr(), snapshot)
            .await
            .is_err()
    );
    assert!(
        target
            .collection::<Note>()
            .get(&"private".to_owned())
            .await
            .unwrap()
            .is_none()
    );

    source_node.shutdown().await.unwrap();
    target_node.shutdown().await.unwrap();
    drop(source);
    drop(target);
    source_device.close().await.unwrap();
    target_device.close().await.unwrap();
}

#[tokio::test]
async fn three_partitioned_peers_converge_after_reordered_pairwise_sessions() {
    let seed = DomainSeed::generate().unwrap();
    let dirs = [
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    ];
    let a = IrohDb::create_in_domain(dirs[0].path(), &seed)
        .await
        .unwrap();
    let b = IrohDb::create_in_domain(dirs[1].path(), &seed)
        .await
        .unwrap();
    let c = IrohDb::create_in_domain(dirs[2].path(), &seed)
        .await
        .unwrap();
    for db in [&a, &b, &c] {
        for peer in [a.author_id(), b.author_id(), c.author_id()] {
            db.trust_device(peer).unwrap();
        }
    }
    let a_notes = a.collection::<Note>();
    let b_notes = b.collection::<Note>();
    let c_notes = c.collection::<Note>();
    a_notes.put(note("same", "a", a.author_id())).await.unwrap();
    b_notes.put(note("same", "b", b.author_id())).await.unwrap();
    c_notes.put(note("same", "c", c.author_id())).await.unwrap();

    let a_node = a.start_sync().await.unwrap();
    let b_node = b.start_sync().await.unwrap();
    let c_node = c.start_sync().await.unwrap();
    a_node.sync_with(b_node.addr()).await.unwrap();
    b_node.sync_with(c_node.addr()).await.unwrap();
    a_node.sync_with(c_node.addr()).await.unwrap();

    assert_eq!(a.state_root().unwrap(), b.state_root().unwrap());
    assert_eq!(b.state_root().unwrap(), c.state_root().unwrap());
    assert_eq!(
        a_notes.get(&"same".to_owned()).await.unwrap(),
        c_notes.get(&"same".to_owned()).await.unwrap()
    );

    a_node.shutdown().await.unwrap();
    b_node.shutdown().await.unwrap();
    c_node.shutdown().await.unwrap();
    drop(a_notes);
    drop(b_notes);
    drop(c_notes);
    a.close().await.unwrap();
    b.close().await.unwrap();
    c.close().await.unwrap();
}

#[tokio::test]
async fn unauthorized_real_session_leaves_accepted_state_unchanged() {
    let seed = DomainSeed::generate().unwrap();
    let left_dir = tempfile::tempdir().unwrap();
    let right_dir = tempfile::tempdir().unwrap();
    let left = IrohDb::create_in_domain(left_dir.path(), &seed)
        .await
        .unwrap();
    let right = IrohDb::create_in_domain(right_dir.path(), &seed)
        .await
        .unwrap();
    right.trust_device(left.author_id()).unwrap();
    left.collection::<Note>();
    right
        .collection::<Note>()
        .put(note("blocked", "private", right.author_id()))
        .await
        .unwrap();
    let root = left.state_root().unwrap();
    let left_node = left.start_sync().await.unwrap();
    let right_node = right.start_sync().await.unwrap();

    assert!(right_node.sync_with(left_node.addr()).await.is_err());
    assert_eq!(left.state_root().unwrap(), root);

    left_node.shutdown().await.unwrap();
    right_node.shutdown().await.unwrap();
    left.close().await.unwrap();
    right.close().await.unwrap();
}

#[tokio::test]
async fn stable_device_identity_resumes_sync_after_clean_restart() {
    let seed = DomainSeed::generate().unwrap();
    let left_dir = tempfile::tempdir().unwrap();
    let right_dir = tempfile::tempdir().unwrap();
    let left = IrohDb::create_in_domain(left_dir.path(), &seed)
        .await
        .unwrap();
    let right = IrohDb::create_in_domain(right_dir.path(), &seed)
        .await
        .unwrap();
    let left_author = left.author_id();
    left.trust_device(right.author_id()).unwrap();
    right.trust_device(left_author).unwrap();
    let left_notes = left.collection::<Note>();
    let right_notes = right.collection::<Note>();
    left_notes
        .put(note("before", "restart", left_author))
        .await
        .unwrap();
    let left_node = left.start_sync().await.unwrap();
    let right_node = right.start_sync().await.unwrap();
    left_node.sync_with(right_node.addr()).await.unwrap();
    left_node.shutdown().await.unwrap();
    drop(left_notes);
    left.close().await.unwrap();

    right_notes
        .put(note("after", "restart", right.author_id()))
        .await
        .unwrap();
    let reopened = IrohDb::open(left_dir.path()).await.unwrap();
    assert_eq!(reopened.author_id(), left_author);
    let reopened_notes = reopened.collection::<Note>();
    let reopened_node = reopened.start_sync().await.unwrap();
    reopened_node.sync_with(right_node.addr()).await.unwrap();
    assert!(
        reopened_notes
            .get(&"after".to_owned())
            .await
            .unwrap()
            .is_some()
    );

    reopened_node.shutdown().await.unwrap();
    right_node.shutdown().await.unwrap();
    drop(reopened_notes);
    drop(right_notes);
    reopened.close().await.unwrap();
    right.close().await.unwrap();
}
