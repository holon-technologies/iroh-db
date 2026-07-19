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
