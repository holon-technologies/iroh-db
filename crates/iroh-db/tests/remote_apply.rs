use iroh_db::{
    AuthorId, CapabilityId, ChangeKind, DbError, DomainSeed, Dot, IrohDb, IrohRecord, Lww,
    RemoteApply, SubscriptionEvent, TransactionId, VersionVector,
};
use iroh_db_core::{CommitBody, CommitHeader, Operation, OperationKind};
use iroh_db_security::{LocalCredentials, seal_commit};
use iroh_db_store::{IndexValue, MaterializedRecord};

#[derive(Debug, Clone, PartialEq, Eq, IrohRecord)]
#[iroh_db(collection = "shared-notes", version = 1)]
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
async fn authenticated_concurrent_commits_merge_and_duplicate_idempotently() {
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
    let right_author = right.author_id();
    left.trust_device(right_author).unwrap();
    right.trust_device(left_author).unwrap();
    let left_notes = left.collection::<Note>();
    let right_notes = right.collection::<Note>();

    left_notes
        .put(note("same", "left", left_author))
        .await
        .unwrap();
    right_notes
        .put(note("same", "right", right_author))
        .await
        .unwrap();
    let left_commit = left.commit_envelopes().await.unwrap().pop().unwrap();
    let right_commit = right.commit_envelopes().await.unwrap().pop().unwrap();

    assert!(matches!(
        left.accept_remote_commit(right_author, right_commit.clone())
            .await
            .unwrap(),
        RemoteApply::Applied(_)
    ));
    assert!(matches!(
        right
            .accept_remote_commit(left_author, left_commit)
            .await
            .unwrap(),
        RemoteApply::Applied(_)
    ));
    assert_eq!(left.state_root().unwrap(), right.state_root().unwrap());
    assert_eq!(
        left_notes.get(&"same".to_owned()).await.unwrap(),
        right_notes.get(&"same".to_owned()).await.unwrap()
    );
    assert!(matches!(
        left.accept_remote_commit(right_author, right_commit)
            .await
            .unwrap(),
        RemoteApply::Duplicate(_)
    ));

    drop(left_notes);
    drop(right_notes);
    left.close().await.unwrap();
    right.close().await.unwrap();
}

#[tokio::test]
async fn untrusted_peer_cannot_mutate_state() {
    let seed = DomainSeed::generate().unwrap();
    let left_dir = tempfile::tempdir().unwrap();
    let right_dir = tempfile::tempdir().unwrap();
    let left = IrohDb::create_in_domain(left_dir.path(), &seed)
        .await
        .unwrap();
    let right = IrohDb::create_in_domain(right_dir.path(), &seed)
        .await
        .unwrap();
    left.collection::<Note>();
    right
        .collection::<Note>()
        .put(note("blocked", "secret", right.author_id()))
        .await
        .unwrap();
    let envelope = right.commit_envelopes().await.unwrap().pop().unwrap();
    let root = left.state_root().unwrap();

    assert!(matches!(
        left.accept_remote_commit(right.author_id(), envelope).await,
        Err(DbError::UnauthorizedDevice)
    ));
    assert_eq!(left.state_root().unwrap(), root);

    left.close().await.unwrap();
    right.close().await.unwrap();
}

#[tokio::test]
async fn authenticated_writer_cannot_forge_causal_metadata() {
    let seed = DomainSeed::generate().unwrap();
    let receiver_dir = tempfile::tempdir().unwrap();
    let writer_dir = tempfile::tempdir().unwrap();
    let receiver = IrohDb::create_in_domain(receiver_dir.path(), &seed)
        .await
        .unwrap();
    let writer = IrohDb::create_in_domain(writer_dir.path(), &seed)
        .await
        .unwrap();
    receiver.collection::<Note>();
    receiver.trust_device(writer.author_id()).unwrap();
    let credentials = LocalCredentials::load_or_create(writer_dir.path().join("keys")).unwrap();
    let forged_author = AuthorId::from_bytes([0xff; 32]);
    let forged = note("forged", "dominant", forged_author);
    let schema = Note::schema().unwrap();
    let record_id = forged.record_id().unwrap();
    let mutation = MaterializedRecord::upsert(
        schema.clone(),
        record_id.clone(),
        forged.encode_record().unwrap(),
        forged
            .field_values(Note::text.field_id())
            .unwrap()
            .into_iter()
            .map(|value| IndexValue::new(Note::text.field_id(), value))
            .collect(),
    )
    .unwrap();
    let operation = Operation::new(
        schema.collection_id(),
        record_id,
        0,
        OperationKind::FieldStateMerge,
        mutation.encode_canonical().unwrap(),
    )
    .unwrap();
    let body = CommitBody::new(TransactionId::from_bytes([3; 32]), vec![operation]).unwrap();
    let header = CommitHeader::new(
        seed.domain_id(),
        seed.epoch(),
        credentials.signer().author(),
        0,
        Vec::new(),
        CapabilityId::from_bytes([4; 32]),
        vec![schema.schema_id()],
        [5; 24],
    )
    .unwrap();
    let envelope = seal_commit(header, &body, &seed.domain_key(), &credentials.signer()).unwrap();
    let root_before = receiver.state_root().unwrap();

    assert!(matches!(
        receiver
            .accept_remote_commit(writer.author_id(), envelope)
            .await,
        Err(DbError::InvalidRemoteCommit(message))
            if message == "record contains causal metadata not issued by its commit"
    ));
    assert_eq!(receiver.state_root().unwrap(), root_before);
    assert!(receiver.commit_envelopes().await.unwrap().is_empty());

    writer.close().await.unwrap();
    receiver.close().await.unwrap();
}

fn equivocation_commit(
    seed: &DomainSeed,
    credentials: &LocalCredentials,
    text: &str,
    variant: u8,
) -> iroh_db::CommitEnvelope {
    let author = credentials.signer().author();
    let canonical = note("equivocated", text, author);
    let schema = Note::schema().unwrap();
    let record_id = canonical.record_id().unwrap();
    let mutation = MaterializedRecord::upsert(
        schema.clone(),
        record_id.clone(),
        canonical.encode_record().unwrap(),
        canonical
            .field_values(Note::text.field_id())
            .unwrap()
            .into_iter()
            .map(|value| IndexValue::new(Note::text.field_id(), value))
            .collect(),
    )
    .unwrap();
    let operation = Operation::new(
        schema.collection_id(),
        record_id,
        0,
        OperationKind::FieldStateMerge,
        mutation.encode_canonical().unwrap(),
    )
    .unwrap();
    let body = CommitBody::new(TransactionId::from_bytes([variant; 32]), vec![operation]).unwrap();
    let header = CommitHeader::new(
        seed.domain_id(),
        seed.epoch(),
        author,
        0,
        Vec::new(),
        CapabilityId::from_bytes([4; 32]),
        vec![schema.schema_id()],
        [variant; 24],
    )
    .unwrap();
    seal_commit(header, &body, &seed.domain_key(), &credentials.signer()).unwrap()
}

fn post_snapshot_equivocation_commit(
    seed: &DomainSeed,
    credentials: &LocalCredentials,
    dependency: iroh_db::CommitId,
    dependency_author: AuthorId,
    text: &str,
    variant: u8,
) -> iroh_db::CommitEnvelope {
    let author = credentials.signer().author();
    let mut causal_text = Lww::new();
    let mut context = VersionVector::new();
    context.observe(Dot::new(dependency_author, 0, 0));
    causal_text
        .assign(text.into(), Dot::new(author, 0, 0), context)
        .unwrap();
    let canonical = Note {
        id: "equivocated-after-snapshot".into(),
        text: causal_text,
    };
    let schema = Note::schema().unwrap();
    let record_id = canonical.record_id().unwrap();
    let mutation = MaterializedRecord::upsert(
        schema.clone(),
        record_id.clone(),
        canonical.encode_record().unwrap(),
        canonical
            .field_values(Note::text.field_id())
            .unwrap()
            .into_iter()
            .map(|value| IndexValue::new(Note::text.field_id(), value))
            .collect(),
    )
    .unwrap();
    let operation = Operation::new(
        schema.collection_id(),
        record_id,
        0,
        OperationKind::FieldStateMerge,
        mutation.encode_canonical().unwrap(),
    )
    .unwrap();
    let body = CommitBody::new(TransactionId::from_bytes([variant; 32]), vec![operation]).unwrap();
    let header = CommitHeader::new(
        seed.domain_id(),
        seed.epoch(),
        author,
        0,
        vec![dependency],
        CapabilityId::from_bytes([4; 32]),
        vec![schema.schema_id()],
        [variant; 24],
    )
    .unwrap();
    seal_commit(header, &body, &seed.domain_key(), &credentials.signer()).unwrap()
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn replicas_quarantine_equivocation_independently_of_receipt_order() {
    let seed = DomainSeed::generate().unwrap();
    let first_dir = tempfile::tempdir().unwrap();
    let second_dir = tempfile::tempdir().unwrap();
    let writer_dir = tempfile::tempdir().unwrap();
    let first = IrohDb::create_in_domain(first_dir.path(), &seed)
        .await
        .unwrap();
    let second = IrohDb::create_in_domain(second_dir.path(), &seed)
        .await
        .unwrap();
    let writer = IrohDb::create_in_domain(writer_dir.path(), &seed)
        .await
        .unwrap();
    let first_notes = first.collection::<Note>();
    second.collection::<Note>();
    let mut changes = first_notes.subscribe().unwrap();
    assert!(matches!(
        changes.recv().await.unwrap(),
        SubscriptionEvent::Initial(records) if records.is_empty()
    ));
    first.trust_device(writer.author_id()).unwrap();
    second.trust_device(writer.author_id()).unwrap();
    let credentials = LocalCredentials::load_or_create(writer_dir.path().join("keys")).unwrap();
    let left = equivocation_commit(&seed, &credentials, "left", 11);
    let right = equivocation_commit(&seed, &credentials, "right", 12);
    let empty_root = first.state_root().unwrap();

    assert!(matches!(
        first
            .accept_remote_commit(writer.author_id(), left.clone())
            .await
            .unwrap(),
        RemoteApply::Applied(_)
    ));
    assert!(matches!(
        changes.recv().await.unwrap(),
        SubscriptionEvent::Changes(batch)
            if batch.changes().iter().any(|change| change.kind() == ChangeKind::Upserted)
    ));
    assert!(matches!(
        second
            .accept_remote_commit(writer.author_id(), right.clone())
            .await
            .unwrap(),
        RemoteApply::Applied(_)
    ));
    assert_ne!(first.state_root().unwrap(), second.state_root().unwrap());

    assert!(matches!(
        first
            .accept_remote_commit(writer.author_id(), right.clone())
            .await
            .unwrap(),
        RemoteApply::Quarantined { author, sequence: 0 } if author == writer.author_id()
    ));
    assert!(matches!(
        tokio::time::timeout(std::time::Duration::from_secs(1), changes.recv())
            .await
            .unwrap()
            .unwrap(),
        SubscriptionEvent::Changes(batch)
            if batch.changes().iter().any(|change| change.kind() == ChangeKind::Deleted)
    ));
    assert!(matches!(
        second
            .accept_remote_commit(writer.author_id(), left.clone())
            .await
            .unwrap(),
        RemoteApply::Quarantined { author, sequence: 0 } if author == writer.author_id()
    ));
    assert_eq!(first.state_root().unwrap(), empty_root);
    assert_eq!(second.state_root().unwrap(), empty_root);
    assert_eq!(first.state_root().unwrap(), second.state_root().unwrap());
    assert_eq!(
        first
            .operational_metrics()
            .unwrap()
            .equivocation_quarantines(),
        1
    );
    assert_eq!(
        second
            .operational_metrics()
            .unwrap()
            .equivocation_quarantines(),
        1
    );
    assert!(first.commit_envelopes().await.unwrap().is_empty());
    assert!(second.commit_envelopes().await.unwrap().is_empty());
    assert!(matches!(
        first
            .accept_remote_commit(writer.author_id(), right)
            .await
            .unwrap(),
        RemoteApply::Quarantined { .. }
    ));
    assert!(matches!(
        second
            .accept_remote_commit(writer.author_id(), left)
            .await
            .unwrap(),
        RemoteApply::Quarantined { .. }
    ));
    let third = equivocation_commit(&seed, &credentials, "third", 13);
    assert!(matches!(
        first
            .accept_remote_commit(writer.author_id(), third)
            .await
            .unwrap(),
        RemoteApply::Quarantined { author, sequence: 0 } if author == writer.author_id()
    ));
    assert_eq!(first.state_root().unwrap(), empty_root);

    drop(changes);
    drop(first_notes);
    writer.close().await.unwrap();
    first.close().await.unwrap();
    second.close().await.unwrap();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn post_snapshot_equivocation_quarantine_preserves_baseline_state() {
    let seed = DomainSeed::generate().unwrap();
    let source_dir = tempfile::tempdir().unwrap();
    let receiver_dir = tempfile::tempdir().unwrap();
    let reverse_receiver_dir = tempfile::tempdir().unwrap();
    let writer_dir = tempfile::tempdir().unwrap();
    let source = IrohDb::create_in_domain(source_dir.path(), &seed)
        .await
        .unwrap();
    let receiver = IrohDb::create_in_domain(receiver_dir.path(), &seed)
        .await
        .unwrap();
    let reverse_receiver = IrohDb::create_in_domain(reverse_receiver_dir.path(), &seed)
        .await
        .unwrap();
    let writer = IrohDb::create_in_domain(writer_dir.path(), &seed)
        .await
        .unwrap();
    source.trust_device(receiver.author_id()).unwrap();
    source.trust_device(reverse_receiver.author_id()).unwrap();
    receiver.trust_device(source.author_id()).unwrap();
    receiver.trust_device(writer.author_id()).unwrap();
    reverse_receiver.trust_device(source.author_id()).unwrap();
    reverse_receiver.trust_device(writer.author_id()).unwrap();
    let source_notes = source.collection::<Note>();
    let receiver_notes = receiver.collection::<Note>();
    let reverse_receiver_notes = reverse_receiver.collection::<Note>();
    source_notes
        .put(note("snapshot-base", "preserved", source.author_id()))
        .await
        .unwrap();
    let base = source.commit_envelopes().await.unwrap().pop().unwrap();
    let base_id = base.commit_id();
    let snapshot = source.snapshot().await.unwrap();
    let source_node = source.start_sync().await.unwrap();
    let receiver_node = receiver.start_sync().await.unwrap();
    let reverse_receiver_node = reverse_receiver.start_sync().await.unwrap();
    receiver_node
        .bootstrap_from(source_node.addr(), snapshot)
        .await
        .unwrap();
    reverse_receiver_node
        .bootstrap_from(source_node.addr(), snapshot)
        .await
        .unwrap();
    let baseline_root = receiver.state_root().unwrap();
    assert_eq!(reverse_receiver.state_root().unwrap(), baseline_root);
    source_node.shutdown().await.unwrap();
    receiver_node.shutdown().await.unwrap();
    reverse_receiver_node.shutdown().await.unwrap();

    let credentials = LocalCredentials::load_or_create(writer_dir.path().join("keys")).unwrap();
    let left = post_snapshot_equivocation_commit(
        &seed,
        &credentials,
        base_id,
        source.author_id(),
        "left",
        21,
    );
    let right = post_snapshot_equivocation_commit(
        &seed,
        &credentials,
        base_id,
        source.author_id(),
        "right",
        22,
    );
    assert!(matches!(
        receiver
            .accept_remote_commit(writer.author_id(), left.clone())
            .await
            .unwrap(),
        RemoteApply::Applied(_)
    ));
    assert!(matches!(
        receiver
            .accept_remote_commit(writer.author_id(), right.clone())
            .await
            .unwrap(),
        RemoteApply::Quarantined { author, sequence: 0 } if author == writer.author_id()
    ));
    assert!(matches!(
        reverse_receiver
            .accept_remote_commit(writer.author_id(), right.clone())
            .await
            .unwrap(),
        RemoteApply::Applied(_)
    ));
    assert!(matches!(
        reverse_receiver
            .accept_remote_commit(writer.author_id(), left.clone())
            .await
            .unwrap(),
        RemoteApply::Quarantined { author, sequence: 0 } if author == writer.author_id()
    ));

    assert_eq!(receiver.state_root().unwrap(), baseline_root);
    assert_eq!(reverse_receiver.state_root().unwrap(), baseline_root);
    assert!(
        receiver_notes
            .get(&"snapshot-base".to_owned())
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        reverse_receiver_notes
            .get(&"snapshot-base".to_owned())
            .await
            .unwrap()
            .is_some()
    );

    source_notes
        .put(note(
            "post-quarantine",
            "sequence-floor",
            source.author_id(),
        ))
        .await
        .unwrap();
    let tail = source
        .commit_envelopes()
        .await
        .unwrap()
        .into_iter()
        .find(|commit| commit.header().author_sequence() == 1)
        .unwrap();
    assert!(matches!(
        receiver
            .accept_remote_commit(source.author_id(), tail.clone())
            .await
            .unwrap(),
        RemoteApply::Applied(_)
    ));
    assert!(matches!(
        reverse_receiver
            .accept_remote_commit(source.author_id(), tail)
            .await
            .unwrap(),
        RemoteApply::Applied(_)
    ));
    let expected_root = source.state_root().unwrap();
    assert_eq!(receiver.state_root().unwrap(), expected_root);
    assert_eq!(reverse_receiver.state_root().unwrap(), expected_root);
    drop(source_notes);
    drop(receiver_notes);
    drop(reverse_receiver_notes);
    writer.close().await.unwrap();
    source.close().await.unwrap();
    receiver.close().await.unwrap();
    reverse_receiver.close().await.unwrap();

    for directory in [&receiver_dir, &reverse_receiver_dir] {
        let reopened_device = IrohDb::open(directory.path()).await.unwrap();
        let reopened = reopened_device.domain(seed.domain_id()).unwrap();
        let notes = reopened.collection::<Note>();
        assert!(reopened.verify().await.unwrap().derived_consistent());
        assert_eq!(reopened.state_root().unwrap(), expected_root);
        assert!(
            notes
                .get(&"snapshot-base".to_owned())
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            notes
                .get(&"post-quarantine".to_owned())
                .await
                .unwrap()
                .is_some()
        );
        drop(notes);
        drop(reopened);
        reopened_device.close().await.unwrap();
    }
}

#[tokio::test]
async fn concurrent_update_wins_over_delete_in_every_receipt_order() {
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
        .put(note("same", "base", left.author_id()))
        .await
        .unwrap();
    let base = left.commit_envelopes().await.unwrap().pop().unwrap();
    right
        .accept_remote_commit(left.author_id(), base)
        .await
        .unwrap();

    left_notes.delete(&"same".to_owned()).await.unwrap();
    right_notes
        .put(note("same", "updated", right.author_id()))
        .await
        .unwrap();
    let delete = left
        .commit_envelopes()
        .await
        .unwrap()
        .into_iter()
        .find(|commit| {
            commit.header().author() == left.author_id() && commit.header().author_sequence() == 1
        })
        .unwrap();
    let update = right
        .commit_envelopes()
        .await
        .unwrap()
        .into_iter()
        .find(|commit| commit.header().author() == right.author_id())
        .unwrap();

    left.accept_remote_commit(right.author_id(), update)
        .await
        .unwrap();
    right
        .accept_remote_commit(left.author_id(), delete)
        .await
        .unwrap();

    assert_eq!(left.state_root().unwrap(), right.state_root().unwrap());
    assert_eq!(
        left_notes
            .get(&"same".to_owned())
            .await
            .unwrap()
            .unwrap()
            .text
            .get()
            .map(String::as_str),
        Some("updated")
    );
    assert!(right_notes.get(&"same".to_owned()).await.unwrap().is_some());

    drop(left_notes);
    drop(right_notes);
    left.close().await.unwrap();
    right.close().await.unwrap();
}
