use iroh_db::{
    AuthorId, CapabilityId, DbError, DomainSeed, Dot, IrohDb, IrohRecord, Lww, RemoteApply,
    TransactionId, VersionVector,
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

#[tokio::test]
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
    first.collection::<Note>();
    second.collection::<Note>();
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
        second
            .accept_remote_commit(writer.author_id(), left.clone())
            .await
            .unwrap(),
        RemoteApply::Quarantined { author, sequence: 0 } if author == writer.author_id()
    ));
    assert_eq!(first.state_root().unwrap(), empty_root);
    assert_eq!(second.state_root().unwrap(), empty_root);
    assert_eq!(first.state_root().unwrap(), second.state_root().unwrap());
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

    writer.close().await.unwrap();
    first.close().await.unwrap();
    second.close().await.unwrap();
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
