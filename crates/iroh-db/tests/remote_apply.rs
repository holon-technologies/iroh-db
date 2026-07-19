use iroh_db::{
    AuthorId, DbError, DomainSeed, Dot, IrohDb, IrohRecord, Lww, RemoteApply, VersionVector,
};

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
