use iroh_db::{AuthorId, DomainSeed, Dot, IrohDb, IrohRecord, Lww, VersionVector};

#[derive(Debug, Clone, PartialEq, Eq, IrohRecord)]
#[iroh_db(collection = "domain-notes", version = 1)]
struct Note {
    #[iroh_db(id, field_id = 1)]
    id: String,
    #[iroh_db(field_id = 2)]
    text: Lww<String>,
}

fn note(text: &str, author: AuthorId) -> Note {
    let mut field = Lww::new();
    field
        .assign(text.into(), Dot::new(author, 0, 0), VersionVector::new())
        .unwrap();
    Note {
        id: "same-key".into(),
        text: field,
    }
}

#[tokio::test]
async fn one_device_store_keeps_domains_records_blobs_and_reopen_isolated() {
    let root = tempfile::tempdir().unwrap();
    let default = IrohDb::open(root.path()).await.unwrap();
    let shared_seed = DomainSeed::generate().unwrap();
    let shared = default.attach_domain(&shared_seed).unwrap();
    let private_notes = default.collection::<Note>();
    let shared_notes = shared.collection::<Note>();
    private_notes
        .put(note("private", default.author_id()))
        .await
        .unwrap();
    shared_notes
        .put(note("shared", shared.author_id()))
        .await
        .unwrap();
    let private_blob = default
        .blobs()
        .import_bytes(b"private bytes".to_vec(), None)
        .await
        .unwrap();

    assert_ne!(default.state_root().unwrap(), shared.state_root().unwrap());
    assert_eq!(
        private_notes
            .get(&"same-key".to_owned())
            .await
            .unwrap()
            .unwrap()
            .text
            .get()
            .map(String::as_str),
        Some("private")
    );
    assert_eq!(
        shared_notes
            .get(&"same-key".to_owned())
            .await
            .unwrap()
            .unwrap()
            .text
            .get()
            .map(String::as_str),
        Some("shared")
    );
    assert!(shared.blobs().open(&private_blob).await.is_err());
    let default_domain = default.domain_id();
    let author = default.author_id();

    drop(private_notes);
    drop(shared_notes);
    drop(shared);
    default.close().await.unwrap();

    let reopened = IrohDb::open(root.path()).await.unwrap();
    assert_eq!(reopened.author_id(), author);
    assert_eq!(reopened.domain_id(), default_domain);
    assert!(
        reopened
            .domains()
            .unwrap()
            .contains(&shared_seed.domain_id())
    );
    let reopened_shared = reopened.domain(shared_seed.domain_id()).unwrap();
    assert!(
        reopened_shared
            .collection::<Note>()
            .get(&"same-key".to_owned())
            .await
            .unwrap()
            .is_some()
    );
    drop(reopened_shared);
    reopened.close().await.unwrap();
}
