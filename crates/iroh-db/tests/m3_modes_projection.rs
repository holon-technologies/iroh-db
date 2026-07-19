use iroh_db::{
    AuthorId, ConsistencyMode, Dot, Immutable, IrohDb, IrohRecord, Lww, Permission, PermissionSet,
    VersionVector,
};

#[derive(Debug, Clone, PartialEq, Eq, IrohRecord)]
#[iroh_db(collection = "projection-notes", version = 1)]
struct Note {
    #[iroh_db(id, field_id = 1)]
    id: String,
    #[iroh_db(field_id = 2)]
    text: Lww<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, IrohRecord)]
#[iroh_db(collection = "audit-events", version = 1)]
struct AuditEvent {
    #[iroh_db(id, field_id = 1)]
    id: String,
    #[iroh_db(field_id = 2)]
    message: Immutable<String>,
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

fn immutable(value: &str, author: AuthorId) -> Immutable<String> {
    let mut field = Immutable::new();
    field
        .set(value.into(), Dot::new(author, 0, 0), VersionVector::new())
        .unwrap();
    field
}

#[tokio::test]
async fn consistency_modes_enforce_single_writer_and_append_only_rules() {
    let owner_dir = tempfile::tempdir().unwrap();
    let member_dir = tempfile::tempdir().unwrap();
    let owner_device = IrohDb::open(owner_dir.path()).await.unwrap();
    let member_device = IrohDb::open(member_dir.path()).await.unwrap();
    let single = owner_device
        .create_domain(ConsistencyMode::SingleWriter)
        .unwrap();
    let invitation = single
        .invite(
            member_device.author_id(),
            PermissionSet::from_permissions(&[Permission::Read, Permission::Write]),
            PermissionSet::empty(),
            None,
        )
        .unwrap();
    let member = member_device.import_invitation(&invitation).unwrap();
    assert!(
        member
            .collection::<Note>()
            .put(note("blocked", "not writer", member.author_id()))
            .await
            .is_err()
    );
    single
        .collection::<Note>()
        .put(note("owner", "writer", single.author_id()))
        .await
        .unwrap();

    let append = owner_device
        .create_domain(ConsistencyMode::AppendOnly)
        .unwrap();
    let events = append.collection::<AuditEvent>();
    events
        .put(AuditEvent {
            id: "one".into(),
            message: immutable("created", append.author_id()),
        })
        .await
        .unwrap();
    assert!(
        events
            .put(AuditEvent {
                id: "one".into(),
                message: immutable("changed", append.author_id()),
            })
            .await
            .is_err()
    );
    assert!(events.delete(&"one".to_owned()).await.is_err());

    drop(events);
    drop(single);
    drop(member);
    drop(append);
    owner_device.close().await.unwrap();
    member_device.close().await.unwrap();
}

#[tokio::test]
async fn projection_creates_independent_history_and_groups_remain_ux_metadata() {
    let directory = tempfile::tempdir().unwrap();
    let device = IrohDb::open(directory.path()).await.unwrap();
    let source = device.create_domain(ConsistencyMode::MultiWriter).unwrap();
    let destination = device.create_domain(ConsistencyMode::MultiWriter).unwrap();
    let source_notes = source.collection::<Note>();
    source_notes
        .put(note("share", "visible", source.author_id()))
        .await
        .unwrap();
    source_notes
        .put(note("secret", "private", source.author_id()))
        .await
        .unwrap();
    let source_commits: Vec<_> = source
        .commit_envelopes()
        .await
        .unwrap()
        .into_iter()
        .map(|commit| commit.commit_id())
        .collect();

    let report = source
        .project::<Note, _>(&destination, |record| record.id == "share")
        .await
        .unwrap();
    assert_eq!(report.selected(), 1);
    let destination_notes = destination.collection::<Note>();
    assert!(
        destination_notes
            .get(&"share".to_owned())
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        destination_notes
            .get(&"secret".to_owned())
            .await
            .unwrap()
            .is_none()
    );
    let destination_commits = destination.commit_envelopes().await.unwrap();
    assert_eq!(destination_commits.len(), 1);
    assert!(!source_commits.contains(&destination_commits[0].commit_id()));
    assert!(destination_commits[0].header().dependencies().is_empty());

    source
        .set_device_group("family", &[source.author_id(), destination.author_id()])
        .unwrap();
    let groups = source.device_groups().unwrap();
    assert_eq!(groups[0].label(), "family");
    assert_eq!(groups[0].members().len(), 1);
    assert!(destination.device_groups().unwrap().is_empty());

    drop(source_notes);
    drop(destination_notes);
    drop(source);
    drop(destination);
    device.close().await.unwrap();
}
