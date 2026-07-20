use iroh_db::{
    AuthorId, BlobHash, CapabilityId, CommitBody, CommitEnvelope, CommitHeader, ConsistencyMode,
    DbError, DomainSeed, Dot, IrohDb, IrohRecord, Lww, MigrationError, MigrationId,
    MigrationReport, Operation, OperationKind, Permission, PermissionSet, RemoteApply,
    SchemaActivation, SchemaStage, TransactionId, VersionVector, staging_digest,
};
use iroh_db_security::{LocalCredentials, seal_commit};
use iroh_db_store::{IndexValue, MaterializedRecord, StoreError};

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(transparent)]
struct TrackId(#[n(0)] String);

#[derive(Debug, Clone, PartialEq, Eq, IrohRecord)]
#[iroh_db(collection = "migration-tracks", version = 1)]
struct TrackV1 {
    #[iroh_db(id, field_id = 1)]
    id: TrackId,
    #[iroh_db(field_id = 2)]
    title: Lww<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, IrohRecord)]
#[iroh_db(collection = "migration-tracks", version = 2)]
struct TrackV2 {
    #[iroh_db(id, field_id = 1)]
    id: TrackId,
    #[iroh_db(field_id = 2)]
    title: Lww<String>,
    #[iroh_db(field_id = 3, index)]
    genre: Lww<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, IrohRecord)]
#[iroh_db(collection = "migration-tracks", version = 3)]
struct TrackV3 {
    #[iroh_db(id, field_id = 1)]
    id: TrackId,
    #[iroh_db(field_id = 2)]
    title: Lww<String>,
    #[iroh_db(field_id = 3, index)]
    genre: Lww<String>,
    #[iroh_db(field_id = 4)]
    mood: Lww<String>,
}

fn register(value: &str, operation: u32) -> Lww<String> {
    let mut field = Lww::new();
    field
        .assign(
            value.to_owned(),
            Dot::new(AuthorId::from_bytes([7; 32]), 0, operation),
            VersionVector::new(),
        )
        .unwrap();
    field
}

#[allow(clippy::unnecessary_wraps)]
fn migrate_track(old: TrackV1) -> Result<TrackV2, MigrationError> {
    Ok(TrackV2 {
        id: old.id,
        title: old.title,
        genre: register("Trip hop", 1),
    })
}

#[allow(clippy::unnecessary_wraps)]
fn migrate_track_v3(old: TrackV2) -> Result<TrackV3, MigrationError> {
    Ok(TrackV3 {
        id: old.id,
        title: old.title,
        genre: old.genre,
        mood: register("Nocturnal", 2),
    })
}

fn activation_envelope(
    seed: &DomainSeed,
    credentials: &LocalCredentials,
    activation: &SchemaActivation,
    nonce: u8,
) -> CommitEnvelope {
    let operation = Operation::new(
        activation.to().collection_id(),
        vec![],
        0,
        OperationKind::SchemaActivate,
        activation.encode_canonical(),
    )
    .unwrap();
    let body = CommitBody::new(TransactionId::from_bytes([nonce; 32]), vec![operation]).unwrap();
    let header = CommitHeader::new(
        seed.domain_id(),
        seed.epoch(),
        credentials.signer().author(),
        0,
        vec![],
        CapabilityId::from_bytes([nonce; 32]),
        vec![activation.from().schema_id(), activation.to().schema_id()],
        [nonce; 24],
    )
    .unwrap();
    seal_commit(header, &body, &seed.domain_key(), &credentials.signer()).unwrap()
}

fn stage_envelope(
    seed: &DomainSeed,
    credentials: &LocalCredentials,
    stage: &SchemaStage,
    dependency: iroh_db::CommitId,
) -> CommitEnvelope {
    let operation = Operation::new(
        stage.to().collection_id(),
        stage.source_record_id().to_vec(),
        0,
        OperationKind::SchemaStage,
        stage.encode_canonical(),
    )
    .unwrap();
    let body = CommitBody::new(TransactionId::from_bytes([71; 32]), vec![operation]).unwrap();
    let header = CommitHeader::new(
        seed.domain_id(),
        0,
        credentials.signer().author(),
        0,
        vec![dependency],
        CapabilityId::from_bytes([72; 32]),
        vec![stage.from().schema_id(), stage.to().schema_id()],
        [73; 24],
    )
    .unwrap();
    seal_commit(header, &body, &seed.domain_key(), &credentials.signer()).unwrap()
}

fn source_bound_migration_id(
    domain_id: iroh_db::DomainId,
    record_id: &[u8],
    state: &[u8],
) -> MigrationId {
    let mut source = blake3::Hasher::new();
    source.update(b"iroh-db/schema-source-cut/v1");
    source.update(&1_u64.to_be_bytes());
    source.update(&(record_id.len() as u64).to_be_bytes());
    source.update(record_id);
    source.update(&(state.len() as u64).to_be_bytes());
    source.update(state);

    let mut attempt = blake3::Hasher::new();
    attempt.update(b"iroh-db/schema-migration/v1");
    attempt.update(domain_id.as_bytes());
    attempt.update(TrackV1::schema().unwrap().schema_id().as_bytes());
    attempt.update(TrackV2::schema().unwrap().schema_id().as_bytes());
    attempt.update(source.finalize().as_bytes());
    MigrationId::from_bytes(*attempt.finalize().as_bytes())
}

#[tokio::test]
async fn registered_migration_is_atomic_rebuildable_resumable_and_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    let original = IrohDb::open(directory.path()).await.unwrap();
    let tracks = original.collection::<TrackV1>();
    tracks
        .put(TrackV1 {
            id: TrackId("teardrop".into()),
            title: register("Teardrop", 0),
        })
        .await
        .unwrap();
    drop(tracks);
    original.close().await.unwrap();

    let (migrated, report) = IrohDb::builder(directory.path())
        .migration::<TrackV1, TrackV2>(migrate_track)
        .unwrap()
        .open_with_report()
        .await
        .unwrap();
    assert_eq!(report.staged(), 1);
    assert_eq!(report.activated(), 1);
    assert_eq!(report.activation_commits().len(), 1);
    let metrics = migrated.operational_metrics().unwrap();
    assert_eq!(metrics.active_migrations(), 1);
    assert_eq!(metrics.staged_migration_records(), 1);
    assert_eq!(metrics.frozen_migrations(), 0);
    let tracks = migrated.collection::<TrackV2>();
    let track = tracks
        .get(&TrackId("teardrop".into()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(track.title.get().map(String::as_str), Some("Teardrop"));
    assert_eq!(track.genre.get().map(String::as_str), Some("Trip hop"));
    assert!(migrated.verify().await.unwrap().derived_consistent());
    let commit_count = migrated.commit_envelopes().await.unwrap().len();
    drop(tracks);
    migrated.close().await.unwrap();

    let (reopened, report) = IrohDb::builder(directory.path())
        .migration::<TrackV1, TrackV2>(migrate_track)
        .unwrap()
        .open_with_report()
        .await
        .unwrap();
    assert_eq!(report.already_activated(), 1);
    assert_eq!(
        reopened.run_migrations().await.unwrap().already_activated(),
        1
    );
    assert_eq!(
        reopened.commit_envelopes().await.unwrap().len(),
        commit_count
    );
    assert!(reopened.verify().await.unwrap().derived_consistent());
}

#[tokio::test]
async fn a_new_schema_cannot_bypass_the_registered_migration_path() {
    let directory = tempfile::tempdir().unwrap();
    let database = IrohDb::open(directory.path()).await.unwrap();
    database
        .collection::<TrackV1>()
        .put(TrackV1 {
            id: TrackId("angel".into()),
            title: register("Angel", 0),
        })
        .await
        .unwrap();

    let error = database
        .collection::<TrackV2>()
        .put(TrackV2 {
            id: TrackId("angel".into()),
            title: register("Angel", 0),
            genre: register("Trip hop", 1),
        })
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        DbError::SchemaMigrationRequired {
            stored_version: 1,
            requested_version: 2,
            ..
        }
    ));
}

#[tokio::test]
async fn application_can_defer_and_explicitly_run_registered_migrations() {
    let directory = tempfile::tempdir().unwrap();
    let database = IrohDb::open(directory.path()).await.unwrap();
    database
        .collection::<TrackV1>()
        .put(TrackV1 {
            id: TrackId("deferred".into()),
            title: register("Deferred", 0),
        })
        .await
        .unwrap();
    database.close().await.unwrap();

    let (database, opening) = IrohDb::builder(directory.path())
        .migration::<TrackV1, TrackV2>(migrate_track)
        .unwrap()
        .defer_migrations()
        .open_with_report()
        .await
        .unwrap();
    assert_eq!(opening, MigrationReport::default());
    assert!(
        database
            .collection::<TrackV1>()
            .get(&TrackId("deferred".into()))
            .await
            .unwrap()
            .is_some()
    );

    let report = database.run_migrations().await.unwrap();
    assert_eq!(report.staged(), 1);
    assert_eq!(report.activated(), 1);
    assert!(
        database
            .collection::<TrackV2>()
            .get(&TrackId("deferred".into()))
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn changed_source_cut_starts_a_new_attempt_after_durable_staging() {
    let seed = DomainSeed::generate().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let stager_directory = tempfile::tempdir().unwrap();
    let stager = LocalCredentials::create_for_domain(stager_directory.path(), &seed).unwrap();
    let database = IrohDb::create_in_domain(directory.path(), &seed)
        .await
        .unwrap();
    database.trust_device(stager.signer().author()).unwrap();
    let tracks = database.collection::<TrackV1>();
    tracks
        .put(TrackV1 {
            id: TrackId("resume".into()),
            title: register("Before", 0),
        })
        .await
        .unwrap();
    let base = database.commit_envelopes().await.unwrap().pop().unwrap();
    let source = tracks
        .get(&TrackId("resume".into()))
        .await
        .unwrap()
        .unwrap();
    let source_id = source.record_id().unwrap();
    let source_state = source.encode_record().unwrap();
    let target = migrate_track(source).unwrap();
    let target_state = target.encode_record().unwrap();
    let target_indexes = target
        .field_values(3)
        .unwrap()
        .into_iter()
        .map(|value| IndexValue::new(3, value))
        .collect();
    let target_record = MaterializedRecord::upsert(
        TrackV2::schema().unwrap(),
        source_id.clone(),
        target_state,
        target_indexes,
    )
    .unwrap();
    let stale_stage = SchemaStage::new(
        source_bound_migration_id(seed.domain_id(), &source_id, &source_state),
        TrackV1::schema().unwrap(),
        TrackV2::schema().unwrap(),
        source_id,
        BlobHash::from_bytes(*blake3::hash(&source_state).as_bytes()),
        target_record.encode_canonical().unwrap(),
    )
    .unwrap();
    drop(tracks);
    database.collection::<TrackV2>();
    assert!(matches!(
        database
            .accept_remote_commit(
                stager.signer().author(),
                stage_envelope(&seed, &stager, &stale_stage, base.commit_id()),
            )
            .await
            .unwrap(),
        RemoteApply::Applied(_)
    ));

    let tracks = database.collection::<TrackV1>();
    tracks
        .put(TrackV1 {
            id: TrackId("resume".into()),
            title: register("After", 1),
        })
        .await
        .unwrap();
    drop(tracks);
    database.close().await.unwrap();

    let (migrated, report) = IrohDb::builder(directory.path())
        .migration::<TrackV1, TrackV2>(migrate_track)
        .unwrap()
        .open_with_report()
        .await
        .unwrap();
    assert_eq!(report.staged(), 1);
    assert_eq!(report.already_staged(), 0);
    assert_eq!(report.activated(), 1);
    let record = migrated
        .collection::<TrackV2>()
        .get(&TrackId("resume".into()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.title.get().map(String::as_str), Some("After"));
    assert!(migrated.verify().await.unwrap().derived_consistent());
}

#[tokio::test]
async fn offline_old_schema_commit_is_retained_but_invisible_in_both_receipt_orders() {
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

    left.collection::<TrackV1>()
        .put(TrackV1 {
            id: TrackId("teardrop".into()),
            title: register("Teardrop", 0),
        })
        .await
        .unwrap();
    let base = left
        .commit_envelopes()
        .await
        .unwrap()
        .into_iter()
        .find(|envelope| envelope.header().author() == left.author_id())
        .unwrap();
    right.collection::<TrackV1>();
    right
        .accept_remote_commit(left.author_id(), base)
        .await
        .unwrap();

    right
        .collection::<TrackV1>()
        .put(TrackV1 {
            id: TrackId("offline".into()),
            title: register("Offline", 0),
        })
        .await
        .unwrap();
    let old_schema_commit = right
        .commit_envelopes()
        .await
        .unwrap()
        .into_iter()
        .find(|envelope| envelope.header().author() == right.author_id())
        .unwrap();
    right.collection::<TrackV2>();

    left.close().await.unwrap();
    let left = IrohDb::builder(left_dir.path())
        .migration::<TrackV1, TrackV2>(migrate_track)
        .unwrap()
        .open()
        .await
        .unwrap();
    let mut migration_commits: Vec<_> = left
        .commit_envelopes()
        .await
        .unwrap()
        .into_iter()
        .filter(|envelope| {
            envelope.header().author() == left.author_id()
                && envelope.header().author_sequence() > 0
        })
        .collect();
    migration_commits.sort_by_key(|envelope| envelope.header().author_sequence());
    for envelope in migration_commits {
        assert!(matches!(
            right
                .accept_remote_commit(left.author_id(), envelope)
                .await
                .unwrap(),
            RemoteApply::Applied(_)
        ));
    }
    assert!(matches!(
        left.accept_remote_commit(right.author_id(), old_schema_commit)
            .await
            .unwrap(),
        RemoteApply::SchemaRebaseRequired { .. }
    ));

    let left_tracks = left.collection::<TrackV2>();
    let right_tracks = right.collection::<TrackV2>();
    assert!(
        left_tracks
            .get(&TrackId("offline".into()))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        right_tracks
            .get(&TrackId("offline".into()))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(left.state_root().unwrap(), right.state_root().unwrap());
    assert!(left.verify().await.unwrap().derived_consistent());
    assert!(right.verify().await.unwrap().derived_consistent());
}

#[tokio::test]
async fn empty_but_registered_collection_activates_without_stages() {
    let directory = tempfile::tempdir().unwrap();
    let database = IrohDb::open(directory.path()).await.unwrap();
    let tracks = database.collection::<TrackV1>();
    let id = TrackId("deleted".into());
    tracks
        .put(TrackV1 {
            id: id.clone(),
            title: register("Temporary", 0),
        })
        .await
        .unwrap();
    tracks.delete(&id).await.unwrap();
    drop(tracks);
    database.close().await.unwrap();

    let migrated = IrohDb::builder(directory.path())
        .migration::<TrackV1, TrackV2>(migrate_track)
        .unwrap()
        .open()
        .await
        .unwrap();
    assert!(
        migrated
            .collection::<TrackV2>()
            .query()
            .fetch()
            .await
            .unwrap()
            .is_empty()
    );
    assert!(migrated.verify().await.unwrap().derived_consistent());
}

#[tokio::test]
async fn migration_is_bounded_across_multiple_stage_commits() {
    let directory = tempfile::tempdir().unwrap();
    let database = IrohDb::open(directory.path()).await.unwrap();
    let mut transaction = database.transaction();
    for index in 0..257_u32 {
        transaction
            .put(TrackV1 {
                id: TrackId(format!("track-{index:03}")),
                title: register(&format!("Track {index}"), index),
            })
            .unwrap();
    }
    transaction.commit().await.unwrap();
    database.close().await.unwrap();

    let migrated = IrohDb::builder(directory.path())
        .migration::<TrackV1, TrackV2>(migrate_track)
        .unwrap()
        .open()
        .await
        .unwrap();
    assert_eq!(
        migrated
            .collection::<TrackV2>()
            .query()
            .fetch()
            .await
            .unwrap()
            .len(),
        257
    );
    // One source commit, two bounded stage commits, and one activation.
    assert_eq!(migrated.commit_envelopes().await.unwrap().len(), 4);
    assert!(migrated.verify().await.unwrap().derived_consistent());
}

#[tokio::test]
async fn builder_migrates_each_locally_attached_domain_independently() {
    let directory = tempfile::tempdir().unwrap();
    let database = IrohDb::open(directory.path()).await.unwrap();
    database
        .collection::<TrackV1>()
        .put(TrackV1 {
            id: TrackId("private".into()),
            title: register("Private", 0),
        })
        .await
        .unwrap();
    let shared = database
        .create_domain(ConsistencyMode::MultiWriter)
        .unwrap();
    let shared_id = shared.domain_id();
    shared
        .collection::<TrackV1>()
        .put(TrackV1 {
            id: TrackId("shared".into()),
            title: register("Shared", 0),
        })
        .await
        .unwrap();
    drop(shared);
    database.close().await.unwrap();

    let migrated = IrohDb::builder(directory.path())
        .migration::<TrackV1, TrackV2>(migrate_track)
        .unwrap()
        .open()
        .await
        .unwrap();
    assert!(
        migrated
            .collection::<TrackV2>()
            .get(&TrackId("private".into()))
            .await
            .unwrap()
            .is_some()
    );
    let shared = migrated.domain(shared_id).unwrap();
    assert!(
        shared
            .collection::<TrackV2>()
            .get(&TrackId("shared".into()))
            .await
            .unwrap()
            .is_some()
    );
    assert!(migrated.verify().await.unwrap().derived_consistent());
    assert!(shared.verify().await.unwrap().derived_consistent());
}

#[tokio::test]
async fn incompatible_activation_siblings_freeze_in_both_receipt_orders() {
    let seed = DomainSeed::generate().unwrap();
    let author_one_dir = tempfile::tempdir().unwrap();
    let author_two_dir = tempfile::tempdir().unwrap();
    let author_one = LocalCredentials::create_for_domain(author_one_dir.path(), &seed).unwrap();
    let author_two = LocalCredentials::create_for_domain(author_two_dir.path(), &seed).unwrap();
    let first = SchemaActivation::new(
        MigrationId::from_bytes([1; 32]),
        TrackV1::schema().unwrap(),
        TrackV2::schema().unwrap(),
        0,
        staging_digest(&[]).unwrap(),
    )
    .unwrap();
    let second = SchemaActivation::new(
        MigrationId::from_bytes([2; 32]),
        TrackV1::schema().unwrap(),
        TrackV2::schema().unwrap(),
        0,
        staging_digest(&[]).unwrap(),
    )
    .unwrap();
    let first_envelope = activation_envelope(&seed, &author_one, &first, 1);
    let second_envelope = activation_envelope(&seed, &author_two, &second, 2);

    for (initial, conflicting) in [
        (first_envelope.clone(), second_envelope.clone()),
        (second_envelope, first_envelope),
    ] {
        let receiver_dir = tempfile::tempdir().unwrap();
        let receiver = IrohDb::create_in_domain(receiver_dir.path(), &seed)
            .await
            .unwrap();
        receiver.trust_device(initial.header().author()).unwrap();
        receiver
            .trust_device(conflicting.header().author())
            .unwrap();
        receiver.collection::<TrackV1>();
        receiver.collection::<TrackV2>();
        assert!(matches!(
            receiver
                .accept_remote_commit(initial.header().author(), initial)
                .await
                .unwrap(),
            RemoteApply::Applied(_)
        ));
        assert!(matches!(
            receiver
                .accept_remote_commit(conflicting.header().author(), conflicting)
                .await,
            Err(DbError::Store(StoreError::SchemaMigrationFork { .. }))
        ));
        assert_eq!(receiver.commit_envelopes().await.unwrap().len(), 2);
        assert_eq!(
            receiver.operational_metrics().unwrap().frozen_migrations(),
            1
        );
        assert!(matches!(
            receiver
                .collection::<TrackV2>()
                .get(&TrackId("blocked".into()))
                .await,
            Err(DbError::SchemaMigrationFrozen(_))
        ));
    }
}

#[tokio::test]
async fn only_controlled_domain_controller_can_coordinate_migration() {
    let owner_dir = tempfile::tempdir().unwrap();
    let member_dir = tempfile::tempdir().unwrap();
    let owner_device = IrohDb::open(owner_dir.path()).await.unwrap();
    let member_device = IrohDb::open(member_dir.path()).await.unwrap();
    let owner = owner_device
        .create_domain(ConsistencyMode::MultiWriter)
        .unwrap();
    let domain_id = owner.domain_id();
    let invitation = owner
        .invite(
            member_device.author_id(),
            PermissionSet::from_permissions(&[Permission::Read, Permission::Write]),
            PermissionSet::empty(),
            None,
        )
        .unwrap();
    let member = member_device.import_invitation(&invitation).unwrap();
    owner
        .collection::<TrackV1>()
        .put(TrackV1 {
            id: TrackId("controlled".into()),
            title: register("Controlled", 0),
        })
        .await
        .unwrap();
    let base = owner.commit_envelopes().await.unwrap().pop().unwrap();
    member.collection::<TrackV1>();
    member
        .accept_remote_commit(owner.author_id(), base)
        .await
        .unwrap();
    drop(owner);
    drop(member);
    owner_device.close().await.unwrap();
    member_device.close().await.unwrap();

    assert!(matches!(
        IrohDb::builder(member_dir.path())
            .migration::<TrackV1, TrackV2>(migrate_track)
            .unwrap()
            .open()
            .await,
        Err(DbError::UnauthorizedDevice)
    ));

    let owner_device = IrohDb::builder(owner_dir.path())
        .migration::<TrackV1, TrackV2>(migrate_track)
        .unwrap()
        .open()
        .await
        .unwrap();
    let owner = owner_device.domain(domain_id).unwrap();
    let mut migration_commits: Vec<_> = owner
        .commit_envelopes()
        .await
        .unwrap()
        .into_iter()
        .filter(|envelope| envelope.header().author_sequence() > 0)
        .collect();
    migration_commits.sort_by_key(|envelope| envelope.header().author_sequence());

    let member_device = IrohDb::builder(member_dir.path())
        .migration::<TrackV1, TrackV2>(migrate_track)
        .unwrap()
        .defer_migrations()
        .open()
        .await
        .unwrap();
    let member = member_device.domain(domain_id).unwrap();
    for envelope in migration_commits {
        member
            .accept_remote_commit(owner.author_id(), envelope)
            .await
            .unwrap();
    }
    assert!(
        member
            .collection::<TrackV2>()
            .get(&TrackId("controlled".into()))
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn snapshot_bootstrap_preserves_active_cut_for_late_old_schema_tail() {
    let seed = DomainSeed::generate().unwrap();
    let source_dir = tempfile::tempdir().unwrap();
    let target_dir = tempfile::tempdir().unwrap();
    let old_writer_dir = tempfile::tempdir().unwrap();
    let source = IrohDb::create_in_domain(source_dir.path(), &seed)
        .await
        .unwrap();
    let target = IrohDb::create_in_domain(target_dir.path(), &seed)
        .await
        .unwrap();
    let old_writer = IrohDb::create_in_domain(old_writer_dir.path(), &seed)
        .await
        .unwrap();
    source.trust_device(target.author_id()).unwrap();
    target.trust_device(source.author_id()).unwrap();
    target.trust_device(old_writer.author_id()).unwrap();
    source
        .collection::<TrackV1>()
        .put(TrackV1 {
            id: TrackId("snapshot".into()),
            title: register("Snapshot", 0),
        })
        .await
        .unwrap();
    old_writer
        .collection::<TrackV1>()
        .put(TrackV1 {
            id: TrackId("late-old".into()),
            title: register("Late", 0),
        })
        .await
        .unwrap();
    let old_commit = old_writer.commit_envelopes().await.unwrap().pop().unwrap();
    source.close().await.unwrap();

    let source = IrohDb::builder(source_dir.path())
        .migration::<TrackV1, TrackV2>(migrate_track)
        .unwrap()
        .open()
        .await
        .unwrap();
    target.collection::<TrackV1>();
    target.collection::<TrackV2>();
    let snapshot = source.snapshot().await.unwrap();
    let source_node = source.start_sync().await.unwrap();
    let target_node = target.start_sync().await.unwrap();
    target_node
        .bootstrap_from(source_node.addr(), snapshot)
        .await
        .unwrap();

    assert!(matches!(
        target
            .accept_remote_commit(old_writer.author_id(), old_commit)
            .await
            .unwrap(),
        RemoteApply::SchemaRebaseRequired { .. }
    ));
    assert!(
        target
            .collection::<TrackV2>()
            .get(&TrackId("snapshot".into()))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        target
            .collection::<TrackV2>()
            .get(&TrackId("late-old".into()))
            .await
            .unwrap()
            .is_none()
    );
    assert!(target.verify().await.unwrap().derived_consistent());

    source_node.shutdown().await.unwrap();
    target_node.shutdown().await.unwrap();
}

#[tokio::test]
async fn adjacent_migration_chain_rebuilds_and_reopens_at_latest_version() {
    let directory = tempfile::tempdir().unwrap();
    let database = IrohDb::open(directory.path()).await.unwrap();
    database
        .collection::<TrackV1>()
        .put(TrackV1 {
            id: TrackId("chain".into()),
            title: register("Chain", 0),
        })
        .await
        .unwrap();
    database.close().await.unwrap();

    let (database, report) = IrohDb::builder(directory.path())
        .migration::<TrackV1, TrackV2>(migrate_track)
        .unwrap()
        .migration::<TrackV2, TrackV3>(migrate_track_v3)
        .unwrap()
        .open_with_report()
        .await
        .unwrap();
    assert_eq!(report.activated(), 2);
    let track = database
        .collection::<TrackV3>()
        .get(&TrackId("chain".into()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(track.mood.get().map(String::as_str), Some("Nocturnal"));
    assert!(database.verify().await.unwrap().derived_consistent());
    database.close().await.unwrap();

    let (reopened, report) = IrohDb::builder(directory.path())
        .migration::<TrackV1, TrackV2>(migrate_track)
        .unwrap()
        .migration::<TrackV2, TrackV3>(migrate_track_v3)
        .unwrap()
        .open_with_report()
        .await
        .unwrap();
    assert_eq!(report.already_activated(), 2);
    assert!(reopened.verify().await.unwrap().derived_consistent());
}
