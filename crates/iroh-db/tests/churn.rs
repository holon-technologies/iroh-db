use iroh_db::{AuthorId, Dot, IrohDb, IrohRecord, Lww, VersionVector};

#[derive(Debug, Clone, PartialEq, Eq, IrohRecord)]
#[iroh_db(collection = "churn-notes", version = 1)]
struct Note {
    #[iroh_db(id, field_id = 1)]
    id: String,
    #[iroh_db(field_id = 2)]
    value: Lww<String>,
}

fn note(peer: usize, round: usize, author: AuthorId) -> Note {
    let mut value = Lww::new();
    value
        .assign(
            format!("peer-{peer}-round-{round}"),
            Dot::new(author, u64::try_from(round).unwrap(), 0),
            VersionVector::new(),
        )
        .unwrap();
    Note {
        id: format!("{peer}-{round}"),
        value,
    }
}

#[tokio::test]
async fn repeated_partition_reconnect_schedule_converges() {
    run_schedule(8).await;
}

#[tokio::test]
#[ignore = "extended production soak; set IROH_DB_SOAK_ROUNDS and run explicitly"]
async fn extended_partition_reconnect_soak() {
    let rounds = std::env::var("IROH_DB_SOAK_ROUNDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(10_000);
    run_schedule(rounds).await;
}

#[allow(clippy::too_many_lines)]
async fn run_schedule(rounds: usize) {
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let c_dir = tempfile::tempdir().unwrap();
    let a = IrohDb::open(a_dir.path()).await.unwrap();
    let seed = a.domain_seed();
    let b = IrohDb::create_in_domain(b_dir.path(), &seed).await.unwrap();
    let c = IrohDb::create_in_domain(c_dir.path(), &seed).await.unwrap();
    for database in [&a, &b, &c] {
        for author in [a.author_id(), b.author_id(), c.author_id()] {
            database.trust_device(author).unwrap();
        }
    }
    let a_notes = a.collection::<Note>();
    let b_notes = b.collection::<Note>();
    let c_notes = c.collection::<Note>();
    let a_node = a.start_sync().await.unwrap();
    let b_node = b.start_sync().await.unwrap();
    let c_node = c.start_sync().await.unwrap();

    for round in 0..rounds {
        a_notes.put(note(0, round, a.author_id())).await.unwrap();
        b_notes.put(note(1, round, b.author_id())).await.unwrap();
        c_notes.put(note(2, round, c.author_id())).await.unwrap();
        match round % 3 {
            0 => {
                a_node.sync_with(b_node.addr()).await.unwrap();
                b_node.sync_with(c_node.addr()).await.unwrap();
            }
            1 => {
                c_node.sync_with(a_node.addr()).await.unwrap();
                a_node.sync_with(b_node.addr()).await.unwrap();
            }
            _ => {
                b_node.sync_with(c_node.addr()).await.unwrap();
                c_node.sync_with(a_node.addr()).await.unwrap();
            }
        }
    }
    a_node.sync_with(b_node.addr()).await.unwrap();
    b_node.sync_with(c_node.addr()).await.unwrap();
    c_node.sync_with(a_node.addr()).await.unwrap();
    assert_eq!(a.state_root().unwrap(), b.state_root().unwrap());
    assert_eq!(b.state_root().unwrap(), c.state_root().unwrap());
    assert_eq!(a_notes.query().fetch().await.unwrap().len(), rounds * 3);

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
