use std::time::Duration;

use iroh_db::{AuthorId, Dot, IrohRecord, Lww, VersionVector};
use iroh_db_testkit::{FaultStep, TestCluster, TestkitError, rotating_partition};

#[derive(Debug, Clone, PartialEq, Eq, IrohRecord)]
#[iroh_db(collection = "testkit-notes", version = 1)]
struct Note {
    #[iroh_db(id, field_id = 1)]
    id: String,
    #[iroh_db(field_id = 2)]
    value: Lww<String>,
}

fn note(id: &str, value: &str, author: AuthorId) -> Note {
    let mut field = Lww::new();
    field
        .assign(
            value.to_owned(),
            Dot::new(author, 0, 0),
            VersionVector::new(),
        )
        .unwrap();
    Note {
        id: id.to_owned(),
        value: field,
    }
}

#[tokio::test]
async fn cluster_rejects_invalid_size_and_timeout() {
    assert!(matches!(
        TestCluster::builder(1).build().await,
        Err(TestkitError::InvalidPeerCount(1))
    ));
    assert!(matches!(
        TestCluster::builder(2)
            .operation_timeout(Duration::ZERO)
            .build()
            .await,
        Err(TestkitError::InvalidOperationTimeout)
    ));
}

#[tokio::test]
async fn real_peers_sync_and_report_convergence() {
    let cluster = TestCluster::new(3).await.unwrap();
    for index in 0..cluster.len() {
        drop(cluster.peer(index).unwrap().collection::<Note>());
    }
    let author = cluster.peer(0).unwrap().author_id();
    cluster
        .peer(0)
        .unwrap()
        .collection::<Note>()
        .put(note("one", "from-zero", author))
        .await
        .unwrap();

    cluster.sync(1, 0).await.unwrap();
    assert_eq!(
        cluster
            .peer(1)
            .unwrap()
            .collection::<Note>()
            .get(&"one".to_owned())
            .await
            .unwrap()
            .unwrap()
            .value
            .get()
            .map(String::as_str),
        Some("from-zero")
    );
    cluster.converge().await.unwrap();
    let report = cluster.convergence().unwrap();
    assert_eq!(report.peers(), 3);
    assert_eq!(
        report.state_root(),
        cluster.peer(0).unwrap().state_root().unwrap()
    );
    cluster.shutdown().await.unwrap();
}

#[tokio::test]
async fn stopped_nodes_fail_closed_then_rejoin() {
    let mut cluster = TestCluster::new(2).await.unwrap();
    cluster.stop_node(1).await.unwrap();
    assert!(matches!(
        cluster.sync(0, 1).await,
        Err(TestkitError::NodeStopped(1))
    ));
    assert!(matches!(
        cluster.stop_node(1).await,
        Err(TestkitError::NodeStopped(1))
    ));
    cluster.start_node(1).await.unwrap();
    assert!(matches!(
        cluster.start_node(1).await,
        Err(TestkitError::NodeRunning(1))
    ));
    cluster.sync(0, 1).await.unwrap();
    cluster.shutdown().await.unwrap();
}

#[tokio::test]
async fn durable_restart_preserves_identity_and_state() {
    let mut cluster = TestCluster::new(2).await.unwrap();
    let author = cluster.peer(1).unwrap().author_id();
    cluster
        .peer(1)
        .unwrap()
        .collection::<Note>()
        .put(note("durable", "before-restart", author))
        .await
        .unwrap();

    cluster.restart_peer(1).await.unwrap();
    assert_eq!(cluster.peer(1).unwrap().author_id(), author);
    assert!(
        cluster
            .peer(1)
            .unwrap()
            .collection::<Note>()
            .get(&"durable".to_owned())
            .await
            .unwrap()
            .is_some()
    );
    cluster.shutdown().await.unwrap();
}

#[tokio::test]
async fn deterministic_fault_schedule_counts_every_transition() {
    assert_eq!(
        rotating_partition(0, 3).unwrap(),
        vec![
            FaultStep::Sync { from: 0, to: 1 },
            FaultStep::Sync { from: 1, to: 2 },
        ]
    );
    assert_eq!(
        rotating_partition(1, 3).unwrap(),
        vec![
            FaultStep::Sync { from: 2, to: 0 },
            FaultStep::Sync { from: 0, to: 1 },
        ]
    );
    let mut cluster = TestCluster::new(3).await.unwrap();
    let report = cluster
        .apply_schedule(&[
            FaultStep::StopNode { peer: 2 },
            FaultStep::StartNode { peer: 2 },
            FaultStep::RestartPeer { peer: 1 },
            FaultStep::Sync { from: 0, to: 2 },
        ])
        .await
        .unwrap();
    assert_eq!(report.stops(), 1);
    assert_eq!(report.starts(), 1);
    assert_eq!(report.restarts(), 1);
    assert_eq!(report.syncs(), 1);
    cluster.shutdown().await.unwrap();
}
