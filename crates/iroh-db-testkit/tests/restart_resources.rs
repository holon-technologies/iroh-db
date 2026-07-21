#![cfg(target_os = "linux")]

use std::{fs, time::Duration};

use iroh_db::IrohDb;
use iroh_db_testkit::TestCluster;

#[tokio::test(flavor = "current_thread")]
async fn repeated_lifecycle_restarts_release_worker_threads() {
    assert_database_reopens_release_worker_threads().await;
    assert_network_restarts_release_worker_threads().await;
    assert_peer_restarts_release_worker_threads().await;
}

async fn assert_peer_restarts_release_worker_threads() {
    let mut cluster = TestCluster::builder(2).build().await.unwrap();

    for _ in 0..3 {
        cluster.restart_peer(0).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let warmed_threads = process_thread_count();

    for _ in 0..8 {
        cluster.restart_peer(0).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let final_threads = process_thread_count();

    cluster.shutdown().await.unwrap();
    assert!(
        final_threads <= warmed_threads + 1,
        "worker threads grew across settled restarts: warmed={warmed_threads}, final={final_threads}"
    );
}

fn process_thread_count() -> usize {
    fs::read_dir("/proc/self/task").unwrap().count()
}

fn process_thread_names() -> Vec<String> {
    let mut names = fs::read_dir("/proc/self/task")
        .unwrap()
        .filter_map(|entry| {
            fs::read_to_string(entry.ok()?.path().join("comm"))
                .ok()
                .map(|name| name.trim().to_owned())
        })
        .collect::<Vec<_>>();
    names.sort();
    names
}

async fn assert_database_reopens_release_worker_threads() {
    let directory = tempfile::tempdir().unwrap();
    let mut database = IrohDb::open(directory.path()).await.unwrap();
    for _ in 0..3 {
        database.close().await.unwrap();
        database = IrohDb::open(directory.path()).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let warmed_threads = process_thread_count();

    for _ in 0..8 {
        database.close().await.unwrap();
        database = IrohDb::open(directory.path()).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let final_threads = process_thread_count();

    database.close().await.unwrap();
    assert!(
        final_threads <= warmed_threads + 1,
        "database workers grew across settled reopens: warmed={warmed_threads}, final={final_threads}, threads={:?}",
        process_thread_names()
    );
}

async fn assert_network_restarts_release_worker_threads() {
    let directory = tempfile::tempdir().unwrap();
    let database = IrohDb::open(directory.path()).await.unwrap();
    for _ in 0..3 {
        database
            .start_sync()
            .await
            .unwrap()
            .shutdown()
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let warmed_threads = process_thread_count();

    for _ in 0..8 {
        database
            .start_sync()
            .await
            .unwrap()
            .shutdown()
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let final_threads = process_thread_count();

    database.close().await.unwrap();
    assert!(
        final_threads <= warmed_threads + 1,
        "network workers grew across settled restarts: warmed={warmed_threads}, final={final_threads}"
    );
}
