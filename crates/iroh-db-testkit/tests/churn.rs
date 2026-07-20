use std::time::{Duration, Instant};

use iroh_db::{AuthorId, Dot, IrohRecord, Lww, VersionVector};
use iroh_db_testkit::{TestCluster, rotating_partition};

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

#[derive(Debug, Clone, Copy)]
struct RunConfig {
    round_limit: Option<usize>,
    minimum_duration: Option<Duration>,
    restart_every: usize,
    operation_timeout: Duration,
}

#[tokio::test]
async fn repeated_partition_reconnect_schedule_converges() {
    run_schedule(RunConfig {
        round_limit: Some(8),
        minimum_duration: None,
        restart_every: 4,
        operation_timeout: Duration::from_secs(10),
    })
    .await;
}

#[tokio::test]
#[ignore = "extended production soak; set IROH_DB_SOAK_DURATION_SECS or IROH_DB_SOAK_ROUNDS"]
async fn extended_partition_reconnect_soak() {
    let minimum_duration = positive_env_u64("IROH_DB_SOAK_DURATION_SECS")
        .unwrap()
        .map(Duration::from_secs);
    let round_limit = if minimum_duration.is_some() {
        None
    } else {
        Some(
            positive_env_usize("IROH_DB_SOAK_ROUNDS")
                .unwrap()
                .unwrap_or(10_000),
        )
    };
    let restart_every = positive_env_usize("IROH_DB_SOAK_RESTART_EVERY")
        .unwrap()
        .unwrap_or(97);
    let operation_timeout = Duration::from_secs(
        positive_env_u64("IROH_DB_SOAK_OPERATION_TIMEOUT_SECS")
            .unwrap()
            .unwrap_or(10),
    );
    run_schedule(RunConfig {
        round_limit,
        minimum_duration,
        restart_every,
        operation_timeout,
    })
    .await;
}

#[allow(clippy::too_many_lines)]
async fn run_schedule(config: RunConfig) {
    assert!(config.round_limit.is_some() || config.minimum_duration.is_some());
    assert!(config.restart_every > 0);
    let started = Instant::now();
    let mut cluster = TestCluster::builder(3)
        .operation_timeout(config.operation_timeout)
        .build()
        .await
        .unwrap();
    for peer in 0..cluster.len() {
        drop(cluster.peer(peer).unwrap().collection::<Note>());
    }

    let mut rounds = 0_usize;
    let mut syncs = 0_usize;
    let mut restarts = 0_usize;
    loop {
        if rounds > 0
            && config
                .minimum_duration
                .is_some_and(|duration| started.elapsed() >= duration)
        {
            break;
        }
        if config.round_limit.is_some_and(|limit| rounds >= limit) {
            break;
        }
        let round_started = Instant::now();
        let writes_started = Instant::now();
        for peer in 0..cluster.len() {
            let database = cluster.peer(peer).unwrap();
            database
                .collection::<Note>()
                .put(note(peer, rounds, database.author_id()))
                .await
                .unwrap();
        }
        let writes_elapsed = writes_started.elapsed();
        let schedule = rotating_partition(rounds, cluster.len()).unwrap();
        let sync_started = Instant::now();
        let report = cluster
            .apply_schedule(&schedule)
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "soak round {rounds} failed after {:.3}s with schedule {schedule:?}: {error}",
                    round_started.elapsed().as_secs_f64()
                )
            });
        let sync_elapsed = sync_started.elapsed();
        syncs += report.syncs();
        rounds += 1;
        if rounds.is_multiple_of(config.restart_every) {
            let peer = (rounds / config.restart_every - 1) % cluster.len();
            cluster.restart_peer(peer).await.unwrap();
            drop(cluster.peer(peer).unwrap().collection::<Note>());
            restarts += 1;
        }
        if rounds.is_multiple_of(25) {
            println!(
                "iroh-db soak progress: rounds={rounds} elapsed_secs={:.3} last_round_secs={:.3} writes_secs={:.3} sync_secs={:.3} syncs={syncs} restarts={restarts}",
                started.elapsed().as_secs_f64(),
                round_started.elapsed().as_secs_f64(),
                writes_elapsed.as_secs_f64(),
                sync_elapsed.as_secs_f64()
            );
        }
    }

    syncs += cluster.converge().await.unwrap().syncs();
    let convergence = cluster.convergence().unwrap();
    assert_eq!(convergence.peers(), 3);
    assert_eq!(
        cluster
            .peer(0)
            .unwrap()
            .collection::<Note>()
            .query()
            .fetch()
            .await
            .unwrap()
            .len(),
        rounds * 3
    );
    println!(
        "iroh-db soak: rounds={rounds} elapsed_secs={:.3} syncs={syncs} restarts={restarts} state_root={}",
        started.elapsed().as_secs_f64(),
        hex(&convergence.state_root())
    );
    cluster.shutdown().await.unwrap();
}

fn positive_env_u64(name: &str) -> Result<Option<u64>, String> {
    parse_positive_u64(name, std::env::var_os(name))
}

fn parse_positive_u64(
    name: &str,
    value: Option<std::ffi::OsString>,
) -> Result<Option<u64>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value
        .into_string()
        .map_err(|_| format!("{name} must be valid UTF-8"))?;
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("{name} must be a positive integer"))?;
    if parsed == 0 {
        return Err(format!("{name} must be a positive integer"));
    }
    Ok(Some(parsed))
}

#[test]
fn qualification_inputs_reject_zero_and_malformed_values() {
    assert_eq!(parse_positive_u64("TEST", None).unwrap(), None);
    assert_eq!(
        parse_positive_u64("TEST", Some("7".into())).unwrap(),
        Some(7)
    );
    assert!(parse_positive_u64("TEST", Some("0".into())).is_err());
    assert!(parse_positive_u64("TEST", Some("nope".into())).is_err());
}

fn positive_env_usize(name: &str) -> Result<Option<usize>, String> {
    positive_env_u64(name)?
        .map(|value| {
            usize::try_from(value).map_err(|_| format!("{name} does not fit this platform"))
        })
        .transpose()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}
