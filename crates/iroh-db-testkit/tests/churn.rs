use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
use std::{
    fs::{self, OpenOptions},
    io::Write as _,
};

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

fn note(peer: usize, round: usize, record_slots: usize, author: AuthorId) -> Note {
    assert!(record_slots > 0);
    let slot = round % record_slots;
    let mut value = Lww::new();
    value
        .assign(
            format!("peer-{peer}-round-{round}"),
            Dot::new(author, u64::try_from(round).unwrap(), 0),
            VersionVector::new(),
        )
        .unwrap();
    Note {
        id: format!("{peer}-{slot}"),
        value,
    }
}

#[test]
fn qualification_record_ids_are_bounded_per_peer() {
    let author = AuthorId::from_bytes([7; 32]);

    assert_eq!(note(2, 0, 4, author).id, note(2, 4, 4, author).id);
    assert_ne!(note(1, 0, 4, author).id, note(2, 0, 4, author).id);
}

#[derive(Debug, Clone)]
struct RunConfig {
    round_limit: Option<usize>,
    minimum_duration: Option<Duration>,
    record_slots: usize,
    restart_every: usize,
    operation_timeout: Duration,
    metrics_path: Option<PathBuf>,
    max_rss_anon_kib: Option<u64>,
}

#[tokio::test]
async fn repeated_partition_reconnect_schedule_converges() {
    run_schedule(RunConfig {
        round_limit: Some(8),
        minimum_duration: None,
        record_slots: 4,
        restart_every: 4,
        operation_timeout: Duration::from_secs(10),
        metrics_path: None,
        max_rss_anon_kib: None,
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
    let record_slots = positive_env_usize("IROH_DB_SOAK_RECORD_SLOTS")
        .unwrap()
        .unwrap_or(256);
    let operation_timeout = Duration::from_secs(
        positive_env_u64("IROH_DB_SOAK_OPERATION_TIMEOUT_SECS")
            .unwrap()
            .unwrap_or(10),
    );
    let metrics_path = std::env::var_os("IROH_DB_SOAK_METRICS_PATH").map(PathBuf::from);
    let max_rss_anon_kib = metrics_path.as_ref().map(|_| {
        positive_env_u64("IROH_DB_SOAK_MAX_RSS_ANON_KIB")
            .unwrap()
            .unwrap_or(256 * 1024)
    });
    run_schedule(RunConfig {
        round_limit,
        minimum_duration,
        record_slots,
        restart_every,
        operation_timeout,
        metrics_path,
        max_rss_anon_kib,
    })
    .await;
}

#[allow(clippy::too_many_lines)]
async fn run_schedule(config: RunConfig) {
    assert!(config.round_limit.is_some() || config.minimum_duration.is_some());
    assert!(config.record_slots > 0);
    assert!(config.restart_every > 0);
    let started = Instant::now();
    if let Some(path) = &config.metrics_path {
        initialize_resource_metrics(path, started).unwrap();
    }
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
                .put(note(
                    peer,
                    rounds,
                    config.record_slots,
                    database.author_id(),
                ))
                .await
                .unwrap();
        }
        let writes_elapsed = writes_started.elapsed();
        let schedule = rotating_partition(rounds, cluster.len()).unwrap();
        let sync_started = Instant::now();
        let report = match cluster.apply_schedule(&schedule).await {
            Ok(report) => report,
            Err(error) => {
                let metrics_error = config
                    .metrics_path
                    .as_ref()
                    .and_then(|path| append_resource_metrics(path, started, rounds).err());
                panic!(
                    "soak round {rounds} failed after {:.3}s (writes {:.3}s, sync {:.3}s) with schedule {schedule:?}: {error}; metrics_error={metrics_error:?}",
                    round_started.elapsed().as_secs_f64(),
                    writes_elapsed.as_secs_f64(),
                    sync_started.elapsed().as_secs_f64(),
                )
            }
        };
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
            if let Some(path) = &config.metrics_path {
                let sample = append_resource_metrics(path, started, rounds).unwrap();
                if let Some(max_rss_anon_kib) = config.max_rss_anon_kib {
                    enforce_anonymous_memory_budget(sample, max_rss_anon_kib)
                        .unwrap_or_else(|error| panic!("soak round {rounds}: {error}"));
                }
            }
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
        rounds.min(config.record_slots) * 3
    );
    println!(
        "iroh-db soak: rounds={rounds} elapsed_secs={:.3} syncs={syncs} restarts={restarts} state_root={}",
        started.elapsed().as_secs_f64(),
        hex(&convergence.state_root())
    );
    if let Some(path) = &config.metrics_path {
        let sample = append_resource_metrics(path, started, rounds).unwrap();
        if let Some(max_rss_anon_kib) = config.max_rss_anon_kib {
            enforce_anonymous_memory_budget(sample, max_rss_anon_kib)
                .unwrap_or_else(|error| panic!("soak final sample: {error}"));
        }
    }
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

#[test]
fn qualification_resource_samples_parse_linux_process_status() {
    let status = concat!(
        "Name:\tiroh-db\n",
        "VmRSS:\t  24700 kB\n",
        "RssAnon:\t  4700 kB\n",
        "RssFile:\t  19000 kB\n",
        "RssShmem:\t  1000 kB\n",
        "Threads:\t13\n",
    );
    let sample = parse_linux_process_status(status).unwrap();

    assert_eq!(sample.rss_kib, 24_700);
    assert_eq!(sample.rss_anon_kib, 4_700);
    assert_eq!(sample.rss_file_kib, 19_000);
    assert_eq!(sample.rss_shmem_kib, 1_000);
    assert_eq!(sample.threads, 13);
}

#[test]
fn qualification_resource_samples_reject_incomplete_process_status() {
    assert!(parse_linux_process_status("Name:\tiroh-db\nThreads:\t3\n").is_err());
    assert!(parse_linux_process_status("Name:\tiroh-db\nVmRSS:\t100 kB\n").is_err());
}

#[test]
fn qualification_rejects_anonymous_memory_budget_breaches() {
    let sample = ProcessResourceSample {
        rss_kib: 100_000,
        rss_anon_kib: 70_000,
        rss_file_kib: 30_000,
        rss_shmem_kib: 0,
        threads: 14,
    };

    assert!(enforce_anonymous_memory_budget(sample, 70_000).is_ok());
    assert!(enforce_anonymous_memory_budget(sample, 69_999).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn qualification_resource_metrics_are_durable_tsv() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("metrics.tsv");
    let started = Instant::now();

    initialize_resource_metrics(&path, started).unwrap();
    append_resource_metrics(&path, started, 25).unwrap();

    let contents = fs::read_to_string(path).unwrap();
    let lines: Vec<_> = contents.lines().collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0].split('\t').count(), 10);
    assert_eq!(lines[1].split('\t').count(), 10);
    assert_eq!(lines[2].split('\t').count(), 10);
    assert_eq!(lines[2].split('\t').nth(1), Some("25"));
}

#[cfg(target_os = "linux")]
#[test]
fn qualification_resource_metrics_parse_host_pressure() {
    let pressure = "some avg10=1.25 avg60=0.30 avg300=0.10 total=42\nfull avg10=0.00";
    assert!((parse_linux_pressure_avg10(pressure).unwrap() - 1.25).abs() < f64::EPSILON);
    assert!(parse_linux_pressure_avg10("full avg10=1.00").is_err());
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcessResourceSample {
    rss_kib: u64,
    rss_anon_kib: u64,
    rss_file_kib: u64,
    rss_shmem_kib: u64,
    threads: u64,
}

fn parse_linux_process_status(status: &str) -> Result<ProcessResourceSample, String> {
    let mut rss_kib = None;
    let mut rss_anon_kib = None;
    let mut rss_file_kib = None;
    let mut rss_shmem_kib = None;
    let mut threads = None;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("VmRSS:") {
            rss_kib = value
                .split_whitespace()
                .next()
                .and_then(|value| value.parse().ok());
        } else if let Some(value) = line.strip_prefix("RssAnon:") {
            rss_anon_kib = value
                .split_whitespace()
                .next()
                .and_then(|value| value.parse().ok());
        } else if let Some(value) = line.strip_prefix("RssFile:") {
            rss_file_kib = value
                .split_whitespace()
                .next()
                .and_then(|value| value.parse().ok());
        } else if let Some(value) = line.strip_prefix("RssShmem:") {
            rss_shmem_kib = value
                .split_whitespace()
                .next()
                .and_then(|value| value.parse().ok());
        } else if let Some(value) = line.strip_prefix("Threads:") {
            threads = value.trim().parse().ok();
        }
    }
    Ok(ProcessResourceSample {
        rss_kib: rss_kib.ok_or_else(|| "process status is missing VmRSS".to_owned())?,
        rss_anon_kib: rss_anon_kib.ok_or_else(|| "process status is missing RssAnon".to_owned())?,
        rss_file_kib: rss_file_kib.ok_or_else(|| "process status is missing RssFile".to_owned())?,
        rss_shmem_kib: rss_shmem_kib
            .ok_or_else(|| "process status is missing RssShmem".to_owned())?,
        threads: threads.ok_or_else(|| "process status is missing Threads".to_owned())?,
    })
}

fn enforce_anonymous_memory_budget(
    sample: ProcessResourceSample,
    max_rss_anon_kib: u64,
) -> Result<(), String> {
    if sample.rss_anon_kib > max_rss_anon_kib {
        return Err(format!(
            "anonymous RSS {} KiB exceeds qualification budget {max_rss_anon_kib} KiB",
            sample.rss_anon_kib
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn initialize_resource_metrics(path: &Path, started: Instant) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("create soak metrics file: {error}"))?;
    writeln!(
        file,
        "elapsed_secs\trounds\trss_kib\trss_anon_kib\trss_file_kib\trss_shmem_kib\tthreads\topen_fds\thost_mem_available_kib\tmemory_pressure_avg10"
    )
    .map_err(|error| format!("write soak metrics header: {error}"))?;
    drop(file);
    append_resource_metrics(path, started, 0).map(drop)
}

#[cfg(target_os = "linux")]
fn append_resource_metrics(
    path: &Path,
    started: Instant,
    rounds: usize,
) -> Result<ProcessResourceSample, String> {
    let process = fs::read_to_string("/proc/self/status")
        .map_err(|error| format!("read process status: {error}"))
        .and_then(|status| parse_linux_process_status(&status))?;
    let open_fds = fs::read_dir("/proc/self/fd")
        .map_err(|error| format!("read process file descriptors: {error}"))?
        .count();
    let meminfo = fs::read_to_string("/proc/meminfo")
        .map_err(|error| format!("read host memory information: {error}"))?;
    let host_mem_available_kib = parse_linux_key_value(&meminfo, "MemAvailable:")?;
    let pressure = fs::read_to_string("/proc/pressure/memory")
        .map_err(|error| format!("read host memory pressure: {error}"))?;
    let memory_pressure_avg10 = parse_linux_pressure_avg10(&pressure)?;
    let mut file = OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(|error| format!("open soak metrics file: {error}"))?;
    writeln!(
        file,
        "{:.3}\t{rounds}\t{}\t{}\t{}\t{}\t{}\t{open_fds}\t{host_mem_available_kib}\t{memory_pressure_avg10:.2}",
        started.elapsed().as_secs_f64(),
        process.rss_kib,
        process.rss_anon_kib,
        process.rss_file_kib,
        process.rss_shmem_kib,
        process.threads,
    )
    .map_err(|error| format!("append soak metrics sample: {error}"))?;
    Ok(process)
}

#[cfg(target_os = "linux")]
fn parse_linux_key_value(contents: &str, key: &str) -> Result<u64, String> {
    contents
        .lines()
        .find_map(|line| {
            line.strip_prefix(key)
                .and_then(|value| value.split_whitespace().next())
                .and_then(|value| value.parse().ok())
        })
        .ok_or_else(|| format!("host metrics are missing {key}"))
}

#[cfg(target_os = "linux")]
fn parse_linux_pressure_avg10(contents: &str) -> Result<f64, String> {
    contents
        .lines()
        .find(|line| line.starts_with("some "))
        .and_then(|line| {
            line.split_whitespace()
                .find_map(|field| field.strip_prefix("avg10="))
        })
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| "host metrics are missing memory pressure avg10".to_owned())
}

#[cfg(not(target_os = "linux"))]
fn initialize_resource_metrics(_path: &Path, _started: Instant) -> Result<(), String> {
    Err("soak resource metrics require Linux /proc".to_owned())
}

#[cfg(not(target_os = "linux"))]
fn append_resource_metrics(
    _path: &Path,
    _started: Instant,
    _rounds: usize,
) -> Result<ProcessResourceSample, String> {
    Err("soak resource metrics require Linux /proc".to_owned())
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
