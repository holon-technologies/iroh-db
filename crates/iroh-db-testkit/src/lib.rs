//! Real-iroh peer fixtures and deterministic fault injection for iroh-db.

#![forbid(unsafe_code)]

use std::{future::Future, path::Path, pin::Pin, time::Duration};

use iroh::EndpointAddr;
use iroh_db::{DbError, IrohDb, SyncNode, SyncReport};
use tempfile::TempDir;

const DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_secs(10);

/// A deterministic network or lifecycle transition applied to a test cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultStep {
    /// Reconcile the source peer with the target peer.
    Sync { from: usize, to: usize },
    /// Stop one peer's network protocols while leaving its database open.
    StopNode { peer: usize },
    /// Start network protocols for a stopped peer.
    StartNode { peer: usize },
    /// Stop, close, reopen, and restart one durable peer.
    RestartPeer { peer: usize },
}

/// Typed failures from cluster setup, fault execution, or qualification.
#[derive(Debug, thiserror::Error)]
pub enum TestkitError {
    #[error("test clusters require at least two peers, got {0}")]
    InvalidPeerCount(usize),
    #[error("test-cluster operation timeout must be non-zero")]
    InvalidOperationTimeout,
    #[error("peer index {index} is outside a {peers}-peer cluster")]
    InvalidPeerIndex { index: usize, peers: usize },
    #[error("peer {0} is unavailable after an incomplete lifecycle transition")]
    PeerUnavailable(usize),
    #[error("peer {0} network node is stopped")]
    NodeStopped(usize),
    #[error("peer {0} network node is already running")]
    NodeRunning(usize),
    #[error("test-cluster operation timed out: {0}")]
    Timeout(&'static str),
    #[error("test peers did not converge to one state root")]
    Diverged,
    #[error("database operation failed: {0}")]
    Database(#[from] DbError),
    #[error("test fixture filesystem failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Counts of deterministic fault steps completed by a schedule.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FaultReport {
    syncs: usize,
    stops: usize,
    starts: usize,
    restarts: usize,
}

impl FaultReport {
    pub const fn syncs(self) -> usize {
        self.syncs
    }

    pub const fn stops(self) -> usize {
        self.stops
    }

    pub const fn starts(self) -> usize {
        self.starts
    }

    pub const fn restarts(self) -> usize {
        self.restarts
    }
}

/// Successful whole-cluster convergence evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConvergenceReport {
    peers: usize,
    state_root: [u8; 32],
}

impl ConvergenceReport {
    pub const fn peers(self) -> usize {
        self.peers
    }

    pub const fn state_root(self) -> [u8; 32] {
        self.state_root
    }
}

/// Builder for a temporary real-iroh cluster.
#[derive(Debug, Clone, Copy)]
pub struct TestClusterBuilder {
    peers: usize,
    operation_timeout: Duration,
}

impl TestClusterBuilder {
    /// Sets the deadline independently applied to every network/lifecycle action.
    #[must_use]
    pub const fn operation_timeout(mut self, timeout: Duration) -> Self {
        self.operation_timeout = timeout;
        self
    }

    /// Creates databases in one domain, establishes mutual trust, and starts all nodes.
    pub async fn build(self) -> Result<TestCluster, TestkitError> {
        if self.peers < 2 {
            return Err(TestkitError::InvalidPeerCount(self.peers));
        }
        if self.operation_timeout.is_zero() {
            return Err(TestkitError::InvalidOperationTimeout);
        }

        let mut roots = Vec::with_capacity(self.peers);
        for _ in 0..self.peers {
            roots.push(tempfile::tempdir()?);
        }
        let first = within(
            self.operation_timeout,
            "open first peer",
            Box::pin(IrohDb::open(roots[0].path())),
        )
        .await?;
        let seed = first.domain_seed();
        let mut databases = Vec::with_capacity(self.peers);
        databases.push(Some(first));
        for root in roots.iter().skip(1) {
            databases.push(Some(
                within(
                    self.operation_timeout,
                    "create domain peer",
                    Box::pin(IrohDb::create_in_domain(root.path(), &seed)),
                )
                .await?,
            ));
        }
        let authors = databases
            .iter()
            .enumerate()
            .map(|(index, database)| {
                database
                    .as_ref()
                    .ok_or(TestkitError::PeerUnavailable(index))
                    .map(IrohDb::author_id)
            })
            .collect::<Result<Vec<_>, _>>()?;
        for (index, database) in databases.iter().enumerate() {
            let database = database
                .as_ref()
                .ok_or(TestkitError::PeerUnavailable(index))?;
            for author in &authors {
                database.trust_device(*author)?;
            }
        }
        let mut nodes = Vec::with_capacity(self.peers);
        for (index, database) in databases.iter().enumerate() {
            let database = database
                .as_ref()
                .ok_or(TestkitError::PeerUnavailable(index))?;
            nodes.push(Some(
                within(
                    self.operation_timeout,
                    "start peer node",
                    Box::pin(database.start_sync()),
                )
                .await?,
            ));
        }
        Ok(TestCluster {
            roots,
            databases,
            nodes,
            operation_timeout: self.operation_timeout,
        })
    }
}

/// An isolated temporary cluster that exercises the production iroh protocols.
pub struct TestCluster {
    roots: Vec<TempDir>,
    databases: Vec<Option<IrohDb>>,
    nodes: Vec<Option<SyncNode>>,
    operation_timeout: Duration,
}

impl TestCluster {
    /// Returns a builder using a ten-second deadline per operation.
    pub const fn builder(peers: usize) -> TestClusterBuilder {
        TestClusterBuilder {
            peers,
            operation_timeout: DEFAULT_OPERATION_TIMEOUT,
        }
    }

    /// Creates a cluster with the default operation deadline.
    pub async fn new(peers: usize) -> Result<Self, TestkitError> {
        Box::pin(Self::builder(peers).build()).await
    }

    /// Returns the number of peer slots.
    pub fn len(&self) -> usize {
        self.databases.len()
    }

    /// Returns whether the cluster has no peer slots.
    pub fn is_empty(&self) -> bool {
        self.databases.is_empty()
    }

    /// Borrows one open embedded database.
    pub fn peer(&self, index: usize) -> Result<&IrohDb, TestkitError> {
        self.validate_index(index)?;
        self.databases[index]
            .as_ref()
            .ok_or(TestkitError::PeerUnavailable(index))
    }

    /// Returns the durable temporary root owned for one peer.
    pub fn root(&self, index: usize) -> Result<&Path, TestkitError> {
        self.validate_index(index)?;
        Ok(self.roots[index].path())
    }

    /// Returns the currently running endpoint address for one peer.
    pub fn node_addr(&self, index: usize) -> Result<EndpointAddr, TestkitError> {
        self.validate_index(index)?;
        self.nodes[index]
            .as_ref()
            .map(SyncNode::addr)
            .ok_or(TestkitError::NodeStopped(index))
    }

    /// Reconciles one directed edge under the cluster operation deadline.
    pub async fn sync(&self, from: usize, to: usize) -> Result<SyncReport, TestkitError> {
        self.validate_index(from)?;
        self.validate_index(to)?;
        let source = self.nodes[from]
            .as_ref()
            .ok_or(TestkitError::NodeStopped(from))?;
        let target = self.node_addr(to)?;
        within(
            self.operation_timeout,
            "sync peers",
            Box::pin(source.sync_with(target)),
        )
        .await
    }

    /// Stops one peer's networking while preserving its open local database.
    pub async fn stop_node(&mut self, peer: usize) -> Result<(), TestkitError> {
        self.validate_index(peer)?;
        let node = self.nodes[peer]
            .take()
            .ok_or(TestkitError::NodeStopped(peer))?;
        within(
            self.operation_timeout,
            "stop peer node",
            Box::pin(node.shutdown()),
        )
        .await
    }

    /// Starts networking for one stopped peer.
    pub async fn start_node(&mut self, peer: usize) -> Result<(), TestkitError> {
        self.validate_index(peer)?;
        if self.nodes[peer].is_some() {
            return Err(TestkitError::NodeRunning(peer));
        }
        let database = self.databases[peer]
            .as_ref()
            .ok_or(TestkitError::PeerUnavailable(peer))?;
        self.nodes[peer] = Some(
            within(
                self.operation_timeout,
                "start peer node",
                Box::pin(database.start_sync()),
            )
            .await?,
        );
        Ok(())
    }

    /// Reopens one durable peer and restarts its network protocols.
    pub async fn restart_peer(&mut self, peer: usize) -> Result<(), TestkitError> {
        self.validate_index(peer)?;
        if let Some(node) = self.nodes[peer].take() {
            within(
                self.operation_timeout,
                "stop peer for restart",
                Box::pin(node.shutdown()),
            )
            .await?;
        }
        let database = self.databases[peer]
            .take()
            .ok_or(TestkitError::PeerUnavailable(peer))?;
        within(
            self.operation_timeout,
            "close peer for restart",
            Box::pin(database.close()),
        )
        .await?;
        let reopened = within(
            self.operation_timeout,
            "reopen durable peer",
            Box::pin(IrohDb::open(self.roots[peer].path())),
        )
        .await?;
        self.databases[peer] = Some(reopened);
        Box::pin(self.start_node(peer)).await
    }

    /// Applies deterministic fault steps in order and reports completed transitions.
    pub async fn apply_schedule(
        &mut self,
        schedule: &[FaultStep],
    ) -> Result<FaultReport, TestkitError> {
        let mut report = FaultReport::default();
        for step in schedule {
            match *step {
                FaultStep::Sync { from, to } => {
                    self.sync(from, to).await?;
                    report.syncs += 1;
                }
                FaultStep::StopNode { peer } => {
                    self.stop_node(peer).await?;
                    report.stops += 1;
                }
                FaultStep::StartNode { peer } => {
                    Box::pin(self.start_node(peer)).await?;
                    report.starts += 1;
                }
                FaultStep::RestartPeer { peer } => {
                    Box::pin(self.restart_peer(peer)).await?;
                    report.restarts += 1;
                }
            }
        }
        Ok(report)
    }

    /// Reconciles every directed edge between currently running nodes.
    pub async fn converge(&self) -> Result<FaultReport, TestkitError> {
        let mut report = FaultReport::default();
        for from in 0..self.len() {
            if self.nodes[from].is_none() {
                continue;
            }
            for to in 0..self.len() {
                if from != to && self.nodes[to].is_some() {
                    self.sync(from, to).await?;
                    report.syncs += 1;
                }
            }
        }
        Ok(report)
    }

    /// Verifies that every open peer has the same canonical state root.
    pub fn convergence(&self) -> Result<ConvergenceReport, TestkitError> {
        let mut roots = Vec::with_capacity(self.len());
        for index in 0..self.len() {
            roots.push(self.peer(index)?.state_root()?);
        }
        let Some(state_root) = roots.first().copied() else {
            return Err(TestkitError::Diverged);
        };
        if roots.iter().any(|root| *root != state_root) {
            return Err(TestkitError::Diverged);
        }
        Ok(ConvergenceReport {
            peers: roots.len(),
            state_root,
        })
    }

    /// Best-effort clean shutdown of every node and database.
    pub async fn shutdown(mut self) -> Result<(), TestkitError> {
        let mut first_error = None;
        for node in &mut self.nodes {
            if let Some(node) = node.take()
                && let Err(error) = within(
                    self.operation_timeout,
                    "shutdown peer node",
                    Box::pin(node.shutdown()),
                )
                .await
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        for database in &mut self.databases {
            if let Some(database) = database.take()
                && let Err(error) = within(
                    self.operation_timeout,
                    "close peer database",
                    Box::pin(database.close()),
                )
                .await
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn validate_index(&self, index: usize) -> Result<(), TestkitError> {
        if index < self.len() {
            Ok(())
        } else {
            Err(TestkitError::InvalidPeerIndex {
                index,
                peers: self.len(),
            })
        }
    }
}

/// Two directed links that rotate a two-or-more-peer partition schedule.
pub fn rotating_partition(round: usize, peers: usize) -> Result<Vec<FaultStep>, TestkitError> {
    if peers < 2 {
        return Err(TestkitError::InvalidPeerCount(peers));
    }
    let start = (peers - (round % peers)) % peers;
    let middle = (start + 1) % peers;
    let end = (middle + 1) % peers;
    Ok(vec![
        FaultStep::Sync {
            from: start,
            to: middle,
        },
        FaultStep::Sync {
            from: middle,
            to: end,
        },
    ])
}

async fn within<T>(
    timeout: Duration,
    operation: &'static str,
    future: Pin<Box<dyn Future<Output = Result<T, DbError>> + '_>>,
) -> Result<T, TestkitError> {
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| TestkitError::Timeout(operation))?
        .map_err(TestkitError::from)
}
