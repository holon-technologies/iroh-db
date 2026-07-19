use std::collections::BTreeMap;
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;

use iroh::{
    Endpoint, EndpointAddr, RelayMode,
    address_lookup::memory::MemoryLookup,
    endpoint::{Connection, RecvStream, SendStream, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use iroh_blobs::provider::events::{
    AbortReason, ConnectMode, EventMask, EventSender, ObserveMode, ProviderMessage, RequestMode,
};
use iroh_db_blobs::{BlobEngine, BlobRef, BlobStream, FetchMetrics, FetchOptions};
use iroh_db_core::{AuthorId, BlobHash, CommitEnvelope, CommitId, DomainId};
use iroh_db_security::{Invitation, Permission, verify_gossip_signature};
use iroh_db_sync::{
    GossipHint, MAX_CONTROL_FRAME, MAX_REFERENCES, MAX_SESSION_REFERENCES, SyncFrame,
    missing_commits,
};
use iroh_gossip::{
    api::{Event as GossipEvent, GossipReceiver, GossipSender},
    net::Gossip,
    proto::TopicId,
};
use n0_future::StreamExt as _;

use crate::{DbError, IrohDb, Snapshot};

/// The sole iroh-db control-plane ALPN.
pub const SYNC_ALPN: &[u8] = b"/iroh-db/sync/1";

/// Result counters for one complete bidirectional reconciliation round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncReport {
    received: usize,
    sent: usize,
}

impl SyncReport {
    /// Number of remote commits fetched and accepted locally.
    pub const fn received(self) -> usize {
        self.received
    }

    /// Number of local commits pushed and accepted remotely.
    pub const fn sent(self) -> usize {
        self.sent
    }
}

/// A running iroh endpoint routing sync control and immutable blob protocols.
pub struct SyncNode {
    core: SyncCore,
    gossip: Gossip,
    lookup: MemoryLookup,
    router: Router,
}

impl SyncNode {
    /// Returns this endpoint's currently advertised direct/relay address.
    pub fn addr(&self) -> EndpointAddr {
        self.router.endpoint().addr()
    }

    /// Reconciles both peers over authenticated QUIC and iroh-blobs.
    pub async fn sync_with(&self, remote: EndpointAddr) -> Result<SyncReport, DbError> {
        self.core.sync_with(remote).await
    }

    /// Makes one signed invitation available to its endpoint-bound subject.
    pub fn offer_invitation(&self, invitation: &Invitation) -> Result<(), DbError> {
        let _control_reader = self
            .core
            .db
            .inner
            .control_gate
            .try_read()
            .map_err(|_| DbError::Operation("control plane is busy".into()))?;
        self.core.require_local_permission(Permission::Invite)?;
        if invitation.descriptor().domain_id() != self.core.domain_id() {
            return Err(protocol_error("invitation targets another domain"));
        }
        if invitation.domain_seed().epoch() != self.core.db.epoch() {
            return Err(DbError::UnauthorizedDevice);
        }
        let payload = invitation.encode_canonical()?;
        self.core
            .pending_invitations
            .write()
            .map_err(|_| protocol_error("invitation registry is unavailable"))?
            .insert(invitation.subject(), payload);
        Ok(())
    }

    /// Requests this authenticated endpoint's offered invitation and imports it locally.
    pub async fn request_invitation(&self, remote: EndpointAddr) -> Result<IrohDb, DbError> {
        let connection = self
            .core
            .endpoint
            .connect(remote, SYNC_ALPN)
            .await
            .map_err(network_error)?;
        let (mut send, mut recv) = connection.open_bi().await.map_err(network_error)?;
        send_frame(
            &mut send,
            &SyncFrame::Hello {
                nonce: random_nonce()?,
                max_frame: max_control_frame(),
            },
        )
        .await?;
        if !matches!(recv_frame(&mut recv).await?, SyncFrame::Hello { .. }) {
            return Err(protocol_error("expected hello"));
        }
        send_frame(&mut send, &SyncFrame::InvitationRequest).await?;
        let SyncFrame::Invitation { payload } = recv_frame(&mut recv).await? else {
            return Err(DbError::UnauthorizedDevice);
        };
        let invitation = Invitation::decode_canonical(&payload)?;
        let domain = self.core.db.import_invitation(&invitation)?;
        send.finish().map_err(network_error)?;
        Ok(domain)
    }

    /// Fetches and installs a trusted encrypted snapshot before ordinary tail reconciliation.
    pub async fn bootstrap_from(
        &self,
        remote: EndpointAddr,
        snapshot: Snapshot,
    ) -> Result<(), DbError> {
        self.core.require_local_blob_fetch()?;
        self.core.require_trusted(author_id(remote.id))?;
        let connection = self
            .core
            .endpoint
            .connect(remote, iroh_blobs::ALPN)
            .await
            .map_err(network_error)?;
        let engine = self.core.db.blob_engine();
        engine
            .fetch_from(&self.core.db.inner.blobs, connection, &snapshot.blob_ref())
            .await?;
        self.core.db.install_snapshot(snapshot).await
    }

    /// Downloads a complete encrypted blob from one authorized provider into pinned storage.
    pub async fn fetch_blob_from(
        &self,
        remote: EndpointAddr,
        reference: &BlobRef,
    ) -> Result<(), DbError> {
        self.core.require_local_blob_fetch()?;
        self.core.require_trusted(author_id(remote.id))?;
        let connection = self
            .core
            .endpoint
            .connect(remote, iroh_blobs::ALPN)
            .await
            .map_err(network_error)?;
        self.core
            .blob_engine()
            .fetch_from(&self.core.db.inner.blobs, connection, reference)
            .await
            .map_err(DbError::from)
    }

    /// Opens a lazy seekable stream whose missing chunks rotate across authorized providers.
    pub async fn stream_blob_from(
        &self,
        providers: Vec<EndpointAddr>,
        reference: &BlobRef,
        options: FetchOptions,
    ) -> Result<(BlobStream, FetchMetrics), DbError> {
        self.core.require_local_blob_fetch()?;
        let mut connections = Vec::with_capacity(providers.len());
        for provider in providers {
            self.core.require_trusted(author_id(provider.id))?;
            connections.push(
                self.core
                    .endpoint
                    .connect(provider, iroh_blobs::ALPN)
                    .await
                    .map_err(network_error)?,
            );
        }
        self.core
            .blob_engine()
            .open_from_providers(
                self.core.db.inner.blobs.as_ref().clone(),
                connections,
                reference,
                options,
            )
            .await
            .map_err(DbError::from)
    }

    /// Joins this domain's unguessable gossip topic using optional bootstrap endpoints.
    pub async fn join_gossip(
        &self,
        bootstrap: Vec<EndpointAddr>,
    ) -> Result<GossipSession, DbError> {
        self.core.require_local_permission(Permission::Read)?;
        for peer in &bootstrap {
            self.lookup.add_endpoint_info(peer.clone());
        }
        let peers: Vec<_> = bootstrap.into_iter().map(|peer| peer.id).collect();
        let topic = self.core.gossip_topic()?;
        let topic = if peers.is_empty() {
            self.gossip.subscribe(topic, peers).await
        } else {
            self.gossip.subscribe_and_join(topic, peers).await
        }
        .map_err(network_error)?;
        let (sender, receiver) = topic.split();
        Ok(GossipSession {
            core: self.core.clone(),
            sender,
            receiver,
            counter: Arc::new(AtomicU64::new(initial_gossip_counter())),
            seen: BTreeMap::new(),
        })
    }

    /// Stops network protocols without closing the embedded database.
    pub async fn shutdown(self) -> Result<(), DbError> {
        self.router
            .shutdown()
            .await
            .map_err(|error| DbError::Network(error.to_string()))
    }
}

/// An active, lossy gossip subscription that can announce and act on sync hints.
pub struct GossipSession {
    core: SyncCore,
    sender: GossipSender,
    receiver: GossipReceiver,
    counter: Arc<AtomicU64>,
    seen: BTreeMap<AuthorId, u64>,
}

impl GossipSession {
    /// Broadcasts a signed hash-only hint for the current commit frontier.
    pub async fn announce(&self) -> Result<GossipHint, DbError> {
        self.core.require_local_permission(Permission::Read)?;
        let commits = self.core.commit_ids()?;
        let commit = commits
            .last()
            .copied()
            .ok_or_else(|| protocol_error("cannot announce an empty commit set"))?;
        let frontier_digest = digest_commits(&commits);
        let counter = self.counter.fetch_add(1, Ordering::Relaxed);
        let signer = self.core.db.inner.credentials.signer();
        let unsigned = GossipHint::new(signer.author(), commit, frontier_digest, counter, [0; 64]);
        let signature = signer.sign_gossip(&unsigned.signing_bytes().map_err(sync_error)?);
        let hint = GossipHint::new(signer.author(), commit, frontier_digest, counter, signature);
        self.sender
            .broadcast(hint.encode_canonical().map_err(sync_error)?.into())
            .await
            .map_err(network_error)?;
        Ok(hint)
    }

    /// Waits for a valid hint and runs ordinary authenticated reconciliation with its provider.
    pub async fn sync_next(&mut self) -> Result<SyncReport, DbError> {
        self.core.require_local_permission(Permission::Read)?;
        loop {
            let event = self
                .receiver
                .next()
                .await
                .ok_or_else(|| protocol_error("gossip subscription closed"))?
                .map_err(network_error)?;
            let GossipEvent::Received(message) = event else {
                continue;
            };
            let provider = author_id(message.delivered_from);
            if !self.core.peer_has_permission(provider, Permission::Read) {
                continue;
            }
            let Ok(hint) = GossipHint::decode_canonical(&message.content) else {
                continue;
            };
            if !self
                .core
                .peer_has_permission(hint.author(), Permission::Read)
                || verify_gossip_signature(
                    hint.author(),
                    &hint.signing_bytes().map_err(sync_error)?,
                    hint.signature(),
                )
                .is_err()
                || self
                    .seen
                    .get(&hint.author())
                    .is_some_and(|counter| *counter >= hint.counter())
            {
                continue;
            }
            self.seen.insert(hint.author(), hint.counter());
            return self
                .core
                .sync_with(EndpointAddr::new(message.delivered_from))
                .await;
        }
    }
}

#[derive(Clone)]
struct SyncCore {
    db: IrohDb,
    endpoint: Endpoint,
    pending_invitations: Arc<RwLock<BTreeMap<AuthorId, Vec<u8>>>>,
}

#[derive(Clone)]
struct SyncProtocol {
    core: SyncCore,
}

impl std::fmt::Debug for SyncProtocol {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SyncProtocol")
    }
}

impl IrohDb {
    /// Starts a local iroh endpoint with sync and iroh-blobs protocol handlers.
    pub async fn start_sync(&self) -> Result<SyncNode, DbError> {
        let lookup = MemoryLookup::new();
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(self.inner.credentials.endpoint_secret_key())
            .address_lookup(lookup.clone())
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .map_err(|error| DbError::Network(error.to_string()))?;
        let core = SyncCore {
            db: self.clone(),
            endpoint: endpoint.clone(),
            pending_invitations: Arc::new(RwLock::new(BTreeMap::new())),
        };
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let blob_events = core.blob_provider_events();
        let router = Router::builder(endpoint)
            .accept(SYNC_ALPN, SyncProtocol { core: core.clone() })
            .accept(
                iroh_blobs::ALPN,
                self.inner.blobs.protocol_with_events(blob_events),
            )
            .accept(iroh_gossip::ALPN, gossip.clone())
            .spawn();
        Ok(SyncNode {
            core,
            gossip,
            lookup,
            router,
        })
    }
}

impl ProtocolHandler for SyncProtocol {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let peer = connection.remote_id();
        let (mut send, mut recv) = connection.accept_bi().await?;
        self.core
            .serve(peer, &mut send, &mut recv)
            .await
            .map_err(AcceptError::from_err)?;
        send.finish()?;
        connection.closed().await;
        Ok(())
    }
}

impl SyncCore {
    async fn sync_with(&self, remote: EndpointAddr) -> Result<SyncReport, DbError> {
        let peer = author_id(remote.id);
        self.require_local_blob_fetch()?;
        self.require_trusted(peer)?;
        let connection = self
            .endpoint
            .connect(remote.clone(), SYNC_ALPN)
            .await
            .map_err(network_error)?;
        let blobs_connection = self
            .endpoint
            .connect(remote, iroh_blobs::ALPN)
            .await
            .map_err(network_error)?;
        let (mut send, mut recv) = connection.open_bi().await.map_err(network_error)?;

        self.outbound_handshake(peer, &mut send, &mut recv).await?;

        let local = self.commit_ids()?;
        send_commit_pages(&mut send, FrameKind::Frontier, &local).await?;
        let remote = recv_commit_pages(&mut recv, FrameKind::Frontier).await?;
        let receive = missing_commits(&local, &remote).map_err(sync_error)?;
        send_commit_pages(&mut send, FrameKind::Need, &receive).await?;
        let to_send = recv_commit_pages(&mut recv, FrameKind::Need).await?;
        let expected_send = missing_commits(&remote, &local).map_err(sync_error)?;
        if to_send != expected_send {
            return Err(protocol_error("peer requested an invalid reference set"));
        }

        self.fetch_blobs(blobs_connection, &receive).await?;
        self.apply_downloaded(peer, &receive).await?;
        send_commit_pages(&mut send, FrameKind::Refs, &to_send).await?;
        send_frame(&mut send, &SyncFrame::Done).await?;
        if recv_frame(&mut recv).await? != SyncFrame::Done {
            return Err(protocol_error("expected done"));
        }
        send.finish().map_err(network_error)?;
        Ok(SyncReport {
            received: receive.len(),
            sent: to_send.len(),
        })
    }

    async fn outbound_handshake(
        &self,
        peer: AuthorId,
        send: &mut SendStream,
        recv: &mut RecvStream,
    ) -> Result<(), DbError> {
        self.require_local_permission(Permission::Read)?;
        let local_nonce = random_nonce()?;
        send_frame(
            send,
            &SyncFrame::Hello {
                nonce: local_nonce,
                max_frame: max_control_frame(),
            },
        )
        .await?;
        let SyncFrame::Hello {
            nonce: remote_nonce,
            ..
        } = recv_frame(recv).await?
        else {
            return Err(protocol_error("expected hello"));
        };
        send_frame(
            send,
            &SyncFrame::DomainRequest {
                domain_id: self.domain_id(),
                proof: self.proof(local_nonce, remote_nonce, self.db.author_id())?,
            },
        )
        .await?;
        match recv_frame(recv).await? {
            SyncFrame::DomainRequest { domain_id, proof }
                if domain_id == self.domain_id()
                    && proof == self.proof(local_nonce, remote_nonce, peer)? =>
            {
                Ok(())
            }
            _ => Err(DbError::UnauthorizedDevice),
        }
    }

    async fn fetch_blobs(
        &self,
        connection: Connection,
        receive: &[CommitId],
    ) -> Result<(), DbError> {
        self.require_local_blob_fetch()?;
        for commit_id in receive {
            self.db
                .inner
                .blobs
                .fetch(
                    connection.clone(),
                    BlobHash::from_bytes(commit_id.to_bytes()),
                )
                .await
                .map_err(network_error)?;
        }
        Ok(())
    }

    async fn serve(
        &self,
        peer_endpoint: iroh::EndpointId,
        send: &mut SendStream,
        recv: &mut RecvStream,
    ) -> Result<(), DbError> {
        let peer = author_id(peer_endpoint);
        let SyncFrame::Hello {
            nonce: remote_nonce,
            ..
        } = recv_frame(recv).await?
        else {
            return Err(protocol_error("expected hello"));
        };
        let local_nonce = random_nonce()?;
        send_frame(
            send,
            &SyncFrame::Hello {
                nonce: local_nonce,
                max_frame: max_control_frame(),
            },
        )
        .await?;
        match recv_frame(recv).await? {
            SyncFrame::InvitationRequest => {
                let control_reader = self.db.inner.control_gate.read().await;
                self.require_local_permission(Permission::Invite)?;
                let payload = self
                    .pending_invitations
                    .read()
                    .map_err(|_| protocol_error("invitation registry is unavailable"))?
                    .get(&peer)
                    .cloned()
                    .ok_or(DbError::UnauthorizedDevice)?;
                let invitation = Invitation::decode_canonical(&payload)?;
                if invitation.domain_seed().epoch() != self.db.epoch() {
                    return Err(DbError::UnauthorizedDevice);
                }
                self.pending_invitations
                    .write()
                    .map_err(|_| protocol_error("invitation registry is unavailable"))?
                    .remove(&peer);
                let result = send_frame(send, &SyncFrame::Invitation { payload }).await;
                drop(control_reader);
                return result;
            }
            SyncFrame::DomainRequest { domain_id, proof }
                if self.peer_has_permission(peer, Permission::Read)
                    && domain_id == self.domain_id()
                    && proof == self.proof(remote_nonce, local_nonce, peer)? => {}
            _ => return Err(DbError::UnauthorizedDevice),
        }
        send_frame(
            send,
            &SyncFrame::DomainRequest {
                domain_id: self.domain_id(),
                proof: self.proof(remote_nonce, local_nonce, self.db.author_id())?,
            },
        )
        .await?;

        let remote = recv_commit_pages(recv, FrameKind::Frontier).await?;
        let local = self.commit_ids()?;
        send_commit_pages(send, FrameKind::Frontier, &local).await?;
        let remote_need = recv_commit_pages(recv, FrameKind::Need).await?;
        let expected_remote_need = missing_commits(&remote, &local).map_err(sync_error)?;
        if remote_need != expected_remote_need {
            return Err(protocol_error("peer requested an invalid reference set"));
        }
        let need = missing_commits(&local, &remote).map_err(sync_error)?;
        send_commit_pages(send, FrameKind::Need, &need).await?;
        let pushed = recv_commit_pages(recv, FrameKind::Refs).await?;
        if pushed != need {
            return Err(protocol_error("pushed reference set mismatch"));
        }
        let blobs_connection = self
            .endpoint
            .connect(EndpointAddr::new(peer_endpoint), iroh_blobs::ALPN)
            .await
            .map_err(network_error)?;
        self.fetch_blobs(blobs_connection, &pushed).await?;
        self.apply_downloaded(peer, &pushed).await?;
        if recv_frame(recv).await? != SyncFrame::Done {
            return Err(protocol_error("expected done"));
        }
        send_frame(send, &SyncFrame::Done).await
    }

    fn domain_id(&self) -> DomainId {
        self.db.domain_id()
    }

    fn blob_engine(&self) -> BlobEngine {
        self.db.blob_engine()
    }

    fn require_local_blob_fetch(&self) -> Result<(), DbError> {
        self.require_local_permission(Permission::Read)?;
        self.require_local_permission(Permission::FetchBlobs)?;
        Ok(())
    }

    fn require_local_permission(&self, permission: Permission) -> Result<(), DbError> {
        let active_epoch = self.db.inner.store.current_epoch(self.domain_id())?;
        if self.db.epoch() != active_epoch {
            return Err(DbError::StaleEpoch {
                handle: self.db.epoch(),
                active: active_epoch,
            });
        }
        self.db
            .capability_for_permission(self.db.author_id(), permission, active_epoch)?;
        Ok(())
    }

    fn peer_has_permission(&self, peer: AuthorId, permission: Permission) -> bool {
        let Ok(active_epoch) = self.db.inner.store.current_epoch(self.domain_id()) else {
            return false;
        };
        self.db.epoch() == active_epoch
            && self
                .db
                .capability_for_permission(peer, permission, active_epoch)
                .is_ok()
    }

    fn can_peer_fetch_blob(&self, peer: AuthorId, hash: BlobHash) -> bool {
        self.peer_has_permission(peer, Permission::Read)
            && self.peer_has_permission(peer, Permission::FetchBlobs)
            && self
                .db
                .inner
                .store
                .owns_blob(self.domain_id(), hash)
                .unwrap_or(false)
    }

    fn blob_provider_events(&self) -> EventSender {
        let mask = EventMask {
            connected: ConnectMode::Intercept,
            get: RequestMode::Intercept,
            get_many: RequestMode::Disabled,
            push: RequestMode::Disabled,
            observe: ObserveMode::Intercept,
            ..EventMask::DEFAULT
        };
        let (events, mut receiver) = EventSender::channel(64, mask);
        let core = self.clone();
        tokio::spawn(async move {
            let mut peers = BTreeMap::<u64, AuthorId>::new();
            while let Some(message) = receiver.recv().await {
                match message {
                    ProviderMessage::ClientConnected(message) => {
                        let peer = message.endpoint_id.map(author_id);
                        let allowed = peer.is_some_and(|peer| {
                            core.peer_has_permission(peer, Permission::Read)
                                && core.peer_has_permission(peer, Permission::FetchBlobs)
                        });
                        if let Some(peer) = peer.filter(|_| allowed) {
                            peers.insert(message.connection_id, peer);
                        }
                        let result = allowed.then_some(()).ok_or(AbortReason::Permission);
                        let _ignored = message.tx.send(result).await;
                    }
                    ProviderMessage::ConnectionClosed(message) => {
                        peers.remove(&message.connection_id);
                    }
                    ProviderMessage::GetRequestReceived(message) => {
                        let hash = BlobHash::from_bytes(*message.request.hash.as_bytes());
                        let allowed = message.request.ranges.is_blob()
                            && peers
                                .get(&message.connection_id)
                                .is_some_and(|peer| core.can_peer_fetch_blob(*peer, hash));
                        let result = allowed.then_some(()).ok_or(AbortReason::Permission);
                        let _ignored = message.tx.send(result).await;
                    }
                    ProviderMessage::GetManyRequestReceived(message) => {
                        let _ignored = message.tx.send(Err(AbortReason::Permission)).await;
                    }
                    ProviderMessage::PushRequestReceived(message) => {
                        let _ignored = message.tx.send(Err(AbortReason::Permission)).await;
                    }
                    ProviderMessage::ObserveRequestReceived(message) => {
                        let _ignored = message.tx.send(Err(AbortReason::Permission)).await;
                    }
                    ProviderMessage::Throttle(message) => {
                        let _ignored = message.tx.send(Err(AbortReason::Permission)).await;
                    }
                    ProviderMessage::ClientConnectedNotify(_)
                    | ProviderMessage::GetRequestReceivedNotify(_)
                    | ProviderMessage::GetManyRequestReceivedNotify(_)
                    | ProviderMessage::PushRequestReceivedNotify(_)
                    | ProviderMessage::ObserveRequestReceivedNotify(_) => {}
                }
            }
        });
        events
    }

    fn require_trusted(&self, peer: AuthorId) -> Result<(), DbError> {
        if self
            .db
            .inner
            .store
            .is_author_trusted(self.domain_id(), peer)?
        {
            Ok(())
        } else {
            Err(DbError::UnauthorizedDevice)
        }
    }

    fn proof(
        &self,
        initiator_nonce: [u8; 32],
        responder_nonce: [u8; 32],
        claimant: AuthorId,
    ) -> Result<[u8; 32], DbError> {
        let key = self
            .db
            .domain_key()
            .derive_subkey(self.domain_id().as_bytes(), b"iroh-db/sync-domain-proof/v1")?;
        let mut message = Vec::with_capacity(128);
        message.extend_from_slice(b"iroh-db/sync-domain-proof/v1");
        message.extend_from_slice(self.domain_id().as_bytes());
        message.extend_from_slice(&initiator_nonce);
        message.extend_from_slice(&responder_nonce);
        message.extend_from_slice(claimant.as_bytes());
        Ok(*blake3::keyed_hash(&key, &message).as_bytes())
    }

    fn commit_ids(&self) -> Result<Vec<CommitId>, DbError> {
        self.db
            .inner
            .store
            .list_commit_ids(self.domain_id())
            .map_err(DbError::from)
    }

    fn gossip_topic(&self) -> Result<TopicId, DbError> {
        let topic = self
            .db
            .domain_key()
            .derive_subkey(self.domain_id().as_bytes(), b"iroh-db/gossip-topic/v1")?;
        Ok(TopicId::from_bytes(*topic))
    }

    async fn apply_downloaded(
        &self,
        peer: AuthorId,
        commit_ids: &[CommitId],
    ) -> Result<(), DbError> {
        let mut pending = BTreeMap::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        for commit_id in commit_ids {
            let bytes = self.read_transferred(*commit_id, deadline).await?;
            let envelope = CommitEnvelope::decode_canonical(&bytes)?;
            if envelope.commit_id() != *commit_id {
                return Err(protocol_error("transferred commit hash mismatch"));
            }
            pending.insert(*commit_id, envelope);
        }
        while !pending.is_empty() {
            let ready = pending.iter().find_map(|(&commit_id, envelope)| {
                envelope
                    .header()
                    .dependencies()
                    .iter()
                    .all(|dependency| {
                        self.db
                            .inner
                            .store
                            .contains_commit(*dependency)
                            .unwrap_or(false)
                            || !pending.contains_key(dependency)
                    })
                    .then_some(commit_id)
            });
            let commit_id = ready.ok_or_else(|| protocol_error("dependency graph is cyclic"))?;
            let envelope = pending
                .remove(&commit_id)
                .expect("selected pending commit exists");
            self.db.accept_remote_commit(peer, envelope).await?;
        }
        Ok(())
    }

    async fn read_transferred(
        &self,
        commit_id: CommitId,
        deadline: tokio::time::Instant,
    ) -> Result<Vec<u8>, DbError> {
        let hash = BlobHash::from_bytes(commit_id.to_bytes());
        loop {
            if let Some(bytes) = self
                .db
                .inner
                .blobs
                .read(hash)
                .await
                .map_err(network_error)?
            {
                return Ok(bytes);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(protocol_error("transferred commit is missing"));
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

#[derive(Clone, Copy)]
enum FrameKind {
    Frontier,
    Need,
    Refs,
}

fn expect_commits(frame: SyncFrame, kind: FrameKind) -> Result<Vec<CommitId>, DbError> {
    match (kind, frame) {
        (FrameKind::Frontier, SyncFrame::Frontier { commits })
        | (FrameKind::Need, SyncFrame::Need { commits })
        | (FrameKind::Refs, SyncFrame::Refs { commits }) => Ok(commits),
        _ => Err(protocol_error("unexpected control frame")),
    }
}

async fn send_commit_pages(
    send: &mut SendStream,
    kind: FrameKind,
    commits: &[CommitId],
) -> Result<(), DbError> {
    if commits.len() > MAX_SESSION_REFERENCES {
        return Err(protocol_error("session reference budget exceeded"));
    }
    for page in commits.chunks(MAX_REFERENCES) {
        let frame = match kind {
            FrameKind::Frontier => SyncFrame::Frontier {
                commits: page.to_vec(),
            },
            FrameKind::Need => SyncFrame::Need {
                commits: page.to_vec(),
            },
            FrameKind::Refs => SyncFrame::Refs {
                commits: page.to_vec(),
            },
        };
        send_frame(send, &frame).await?;
    }
    let terminator = match kind {
        FrameKind::Frontier => SyncFrame::Frontier {
            commits: Vec::new(),
        },
        FrameKind::Need => SyncFrame::Need {
            commits: Vec::new(),
        },
        FrameKind::Refs => SyncFrame::Refs {
            commits: Vec::new(),
        },
    };
    send_frame(send, &terminator).await
}

async fn recv_commit_pages(
    recv: &mut RecvStream,
    kind: FrameKind,
) -> Result<Vec<CommitId>, DbError> {
    let mut commits = Vec::new();
    loop {
        let page = expect_commits(recv_frame(recv).await?, kind)?;
        if page.is_empty() {
            return Ok(commits);
        }
        if commits.len().saturating_add(page.len()) > MAX_SESSION_REFERENCES
            || commits.last().is_some_and(|last| *last >= page[0])
        {
            return Err(protocol_error("non-canonical or excessive reference pages"));
        }
        commits.extend(page);
    }
}

async fn send_frame(send: &mut SendStream, frame: &SyncFrame) -> Result<(), DbError> {
    let bytes = frame.encode_canonical().map_err(sync_error)?;
    let length = u32::try_from(bytes.len()).map_err(|_| protocol_error("frame is too large"))?;
    send.write_all(&length.to_be_bytes())
        .await
        .map_err(network_error)?;
    send.write_all(&bytes).await.map_err(network_error)
}

async fn recv_frame(recv: &mut RecvStream) -> Result<SyncFrame, DbError> {
    let mut length = [0_u8; 4];
    recv.read_exact(&mut length).await.map_err(network_error)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_CONTROL_FRAME {
        return Err(protocol_error("frame exceeds negotiated limit"));
    }
    let mut bytes = vec![0_u8; length];
    recv.read_exact(&mut bytes).await.map_err(network_error)?;
    SyncFrame::decode_canonical(&bytes).map_err(sync_error)
}

fn random_nonce() -> Result<[u8; 32], DbError> {
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| DbError::RandomnessUnavailable)?;
    Ok(nonce)
}

fn max_control_frame() -> u32 {
    u32::try_from(MAX_CONTROL_FRAME).expect("control frame limit fits u32")
}

fn digest_commits(commits: &[CommitId]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"iroh-db/frontier-digest/v1");
    for commit in commits {
        hasher.update(commit.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn initial_gossip_counter() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn author_id(endpoint_id: iroh::EndpointId) -> AuthorId {
    AuthorId::from_bytes(*endpoint_id.as_bytes())
}

#[allow(clippy::needless_pass_by_value)]
fn network_error(error: impl std::fmt::Display) -> DbError {
    DbError::Network(error.to_string())
}

#[allow(clippy::needless_pass_by_value)]
fn sync_error(error: impl std::fmt::Display) -> DbError {
    DbError::Network(error.to_string())
}

fn protocol_error(message: &str) -> DbError {
    DbError::Network(message.into())
}

#[cfg(test)]
mod tests {
    use iroh_db_security::{ConsistencyMode, Permission, PermissionSet};

    use super::*;

    #[tokio::test]
    async fn raw_blob_connection_is_rejected_without_fetch_capability() {
        let source_directory = tempfile::tempdir().unwrap();
        let target_directory = tempfile::tempdir().unwrap();
        let source_device = IrohDb::open(source_directory.path()).await.unwrap();
        let target_device = IrohDb::open(target_directory.path()).await.unwrap();
        let source = source_device
            .create_domain(ConsistencyMode::MultiWriter)
            .unwrap();
        let invitation = source
            .invite(
                target_device.author_id(),
                PermissionSet::from_permissions(&[Permission::Read]),
                PermissionSet::empty(),
                None,
            )
            .unwrap();
        let target = target_device.import_invitation(&invitation).unwrap();
        let reference = source
            .blobs()
            .import_bytes(b"provider protected".to_vec(), None)
            .await
            .unwrap();
        let source_node = source.start_sync().await.unwrap();
        let target_node = target.start_sync().await.unwrap();
        let connection = target_node
            .core
            .endpoint
            .connect(source_node.addr(), iroh_blobs::ALPN)
            .await
            .unwrap();

        assert!(
            target
                .inner
                .blobs
                .fetch(connection, reference.manifest_hash())
                .await
                .is_err()
        );
        assert!(
            target
                .inner
                .blobs
                .read(reference.manifest_hash())
                .await
                .unwrap()
                .is_none()
        );

        source_node.shutdown().await.unwrap();
        target_node.shutdown().await.unwrap();
        drop(source);
        drop(target);
        source_device.close().await.unwrap();
        target_device.close().await.unwrap();
    }
}
