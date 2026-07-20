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
use iroh_db_security::{
    CapabilityCertificate, ControlTransition, DomainSeed, Invitation, Permission,
    verify_gossip_signature,
};
use iroh_db_sync::{
    GossipHint, MAX_CONTROL_FRAME, MAX_PROTOCOL_VERSION, MAX_REFERENCES, MAX_SESSION_REFERENCES,
    MIN_PROTOCOL_VERSION, SyncFrame, missing_commits, negotiate_protocol,
};
use iroh_gossip::{
    api::{Event as GossipEvent, GossipReceiver, GossipSender},
    net::Gossip,
    proto::TopicId,
};
use n0_future::StreamExt as _;

use crate::{DbError, IrohDb, Snapshot};

/// The sole iroh-db control-plane ALPN.
pub const SYNC_ALPN: &[u8] = b"/iroh-db/sync/3";

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
        let expected_issuer = author_id(remote.id);
        let connection = self
            .core
            .endpoint
            .connect(remote, SYNC_ALPN)
            .await
            .map_err(network_error)?;
        let (mut send, mut recv) = connection.open_bi().await.map_err(network_error)?;
        send_frame(&mut send, &hello_frame(random_nonce()?)).await?;
        let SyncFrame::Hello {
            min_protocol,
            max_protocol,
            ..
        } = recv_frame(&mut recv).await?
        else {
            return Err(protocol_error("expected hello"));
        };
        negotiate_protocol(
            MIN_PROTOCOL_VERSION,
            MAX_PROTOCOL_VERSION,
            min_protocol,
            max_protocol,
        )
        .map_err(network_error)?;
        send_frame(&mut send, &SyncFrame::InvitationRequest).await?;
        let SyncFrame::Invitation { payload } = recv_frame(&mut recv).await? else {
            return Err(DbError::UnauthorizedDevice);
        };
        let invitation = Invitation::decode_canonical(&payload)?;
        if invitation.issuer() != expected_issuer {
            return Err(DbError::UnauthorizedDevice);
        }
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

#[derive(Clone, Copy)]
struct AuthorityPosition {
    epoch: u64,
    sequence: u64,
    head: Option<[u8; 32]>,
}

struct HandshakeState {
    remote_authority: AuthorityPosition,
    remote_capability_chain: Vec<Vec<u8>>,
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
    #[tracing::instrument(name = "iroh_db.sync", skip_all)]
    async fn sync_with(&self, remote: EndpointAddr) -> Result<SyncReport, DbError> {
        let result = self.sync_with_inner(remote).await;
        let (received, sent) = result
            .as_ref()
            .map_or((0, 0), |report| (report.received(), report.sent()));
        self.db
            .inner
            .telemetry
            .record_sync(received, sent, result.is_err());
        result
    }

    async fn sync_with_inner(&self, remote: EndpointAddr) -> Result<SyncReport, DbError> {
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

        let handshake = self.outbound_handshake(peer, &mut send, &mut recv).await?;
        let mut remote_authority = handshake.remote_authority;
        let mut report = SyncReport {
            received: 0,
            sent: 0,
        };
        while self.db.epoch() != remote_authority.epoch {
            let boundary = self.db.epoch().min(remote_authority.epoch);
            let round = self
                .outbound_commit_round(
                    peer,
                    &mut send,
                    &mut recv,
                    blobs_connection.clone(),
                    boundary,
                )
                .await?;
            report.received += round.received;
            report.sent += round.sent;
            if self.db.epoch() > remote_authority.epoch {
                let next_sequence = remote_authority
                    .sequence
                    .checked_add(1)
                    .ok_or_else(|| protocol_error("remote control sequence exhausted"))?;
                let disclosure = self.db.inner.control_gate.read().await;
                let grant = self.control_grant(next_sequence, peer)?;
                send_frame(&mut send, &grant).await?;
                drop(disclosure);
                expect_done(&mut recv).await?;
                remote_authority.epoch = remote_authority
                    .epoch
                    .checked_add(1)
                    .ok_or_else(|| protocol_error("remote control epoch exhausted"))?;
                remote_authority.sequence = next_sequence;
                remote_authority.head = Some(self.control_id(next_sequence)?);
            } else {
                let grant = recv_frame(&mut recv).await?;
                self.apply_control_grant(grant)?;
                send_frame(&mut send, &SyncFrame::Done).await?;
            }
        }
        self.finalize_peer_authority(
            peer,
            remote_authority,
            &handshake.remote_capability_chain,
            &mut send,
            &mut recv,
        )
        .await?;
        let round = self
            .outbound_commit_round(
                peer,
                &mut send,
                &mut recv,
                blobs_connection,
                self.db.epoch(),
            )
            .await?;
        report.received += round.received;
        report.sent += round.sent;
        send.finish().map_err(network_error)?;
        Ok(report)
    }

    async fn outbound_commit_round(
        &self,
        peer: AuthorId,
        send: &mut SendStream,
        recv: &mut RecvStream,
        blobs_connection: Connection,
        max_epoch: u64,
    ) -> Result<SyncReport, DbError> {
        let local = self.commit_ids_through(max_epoch)?;
        send_commit_pages(send, FrameKind::Frontier, &local).await?;
        let remote = recv_commit_pages(recv, FrameKind::Frontier).await?;
        let receive = missing_commits(&local, &remote).map_err(sync_error)?;
        send_commit_pages(send, FrameKind::Need, &receive).await?;
        let to_send = recv_commit_pages(recv, FrameKind::Need).await?;
        let expected_send = missing_commits(&remote, &local).map_err(sync_error)?;
        if to_send != expected_send {
            return Err(protocol_error("peer requested an invalid reference set"));
        }

        self.fetch_blobs(blobs_connection, &receive).await?;
        self.apply_downloaded(peer, &receive).await?;
        send_commit_pages(send, FrameKind::Refs, &to_send).await?;
        send_frame(send, &SyncFrame::Done).await?;
        expect_done(recv).await?;
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
    ) -> Result<HandshakeState, DbError> {
        self.require_local_permission(Permission::Read)?;
        let local_nonce = random_nonce()?;
        send_frame(send, &hello_frame(local_nonce)).await?;
        let SyncFrame::Hello {
            nonce: remote_nonce,
            min_protocol,
            max_protocol,
            ..
        } = recv_frame(recv).await?
        else {
            return Err(protocol_error("expected hello"));
        };
        negotiate_protocol(
            MIN_PROTOCOL_VERSION,
            MAX_PROTOCOL_VERSION,
            min_protocol,
            max_protocol,
        )
        .map_err(network_error)?;
        send_frame(send, &self.authority_state()?).await?;
        let SyncFrame::AuthorityState {
            epoch: remote_epoch,
            sequence,
            head,
        } = recv_frame(recv).await?
        else {
            return Err(protocol_error("expected authority state"));
        };
        let proof_epoch = self.db.epoch().min(remote_epoch);
        send_frame(
            send,
            &SyncFrame::DomainRequest {
                domain_id: self.domain_id(),
                epoch: proof_epoch,
                proof: self.proof(local_nonce, remote_nonce, self.db.author_id(), proof_epoch)?,
                capability_chain: self.local_capability_chain()?,
            },
        )
        .await?;
        match recv_frame(recv).await? {
            SyncFrame::DomainRequest {
                domain_id,
                epoch,
                proof,
                capability_chain,
            } if domain_id == self.domain_id()
                && epoch == proof_epoch
                && proof == self.proof(local_nonce, remote_nonce, peer, proof_epoch)? =>
            {
                self.authenticate_peer_capability(peer, &capability_chain)
                    .await?;
                Ok(HandshakeState {
                    remote_authority: AuthorityPosition {
                        epoch: remote_epoch,
                        sequence,
                        head,
                    },
                    remote_capability_chain: capability_chain,
                })
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

    #[allow(clippy::too_many_lines)]
    async fn serve(
        &self,
        peer_endpoint: iroh::EndpointId,
        send: &mut SendStream,
        recv: &mut RecvStream,
    ) -> Result<(), DbError> {
        let peer = author_id(peer_endpoint);
        let SyncFrame::Hello {
            nonce: remote_nonce,
            min_protocol,
            max_protocol,
            ..
        } = recv_frame(recv).await?
        else {
            return Err(protocol_error("expected hello"));
        };
        negotiate_protocol(
            MIN_PROTOCOL_VERSION,
            MAX_PROTOCOL_VERSION,
            min_protocol,
            max_protocol,
        )
        .map_err(network_error)?;
        let local_nonce = random_nonce()?;
        send_frame(send, &hello_frame(local_nonce)).await?;
        let next = recv_frame(recv).await?;
        if next == SyncFrame::InvitationRequest {
            return self.serve_invitation(peer, send).await;
        }
        let SyncFrame::AuthorityState {
            epoch: remote_epoch,
            sequence: remote_sequence,
            head: remote_head,
        } = next
        else {
            return Err(protocol_error("expected authority state"));
        };
        send_frame(send, &self.authority_state()?).await?;
        let proof_epoch = self.db.epoch().min(remote_epoch);
        let SyncFrame::DomainRequest {
            domain_id,
            epoch,
            proof,
            capability_chain,
        } = recv_frame(recv).await?
        else {
            return Err(DbError::UnauthorizedDevice);
        };
        if domain_id != self.domain_id()
            || epoch != proof_epoch
            || proof != self.proof(remote_nonce, local_nonce, peer, proof_epoch)?
        {
            return Err(DbError::UnauthorizedDevice);
        }
        self.authenticate_peer_capability(peer, &capability_chain)
            .await?;
        send_frame(
            send,
            &SyncFrame::DomainRequest {
                domain_id: self.domain_id(),
                epoch: proof_epoch,
                proof: self.proof(remote_nonce, local_nonce, self.db.author_id(), proof_epoch)?,
                capability_chain: self.local_capability_chain()?,
            },
        )
        .await?;
        let blobs_connection = self
            .endpoint
            .connect(EndpointAddr::new(peer_endpoint), iroh_blobs::ALPN)
            .await
            .map_err(network_error)?;
        let mut remote_authority = AuthorityPosition {
            epoch: remote_epoch,
            sequence: remote_sequence,
            head: remote_head,
        };
        while self.db.epoch() != remote_authority.epoch {
            let boundary = self.db.epoch().min(remote_authority.epoch);
            self.serve_commit_round(peer, send, recv, blobs_connection.clone(), boundary)
                .await?;
            if self.db.epoch() > remote_authority.epoch {
                let next_sequence = remote_authority
                    .sequence
                    .checked_add(1)
                    .ok_or_else(|| protocol_error("remote control sequence exhausted"))?;
                let disclosure = self.db.inner.control_gate.read().await;
                let grant = self.control_grant(next_sequence, peer)?;
                send_frame(send, &grant).await?;
                drop(disclosure);
                expect_done(recv).await?;
                remote_authority.epoch = remote_authority
                    .epoch
                    .checked_add(1)
                    .ok_or_else(|| protocol_error("remote control epoch exhausted"))?;
                remote_authority.sequence = next_sequence;
                remote_authority.head = Some(self.control_id(next_sequence)?);
            } else {
                let grant = recv_frame(recv).await?;
                self.apply_control_grant(grant)?;
                send_frame(send, &SyncFrame::Done).await?;
            }
        }
        self.finalize_peer_authority(peer, remote_authority, &capability_chain, send, recv)
            .await?;
        self.serve_commit_round(peer, send, recv, blobs_connection, self.db.epoch())
            .await
    }

    async fn finalize_peer_authority(
        &self,
        peer: AuthorId,
        remote_authority: AuthorityPosition,
        capability_chain: &[Vec<u8>],
        send: &mut SendStream,
        recv: &mut RecvStream,
    ) -> Result<(), DbError> {
        self.reconcile_authority_head(remote_authority, send, recv)
            .await?;
        self.authenticate_peer_capability(peer, capability_chain)
            .await
    }

    async fn serve_invitation(&self, peer: AuthorId, send: &mut SendStream) -> Result<(), DbError> {
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
        result
    }

    async fn serve_commit_round(
        &self,
        peer: AuthorId,
        send: &mut SendStream,
        recv: &mut RecvStream,
        blobs_connection: Connection,
        max_epoch: u64,
    ) -> Result<(), DbError> {
        let remote = recv_commit_pages(recv, FrameKind::Frontier).await?;
        let local = self.commit_ids_through(max_epoch)?;
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
        self.fetch_blobs(blobs_connection, &pushed).await?;
        self.apply_downloaded(peer, &pushed).await?;
        expect_done(recv).await?;
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

    fn peer_has_permission_at(&self, peer: AuthorId, permission: Permission, epoch: u64) -> bool {
        let Ok(Some(capability_id)) = self
            .db
            .inner
            .store
            .active_capability(self.domain_id(), peer)
        else {
            return false;
        };
        self.db
            .inner
            .store
            .authorize_capability(self.domain_id(), peer, capability_id, permission, epoch)
            .unwrap_or(false)
    }

    async fn authenticate_peer_capability(
        &self,
        peer: AuthorId,
        encoded_chain: &[Vec<u8>],
    ) -> Result<(), DbError> {
        let _control_writer = self.db.inner.control_gate.write().await;
        let Some(descriptor) = self.db.inner.store.domain_descriptor(self.domain_id())? else {
            return self.require_trusted(peer);
        };
        let chain = encoded_chain
            .iter()
            .map(|bytes| CapabilityCertificate::decode_canonical(bytes).map_err(DbError::from))
            .collect::<Result<Vec<_>, _>>()?;
        let root = chain.first().ok_or(DbError::UnauthorizedDevice)?;
        if root.domain_id() != self.domain_id()
            || root.subject() != descriptor.owner()
            || root.issuer_capability().is_some()
        {
            return Err(DbError::UnauthorizedDevice);
        }
        for pair in chain.windows(2) {
            pair[1].validate_delegation(&pair[0])?;
        }
        let leaf = chain.last().ok_or(DbError::UnauthorizedDevice)?;
        if leaf.subject() != peer {
            return Err(DbError::UnauthorizedDevice);
        }
        let current_sequence = self
            .db
            .inner
            .store
            .current_control_sequence(self.domain_id())?;
        let anchor_is_ahead = chain
            .iter()
            .any(|capability| capability.issued_control_sequence() > current_sequence);
        if !anchor_is_ahead
            && (!leaf.permits(Permission::Read, self.db.epoch())
                || !leaf.permits(Permission::FetchBlobs, self.db.epoch()))
        {
            return Err(DbError::UnauthorizedDevice);
        }
        let leaf_id = match self.db.inner.store.install_capability_chain_atomic(&chain) {
            Ok(leaf_id) => leaf_id,
            Err(iroh_db_store::StoreError::InvalidAuthority(_)) if anchor_is_ahead => {
                let Some(active) = self
                    .db
                    .inner
                    .store
                    .active_capability(self.domain_id(), peer)?
                else {
                    return Err(DbError::UnauthorizedDevice);
                };
                if !self
                    .db
                    .inner
                    .store
                    .is_author_trusted(self.domain_id(), peer)?
                    || !self.db.inner.store.authorize_capability(
                        self.domain_id(),
                        peer,
                        active,
                        Permission::Read,
                        self.db.epoch(),
                    )?
                    || !self.db.inner.store.authorize_capability(
                        self.domain_id(),
                        peer,
                        active,
                        Permission::FetchBlobs,
                        self.db.epoch(),
                    )?
                {
                    return Err(DbError::UnauthorizedDevice);
                }
                return Ok(());
            }
            Err(error) => return Err(DbError::Store(error)),
        };
        if !self.db.inner.store.authorize_capability(
            self.domain_id(),
            peer,
            leaf_id,
            Permission::Read,
            self.db.epoch(),
        )? || !self.db.inner.store.authorize_capability(
            self.domain_id(),
            peer,
            leaf_id,
            Permission::FetchBlobs,
            self.db.epoch(),
        )? {
            return Err(DbError::UnauthorizedDevice);
        }
        self.db.inner.store.trust_author(self.domain_id(), peer)?;
        Ok(())
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
        epoch: u64,
    ) -> Result<[u8; 32], DbError> {
        let key = self
            .db
            .inner
            .credentials
            .load_domain_epoch(self.domain_id(), epoch)?
            .domain_key()
            .derive_subkey(self.domain_id().as_bytes(), b"iroh-db/sync-domain-proof/v1")?;
        let mut message = Vec::with_capacity(128);
        message.extend_from_slice(b"iroh-db/sync-domain-proof/v1");
        message.extend_from_slice(self.domain_id().as_bytes());
        message.extend_from_slice(&epoch.to_be_bytes());
        message.extend_from_slice(&initiator_nonce);
        message.extend_from_slice(&responder_nonce);
        message.extend_from_slice(claimant.as_bytes());
        Ok(*blake3::keyed_hash(&key, &message).as_bytes())
    }

    fn authority_state(&self) -> Result<SyncFrame, DbError> {
        let head = self.db.inner.store.control_head(self.domain_id())?;
        Ok(SyncFrame::AuthorityState {
            epoch: self.db.inner.store.current_epoch(self.domain_id())?,
            sequence: head.as_ref().map_or(0, ControlTransition::sequence),
            head: head.as_ref().map(ControlTransition::id).transpose()?,
        })
    }

    fn local_capability_chain(&self) -> Result<Vec<Vec<u8>>, DbError> {
        let Some(capability) = self.db.active_capability()? else {
            return Ok(Vec::new());
        };
        self.db
            .inner
            .store
            .capability_chain(capability.id()?)?
            .iter()
            .map(|capability| capability.encode_canonical().map_err(DbError::from))
            .collect()
    }

    fn control_grant(&self, sequence: u64, peer: AuthorId) -> Result<SyncFrame, DbError> {
        if sequence == 0 {
            return Err(protocol_error("control grant sequence cannot be zero"));
        }
        let control = self
            .db
            .inner
            .store
            .accepted_control_at_sequence(self.domain_id(), sequence)?
            .ok_or_else(|| protocol_error("requested control transition is unavailable"))?;
        if !self
            .db
            .inner
            .store
            .is_author_trusted(self.domain_id(), peer)?
            || !self.peer_has_permission_at(peer, Permission::Read, control.new_epoch())
            || !self.peer_has_permission_at(peer, Permission::FetchBlobs, control.new_epoch())
        {
            return Err(DbError::UnauthorizedDevice);
        }
        let capability_chain = self
            .db
            .inner
            .store
            .capability_chain(control.controller_capability())?
            .iter()
            .map(|capability| capability.encode_canonical().map_err(DbError::from))
            .collect::<Result<Vec<_>, _>>()?;
        let seed = self
            .db
            .inner
            .credentials
            .load_domain_epoch(self.domain_id(), control.new_epoch())?;
        Ok(SyncFrame::ControlGrant {
            transition: control.encode_canonical()?,
            epoch_key: seed.epoch_key_bytes(),
            capability_chain,
        })
    }

    fn control_id(&self, sequence: u64) -> Result<[u8; 32], DbError> {
        if sequence == 0 {
            return Err(protocol_error("control sequence cannot be zero"));
        }
        self.db
            .inner
            .store
            .accepted_control_at_sequence(self.domain_id(), sequence)?
            .ok_or_else(|| protocol_error("control transition is unavailable"))?
            .id()
            .map_err(DbError::from)
    }

    async fn reconcile_authority_head(
        &self,
        remote: AuthorityPosition,
        send: &mut SendStream,
        recv: &mut RecvStream,
    ) -> Result<(), DbError> {
        let SyncFrame::AuthorityState {
            epoch,
            sequence,
            head,
        } = self.authority_state()?
        else {
            unreachable!("authority_state always returns AuthorityState")
        };
        if epoch == remote.epoch && sequence == remote.sequence && head == remote.head {
            return Ok(());
        }
        if epoch != remote.epoch || sequence != remote.sequence {
            return Err(protocol_error("authority positions do not converge"));
        }
        let local_head = head.ok_or_else(|| protocol_error("local control head is missing"))?;
        let remote_head = remote
            .head
            .ok_or_else(|| protocol_error("remote control head is missing"))?;
        let local = self
            .db
            .inner
            .store
            .control_transition(self.domain_id(), local_head)?
            .ok_or_else(|| protocol_error("local control object is missing"))?;
        send_frame(
            send,
            &SyncFrame::ControlEvidence {
                transition: local.encode_canonical()?,
            },
        )
        .await?;
        let SyncFrame::ControlEvidence { transition } = recv_frame(recv).await? else {
            return Err(protocol_error("expected control evidence"));
        };
        let conflicting = ControlTransition::decode_canonical(&transition)?;
        if conflicting.id()? != remote_head {
            return Err(protocol_error(
                "remote control evidence does not match its head",
            ));
        }
        match self.db.inner.store.observe_control(&conflicting) {
            Err(error @ iroh_db_store::StoreError::ControlFork { .. }) => {
                Err(DbError::Store(error))
            }
            Err(error) => Err(DbError::Store(error)),
            Ok(()) => Err(protocol_error("authority heads do not converge")),
        }
    }

    fn apply_control_grant(&self, frame: SyncFrame) -> Result<(), DbError> {
        let SyncFrame::ControlGrant {
            transition,
            epoch_key,
            capability_chain,
        } = frame
        else {
            return Err(protocol_error("expected control grant"));
        };
        let control = ControlTransition::decode_canonical(&transition)?;
        self.validate_incoming_control(&control)?;
        let seed = DomainSeed::from_epoch_key(self.domain_id(), control.new_epoch(), epoch_key);
        if seed.distribution_digest() != control.key_distribution_digest()
            || control.revoked_subjects().contains(&self.db.author_id())
        {
            return Err(DbError::UnauthorizedDevice);
        }
        let capability_chain = capability_chain
            .iter()
            .map(|bytes| CapabilityCertificate::decode_canonical(bytes).map_err(DbError::from))
            .collect::<Result<Vec<_>, _>>()?;
        for capability in &capability_chain {
            if capability.domain_id() != self.domain_id() {
                return Err(DbError::UnauthorizedDevice);
            }
        }
        self.db
            .apply_epoch_rotation_with_capabilities(&control, &seed, &capability_chain)?;
        for subject in [control.author(), control.controller()] {
            if !control.revoked_subjects().contains(&subject) {
                self.db
                    .inner
                    .store
                    .trust_author(self.domain_id(), subject)?;
            }
        }
        Ok(())
    }

    fn validate_incoming_control(&self, control: &ControlTransition) -> Result<(), DbError> {
        let head = self.db.inner.store.control_head(self.domain_id())?;
        let expected_sequence = head
            .as_ref()
            .map_or(Some(1), |head| head.sequence().checked_add(1))
            .ok_or_else(|| protocol_error("control sequence exhausted"))?;
        let expected_predecessor = head.as_ref().map(ControlTransition::id).transpose()?;
        let can_control = self.db.inner.store.authorize_capability(
            self.domain_id(),
            control.author(),
            control.author_capability(),
            Permission::Revoke,
            self.db.epoch(),
        )? || self.db.inner.store.authorize_capability(
            self.domain_id(),
            control.author(),
            control.author_capability(),
            Permission::Admin,
            self.db.epoch(),
        )?;
        if control.domain_id() != self.domain_id()
            || control.sequence() != expected_sequence
            || control.predecessor() != expected_predecessor
            || control.previous_epoch() != self.db.epoch()
            || control.cut() != self.db.inner.store.frontier(self.domain_id())?
            || control.author() != self.db.inner.store.current_controller(self.domain_id())?
            || !can_control
        {
            return Err(DbError::UnauthorizedDevice);
        }
        Ok(())
    }

    fn commit_ids_through(&self, epoch: u64) -> Result<Vec<CommitId>, DbError> {
        if epoch == self.db.inner.store.current_epoch(self.domain_id())? {
            self.db
                .inner
                .store
                .list_commit_ids(self.domain_id())
                .map_err(DbError::from)
        } else {
            self.db
                .inner
                .store
                .list_stored_commit_ids_through(self.domain_id(), epoch)
                .map_err(DbError::from)
        }
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
                            .contains_commit(self.domain_id(), *dependency)
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

async fn expect_done(recv: &mut RecvStream) -> Result<(), DbError> {
    if recv_frame(recv).await? == SyncFrame::Done {
        Ok(())
    } else {
        Err(protocol_error("expected done"))
    }
}

fn random_nonce() -> Result<[u8; 32], DbError> {
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| DbError::RandomnessUnavailable)?;
    Ok(nonce)
}

fn max_control_frame() -> u32 {
    u32::try_from(MAX_CONTROL_FRAME).expect("control frame limit fits u32")
}

fn hello_frame(nonce: [u8; 32]) -> SyncFrame {
    SyncFrame::Hello {
        nonce,
        max_frame: max_control_frame(),
        min_protocol: MIN_PROTOCOL_VERSION,
        max_protocol: MAX_PROTOCOL_VERSION,
    }
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

    #[tokio::test]
    async fn wrong_epoch_key_is_rejected_before_authority_mutation() {
        let owner_directory = tempfile::tempdir().unwrap();
        let member_directory = tempfile::tempdir().unwrap();
        let owner_device = IrohDb::open(owner_directory.path()).await.unwrap();
        let member_device = IrohDb::open(member_directory.path()).await.unwrap();
        let owner = owner_device
            .create_domain(ConsistencyMode::MultiWriter)
            .unwrap();
        let invitation = owner
            .invite(
                member_device.author_id(),
                PermissionSet::from_permissions(&[Permission::Read, Permission::FetchBlobs]),
                PermissionSet::empty(),
                None,
            )
            .unwrap();
        let member = member_device.import_invitation(&invitation).unwrap();
        let member_node = member.start_sync().await.unwrap();
        let (rotated, control) = owner.rotate_epoch(&[]).unwrap();
        let grant = SyncFrame::ControlGrant {
            transition: control.encode_canonical().unwrap(),
            epoch_key: [0; 32],
            capability_chain: Vec::new(),
        };

        assert!(matches!(
            member_node.core.apply_control_grant(grant),
            Err(DbError::UnauthorizedDevice)
        ));
        assert_eq!(member.domain_seed().epoch(), 0);
        assert!(
            member
                .inner
                .store
                .control_head(member.domain_id())
                .unwrap()
                .is_none()
        );

        member_node.shutdown().await.unwrap();
        drop(owner);
        drop(rotated);
        drop(member);
        owner_device.close().await.unwrap();
        member_device.close().await.unwrap();
    }
}
