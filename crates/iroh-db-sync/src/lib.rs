//! Bounded reconciliation protocol layered over iroh and iroh-blobs.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use iroh_db_core::{AuthorId, CommitId, DomainId};

/// The default and accepted maximum encoded control-frame size.
pub const MAX_CONTROL_FRAME: usize = 1024 * 1024;
/// Maximum immutable references carried by one control frame.
pub const MAX_REFERENCES: usize = 4_096;
/// Maximum aggregate immutable references accepted during one reconciliation round.
pub const MAX_SESSION_REFERENCES: usize = 65_536;
const PROTOCOL_VERSION: u16 = 2;
const GOSSIP_VERSION: u16 = 1;
/// Maximum encoded gossip announcement size.
pub const MAX_GOSSIP_HINT: usize = 512;
/// Maximum capability objects carried by one authenticated authority message.
pub const MAX_CAPABILITY_CHAIN: usize = 9;
/// Maximum canonical capability-certificate size.
pub const MAX_CAPABILITY_BYTES: usize = 4_096;

/// One signed, content-free commit availability hint sent through iroh-gossip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GossipHint {
    author: AuthorId,
    commit: CommitId,
    frontier_digest: [u8; 32],
    counter: u64,
    signature: [u8; 64],
}

impl GossipHint {
    /// Constructs a hint after the caller signs [`Self::signing_bytes`].
    pub const fn new(
        author: AuthorId,
        commit: CommitId,
        frontier_digest: [u8; 32],
        counter: u64,
        signature: [u8; 64],
    ) -> Self {
        Self {
            author,
            commit,
            frontier_digest,
            counter,
            signature,
        }
    }

    /// Returns the announcing device identity.
    pub const fn author(&self) -> AuthorId {
        self.author
    }

    /// Returns one immutable commit advertised as available.
    pub const fn commit(&self) -> CommitId {
        self.commit
    }

    /// Returns the digest of the announcer's complete frontier.
    pub const fn frontier_digest(&self) -> [u8; 32] {
        self.frontier_digest
    }

    /// Returns the per-process monotonic replay counter.
    pub const fn counter(&self) -> u64 {
        self.counter
    }

    /// Returns the detached endpoint signature.
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Encodes the exact bytes covered by the gossip-specific signature context.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, SyncFrameError> {
        encode_hint_content(self.author, self.commit, self.frontier_digest, self.counter)
    }

    /// Encodes the complete strict announcement.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, SyncFrameError> {
        let bytes = minicbor::to_vec(GossipWire {
            content: self.signing_bytes()?,
            signature: self.signature,
        })
        .map_err(codec_error)?;
        if bytes.len() > MAX_GOSSIP_HINT {
            return Err(SyncFrameError::GossipHintTooLarge(bytes.len()));
        }
        Ok(bytes)
    }

    /// Strictly decodes one signed announcement.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, SyncFrameError> {
        if bytes.len() > MAX_GOSSIP_HINT {
            return Err(SyncFrameError::GossipHintTooLarge(bytes.len()));
        }
        let mut decoder = minicbor::Decoder::new(bytes);
        let wire: GossipWire = decoder.decode().map_err(codec_error)?;
        if decoder.position() != bytes.len() {
            return Err(SyncFrameError::NonCanonical);
        }
        let content: GossipContent = decode_exact(&wire.content)?;
        if content.version != GOSSIP_VERSION {
            return Err(SyncFrameError::UnsupportedVersion(content.version));
        }
        let hint = Self::new(
            content.author,
            content.commit,
            content.frontier_digest.into(),
            content.counter,
            wire.signature,
        );
        if hint.signing_bytes()? != wire.content || hint.encode_canonical()? != bytes {
            return Err(SyncFrameError::NonCanonical);
        }
        Ok(hint)
    }
}

/// One canonical `/iroh-db/sync/1` control-plane message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncFrame {
    /// Negotiates the protocol and binds a fresh session nonce.
    Hello {
        /// Random session nonce.
        nonce: [u8; 32],
        /// Largest control frame accepted by the sender.
        max_frame: u32,
    },
    /// Proves possession of authorization material for exactly one domain.
    DomainRequest {
        /// Requested security domain.
        domain_id: DomainId,
        /// Historical epoch selected for the nonce-bound proof.
        epoch: u64,
        /// Nonce-bound capability/key proof.
        proof: [u8; 32],
        /// Root-to-leaf capability evidence for the authenticated endpoint.
        capability_chain: Vec<Vec<u8>>,
    },
    /// Advertises the durable authority position before data reconciliation.
    AuthorityState {
        /// Active domain epoch.
        epoch: u64,
        /// Accepted control sequence, equal to the epoch for format v2.
        sequence: u64,
        /// Canonical control-head ID, absent at genesis.
        head: Option<[u8; 32]>,
    },
    /// Delivers one signed successor and digest-bound key over authenticated QUIC.
    ControlGrant {
        /// Canonical signed [`iroh_db_security::ControlTransition`] bytes.
        transition: Vec<u8>,
        /// Symmetric key for the transition's new epoch.
        epoch_key: [u8; 32],
        /// Capability evidence required to validate transition authority.
        capability_chain: Vec<Vec<u8>>,
    },
    /// Advertises a bounded local commit frontier or accepted set.
    Frontier {
        /// Canonically sorted unique commit IDs.
        commits: Vec<CommitId>,
    },
    /// Requests missing immutable commit objects.
    Need {
        /// Canonically sorted unique commit IDs.
        commits: Vec<CommitId>,
    },
    /// Announces immutable hashes available through iroh-blobs.
    Refs {
        /// Canonically sorted unique commit IDs.
        commits: Vec<CommitId>,
    },
    /// Acknowledges durable acceptance of one commit.
    Ack {
        /// Accepted commit ID.
        commit: CommitId,
    },
    /// Completes a successful reconciliation round.
    Done,
    /// Reports a bounded protocol error without sensitive context.
    Error {
        /// Stable protocol error code.
        code: u16,
    },
    /// Requests an endpoint-targeted invitation before domain membership exists.
    InvitationRequest,
    /// Delivers signed invitation bytes inside the authenticated QUIC session.
    Invitation {
        /// Canonical signed invitation payload.
        payload: Vec<u8>,
    },
}

impl SyncFrame {
    /// Encodes a strict, deterministic control frame.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, SyncFrameError> {
        validate(self)?;
        let wire = WireFrame::from(self);
        let bytes = minicbor::to_vec(wire).map_err(codec_error)?;
        if bytes.len() > MAX_CONTROL_FRAME {
            return Err(SyncFrameError::FrameTooLarge(bytes.len()));
        }
        Ok(bytes)
    }

    /// Strictly decodes one bounded canonical control frame.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, SyncFrameError> {
        if bytes.len() > MAX_CONTROL_FRAME {
            return Err(SyncFrameError::FrameTooLarge(bytes.len()));
        }
        let mut decoder = minicbor::Decoder::new(bytes);
        let wire: WireFrame = decoder.decode().map_err(codec_error)?;
        if decoder.position() != bytes.len() {
            return Err(SyncFrameError::NonCanonical);
        }
        let frame = Self::try_from(wire)?;
        if frame.encode_canonical()? != bytes {
            return Err(SyncFrameError::NonCanonical);
        }
        Ok(frame)
    }
}

/// Returns commit IDs accepted remotely but absent locally.
pub fn missing_commits(
    local: &[CommitId],
    remote: &[CommitId],
) -> Result<Vec<CommitId>, SyncFrameError> {
    if local.len() > MAX_SESSION_REFERENCES {
        return Err(SyncFrameError::TooManyReferences(local.len()));
    }
    if remote.len() > MAX_SESSION_REFERENCES {
        return Err(SyncFrameError::TooManyReferences(remote.len()));
    }
    let local = local.iter().copied().collect::<BTreeSet<_>>();
    Ok(remote
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .difference(&local)
        .copied()
        .collect())
}

/// A rejected control frame or reconciliation plan.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SyncFrameError {
    /// A frame exceeded the hard control-plane bound.
    #[error("control frame is too large: {0}")]
    FrameTooLarge(usize),
    /// A frame exceeded the per-message immutable-reference bound.
    #[error("control frame contains too many references: {0}")]
    TooManyReferences(usize),
    /// Immutable references were not sorted and unique.
    #[error("control-frame references are not canonical")]
    NonCanonicalReferences,
    /// The encoded version is not supported.
    #[error("unsupported sync protocol version: {0}")]
    UnsupportedVersion(u16),
    /// The frame kind and its populated fields disagree.
    #[error("control frame shape is invalid")]
    InvalidShape,
    /// CBOR was malformed or outside protocol types.
    #[error("control frame codec failed: {0}")]
    Codec(String),
    /// Valid CBOR did not use the unique canonical representation.
    #[error("control frame is not canonical")]
    NonCanonical,
    /// A gossip announcement exceeded its much smaller hard bound.
    #[error("gossip hint is too large: {0}")]
    GossipHintTooLarge(usize),
    /// An invitation payload exceeded its 64 KiB bound.
    #[error("invitation payload is too large: {0}")]
    InvitationTooLarge(usize),
    /// An authority message exceeded the maximum capability-chain depth.
    #[error("authority message contains too many capability objects: {0}")]
    TooManyAuthorityObjects(usize),
    /// One canonical capability object exceeded its hard bound.
    #[error("authority object is too large: {0}")]
    AuthorityObjectTooLarge(usize),
}

#[derive(minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
struct GossipContent {
    #[n(0)]
    version: u16,
    #[n(1)]
    author: AuthorId,
    #[n(2)]
    commit: CommitId,
    #[n(3)]
    frontier_digest: minicbor::bytes::ByteArray<32>,
    #[n(4)]
    counter: u64,
}

#[derive(minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
struct GossipWire {
    #[n(0)]
    content: Vec<u8>,
    #[n(1)]
    signature: [u8; 64],
}

#[derive(minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
struct WireFrame {
    #[n(0)]
    version: u16,
    #[n(1)]
    kind: u8,
    #[n(2)]
    domain_id: Option<DomainId>,
    #[n(3)]
    nonce_or_proof: Option<minicbor::bytes::ByteArray<32>>,
    #[n(4)]
    commits: Vec<CommitId>,
    #[n(5)]
    max_frame: Option<u32>,
    #[n(6)]
    commit: Option<CommitId>,
    #[n(7)]
    error_code: Option<u16>,
    #[n(8)]
    payload: Option<Vec<u8>>,
    #[n(9)]
    epoch: Option<u64>,
    #[n(10)]
    sequence: Option<u64>,
    #[n(11)]
    head: Option<minicbor::bytes::ByteArray<32>>,
    #[n(12)]
    payloads: Vec<Vec<u8>>,
    #[n(13)]
    epoch_key: Option<minicbor::bytes::ByteArray<32>>,
}

impl From<&SyncFrame> for WireFrame {
    fn from(frame: &SyncFrame) -> Self {
        let mut wire = Self {
            version: PROTOCOL_VERSION,
            kind: 0,
            domain_id: None,
            nonce_or_proof: None,
            commits: Vec::new(),
            max_frame: None,
            commit: None,
            error_code: None,
            payload: None,
            epoch: None,
            sequence: None,
            head: None,
            payloads: Vec::new(),
            epoch_key: None,
        };
        match frame {
            SyncFrame::Hello { nonce, max_frame } => {
                wire.kind = 0;
                wire.nonce_or_proof = Some((*nonce).into());
                wire.max_frame = Some(*max_frame);
            }
            SyncFrame::DomainRequest {
                domain_id,
                epoch,
                proof,
                capability_chain,
            } => {
                wire.kind = 1;
                wire.domain_id = Some(*domain_id);
                wire.nonce_or_proof = Some((*proof).into());
                wire.epoch = Some(*epoch);
                wire.payloads.clone_from(capability_chain);
            }
            SyncFrame::Frontier { commits } => {
                wire.kind = 2;
                wire.commits.clone_from(commits);
            }
            SyncFrame::Need { commits } => {
                wire.kind = 3;
                wire.commits.clone_from(commits);
            }
            SyncFrame::Refs { commits } => {
                wire.kind = 4;
                wire.commits.clone_from(commits);
            }
            SyncFrame::Ack { commit } => {
                wire.kind = 5;
                wire.commit = Some(*commit);
            }
            SyncFrame::Done => wire.kind = 6,
            SyncFrame::Error { code } => {
                wire.kind = 7;
                wire.error_code = Some(*code);
            }
            SyncFrame::InvitationRequest => wire.kind = 8,
            SyncFrame::Invitation { payload } => {
                wire.kind = 9;
                wire.payload = Some(payload.clone());
            }
            SyncFrame::AuthorityState {
                epoch,
                sequence,
                head,
            } => {
                wire.kind = 10;
                wire.epoch = Some(*epoch);
                wire.sequence = Some(*sequence);
                wire.head = head.map(Into::into);
            }
            SyncFrame::ControlGrant {
                transition,
                epoch_key,
                capability_chain,
            } => {
                wire.kind = 11;
                wire.payload = Some(transition.clone());
                wire.epoch_key = Some((*epoch_key).into());
                wire.payloads.clone_from(capability_chain);
            }
        }
        wire
    }
}

impl TryFrom<WireFrame> for SyncFrame {
    type Error = SyncFrameError;

    fn try_from(wire: WireFrame) -> Result<Self, SyncFrameError> {
        if wire.version != PROTOCOL_VERSION {
            return Err(SyncFrameError::UnsupportedVersion(wire.version));
        }
        if wire.kind >= 10 {
            let frame = decode_authority_frame(wire)?;
            validate(&frame)?;
            return Ok(frame);
        }
        let empty_refs = wire.commits.is_empty();
        let frame = match wire.kind {
            0 if wire.domain_id.is_none()
                && empty_refs
                && wire.commit.is_none()
                && wire.error_code.is_none()
                && wire.payload.is_none() =>
            {
                Self::Hello {
                    nonce: fixed_proof(wire.nonce_or_proof)?,
                    max_frame: wire.max_frame.ok_or(SyncFrameError::InvalidShape)?,
                }
            }
            1 if wire.max_frame.is_none()
                && empty_refs
                && wire.commit.is_none()
                && wire.error_code.is_none()
                && wire.payload.is_none()
                && wire.sequence.is_none()
                && wire.head.is_none()
                && wire.epoch_key.is_none() =>
            {
                Self::DomainRequest {
                    domain_id: wire.domain_id.ok_or(SyncFrameError::InvalidShape)?,
                    epoch: wire.epoch.ok_or(SyncFrameError::InvalidShape)?,
                    proof: fixed_proof(wire.nonce_or_proof)?,
                    capability_chain: wire.payloads,
                }
            }
            2 if unused_scalar_fields(&wire) => Self::Frontier {
                commits: wire.commits,
            },
            3 if unused_scalar_fields(&wire) => Self::Need {
                commits: wire.commits,
            },
            4 if unused_scalar_fields(&wire) => Self::Refs {
                commits: wire.commits,
            },
            5 if wire.domain_id.is_none()
                && wire.nonce_or_proof.is_none()
                && empty_refs
                && wire.max_frame.is_none()
                && wire.error_code.is_none()
                && wire.payload.is_none() =>
            {
                Self::Ack {
                    commit: wire.commit.ok_or(SyncFrameError::InvalidShape)?,
                }
            }
            6 if unused_scalar_fields(&wire) && empty_refs => Self::Done,
            7 if wire.domain_id.is_none()
                && wire.nonce_or_proof.is_none()
                && empty_refs
                && wire.max_frame.is_none()
                && wire.commit.is_none()
                && wire.payload.is_none() =>
            {
                Self::Error {
                    code: wire.error_code.ok_or(SyncFrameError::InvalidShape)?,
                }
            }
            8 if unused_scalar_fields(&wire) && empty_refs => Self::InvitationRequest,
            9 if unused_scalar_fields_except_payload(&wire) && empty_refs => Self::Invitation {
                payload: wire.payload.ok_or(SyncFrameError::InvalidShape)?,
            },
            _ => return Err(SyncFrameError::InvalidShape),
        };
        validate(&frame)?;
        Ok(frame)
    }
}

fn decode_authority_frame(wire: WireFrame) -> Result<SyncFrame, SyncFrameError> {
    let common_shape = wire.domain_id.is_none()
        && wire.nonce_or_proof.is_none()
        && wire.commits.is_empty()
        && wire.max_frame.is_none()
        && wire.commit.is_none()
        && wire.error_code.is_none();
    match wire.kind {
        10 if common_shape
            && wire.payload.is_none()
            && wire.payloads.is_empty()
            && wire.epoch_key.is_none() =>
        {
            Ok(SyncFrame::AuthorityState {
                epoch: wire.epoch.ok_or(SyncFrameError::InvalidShape)?,
                sequence: wire.sequence.ok_or(SyncFrameError::InvalidShape)?,
                head: wire.head.map(Into::into),
            })
        }
        11 if common_shape
            && wire.epoch.is_none()
            && wire.sequence.is_none()
            && wire.head.is_none() =>
        {
            Ok(SyncFrame::ControlGrant {
                transition: wire.payload.ok_or(SyncFrameError::InvalidShape)?,
                epoch_key: wire
                    .epoch_key
                    .map(Into::into)
                    .ok_or(SyncFrameError::InvalidShape)?,
                capability_chain: wire.payloads,
            })
        }
        _ => Err(SyncFrameError::InvalidShape),
    }
}

fn unused_scalar_fields(wire: &WireFrame) -> bool {
    wire.domain_id.is_none()
        && wire.nonce_or_proof.is_none()
        && wire.max_frame.is_none()
        && wire.commit.is_none()
        && wire.error_code.is_none()
        && wire.payload.is_none()
        && wire.epoch.is_none()
        && wire.sequence.is_none()
        && wire.head.is_none()
        && wire.payloads.is_empty()
        && wire.epoch_key.is_none()
}

fn unused_scalar_fields_except_payload(wire: &WireFrame) -> bool {
    wire.domain_id.is_none()
        && wire.nonce_or_proof.is_none()
        && wire.max_frame.is_none()
        && wire.commit.is_none()
        && wire.error_code.is_none()
        && wire.epoch.is_none()
        && wire.sequence.is_none()
        && wire.head.is_none()
        && wire.payloads.is_empty()
        && wire.epoch_key.is_none()
}

fn fixed_proof(value: Option<minicbor::bytes::ByteArray<32>>) -> Result<[u8; 32], SyncFrameError> {
    value.map(Into::into).ok_or(SyncFrameError::InvalidShape)
}

fn validate(frame: &SyncFrame) -> Result<(), SyncFrameError> {
    match frame {
        SyncFrame::Hello { max_frame, .. }
            if *max_frame == 0 || *max_frame as usize > MAX_CONTROL_FRAME =>
        {
            Err(SyncFrameError::FrameTooLarge(*max_frame as usize))
        }
        SyncFrame::AuthorityState {
            epoch, sequence, ..
        } if epoch != sequence => Err(SyncFrameError::InvalidShape),
        SyncFrame::Frontier { commits }
        | SyncFrame::Need { commits }
        | SyncFrame::Refs { commits } => validate_references(commits),
        SyncFrame::Invitation { payload } if payload.len() > 64 * 1024 => {
            Err(SyncFrameError::InvitationTooLarge(payload.len()))
        }
        SyncFrame::DomainRequest {
            capability_chain, ..
        }
        | SyncFrame::ControlGrant {
            capability_chain, ..
        } => validate_capability_chain(capability_chain),
        _ => Ok(()),
    }
}

fn validate_capability_chain(chain: &[Vec<u8>]) -> Result<(), SyncFrameError> {
    if chain.len() > MAX_CAPABILITY_CHAIN {
        return Err(SyncFrameError::TooManyAuthorityObjects(chain.len()));
    }
    if let Some(object) = chain
        .iter()
        .find(|object| object.len() > MAX_CAPABILITY_BYTES)
    {
        return Err(SyncFrameError::AuthorityObjectTooLarge(object.len()));
    }
    Ok(())
}

fn validate_references(commits: &[CommitId]) -> Result<(), SyncFrameError> {
    if commits.len() > MAX_REFERENCES {
        return Err(SyncFrameError::TooManyReferences(commits.len()));
    }
    if commits.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(SyncFrameError::NonCanonicalReferences);
    }
    Ok(())
}

fn encode_hint_content(
    author: AuthorId,
    commit: CommitId,
    frontier_digest: [u8; 32],
    counter: u64,
) -> Result<Vec<u8>, SyncFrameError> {
    minicbor::to_vec(GossipContent {
        version: GOSSIP_VERSION,
        author,
        commit,
        frontier_digest: frontier_digest.into(),
        counter,
    })
    .map_err(codec_error)
}

fn decode_exact(bytes: &[u8]) -> Result<GossipContent, SyncFrameError> {
    let mut decoder = minicbor::Decoder::new(bytes);
    let content = decoder.decode().map_err(codec_error)?;
    if decoder.position() != bytes.len() {
        return Err(SyncFrameError::NonCanonical);
    }
    Ok(content)
}

#[allow(clippy::needless_pass_by_value)]
fn codec_error(error: impl std::fmt::Display) -> SyncFrameError {
    SyncFrameError::Codec(error.to_string())
}
