use iroh_db_core::{AuthorId, CapabilityId, CommitId, DomainId};

use crate::{
    IrohSigner,
    key::{
        capability_signature_message, control_signature_message,
        domain_descriptor_signature_message,
    },
};

const DESCRIPTOR_VERSION: u16 = 1;
const CAPABILITY_VERSION: u16 = 2;
const CONTROL_VERSION: u16 = 3;
const MAX_DELEGATION_DEPTH: u8 = 8;
const MAX_CONTROL_COMMITS: usize = 65_536;
const MAX_CONTROL_REVOKED: usize = 1_024;

/// A domain's immutable replicated write policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(index_only)]
#[repr(u8)]
pub enum ConsistencyMode {
    /// Every endpoint with `WRITE` may author data commits.
    #[n(0)]
    MultiWriter = 0,
    /// Only the control state's designated writer may author data commits.
    #[n(1)]
    SingleWriter = 1,
    /// Writers may only create immutable records once.
    #[n(2)]
    AppendOnly = 2,
}

/// One independently grantable domain permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Permission {
    Read = 1 << 0,
    Write = 1 << 1,
    Invite = 1 << 2,
    Revoke = 1 << 3,
    FetchBlobs = 1 << 4,
    Snapshot = 1 << 5,
    Admin = 1 << 6,
}

const ALL_PERMISSION_BITS: u16 = (1 << 7) - 1;

/// A validated compact set of explicit permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PermissionSet(u16);

impl PermissionSet {
    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn all() -> Self {
        Self(ALL_PERMISSION_BITS)
    }

    pub fn from_permissions(permissions: &[Permission]) -> Self {
        Self(
            permissions
                .iter()
                .fold(0, |bits, permission| bits | *permission as u16),
        )
    }

    pub const fn from_bits(bits: u16) -> Result<Self, AuthorityError> {
        if bits & !ALL_PERMISSION_BITS == 0 {
            Ok(Self(bits))
        } else {
            Err(AuthorityError::UnknownPermissionBits(bits))
        }
    }

    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn contains(self, permission: Permission) -> bool {
        self.0 & permission as u16 != 0
    }

    pub const fn contains_all(self, permissions: Self) -> bool {
        self.0 & permissions.0 == permissions.0
    }
}

/// A signed immutable domain genesis descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainDescriptor {
    domain_id: DomainId,
    mode: ConsistencyMode,
    owner: AuthorId,
    nonce: [u8; 32],
    signature: [u8; 64],
}

impl DomainDescriptor {
    pub fn issue(
        domain_id: DomainId,
        mode: ConsistencyMode,
        owner: &IrohSigner,
        nonce: [u8; 32],
    ) -> Result<Self, AuthorityError> {
        let mut descriptor = Self {
            domain_id,
            mode,
            owner: owner.author(),
            nonce,
            signature: [0; 64],
        };
        descriptor.signature = owner.sign_domain_descriptor(&descriptor.signing_bytes()?);
        Ok(descriptor)
    }

    pub const fn domain_id(&self) -> DomainId {
        self.domain_id
    }

    pub const fn mode(&self) -> ConsistencyMode {
        self.mode
    }

    pub const fn owner(&self) -> AuthorId {
        self.owner
    }

    pub fn verify(&self) -> Result<(), AuthorityError> {
        verify_signature(
            self.owner,
            &domain_descriptor_signature_message(&self.signing_bytes()?),
            &self.signature,
        )
    }

    pub fn encode_canonical(&self) -> Result<Vec<u8>, AuthorityError> {
        minicbor::to_vec(DescriptorWire {
            content: self.signing_bytes()?,
            signature: self.signature,
        })
        .map_err(codec_error)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, AuthorityError> {
        let wire: DescriptorWire = decode_exact(bytes)?;
        let content: DescriptorContent = decode_exact(&wire.content)?;
        if content.version != DESCRIPTOR_VERSION {
            return Err(AuthorityError::UnsupportedVersion(content.version));
        }
        let descriptor = Self {
            domain_id: content.domain_id,
            mode: content.mode,
            owner: content.owner,
            nonce: content.nonce,
            signature: wire.signature,
        };
        if descriptor.signing_bytes()? != wire.content || descriptor.encode_canonical()? != bytes {
            return Err(AuthorityError::NonCanonical);
        }
        descriptor.verify()?;
        Ok(descriptor)
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, AuthorityError> {
        minicbor::to_vec(DescriptorContent {
            version: DESCRIPTOR_VERSION,
            domain_id: self.domain_id,
            mode: self.mode,
            owner: self.owner,
            nonce: self.nonce,
        })
        .map_err(codec_error)
    }
}

/// A signed endpoint-targeted capability certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityCertificate {
    domain_id: DomainId,
    subject: AuthorId,
    issuer_capability: Option<CapabilityId>,
    permissions: PermissionSet,
    delegation_permissions: PermissionSet,
    issued_control_sequence: u64,
    issued_control_head: Option<[u8; 32]>,
    valid_from_epoch: u64,
    valid_through_epoch: Option<u64>,
    depth: u8,
    nonce: [u8; 32],
    issuer_endpoint: AuthorId,
    signature: [u8; 64],
}

impl CapabilityCertificate {
    pub fn issue_root(
        domain_id: DomainId,
        permissions: PermissionSet,
        owner: &IrohSigner,
        nonce: [u8; 32],
    ) -> Result<Self, AuthorityError> {
        Self::issue(
            domain_id,
            owner.author(),
            None,
            permissions,
            permissions,
            0,
            None,
            0,
            None,
            0,
            nonce,
            owner,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn delegate(
        &self,
        issuer: &IrohSigner,
        subject: AuthorId,
        permissions: PermissionSet,
        delegation_permissions: PermissionSet,
        valid_from_epoch: u64,
        valid_through_epoch: Option<u64>,
        nonce: [u8; 32],
    ) -> Result<Self, AuthorityError> {
        self.delegate_at_control(
            issuer,
            subject,
            permissions,
            delegation_permissions,
            self.issued_control_sequence,
            self.issued_control_head,
            valid_from_epoch,
            valid_through_epoch,
            nonce,
        )
    }

    /// Delegates authority anchored to an exact accepted domain-control head.
    #[allow(clippy::too_many_arguments)]
    pub fn delegate_at_control(
        &self,
        issuer: &IrohSigner,
        subject: AuthorId,
        permissions: PermissionSet,
        delegation_permissions: PermissionSet,
        issued_control_sequence: u64,
        issued_control_head: Option<[u8; 32]>,
        valid_from_epoch: u64,
        valid_through_epoch: Option<u64>,
        nonce: [u8; 32],
    ) -> Result<Self, AuthorityError> {
        self.verify_signature()?;
        if issuer.author() != self.subject {
            return Err(AuthorityError::WrongIssuer);
        }
        if !self.delegation_permissions.contains_all(permissions)
            || !self
                .delegation_permissions
                .contains_all(delegation_permissions)
        {
            return Err(AuthorityError::PermissionEscalation);
        }
        if valid_from_epoch < self.valid_from_epoch
            || !epoch_end_within(valid_through_epoch, self.valid_through_epoch)
        {
            return Err(AuthorityError::EpochEscalation);
        }
        if issued_control_sequence < self.issued_control_sequence {
            return Err(AuthorityError::ControlSequenceRegression);
        }
        if issued_control_sequence == self.issued_control_sequence
            && issued_control_head != self.issued_control_head
        {
            return Err(AuthorityError::ControlHeadMismatch);
        }
        let depth = self
            .depth
            .checked_add(1)
            .ok_or(AuthorityError::DelegationTooDeep)?;
        Self::issue(
            self.domain_id,
            subject,
            Some(self.id()?),
            permissions,
            delegation_permissions,
            issued_control_sequence,
            issued_control_head,
            valid_from_epoch,
            valid_through_epoch,
            depth,
            nonce,
            issuer,
        )
    }

    pub const fn domain_id(&self) -> DomainId {
        self.domain_id
    }

    pub const fn subject(&self) -> AuthorId {
        self.subject
    }

    pub const fn issuer_capability(&self) -> Option<CapabilityId> {
        self.issuer_capability
    }

    pub const fn permissions(&self) -> PermissionSet {
        self.permissions
    }

    pub const fn delegation_permissions(&self) -> PermissionSet {
        self.delegation_permissions
    }

    pub const fn issued_control_sequence(&self) -> u64 {
        self.issued_control_sequence
    }

    pub const fn issued_control_head(&self) -> Option<[u8; 32]> {
        self.issued_control_head
    }

    pub const fn valid_from_epoch(&self) -> u64 {
        self.valid_from_epoch
    }

    pub const fn valid_through_epoch(&self) -> Option<u64> {
        self.valid_through_epoch
    }

    pub const fn depth(&self) -> u8 {
        self.depth
    }

    /// Returns the endpoint that signed this certificate.
    pub const fn issuer_endpoint(&self) -> AuthorId {
        self.issuer_endpoint
    }

    pub fn permits(&self, permission: Permission, epoch: u64) -> bool {
        self.permissions.contains(permission)
            && epoch >= self.valid_from_epoch
            && self
                .valid_through_epoch
                .is_none_or(|through| epoch <= through)
    }

    pub fn id(&self) -> Result<CapabilityId, AuthorityError> {
        Ok(CapabilityId::from_bytes(
            *blake3::hash(&self.encode_canonical()?).as_bytes(),
        ))
    }

    pub fn verify_signature(&self) -> Result<(), AuthorityError> {
        verify_signature(
            self.issuer_endpoint,
            &capability_signature_message(&self.signing_bytes()?),
            &self.signature,
        )
    }

    pub fn validate_delegation(&self, issuer: &Self) -> Result<(), AuthorityError> {
        self.verify_signature()?;
        issuer.verify_signature()?;
        if self.domain_id != issuer.domain_id
            || self.issuer_capability != Some(issuer.id()?)
            || self.issuer_endpoint != issuer.subject
            || self.depth != issuer.depth.saturating_add(1)
        {
            return Err(AuthorityError::WrongIssuer);
        }
        if !issuer.delegation_permissions.contains_all(self.permissions)
            || !issuer
                .delegation_permissions
                .contains_all(self.delegation_permissions)
        {
            return Err(AuthorityError::PermissionEscalation);
        }
        if self.valid_from_epoch < issuer.valid_from_epoch
            || !epoch_end_within(self.valid_through_epoch, issuer.valid_through_epoch)
        {
            return Err(AuthorityError::EpochEscalation);
        }
        if self.issued_control_sequence < issuer.issued_control_sequence {
            return Err(AuthorityError::ControlSequenceRegression);
        }
        if self.issued_control_sequence == issuer.issued_control_sequence
            && self.issued_control_head != issuer.issued_control_head
        {
            return Err(AuthorityError::ControlHeadMismatch);
        }
        Ok(())
    }

    pub fn encode_canonical(&self) -> Result<Vec<u8>, AuthorityError> {
        let bytes = minicbor::to_vec(CapabilityWire {
            content: self.signing_bytes()?,
            signature: self.signature,
        })
        .map_err(codec_error)?;
        if bytes.len() > 4096 {
            return Err(AuthorityError::ObjectTooLarge(bytes.len()));
        }
        Ok(bytes)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, AuthorityError> {
        if bytes.len() > 4096 {
            return Err(AuthorityError::ObjectTooLarge(bytes.len()));
        }
        let wire: CapabilityWire = decode_exact(bytes)?;
        let content: CapabilityContent = decode_exact(&wire.content)?;
        if content.version != CAPABILITY_VERSION {
            return Err(AuthorityError::UnsupportedVersion(content.version));
        }
        let capability = Self {
            domain_id: content.domain_id,
            subject: content.subject,
            issuer_capability: content.issuer_capability,
            permissions: PermissionSet::from_bits(content.permissions)?,
            delegation_permissions: PermissionSet::from_bits(content.delegation_permissions)?,
            issued_control_sequence: content.issued_control_sequence,
            issued_control_head: content.issued_control_head,
            valid_from_epoch: content.valid_from_epoch,
            valid_through_epoch: content.valid_through_epoch,
            depth: content.depth,
            nonce: content.nonce,
            issuer_endpoint: content.issuer_endpoint,
            signature: wire.signature,
        };
        capability.validate_shape()?;
        if capability.signing_bytes()? != wire.content || capability.encode_canonical()? != bytes {
            return Err(AuthorityError::NonCanonical);
        }
        capability.verify_signature()?;
        Ok(capability)
    }

    #[allow(clippy::too_many_arguments)]
    fn issue(
        domain_id: DomainId,
        subject: AuthorId,
        issuer_capability: Option<CapabilityId>,
        permissions: PermissionSet,
        delegation_permissions: PermissionSet,
        issued_control_sequence: u64,
        issued_control_head: Option<[u8; 32]>,
        valid_from_epoch: u64,
        valid_through_epoch: Option<u64>,
        depth: u8,
        nonce: [u8; 32],
        issuer: &IrohSigner,
    ) -> Result<Self, AuthorityError> {
        let mut capability = Self {
            domain_id,
            subject,
            issuer_capability,
            permissions,
            delegation_permissions,
            issued_control_sequence,
            issued_control_head,
            valid_from_epoch,
            valid_through_epoch,
            depth,
            nonce,
            issuer_endpoint: issuer.author(),
            signature: [0; 64],
        };
        capability.validate_shape()?;
        capability.signature = issuer.sign_capability(&capability.signing_bytes()?);
        Ok(capability)
    }

    fn validate_shape(&self) -> Result<(), AuthorityError> {
        if self.depth > MAX_DELEGATION_DEPTH {
            return Err(AuthorityError::DelegationTooDeep);
        }
        if self
            .valid_through_epoch
            .is_some_and(|through| through < self.valid_from_epoch)
        {
            return Err(AuthorityError::EpochEscalation);
        }
        if (self.issued_control_sequence == 0) != self.issued_control_head.is_none() {
            return Err(AuthorityError::ControlHeadMismatch);
        }
        if self.depth == 0 {
            if self.issuer_capability.is_some() || self.issuer_endpoint != self.subject {
                return Err(AuthorityError::WrongIssuer);
            }
        } else if self.issuer_capability.is_none() {
            return Err(AuthorityError::WrongIssuer);
        }
        Ok(())
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, AuthorityError> {
        minicbor::to_vec(CapabilityContent {
            version: CAPABILITY_VERSION,
            domain_id: self.domain_id,
            subject: self.subject,
            issuer_capability: self.issuer_capability,
            permissions: self.permissions.bits(),
            delegation_permissions: self.delegation_permissions.bits(),
            issued_control_sequence: self.issued_control_sequence,
            valid_from_epoch: self.valid_from_epoch,
            valid_through_epoch: self.valid_through_epoch,
            depth: self.depth,
            nonce: self.nonce,
            issuer_endpoint: self.issuer_endpoint,
            issued_control_head: self.issued_control_head,
        })
        .map_err(codec_error)
    }
}

/// A signed, immutable, single-successor domain authority transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlTransition {
    domain_id: DomainId,
    sequence: u64,
    predecessor: Option<[u8; 32]>,
    previous_epoch: u64,
    new_epoch: u64,
    cut: Vec<CommitId>,
    revoked_subjects: Vec<AuthorId>,
    writer: AuthorId,
    controller: AuthorId,
    controller_capability: CapabilityId,
    key_distribution_digest: [u8; 32],
    author: AuthorId,
    author_capability: CapabilityId,
    nonce: [u8; 32],
    signature: [u8; 64],
}

impl ControlTransition {
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        domain_id: DomainId,
        sequence: u64,
        predecessor: Option<[u8; 32]>,
        previous_epoch: u64,
        cut: Vec<CommitId>,
        mut revoked_subjects: Vec<AuthorId>,
        writer: AuthorId,
        controller: AuthorId,
        controller_capability: CapabilityId,
        key_distribution_digest: [u8; 32],
        author_capability: CapabilityId,
        nonce: [u8; 32],
        signer: &IrohSigner,
    ) -> Result<Self, AuthorityError> {
        revoked_subjects.sort_unstable();
        revoked_subjects.dedup();
        let mut control = Self {
            domain_id,
            sequence,
            predecessor,
            previous_epoch,
            new_epoch: previous_epoch
                .checked_add(1)
                .ok_or(AuthorityError::InvalidControl)?,
            cut,
            revoked_subjects,
            writer,
            controller,
            controller_capability,
            key_distribution_digest,
            author: signer.author(),
            author_capability,
            nonce,
            signature: [0; 64],
        };
        control.validate_shape()?;
        control.signature = signer.sign_control(&control.signing_bytes()?);
        Ok(control)
    }

    pub const fn domain_id(&self) -> DomainId {
        self.domain_id
    }
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    pub const fn predecessor(&self) -> Option<[u8; 32]> {
        self.predecessor
    }
    pub const fn previous_epoch(&self) -> u64 {
        self.previous_epoch
    }
    pub const fn new_epoch(&self) -> u64 {
        self.new_epoch
    }
    pub fn cut(&self) -> &[CommitId] {
        &self.cut
    }
    pub fn revoked_subjects(&self) -> &[AuthorId] {
        &self.revoked_subjects
    }
    pub const fn writer(&self) -> AuthorId {
        self.writer
    }
    /// Returns the endpoint designated to author the next control transition.
    pub const fn controller(&self) -> AuthorId {
        self.controller
    }
    /// Returns the capability that authorizes the designated successor.
    pub const fn controller_capability(&self) -> CapabilityId {
        self.controller_capability
    }
    pub const fn key_distribution_digest(&self) -> [u8; 32] {
        self.key_distribution_digest
    }
    pub const fn author(&self) -> AuthorId {
        self.author
    }
    pub const fn author_capability(&self) -> CapabilityId {
        self.author_capability
    }

    pub fn id(&self) -> Result<[u8; 32], AuthorityError> {
        Ok(*blake3::hash(&self.encode_canonical()?).as_bytes())
    }

    pub fn verify(&self) -> Result<(), AuthorityError> {
        self.validate_shape()?;
        verify_signature(
            self.author,
            &control_signature_message(&self.signing_bytes()?),
            &self.signature,
        )
    }

    pub fn encode_canonical(&self) -> Result<Vec<u8>, AuthorityError> {
        let bytes = minicbor::to_vec(ControlWire {
            content: self.signing_bytes()?,
            signature: self.signature,
        })
        .map_err(codec_error)?;
        if bytes.len() > 1024 * 1024 {
            return Err(AuthorityError::ObjectTooLarge(bytes.len()));
        }
        Ok(bytes)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, AuthorityError> {
        if bytes.len() > 1024 * 1024 {
            return Err(AuthorityError::ObjectTooLarge(bytes.len()));
        }
        let wire: ControlWire = decode_exact(bytes)?;
        let content: ControlContent = decode_exact(&wire.content)?;
        if content.version != CONTROL_VERSION {
            return Err(AuthorityError::UnsupportedVersion(content.version));
        }
        let control = Self {
            domain_id: content.domain_id,
            sequence: content.sequence,
            predecessor: content.predecessor,
            previous_epoch: content.previous_epoch,
            new_epoch: content.new_epoch,
            cut: content.cut,
            revoked_subjects: content.revoked_subjects,
            writer: content.writer,
            controller: content.controller,
            controller_capability: content.controller_capability,
            key_distribution_digest: content.key_distribution_digest,
            author: content.author,
            author_capability: content.author_capability,
            nonce: content.nonce,
            signature: wire.signature,
        };
        if control.signing_bytes()? != wire.content || control.encode_canonical()? != bytes {
            return Err(AuthorityError::NonCanonical);
        }
        control.verify()?;
        Ok(control)
    }

    fn validate_shape(&self) -> Result<(), AuthorityError> {
        if self.sequence == 0
            || self.previous_epoch == u64::MAX
            || self.new_epoch != self.previous_epoch + 1
            || self.cut.len() > MAX_CONTROL_COMMITS
            || self.revoked_subjects.len() > MAX_CONTROL_REVOKED
            || !strictly_sorted(&self.cut)
            || !strictly_sorted(&self.revoked_subjects)
        {
            return Err(AuthorityError::InvalidControl);
        }
        Ok(())
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, AuthorityError> {
        minicbor::to_vec(ControlContent {
            version: CONTROL_VERSION,
            domain_id: self.domain_id,
            sequence: self.sequence,
            predecessor: self.predecessor,
            previous_epoch: self.previous_epoch,
            new_epoch: self.new_epoch,
            cut: self.cut.clone(),
            revoked_subjects: self.revoked_subjects.clone(),
            writer: self.writer,
            controller: self.controller,
            controller_capability: self.controller_capability,
            key_distribution_digest: self.key_distribution_digest,
            author: self.author,
            author_capability: self.author_capability,
            nonce: self.nonce,
        })
        .map_err(codec_error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityError {
    #[error("authority object codec failed: {0}")]
    Codec(String),
    #[error("authority object is not canonical")]
    NonCanonical,
    #[error("unsupported authority version: {0}")]
    UnsupportedVersion(u16),
    #[error("unknown permission bits: {0:#x}")]
    UnknownPermissionBits(u16),
    #[error("capability delegation expands permissions")]
    PermissionEscalation,
    #[error("capability delegation expands epoch scope")]
    EpochEscalation,
    #[error("capability control-sequence anchor moves backward")]
    ControlSequenceRegression,
    #[error("capability control-head anchor is inconsistent")]
    ControlHeadMismatch,
    #[error("capability issuer or chain link is invalid")]
    WrongIssuer,
    #[error("capability delegation exceeds depth eight")]
    DelegationTooDeep,
    #[error("authority signature is invalid")]
    InvalidSignature,
    #[error("authority endpoint public key is invalid")]
    InvalidAuthor,
    #[error("authority object is too large: {0}")]
    ObjectTooLarge(usize),
    #[error("domain control transition is invalid")]
    InvalidControl,
}

#[derive(minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
struct DescriptorContent {
    #[n(0)]
    version: u16,
    #[n(1)]
    domain_id: DomainId,
    #[n(2)]
    mode: ConsistencyMode,
    #[n(3)]
    owner: AuthorId,
    #[n(4)]
    nonce: [u8; 32],
}

#[derive(minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
struct DescriptorWire {
    #[n(0)]
    content: Vec<u8>,
    #[n(1)]
    signature: [u8; 64],
}

#[derive(minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
struct CapabilityContent {
    #[n(0)]
    version: u16,
    #[n(1)]
    domain_id: DomainId,
    #[n(2)]
    subject: AuthorId,
    #[n(3)]
    issuer_capability: Option<CapabilityId>,
    #[n(4)]
    permissions: u16,
    #[n(5)]
    delegation_permissions: u16,
    #[n(6)]
    issued_control_sequence: u64,
    #[n(7)]
    valid_from_epoch: u64,
    #[n(8)]
    valid_through_epoch: Option<u64>,
    #[n(9)]
    depth: u8,
    #[n(10)]
    nonce: [u8; 32],
    #[n(11)]
    issuer_endpoint: AuthorId,
    #[n(12)]
    issued_control_head: Option<[u8; 32]>,
}

#[derive(minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
struct CapabilityWire {
    #[n(0)]
    content: Vec<u8>,
    #[n(1)]
    signature: [u8; 64],
}

#[derive(minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
struct ControlContent {
    #[n(0)]
    version: u16,
    #[n(1)]
    domain_id: DomainId,
    #[n(2)]
    sequence: u64,
    #[n(3)]
    predecessor: Option<[u8; 32]>,
    #[n(4)]
    previous_epoch: u64,
    #[n(5)]
    new_epoch: u64,
    #[n(6)]
    cut: Vec<CommitId>,
    #[n(7)]
    revoked_subjects: Vec<AuthorId>,
    #[n(8)]
    writer: AuthorId,
    #[n(9)]
    key_distribution_digest: [u8; 32],
    #[n(10)]
    author: AuthorId,
    #[n(11)]
    author_capability: CapabilityId,
    #[n(12)]
    nonce: [u8; 32],
    #[n(13)]
    controller: AuthorId,
    #[n(14)]
    controller_capability: CapabilityId,
}

#[derive(minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
struct ControlWire {
    #[n(0)]
    content: Vec<u8>,
    #[n(1)]
    signature: [u8; 64],
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn epoch_end_within(child: Option<u64>, parent: Option<u64>) -> bool {
    match (child, parent) {
        (Some(child), Some(parent)) => child <= parent,
        (None | Some(_), None) => true,
        (None, Some(_)) => false,
    }
}

fn verify_signature(
    author: AuthorId,
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), AuthorityError> {
    let public_key = iroh_base::PublicKey::try_from(author.as_bytes())
        .map_err(|_| AuthorityError::InvalidAuthor)?;
    public_key
        .verify(message, &iroh_base::Signature::from_bytes(signature))
        .map_err(|_| AuthorityError::InvalidSignature)
}

fn decode_exact<T>(bytes: &[u8]) -> Result<T, AuthorityError>
where
    T: for<'bytes> minicbor::Decode<'bytes, ()>,
{
    let mut decoder = minicbor::Decoder::new(bytes);
    let value = decoder.decode().map_err(codec_error)?;
    if decoder.position() != bytes.len() {
        return Err(AuthorityError::NonCanonical);
    }
    Ok(value)
}

#[allow(clippy::needless_pass_by_value)]
fn codec_error(error: impl std::fmt::Display) -> AuthorityError {
    AuthorityError::Codec(error.to_string())
}
