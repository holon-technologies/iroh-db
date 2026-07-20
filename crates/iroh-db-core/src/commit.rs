use std::fmt;

use minicbor::{Decoder, Encoder};

use crate::{AuthorId, CapabilityId, CollectionId, CommitId, DomainId, SchemaId, TransactionId};

const MAGIC: &str = "iroh-db";
const FORMAT_MAJOR: u16 = 1;
const FORMAT_MINOR: u16 = 0;
const ENVELOPE_KIND: u8 = 2;
const BODY_KIND: u8 = 3;
const MAX_DEPENDENCIES: usize = 4_096;
const MAX_SCHEMAS: usize = 4_096;
const MAX_OPERATIONS: usize = 65_536;
const MAX_RECORD_ID: usize = 1_024;
const MAX_OPERATION_PAYLOAD: usize = 16 * 1024 * 1024;
const MAX_CIPHERTEXT: usize = 64 * 1024 * 1024;

/// The Ed25519 signature attached to a commit envelope.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CommitSignature([u8; 64]);

impl CommitSignature {
    /// Constructs a signature from its exact wire bytes.
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Returns the exact signature bytes.
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Consumes this signature and returns its exact bytes.
    pub const fn to_bytes(self) -> [u8; 64] {
        self.0
    }
}

impl fmt::Debug for CommitSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CommitSignature([redacted])")
    }
}

/// Public authenticated metadata for an encrypted commit body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitHeader {
    domain_id: DomainId,
    epoch: u64,
    author: AuthorId,
    author_sequence: u64,
    dependencies: Vec<CommitId>,
    capability_id: CapabilityId,
    schema_ids: Vec<SchemaId>,
    nonce: [u8; 24],
}

impl CommitHeader {
    /// Validates and constructs a canonical commit header.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        domain_id: DomainId,
        epoch: u64,
        author: AuthorId,
        author_sequence: u64,
        mut dependencies: Vec<CommitId>,
        capability_id: CapabilityId,
        mut schema_ids: Vec<SchemaId>,
        nonce: [u8; 24],
    ) -> Result<Self, CommitCodecError> {
        if dependencies.len() > MAX_DEPENDENCIES {
            return Err(CommitCodecError::TooManyDependencies(dependencies.len()));
        }
        if schema_ids.len() > MAX_SCHEMAS {
            return Err(CommitCodecError::TooManySchemas(schema_ids.len()));
        }
        dependencies.sort_unstable();
        dependencies.dedup();
        schema_ids.sort_unstable();
        schema_ids.dedup();
        Ok(Self {
            domain_id,
            epoch,
            author,
            author_sequence,
            dependencies,
            capability_id,
            schema_ids,
            nonce,
        })
    }

    /// Returns the domain this transaction mutates.
    pub const fn domain_id(&self) -> DomainId {
        self.domain_id
    }

    /// Returns the encryption and authorization epoch.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the authenticated endpoint author.
    pub const fn author(&self) -> AuthorId {
        self.author
    }

    /// Returns the author's contiguous domain-local sequence.
    pub const fn author_sequence(&self) -> u64 {
        self.author_sequence
    }

    /// Returns the sorted, unique causal frontier dependencies.
    pub fn dependencies(&self) -> &[CommitId] {
        &self.dependencies
    }

    /// Returns the capability authorizing the transaction.
    pub const fn capability_id(&self) -> CapabilityId {
        self.capability_id
    }

    /// Returns the sorted, unique schemas used by operations.
    pub fn schema_ids(&self) -> &[SchemaId] {
        &self.schema_ids
    }

    /// Returns the XChaCha20-Poly1305 nonce.
    pub const fn nonce(&self) -> &[u8; 24] {
        &self.nonce
    }
}

/// An immutable signed commit blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitEnvelope {
    header: CommitHeader,
    ciphertext: Vec<u8>,
    signature: CommitSignature,
}

impl CommitEnvelope {
    /// Constructs a bounded commit envelope.
    pub fn new(
        header: CommitHeader,
        ciphertext: Vec<u8>,
        signature: CommitSignature,
    ) -> Result<Self, CommitCodecError> {
        if ciphertext.len() > MAX_CIPHERTEXT {
            return Err(CommitCodecError::CiphertextTooLarge(ciphertext.len()));
        }
        Ok(Self {
            header,
            ciphertext,
            signature,
        })
    }

    /// Returns the authenticated public header.
    pub const fn header(&self) -> &CommitHeader {
        &self.header
    }

    /// Returns the encrypted commit body and AEAD tag.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Returns the author signature.
    pub const fn signature(&self) -> CommitSignature {
        self.signature
    }

    /// Returns the exact canonical bytes covered by the signature.
    pub fn signing_bytes(&self) -> Vec<u8> {
        Self::signing_bytes_for(&self.header, &self.ciphertext)
            .expect("an existing envelope is already size-validated")
    }

    /// Encodes a prospective header and ciphertext for signing.
    pub fn signing_bytes_for(
        header: &CommitHeader,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CommitCodecError> {
        if ciphertext.len() > MAX_CIPHERTEXT {
            return Err(CommitCodecError::CiphertextTooLarge(ciphertext.len()));
        }
        Ok(encode_envelope(header, ciphertext, None))
    }

    /// Encodes the complete durable commit blob.
    pub fn encode_canonical(&self) -> Vec<u8> {
        encode_envelope(&self.header, &self.ciphertext, Some(self.signature))
    }

    /// Strictly decodes the unique durable commit representation.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, CommitCodecError> {
        let envelope = decode_envelope(bytes)?;
        if envelope.encode_canonical() != bytes {
            return Err(CommitCodecError::NonCanonicalEncoding);
        }
        Ok(envelope)
    }

    /// Returns the iroh-blobs-compatible BLAKE3 hash of the exact blob bytes.
    pub fn commit_id(&self) -> CommitId {
        CommitId::from_bytes(*blake3::hash(&self.encode_canonical()).as_bytes())
    }
}

/// A decrypted atomic domain transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitBody {
    transaction_id: TransactionId,
    operations: Vec<Operation>,
}

impl CommitBody {
    /// Constructs a bounded transaction body.
    pub fn new(
        transaction_id: TransactionId,
        operations: Vec<Operation>,
    ) -> Result<Self, CommitCodecError> {
        if operations.len() > MAX_OPERATIONS {
            return Err(CommitCodecError::TooManyOperations(operations.len()));
        }
        Ok(Self {
            transaction_id,
            operations,
        })
    }

    /// Returns the idempotency identity of the local transaction.
    pub const fn transaction_id(&self) -> TransactionId {
        self.transaction_id
    }

    /// Returns operations in transaction order.
    pub fn operations(&self) -> &[Operation] {
        &self.operations
    }

    /// Encodes the transaction body before encryption.
    pub fn encode_canonical(&self) -> Vec<u8> {
        let mut encoder = Encoder::new(Vec::new());
        encode_body(&mut encoder, self).expect("encoding into Vec cannot fail");
        encoder.into_writer()
    }

    /// Strictly decodes a decrypted transaction body.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, CommitCodecError> {
        let body = decode_body(bytes)?;
        if body.encode_canonical() != bytes {
            return Err(CommitCodecError::NonCanonicalEncoding);
        }
        Ok(body)
    }
}

/// The stable operation opcode applied by the materializer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OperationKind {
    /// Adds a record incarnation.
    RecordCreate = 1,
    /// Removes observed record incarnations.
    RecordDelete = 2,
    /// Assigns a causal LWW register.
    LwwAssign = 3,
    /// Adds an observed-remove set element.
    OrSetAdd = 4,
    /// Removes observed set additions.
    OrSetRemove = 5,
    /// Adds a grow-only set element.
    GrowOnlySetAdd = 6,
    /// Increments a PN counter component.
    CounterIncrement = 7,
    /// Decrements a PN counter component.
    CounterDecrement = 8,
    /// Assigns a multi-value register.
    MultiValueAssign = 9,
    /// Sets an immutable value.
    ImmutableSet = 10,
    /// Inserts an ordered-list element.
    OrderedListInsert = 11,
    /// Removes an observed ordered-list element.
    OrderedListRemove = 12,
    /// Merges a complete canonical CRDT field state.
    FieldStateMerge = 13,
    /// Stages one target-schema record without changing visible state.
    SchemaStage = 14,
    /// Atomically activates a completely staged schema transition.
    SchemaActivate = 15,
}

impl TryFrom<u8> for OperationKind {
    type Error = CommitCodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::RecordCreate),
            2 => Ok(Self::RecordDelete),
            3 => Ok(Self::LwwAssign),
            4 => Ok(Self::OrSetAdd),
            5 => Ok(Self::OrSetRemove),
            6 => Ok(Self::GrowOnlySetAdd),
            7 => Ok(Self::CounterIncrement),
            8 => Ok(Self::CounterDecrement),
            9 => Ok(Self::MultiValueAssign),
            10 => Ok(Self::ImmutableSet),
            11 => Ok(Self::OrderedListInsert),
            12 => Ok(Self::OrderedListRemove),
            13 => Ok(Self::FieldStateMerge),
            14 => Ok(Self::SchemaStage),
            15 => Ok(Self::SchemaActivate),
            value => Err(CommitCodecError::UnknownOperationKind(value)),
        }
    }
}

/// One field or record operation in an atomic commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operation {
    collection_id: CollectionId,
    record_id: Vec<u8>,
    field_id: u32,
    kind: OperationKind,
    payload: Vec<u8>,
}

impl Operation {
    /// Constructs a size-bounded operation.
    pub fn new(
        collection_id: CollectionId,
        record_id: Vec<u8>,
        field_id: u32,
        kind: OperationKind,
        payload: Vec<u8>,
    ) -> Result<Self, CommitCodecError> {
        if record_id.len() > MAX_RECORD_ID {
            return Err(CommitCodecError::RecordIdTooLarge(record_id.len()));
        }
        if payload.len() > MAX_OPERATION_PAYLOAD {
            return Err(CommitCodecError::OperationPayloadTooLarge(payload.len()));
        }
        Ok(Self {
            collection_id,
            record_id,
            field_id,
            kind,
            payload,
        })
    }

    /// Returns the target collection.
    pub const fn collection_id(&self) -> CollectionId {
        self.collection_id
    }

    /// Returns the canonical application record key.
    pub fn record_id(&self) -> &[u8] {
        &self.record_id
    }

    /// Returns the stable target field ID, or zero for record operations.
    pub const fn field_id(&self) -> u32 {
        self.field_id
    }

    /// Returns the deterministic operation opcode.
    pub const fn kind(&self) -> OperationKind {
        self.kind
    }

    /// Returns the operation-specific canonical payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Commit format validation or decoding failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommitCodecError {
    /// A commit declared too many causal dependencies.
    #[error("too many commit dependencies: {0}")]
    TooManyDependencies(usize),
    /// A commit declared too many schema references.
    #[error("too many schema references: {0}")]
    TooManySchemas(usize),
    /// A transaction contained too many operations.
    #[error("too many operations: {0}")]
    TooManyOperations(usize),
    /// A record key exceeded the protocol limit.
    #[error("record id is too large: {0} bytes")]
    RecordIdTooLarge(usize),
    /// An operation payload exceeded the protocol limit.
    #[error("operation payload is too large: {0} bytes")]
    OperationPayloadTooLarge(usize),
    /// Encrypted commit bytes exceeded the protocol limit.
    #[error("commit ciphertext is too large: {0} bytes")]
    CiphertextTooLarge(usize),
    /// An unknown operation opcode was encountered.
    #[error("unknown operation kind {0}")]
    UnknownOperationKind(u8),
    /// The object format major, minor, or kind is unsupported.
    #[error("unsupported commit format")]
    UnsupportedFormat,
    /// The binary object was malformed or violated a resource bound.
    #[error("invalid commit encoding: {0}")]
    InvalidEncoding(String),
    /// The object was valid CBOR but not the unique canonical representation.
    #[error("commit encoding is not canonical")]
    NonCanonicalEncoding,
}

fn encode_envelope(
    header: &CommitHeader,
    ciphertext: &[u8],
    signature: Option<CommitSignature>,
) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    let field_count = if signature.is_some() { 14 } else { 13 };
    encoder
        .map(field_count)
        .and_then(|encoder| encoder.u8(0))
        .and_then(|encoder| encoder.str(MAGIC))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.u16(FORMAT_MAJOR))
        .and_then(|encoder| encoder.u8(2))
        .and_then(|encoder| encoder.u16(FORMAT_MINOR))
        .and_then(|encoder| encoder.u8(3))
        .and_then(|encoder| encoder.u8(ENVELOPE_KIND))
        .and_then(|encoder| encoder.u8(4))
        .and_then(|encoder| encoder.bytes(header.domain_id().as_bytes()))
        .and_then(|encoder| encoder.u8(5))
        .and_then(|encoder| encoder.u64(header.epoch()))
        .and_then(|encoder| encoder.u8(6))
        .and_then(|encoder| encoder.bytes(header.author().as_bytes()))
        .and_then(|encoder| encoder.u8(7))
        .and_then(|encoder| encoder.u64(header.author_sequence()))
        .expect("encoding into Vec cannot fail");
    encoder
        .u8(8)
        .and_then(|encoder| encoder.array(header.dependencies().len() as u64))
        .expect("encoding into Vec cannot fail");
    for dependency in header.dependencies() {
        encoder
            .bytes(dependency.as_bytes())
            .expect("encoding into Vec cannot fail");
    }
    encoder
        .u8(9)
        .and_then(|encoder| encoder.bytes(header.capability_id().as_bytes()))
        .and_then(|encoder| encoder.u8(10))
        .and_then(|encoder| encoder.array(header.schema_ids().len() as u64))
        .expect("encoding into Vec cannot fail");
    for schema_id in header.schema_ids() {
        encoder
            .bytes(schema_id.as_bytes())
            .expect("encoding into Vec cannot fail");
    }
    encoder
        .u8(11)
        .and_then(|encoder| encoder.bytes(header.nonce()))
        .and_then(|encoder| encoder.u8(12))
        .and_then(|encoder| encoder.bytes(ciphertext))
        .expect("encoding into Vec cannot fail");
    if let Some(signature) = signature {
        encoder
            .u8(13)
            .and_then(|encoder| encoder.bytes(signature.as_bytes()))
            .expect("encoding into Vec cannot fail");
    }
    encoder.into_writer()
}

fn encode_body(
    encoder: &mut Encoder<Vec<u8>>,
    body: &CommitBody,
) -> Result<(), minicbor::encode::Error<std::convert::Infallible>> {
    encoder.map(6)?;
    encoder.u8(0)?.str(MAGIC)?;
    encoder.u8(1)?.u16(FORMAT_MAJOR)?;
    encoder.u8(2)?.u16(FORMAT_MINOR)?;
    encoder.u8(3)?.u8(BODY_KIND)?;
    encoder.u8(4)?.bytes(body.transaction_id().as_bytes())?;
    encoder.u8(5)?.array(body.operations().len() as u64)?;
    for operation in body.operations() {
        encoder.map(5)?;
        encoder.u8(0)?.bytes(operation.collection_id().as_bytes())?;
        encoder.u8(1)?.bytes(operation.record_id())?;
        encoder.u8(2)?.u32(operation.field_id())?;
        encoder.u8(3)?.u8(operation.kind() as u8)?;
        encoder.u8(4)?.bytes(operation.payload())?;
    }
    Ok(())
}

fn decode_envelope(bytes: &[u8]) -> Result<CommitEnvelope, CommitCodecError> {
    let mut decoder = Decoder::new(bytes);
    expect_map_len(&mut decoder, 14)?;
    decode_preamble(&mut decoder, ENVELOPE_KIND)?;
    expect_key(&mut decoder, 4)?;
    let domain_id = DomainId::from_bytes(read_fixed(&mut decoder, "domain id")?);
    expect_key(&mut decoder, 5)?;
    let epoch = decoder.u64().map_err(decode_error)?;
    expect_key(&mut decoder, 6)?;
    let author = AuthorId::from_bytes(read_fixed(&mut decoder, "author")?);
    expect_key(&mut decoder, 7)?;
    let author_sequence = decoder.u64().map_err(decode_error)?;
    expect_key(&mut decoder, 8)?;
    let dependency_count = read_array_len(&mut decoder, MAX_DEPENDENCIES, "dependencies")?;
    let mut dependencies = Vec::with_capacity(dependency_count);
    for _ in 0..dependency_count {
        dependencies.push(CommitId::from_bytes(read_fixed(
            &mut decoder,
            "dependency",
        )?));
    }
    expect_key(&mut decoder, 9)?;
    let capability_id = CapabilityId::from_bytes(read_fixed(&mut decoder, "capability id")?);
    expect_key(&mut decoder, 10)?;
    let schema_count = read_array_len(&mut decoder, MAX_SCHEMAS, "schema ids")?;
    let mut schema_ids = Vec::with_capacity(schema_count);
    for _ in 0..schema_count {
        schema_ids.push(SchemaId::from_bytes(read_fixed(&mut decoder, "schema id")?));
    }
    expect_key(&mut decoder, 11)?;
    let nonce = read_fixed(&mut decoder, "nonce")?;
    expect_key(&mut decoder, 12)?;
    let ciphertext = read_bounded_bytes(&mut decoder, MAX_CIPHERTEXT, "ciphertext")?;
    expect_key(&mut decoder, 13)?;
    let signature = CommitSignature::from_bytes(read_fixed(&mut decoder, "signature")?);
    if decoder.position() != bytes.len() {
        return Err(CommitCodecError::InvalidEncoding("trailing data".into()));
    }
    let header = CommitHeader::new(
        domain_id,
        epoch,
        author,
        author_sequence,
        dependencies,
        capability_id,
        schema_ids,
        nonce,
    )?;
    CommitEnvelope::new(header, ciphertext, signature)
}

fn decode_body(bytes: &[u8]) -> Result<CommitBody, CommitCodecError> {
    let mut decoder = Decoder::new(bytes);
    expect_map_len(&mut decoder, 6)?;
    decode_preamble(&mut decoder, BODY_KIND)?;
    expect_key(&mut decoder, 4)?;
    let transaction_id = TransactionId::from_bytes(read_fixed(&mut decoder, "transaction id")?);
    expect_key(&mut decoder, 5)?;
    let operation_count = read_array_len(&mut decoder, MAX_OPERATIONS, "operations")?;
    let mut operations = Vec::with_capacity(operation_count);
    for _ in 0..operation_count {
        expect_map_len(&mut decoder, 5)?;
        expect_key(&mut decoder, 0)?;
        let collection_id = CollectionId::from_bytes(read_fixed(&mut decoder, "collection id")?);
        expect_key(&mut decoder, 1)?;
        let record_id = read_bounded_bytes(&mut decoder, MAX_RECORD_ID, "record id")?;
        expect_key(&mut decoder, 2)?;
        let field_id = decoder.u32().map_err(decode_error)?;
        expect_key(&mut decoder, 3)?;
        let kind = OperationKind::try_from(decoder.u8().map_err(decode_error)?)?;
        expect_key(&mut decoder, 4)?;
        let payload = read_bounded_bytes(&mut decoder, MAX_OPERATION_PAYLOAD, "operation payload")?;
        operations.push(Operation::new(
            collection_id,
            record_id,
            field_id,
            kind,
            payload,
        )?);
    }
    if decoder.position() != bytes.len() {
        return Err(CommitCodecError::InvalidEncoding("trailing data".into()));
    }
    CommitBody::new(transaction_id, operations)
}

fn decode_preamble(decoder: &mut Decoder<'_>, kind: u8) -> Result<(), CommitCodecError> {
    expect_key(decoder, 0)?;
    if decoder.str().map_err(decode_error)? != MAGIC {
        return Err(CommitCodecError::UnsupportedFormat);
    }
    expect_key(decoder, 1)?;
    if decoder.u16().map_err(decode_error)? != FORMAT_MAJOR {
        return Err(CommitCodecError::UnsupportedFormat);
    }
    expect_key(decoder, 2)?;
    if decoder.u16().map_err(decode_error)? != FORMAT_MINOR {
        return Err(CommitCodecError::UnsupportedFormat);
    }
    expect_key(decoder, 3)?;
    if decoder.u8().map_err(decode_error)? != kind {
        return Err(CommitCodecError::UnsupportedFormat);
    }
    Ok(())
}

fn expect_map_len(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), CommitCodecError> {
    let actual = decoder
        .map()
        .map_err(decode_error)?
        .ok_or_else(|| CommitCodecError::InvalidEncoding("indefinite map".into()))?;
    if actual != expected {
        return Err(CommitCodecError::InvalidEncoding(format!(
            "expected map length {expected}, got {actual}"
        )));
    }
    Ok(())
}

fn expect_key(decoder: &mut Decoder<'_>, expected: u8) -> Result<(), CommitCodecError> {
    let actual = decoder.u8().map_err(decode_error)?;
    if actual != expected {
        return Err(CommitCodecError::InvalidEncoding(format!(
            "expected key {expected}, got {actual}"
        )));
    }
    Ok(())
}

fn read_array_len(
    decoder: &mut Decoder<'_>,
    maximum: usize,
    name: &str,
) -> Result<usize, CommitCodecError> {
    let count = decoder
        .array()
        .map_err(decode_error)?
        .ok_or_else(|| CommitCodecError::InvalidEncoding(format!("indefinite {name} array")))?;
    let count = usize::try_from(count)
        .map_err(|_| CommitCodecError::InvalidEncoding(format!("{name} count overflow")))?;
    if count > maximum {
        return Err(CommitCodecError::InvalidEncoding(format!(
            "{name} count exceeds {maximum}"
        )));
    }
    Ok(count)
}

fn read_bounded_bytes(
    decoder: &mut Decoder<'_>,
    maximum: usize,
    name: &str,
) -> Result<Vec<u8>, CommitCodecError> {
    let bytes = decoder.bytes().map_err(decode_error)?;
    if bytes.len() > maximum {
        return Err(CommitCodecError::InvalidEncoding(format!(
            "{name} exceeds {maximum} bytes"
        )));
    }
    Ok(bytes.to_vec())
}

fn read_fixed<const LENGTH: usize>(
    decoder: &mut Decoder<'_>,
    name: &str,
) -> Result<[u8; LENGTH], CommitCodecError> {
    let bytes = decoder.bytes().map_err(decode_error)?;
    bytes
        .try_into()
        .map_err(|_| CommitCodecError::InvalidEncoding(format!("{name} must be {LENGTH} bytes")))
}

// `Result::map_err` requires ownership even though formatting only borrows the error.
#[allow(clippy::needless_pass_by_value)]
fn decode_error(error: minicbor::decode::Error) -> CommitCodecError {
    CommitCodecError::InvalidEncoding(error.to_string())
}
