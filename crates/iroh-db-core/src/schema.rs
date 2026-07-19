use std::collections::BTreeSet;

use minicbor::{Decoder, Encoder};

use crate::{CollectionId, SchemaId};

const MAGIC: &str = "iroh-db";
const FORMAT_MAJOR: u16 = 1;
const FORMAT_MINOR: u16 = 0;
const SCHEMA_KIND: u8 = 1;
const MAX_NAME_LEN: usize = 255;
const MAX_TYPE_NAME_LEN: usize = 1_024;
const MAX_FIELDS: usize = 4_096;

/// A built-in deterministic replicated-field strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum CrdtKind {
    /// Causal register with a deterministic concurrent-write tie break.
    Lww = 1,
    /// Add-wins observed-remove set.
    OrSet = 2,
    /// Set that can only grow.
    GrowOnlySet = 3,
    /// Per-author positive/negative counter.
    PnCounter = 4,
    /// Register retaining every causally maximal value.
    MultiValue = 5,
    /// Write-once value that preserves concurrent conflicts.
    Immutable = 6,
    /// Replicated growable ordered list.
    OrderedList = 7,
}

impl TryFrom<u8> for CrdtKind {
    type Error = SchemaError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Lww),
            2 => Ok(Self::OrSet),
            3 => Ok(Self::GrowOnlySet),
            4 => Ok(Self::PnCounter),
            5 => Ok(Self::MultiValue),
            6 => Ok(Self::Immutable),
            7 => Ok(Self::OrderedList),
            value => Err(SchemaError::UnknownCrdtKind(value)),
        }
    }
}

/// The stable replicated contract for one record field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDescriptor {
    id: u32,
    name: String,
    crdt: CrdtKind,
    value_type: String,
    indexed: bool,
    record_id: bool,
}

impl FieldDescriptor {
    /// Declares a replicated field.
    pub fn new(
        id: u32,
        name: impl Into<String>,
        crdt: CrdtKind,
        value_type: impl Into<String>,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            crdt,
            value_type: value_type.into(),
            indexed: false,
            record_id: false,
        }
    }

    /// Marks this field as a materialized secondary index.
    #[must_use]
    pub const fn indexed(mut self) -> Self {
        self.indexed = true;
        self
    }

    /// Marks this field as the unique record identifier.
    #[must_use]
    pub const fn record_id(mut self) -> Self {
        self.record_id = true;
        self
    }

    /// Returns the stable numeric field identifier.
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// Returns the declared Rust field name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the replicated merge strategy.
    pub const fn crdt(&self) -> CrdtKind {
        self.crdt
    }

    /// Returns the stable logical value-type name.
    pub fn value_type(&self) -> &str {
        &self.value_type
    }

    /// Returns whether the field has a secondary index.
    pub const fn is_indexed(&self) -> bool {
        self.indexed
    }

    /// Returns whether the field is the record identifier.
    pub const fn is_record_id(&self) -> bool {
        self.record_id
    }
}

/// A validated, versioned collection schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaDescriptor {
    collection_name: String,
    collection_id: CollectionId,
    version: u32,
    fields: Vec<FieldDescriptor>,
}

impl SchemaDescriptor {
    /// Validates and constructs a collection schema.
    pub fn new(
        collection_name: impl Into<String>,
        version: u32,
        mut fields: Vec<FieldDescriptor>,
    ) -> Result<Self, SchemaError> {
        let collection_name = collection_name.into();
        validate_name("collection", &collection_name, MAX_NAME_LEN)?;
        if fields.len() > MAX_FIELDS {
            return Err(SchemaError::TooManyFields(fields.len()));
        }

        fields.sort_by_key(FieldDescriptor::id);
        let mut ids = BTreeSet::new();
        let mut names = BTreeSet::new();
        let mut record_ids = 0_usize;

        for field in &fields {
            validate_name("field", field.name(), MAX_NAME_LEN)?;
            validate_name("value type", field.value_type(), MAX_TYPE_NAME_LEN)?;
            if !ids.insert(field.id()) {
                return Err(SchemaError::DuplicateFieldId(field.id()));
            }
            if !names.insert(field.name().to_owned()) {
                return Err(SchemaError::DuplicateFieldName(field.name().to_owned()));
            }
            record_ids += usize::from(field.is_record_id());
        }

        match record_ids {
            0 => return Err(SchemaError::MissingRecordId),
            1 => {}
            _ => return Err(SchemaError::MultipleRecordIds),
        }

        let collection_id = CollectionId::for_name(&collection_name);
        Ok(Self {
            collection_name,
            collection_id,
            version,
            fields,
        })
    }

    /// Returns the human-readable declared collection name.
    pub fn collection_name(&self) -> &str {
        &self.collection_name
    }

    /// Returns the stable collection identifier.
    pub const fn collection_id(&self) -> CollectionId {
        self.collection_id
    }

    /// Returns the application-controlled schema version.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Returns fields in canonical numeric-ID order.
    pub fn fields(&self) -> &[FieldDescriptor] {
        &self.fields
    }

    /// Returns the domain-separated hash of the canonical descriptor.
    pub fn schema_id(&self) -> SchemaId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"iroh-db/schema/v1");
        hasher.update(&self.encode_canonical());
        SchemaId::from_bytes(*hasher.finalize().as_bytes())
    }

    /// Encodes the descriptor into its durable canonical representation.
    pub fn encode_canonical(&self) -> Vec<u8> {
        let mut encoder = Encoder::new(Vec::new());
        encode_schema(&mut encoder, self).expect("encoding into Vec cannot fail");
        encoder.into_writer()
    }

    /// Decodes and validates an exact canonical descriptor.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, SchemaError> {
        let decoded = decode_schema(bytes)?;
        if decoded.encode_canonical() != bytes {
            return Err(SchemaError::NonCanonicalEncoding);
        }
        Ok(decoded)
    }
}

/// Schema validation or decoding failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SchemaError {
    /// A required name was empty or exceeded its byte limit.
    #[error("invalid {kind} name length {length}; maximum is {maximum}")]
    InvalidName {
        /// Name category.
        kind: &'static str,
        /// Actual UTF-8 byte length.
        length: usize,
        /// Maximum accepted UTF-8 byte length.
        maximum: usize,
    },
    /// More fields were supplied than the decoder permits.
    #[error("schema contains too many fields: {0}")]
    TooManyFields(usize),
    /// Two fields use the same stable numeric ID.
    #[error("duplicate field id {0}")]
    DuplicateFieldId(u32),
    /// Two fields use the same declared name.
    #[error("duplicate field name {0}")]
    DuplicateFieldName(String),
    /// No record identifier was declared.
    #[error("schema must declare exactly one record id")]
    MissingRecordId,
    /// More than one record identifier was declared.
    #[error("schema declares more than one record id")]
    MultipleRecordIds,
    /// The encoded merge strategy is unknown.
    #[error("unknown CRDT kind {0}")]
    UnknownCrdtKind(u8),
    /// The object uses an unsupported format version or kind.
    #[error("unsupported schema format")]
    UnsupportedFormat,
    /// A collection ID did not match its declared name.
    #[error("collection id does not match the declared name")]
    CollectionIdMismatch,
    /// The CBOR object was malformed or violated a decode limit.
    #[error("invalid schema encoding: {0}")]
    InvalidEncoding(String),
    /// The object was valid CBOR but not the unique canonical byte representation.
    #[error("schema encoding is not canonical")]
    NonCanonicalEncoding,
}

fn validate_name(kind: &'static str, value: &str, maximum: usize) -> Result<(), SchemaError> {
    let length = value.len();
    if length == 0 || length > maximum {
        return Err(SchemaError::InvalidName {
            kind,
            length,
            maximum,
        });
    }
    Ok(())
}

fn encode_schema(
    encoder: &mut Encoder<Vec<u8>>,
    schema: &SchemaDescriptor,
) -> Result<(), minicbor::encode::Error<std::convert::Infallible>> {
    encoder.map(8)?;
    encoder.u8(0)?.str(MAGIC)?;
    encoder.u8(1)?.u16(FORMAT_MAJOR)?;
    encoder.u8(2)?.u16(FORMAT_MINOR)?;
    encoder.u8(3)?.u8(SCHEMA_KIND)?;
    encoder.u8(4)?.str(schema.collection_name())?;
    encoder.u8(5)?.bytes(schema.collection_id().as_bytes())?;
    encoder.u8(6)?.u32(schema.version())?;
    encoder.u8(7)?.array(schema.fields().len() as u64)?;
    for field in schema.fields() {
        encoder.map(6)?;
        encoder.u8(0)?.u32(field.id())?;
        encoder.u8(1)?.str(field.name())?;
        encoder.u8(2)?.u8(field.crdt() as u8)?;
        encoder.u8(3)?.str(field.value_type())?;
        encoder.u8(4)?.bool(field.is_indexed())?;
        encoder.u8(5)?.bool(field.is_record_id())?;
    }
    Ok(())
}

fn decode_schema(bytes: &[u8]) -> Result<SchemaDescriptor, SchemaError> {
    let mut decoder = Decoder::new(bytes);
    expect_map_len(&mut decoder, 8)?;
    expect_key(&mut decoder, 0)?;
    if decoder.str().map_err(decode_error)? != MAGIC {
        return Err(SchemaError::UnsupportedFormat);
    }
    expect_key(&mut decoder, 1)?;
    if decoder.u16().map_err(decode_error)? != FORMAT_MAJOR {
        return Err(SchemaError::UnsupportedFormat);
    }
    expect_key(&mut decoder, 2)?;
    if decoder.u16().map_err(decode_error)? != FORMAT_MINOR {
        return Err(SchemaError::UnsupportedFormat);
    }
    expect_key(&mut decoder, 3)?;
    if decoder.u8().map_err(decode_error)? != SCHEMA_KIND {
        return Err(SchemaError::UnsupportedFormat);
    }
    expect_key(&mut decoder, 4)?;
    let collection_name = decoder.str().map_err(decode_error)?.to_owned();
    expect_key(&mut decoder, 5)?;
    let encoded_collection_id = decoder.bytes().map_err(decode_error)?;
    let encoded_collection_id: [u8; 32] = encoded_collection_id
        .try_into()
        .map_err(|_| SchemaError::InvalidEncoding("collection id must be 32 bytes".into()))?;
    expect_key(&mut decoder, 6)?;
    let version = decoder.u32().map_err(decode_error)?;
    expect_key(&mut decoder, 7)?;
    let field_count = decoder
        .array()
        .map_err(decode_error)?
        .ok_or_else(|| SchemaError::InvalidEncoding("indefinite field array".into()))?;
    let field_count = usize::try_from(field_count)
        .map_err(|_| SchemaError::InvalidEncoding("field count overflow".into()))?;
    if field_count > MAX_FIELDS {
        return Err(SchemaError::TooManyFields(field_count));
    }

    let mut fields = Vec::with_capacity(field_count);
    for _ in 0..field_count {
        expect_map_len(&mut decoder, 6)?;
        expect_key(&mut decoder, 0)?;
        let id = decoder.u32().map_err(decode_error)?;
        expect_key(&mut decoder, 1)?;
        let name = decoder.str().map_err(decode_error)?.to_owned();
        expect_key(&mut decoder, 2)?;
        let crdt = CrdtKind::try_from(decoder.u8().map_err(decode_error)?)?;
        expect_key(&mut decoder, 3)?;
        let value_type = decoder.str().map_err(decode_error)?.to_owned();
        expect_key(&mut decoder, 4)?;
        let indexed = decoder.bool().map_err(decode_error)?;
        expect_key(&mut decoder, 5)?;
        let record_id = decoder.bool().map_err(decode_error)?;

        let mut field = FieldDescriptor::new(id, name, crdt, value_type);
        if indexed {
            field = field.indexed();
        }
        if record_id {
            field = field.record_id();
        }
        fields.push(field);
    }

    if decoder.position() != bytes.len() {
        return Err(SchemaError::InvalidEncoding("trailing data".into()));
    }

    let schema = SchemaDescriptor::new(collection_name, version, fields)?;
    if schema.collection_id().as_bytes() != &encoded_collection_id {
        return Err(SchemaError::CollectionIdMismatch);
    }
    Ok(schema)
}

fn expect_map_len(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), SchemaError> {
    let actual = decoder
        .map()
        .map_err(decode_error)?
        .ok_or_else(|| SchemaError::InvalidEncoding("indefinite map".into()))?;
    if actual != expected {
        return Err(SchemaError::InvalidEncoding(format!(
            "expected map length {expected}, got {actual}"
        )));
    }
    Ok(())
}

fn expect_key(decoder: &mut Decoder<'_>, expected: u8) -> Result<(), SchemaError> {
    let actual = decoder.u8().map_err(decode_error)?;
    if actual != expected {
        return Err(SchemaError::InvalidEncoding(format!(
            "expected key {expected}, got {actual}"
        )));
    }
    Ok(())
}

// `Result::map_err` requires ownership even though formatting only borrows the error.
#[allow(clippy::needless_pass_by_value)]
fn decode_error(error: minicbor::decode::Error) -> SchemaError {
    SchemaError::InvalidEncoding(error.to_string())
}
