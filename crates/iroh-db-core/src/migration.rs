use minicbor::{Decoder, Encoder};

use crate::{BlobHash, MigrationId, SchemaDescriptor, SchemaError};

const MAGIC: &str = "iroh-db";
const FORMAT_MAJOR: u16 = 1;
const FORMAT_MINOR: u16 = 0;
const STAGE_KIND: u8 = 4;
const ACTIVATION_KIND: u8 = 5;
const MAX_RECORD_ID: usize = 1_024;
const MAX_TARGET_RECORD: usize = 16 * 1024 * 1024;

/// One bounded, invisible target record in a causal schema migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaStage {
    migration_id: MigrationId,
    from: SchemaDescriptor,
    to: SchemaDescriptor,
    source_record_id: Vec<u8>,
    source_digest: BlobHash,
    target_record: Vec<u8>,
}

impl SchemaStage {
    /// Validates and constructs one staged record.
    pub fn new(
        migration_id: MigrationId,
        from: SchemaDescriptor,
        to: SchemaDescriptor,
        source_record_id: Vec<u8>,
        source_digest: BlobHash,
        target_record: Vec<u8>,
    ) -> Result<Self, MigrationCodecError> {
        validate_transition(&from, &to)?;
        if source_record_id.len() > MAX_RECORD_ID {
            return Err(MigrationCodecError::RecordIdTooLarge(
                source_record_id.len(),
            ));
        }
        if target_record.len() > MAX_TARGET_RECORD {
            return Err(MigrationCodecError::TargetRecordTooLarge(
                target_record.len(),
            ));
        }
        Ok(Self {
            migration_id,
            from,
            to,
            source_record_id,
            source_digest,
            target_record,
        })
    }

    /// Returns the migration identifier.
    pub const fn migration_id(&self) -> MigrationId {
        self.migration_id
    }

    /// Returns the exact predecessor schema.
    pub const fn from(&self) -> &SchemaDescriptor {
        &self.from
    }

    /// Returns the exact target schema.
    pub const fn to(&self) -> &SchemaDescriptor {
        &self.to
    }

    /// Returns the source record's canonical primary key.
    pub fn source_record_id(&self) -> &[u8] {
        &self.source_record_id
    }

    /// Returns the digest of the canonical source materialization.
    pub const fn source_digest(&self) -> BlobHash {
        self.source_digest
    }

    /// Returns the canonical target materialized-record bytes.
    pub fn target_record(&self) -> &[u8] {
        &self.target_record
    }

    /// Encodes the stage into its unique durable representation.
    pub fn encode_canonical(&self) -> Vec<u8> {
        let mut encoder = Encoder::new(Vec::new());
        encode_stage(&mut encoder, self).expect("encoding into Vec cannot fail");
        encoder.into_writer()
    }

    /// Strictly decodes one canonical stage.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, MigrationCodecError> {
        let decoded = decode_stage(bytes)?;
        if decoded.encode_canonical() != bytes {
            return Err(MigrationCodecError::NonCanonicalEncoding);
        }
        Ok(decoded)
    }
}

/// The atomic publication marker for a complete staged migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaActivation {
    migration_id: MigrationId,
    from: SchemaDescriptor,
    to: SchemaDescriptor,
    staged_records: u64,
    staging_digest: BlobHash,
}

impl SchemaActivation {
    /// Validates and constructs an activation marker.
    pub fn new(
        migration_id: MigrationId,
        from: SchemaDescriptor,
        to: SchemaDescriptor,
        staged_records: u64,
        staging_digest: BlobHash,
    ) -> Result<Self, MigrationCodecError> {
        validate_transition(&from, &to)?;
        Ok(Self {
            migration_id,
            from,
            to,
            staged_records,
            staging_digest,
        })
    }

    /// Returns the migration identifier.
    pub const fn migration_id(&self) -> MigrationId {
        self.migration_id
    }

    /// Returns the exact predecessor schema.
    pub const fn from(&self) -> &SchemaDescriptor {
        &self.from
    }

    /// Returns the exact target schema.
    pub const fn to(&self) -> &SchemaDescriptor {
        &self.to
    }

    /// Returns the exact number of selected stage records.
    pub const fn staged_records(&self) -> u64 {
        self.staged_records
    }

    /// Returns the digest committing to the complete ordered staging set.
    pub const fn staging_digest(&self) -> BlobHash {
        self.staging_digest
    }

    /// Encodes the activation into its unique durable representation.
    pub fn encode_canonical(&self) -> Vec<u8> {
        let mut encoder = Encoder::new(Vec::new());
        encode_activation(&mut encoder, self).expect("encoding into Vec cannot fail");
        encoder.into_writer()
    }

    /// Strictly decodes one canonical activation.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, MigrationCodecError> {
        let decoded = decode_activation(bytes)?;
        if decoded.encode_canonical() != bytes {
            return Err(MigrationCodecError::NonCanonicalEncoding);
        }
        Ok(decoded)
    }
}

/// Validation or canonical-codec failure for migration protocol objects.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MigrationCodecError {
    /// The transition crossed collection identities.
    #[error("migration schemas belong to different collections")]
    CollectionMismatch,
    /// The target did not immediately follow its predecessor.
    #[error("migration versions must be adjacent: {from} -> {to}")]
    NonAdjacentVersion { from: u32, to: u32 },
    /// The stable primary-key contract changed.
    #[error("migration changes the primary-key contract")]
    PrimaryKeyMismatch,
    /// Stages from different migrations or schema transitions were combined.
    #[error("staging set mixes migration identities or schema transitions")]
    MixedStagingSet,
    /// Two stages selected the same source primary key.
    #[error("staging set contains a duplicate source record")]
    DuplicateSourceRecord,
    /// A source key exceeded the protocol bound.
    #[error("migration record id is too large: {0} bytes")]
    RecordIdTooLarge(usize),
    /// A target materialization exceeded the operation payload bound.
    #[error("migration target record is too large: {0} bytes")]
    TargetRecordTooLarge(usize),
    /// A nested schema was invalid.
    #[error(transparent)]
    Schema(#[from] SchemaError),
    /// The object format major, minor, or kind is unsupported.
    #[error("unsupported migration object format")]
    UnsupportedFormat,
    /// The binary object was malformed.
    #[error("invalid migration encoding: {0}")]
    InvalidEncoding(String),
    /// The object was valid CBOR but not its unique representation.
    #[error("migration encoding is not canonical")]
    NonCanonicalEncoding,
}

/// Hashes a complete staging set in canonical source-key order.
pub fn staging_digest(stages: &[SchemaStage]) -> Result<BlobHash, MigrationCodecError> {
    let mut ordered: Vec<_> = stages.iter().collect();
    ordered.sort_unstable_by(|left, right| left.source_record_id.cmp(&right.source_record_id));
    if ordered
        .windows(2)
        .any(|pair| pair[0].source_record_id.as_slice() == pair[1].source_record_id.as_slice())
    {
        return Err(MigrationCodecError::DuplicateSourceRecord);
    }
    if let Some(first) = ordered.first()
        && ordered.iter().any(|stage| {
            stage.migration_id != first.migration_id
                || stage.from.schema_id() != first.from.schema_id()
                || stage.to.schema_id() != first.to.schema_id()
        })
    {
        return Err(MigrationCodecError::MixedStagingSet);
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"iroh-db/schema-staging/v1");
    hasher.update(&(ordered.len() as u64).to_be_bytes());
    for stage in ordered {
        let bytes = stage.encode_canonical();
        hasher.update(&(bytes.len() as u64).to_be_bytes());
        hasher.update(&bytes);
    }
    Ok(BlobHash::from_bytes(*hasher.finalize().as_bytes()))
}

fn validate_transition(
    from: &SchemaDescriptor,
    to: &SchemaDescriptor,
) -> Result<(), MigrationCodecError> {
    if from.collection_id() != to.collection_id() {
        return Err(MigrationCodecError::CollectionMismatch);
    }
    if from.version().checked_add(1) != Some(to.version()) {
        return Err(MigrationCodecError::NonAdjacentVersion {
            from: from.version(),
            to: to.version(),
        });
    }
    let from_id = from.fields().iter().find(|field| field.is_record_id());
    let to_id = to.fields().iter().find(|field| field.is_record_id());
    if from_id.map(|field| (field.id(), field.crdt(), field.value_type()))
        != to_id.map(|field| (field.id(), field.crdt(), field.value_type()))
    {
        return Err(MigrationCodecError::PrimaryKeyMismatch);
    }
    Ok(())
}

fn encode_prefix(
    encoder: &mut Encoder<Vec<u8>>,
    map_len: u64,
    kind: u8,
    migration_id: MigrationId,
    from: &SchemaDescriptor,
    to: &SchemaDescriptor,
) -> Result<(), minicbor::encode::Error<std::convert::Infallible>> {
    encoder.map(map_len)?;
    encoder.u8(0)?.str(MAGIC)?;
    encoder.u8(1)?.u16(FORMAT_MAJOR)?;
    encoder.u8(2)?.u16(FORMAT_MINOR)?;
    encoder.u8(3)?.u8(kind)?;
    encoder.u8(4)?.bytes(migration_id.as_bytes())?;
    encoder.u8(5)?.bytes(&from.encode_canonical())?;
    encoder.u8(6)?.bytes(&to.encode_canonical())?;
    Ok(())
}

fn encode_stage(
    encoder: &mut Encoder<Vec<u8>>,
    stage: &SchemaStage,
) -> Result<(), minicbor::encode::Error<std::convert::Infallible>> {
    encode_prefix(
        encoder,
        10,
        STAGE_KIND,
        stage.migration_id,
        &stage.from,
        &stage.to,
    )?;
    encoder.u8(7)?.bytes(&stage.source_record_id)?;
    encoder.u8(8)?.bytes(stage.source_digest.as_bytes())?;
    encoder.u8(9)?.bytes(&stage.target_record)?;
    Ok(())
}

fn encode_activation(
    encoder: &mut Encoder<Vec<u8>>,
    activation: &SchemaActivation,
) -> Result<(), minicbor::encode::Error<std::convert::Infallible>> {
    encode_prefix(
        encoder,
        9,
        ACTIVATION_KIND,
        activation.migration_id,
        &activation.from,
        &activation.to,
    )?;
    encoder.u8(7)?.u64(activation.staged_records)?;
    encoder.u8(8)?.bytes(activation.staging_digest.as_bytes())?;
    Ok(())
}

fn decode_prefix(
    decoder: &mut Decoder<'_>,
    map_len: u64,
    kind: u8,
) -> Result<(MigrationId, SchemaDescriptor, SchemaDescriptor), MigrationCodecError> {
    expect_map_len(decoder, map_len)?;
    expect_key(decoder, 0)?;
    if decoder.str().map_err(decode_error)? != MAGIC {
        return Err(MigrationCodecError::UnsupportedFormat);
    }
    expect_key(decoder, 1)?;
    if decoder.u16().map_err(decode_error)? != FORMAT_MAJOR {
        return Err(MigrationCodecError::UnsupportedFormat);
    }
    expect_key(decoder, 2)?;
    if decoder.u16().map_err(decode_error)? != FORMAT_MINOR {
        return Err(MigrationCodecError::UnsupportedFormat);
    }
    expect_key(decoder, 3)?;
    if decoder.u8().map_err(decode_error)? != kind {
        return Err(MigrationCodecError::UnsupportedFormat);
    }
    expect_key(decoder, 4)?;
    let migration_id = MigrationId::from_bytes(fixed_bytes(decoder, "migration id")?);
    expect_key(decoder, 5)?;
    let from = SchemaDescriptor::decode_canonical(decoder.bytes().map_err(decode_error)?)?;
    expect_key(decoder, 6)?;
    let to = SchemaDescriptor::decode_canonical(decoder.bytes().map_err(decode_error)?)?;
    Ok((migration_id, from, to))
}

fn decode_stage(bytes: &[u8]) -> Result<SchemaStage, MigrationCodecError> {
    let mut decoder = Decoder::new(bytes);
    let (migration_id, from, to) = decode_prefix(&mut decoder, 10, STAGE_KIND)?;
    expect_key(&mut decoder, 7)?;
    let source_record_id = decoder.bytes().map_err(decode_error)?.to_vec();
    expect_key(&mut decoder, 8)?;
    let source_digest = BlobHash::from_bytes(fixed_bytes(&mut decoder, "source digest")?);
    expect_key(&mut decoder, 9)?;
    let target_record = decoder.bytes().map_err(decode_error)?.to_vec();
    if decoder.position() != bytes.len() {
        return Err(MigrationCodecError::InvalidEncoding("trailing data".into()));
    }
    SchemaStage::new(
        migration_id,
        from,
        to,
        source_record_id,
        source_digest,
        target_record,
    )
}

fn decode_activation(bytes: &[u8]) -> Result<SchemaActivation, MigrationCodecError> {
    let mut decoder = Decoder::new(bytes);
    let (migration_id, from, to) = decode_prefix(&mut decoder, 9, ACTIVATION_KIND)?;
    expect_key(&mut decoder, 7)?;
    let staged_records = decoder.u64().map_err(decode_error)?;
    expect_key(&mut decoder, 8)?;
    let staging_digest = BlobHash::from_bytes(fixed_bytes(&mut decoder, "staging digest")?);
    if decoder.position() != bytes.len() {
        return Err(MigrationCodecError::InvalidEncoding("trailing data".into()));
    }
    SchemaActivation::new(migration_id, from, to, staged_records, staging_digest)
}

fn fixed_bytes(decoder: &mut Decoder<'_>, label: &str) -> Result<[u8; 32], MigrationCodecError> {
    decoder
        .bytes()
        .map_err(decode_error)?
        .try_into()
        .map_err(|_| MigrationCodecError::InvalidEncoding(format!("{label} must be 32 bytes")))
}

fn expect_map_len(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), MigrationCodecError> {
    let actual = decoder
        .map()
        .map_err(decode_error)?
        .ok_or_else(|| MigrationCodecError::InvalidEncoding("indefinite map".into()))?;
    if actual != expected {
        return Err(MigrationCodecError::InvalidEncoding(format!(
            "expected map length {expected}, got {actual}"
        )));
    }
    Ok(())
}

fn expect_key(decoder: &mut Decoder<'_>, expected: u8) -> Result<(), MigrationCodecError> {
    let actual = decoder.u8().map_err(decode_error)?;
    if actual != expected {
        return Err(MigrationCodecError::InvalidEncoding(format!(
            "expected key {expected}, got {actual}"
        )));
    }
    Ok(())
}

#[allow(clippy::needless_pass_by_value)]
fn decode_error(error: minicbor::decode::Error) -> MigrationCodecError {
    MigrationCodecError::InvalidEncoding(error.to_string())
}
