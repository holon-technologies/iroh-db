use iroh_db_core::SchemaDescriptor;

const MAX_RECORD_ID: usize = 1_024;
const MAX_RECORD_STATE: usize = 64 * 1024 * 1024;
const MAX_INDEX_VALUE: usize = 1024 * 1024;

/// One primary-key ordered materialized record returned by a collection scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRecord {
    pub(crate) record_id: Vec<u8>,
    pub(crate) state: Vec<u8>,
}

impl StoredRecord {
    /// Returns the canonical application record ID.
    pub fn record_id(&self) -> &[u8] {
        &self.record_id
    }

    /// Returns the canonical typed-record state.
    pub fn state(&self) -> &[u8] {
        &self.state
    }
}

/// One canonical value emitted into a schema-declared secondary index.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct IndexValue {
    pub(crate) field_id: u32,
    pub(crate) value: Vec<u8>,
}

impl IndexValue {
    /// Creates an index entry for a stable field and canonical value.
    pub fn new(field_id: u32, value: Vec<u8>) -> Self {
        Self { field_id, value }
    }

    /// Returns the indexed stable field ID.
    pub const fn field_id(&self) -> u32 {
        self.field_id
    }

    /// Returns the canonical indexed value.
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

/// One record replacement or deletion applied in the commit metadata transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedRecord {
    pub(crate) schema: SchemaDescriptor,
    pub(crate) record_id: Vec<u8>,
    pub(crate) state: Option<Vec<u8>>,
    pub(crate) indexes: Vec<IndexValue>,
}

impl MaterializedRecord {
    /// Validates a complete canonical record replacement and its index values.
    pub fn upsert(
        schema: SchemaDescriptor,
        record_id: Vec<u8>,
        state: Vec<u8>,
        mut indexes: Vec<IndexValue>,
    ) -> Result<Self, MaterializedError> {
        validate_record_id(&record_id)?;
        if state.len() > MAX_RECORD_STATE {
            return Err(MaterializedError::RecordStateTooLarge(state.len()));
        }
        for index in &indexes {
            if index.field_id == 0 {
                return Err(MaterializedError::InvalidIndexField(0));
            }
            if index.value.len() > MAX_INDEX_VALUE {
                return Err(MaterializedError::IndexValueTooLarge(index.value.len()));
            }
        }
        indexes.sort_unstable();
        indexes.dedup();
        Ok(Self {
            schema,
            record_id,
            state: Some(state),
            indexes,
        })
    }

    /// Validates a record deletion under its registered schema.
    pub fn delete(schema: SchemaDescriptor, record_id: Vec<u8>) -> Result<Self, MaterializedError> {
        validate_record_id(&record_id)?;
        Ok(Self {
            schema,
            record_id,
            state: None,
            indexes: Vec::new(),
        })
    }

    /// Returns the record's registered schema.
    pub const fn schema(&self) -> &SchemaDescriptor {
        &self.schema
    }

    /// Returns the canonical primary key.
    pub fn record_id(&self) -> &[u8] {
        &self.record_id
    }

    /// Returns complete canonical record state, or `None` for deletion.
    pub fn state(&self) -> Option<&[u8]> {
        self.state.as_deref()
    }

    /// Returns canonical secondary-index values.
    pub fn indexes(&self) -> &[IndexValue] {
        &self.indexes
    }

    /// Encodes the complete rebuildable materialization carried by a commit operation.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, MaterializedError> {
        let wire = MaterializedWire {
            schema: self.schema.encode_canonical(),
            record_id: self.record_id.clone(),
            state: self.state.clone(),
            indexes: self
                .indexes
                .iter()
                .map(|index| IndexWire {
                    field_id: index.field_id,
                    value: index.value.clone(),
                })
                .collect(),
        };
        minicbor::to_vec(wire).map_err(codec_error)
    }

    /// Strictly decodes and validates a commit-carried materialization.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, MaterializedError> {
        let mut decoder = minicbor::Decoder::new(bytes);
        let wire: MaterializedWire = decoder.decode().map_err(codec_error)?;
        if decoder.position() != bytes.len() {
            return Err(MaterializedError::NonCanonicalEncoding);
        }
        let schema = SchemaDescriptor::decode_canonical(&wire.schema)
            .map_err(|error| MaterializedError::Schema(error.to_string()))?;
        let indexes = wire
            .indexes
            .into_iter()
            .map(|index| IndexValue::new(index.field_id, index.value))
            .collect();
        let value = match wire.state {
            Some(state) => Self::upsert(schema, wire.record_id, state, indexes)?,
            None if indexes.is_empty() => Self::delete(schema, wire.record_id)?,
            None => return Err(MaterializedError::DeleteHasIndexes),
        };
        if value.encode_canonical()? != bytes {
            return Err(MaterializedError::NonCanonicalEncoding);
        }
        Ok(value)
    }
}

#[derive(minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
struct MaterializedWire {
    #[n(0)]
    schema: Vec<u8>,
    #[n(1)]
    record_id: Vec<u8>,
    #[n(2)]
    state: Option<Vec<u8>>,
    #[n(3)]
    indexes: Vec<IndexWire>,
}

#[derive(minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
struct IndexWire {
    #[n(0)]
    field_id: u32,
    #[n(1)]
    value: Vec<u8>,
}

/// A rejected materialized-record input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MaterializedError {
    /// A record key exceeded the protocol bound.
    #[error("record ID is too large: {0}")]
    RecordIdTooLarge(usize),
    /// A materialized record exceeded the local safety bound.
    #[error("record state is too large: {0}")]
    RecordStateTooLarge(usize),
    /// An index value exceeded the local safety bound.
    #[error("index value is too large: {0}")]
    IndexValueTooLarge(usize),
    /// Field zero is reserved for record-level operations.
    #[error("field {0} cannot be used as a secondary index")]
    InvalidIndexField(u32),
    /// A durable mutation could not be encoded or decoded.
    #[error("materialized record codec failed: {0}")]
    Codec(String),
    /// A durable mutation contained an invalid schema.
    #[error("materialized record schema failed: {0}")]
    Schema(String),
    /// A decoded representation was not uniquely canonical.
    #[error("materialized record encoding is not canonical")]
    NonCanonicalEncoding,
    /// A deletion illegally carried secondary index values.
    #[error("a materialized deletion cannot contain indexes")]
    DeleteHasIndexes,
}

#[allow(clippy::needless_pass_by_value)]
fn codec_error(error: impl std::fmt::Display) -> MaterializedError {
    MaterializedError::Codec(error.to_string())
}

fn validate_record_id(record_id: &[u8]) -> Result<(), MaterializedError> {
    if record_id.len() > MAX_RECORD_ID {
        return Err(MaterializedError::RecordIdTooLarge(record_id.len()));
    }
    Ok(())
}
