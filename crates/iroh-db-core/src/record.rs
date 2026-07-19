use std::{
    any::type_name, collections::BTreeMap, convert::Infallible, marker::PhantomData, sync::Arc,
};

use minicbor::{Decode, Decoder, Encode, Encoder};

use crate::{
    CrdtError, CrdtKind, GrowOnlySet, Immutable, Lww, Merge, MultiValue, OrSet, OrderedList,
    PnCounter, SchemaDescriptor, SchemaError,
};

const MAX_RECORD_FIELDS: usize = 4_096;
const MAX_FIELD_STATE: usize = 16 * 1024 * 1024;

/// Compile-time metadata for one strongly typed query field.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct TypedField<Record, Value> {
    field_id: u32,
    name: &'static str,
    indexed: bool,
    marker: PhantomData<fn() -> (Record, Value)>,
}

/// A type-checked equality predicate over canonical visible field values.
#[derive(Debug)]
pub struct EqualityFilter<Record> {
    field_id: u32,
    encoded_value: Result<Vec<u8>, RecordError>,
    marker: PhantomData<fn() -> Record>,
}

/// A type-checked ordered predicate over canonical visible field values.
pub struct RangeFilter<Record> {
    field_id: u32,
    operator: RangeOperator,
    encoded_bound: Result<Vec<u8>, RecordError>,
    matches: Arc<RangeMatcher>,
    marker: PhantomData<fn() -> Record>,
}

type RangeMatcher = dyn Fn(&[Vec<u8>]) -> Result<bool, RecordError> + Send + Sync;

impl<Record> std::fmt::Debug for RangeFilter<Record> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RangeFilter")
            .field("field_id", &self.field_id)
            .field("operator", &self.operator)
            .finish_non_exhaustive()
    }
}

/// One supported ordered comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RangeOperator {
    /// Strictly less than the bound.
    Less,
    /// Less than or equal to the bound.
    LessOrEqual,
    /// Strictly greater than the bound.
    Greater,
    /// Greater than or equal to the bound.
    GreaterOrEqual,
}

impl<Record> RangeFilter<Record> {
    /// Returns the stable field targeted by this predicate.
    pub const fn field_id(&self) -> u32 {
        self.field_id
    }

    /// Returns the comparison operator.
    pub const fn operator(&self) -> RangeOperator {
        self.operator
    }

    /// Returns the canonical bound or its deferred codec failure.
    pub fn encoded_bound(&self) -> Result<&[u8], &RecordError> {
        self.encoded_bound.as_deref()
    }

    /// Applies this predicate to canonical visible values.
    pub fn matches(&self, values: &[Vec<u8>]) -> Result<bool, RecordError> {
        (self.matches)(values)
    }
}

impl<Record> EqualityFilter<Record> {
    /// Returns the stable field targeted by this predicate.
    pub const fn field_id(&self) -> u32 {
        self.field_id
    }

    /// Returns the canonical equality key or its deferred codec failure.
    pub fn encoded_value(&self) -> Result<&[u8], &RecordError> {
        self.encoded_value.as_deref()
    }
}

impl<Record, Value> TypedField<Record, Value> {
    /// Constructs generated field metadata.
    pub const fn new(field_id: u32, name: &'static str, indexed: bool) -> Self {
        Self {
            field_id,
            name,
            indexed,
            marker: PhantomData,
        }
    }

    /// Returns the stable numeric field ID.
    pub const fn field_id(self) -> u32 {
        self.field_id
    }

    /// Returns the declared Rust field name.
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Returns whether the schema materializes a secondary index.
    pub const fn is_indexed(self) -> bool {
        self.indexed
    }

    /// Builds a type-checked equality predicate.
    pub fn eq(self, value: impl Into<Value>) -> EqualityFilter<Record>
    where
        Value: RecordKey,
    {
        EqualityFilter {
            field_id: self.field_id,
            encoded_value: value.into().encode_key(),
            marker: PhantomData,
        }
    }

    /// Builds a type-checked less-than predicate.
    pub fn lt(self, value: impl Into<Value>) -> RangeFilter<Record>
    where
        Value: RecordKey + Ord + Send + Sync + 'static,
    {
        self.range(value.into(), RangeOperator::Less)
    }

    /// Builds a type-checked less-than-or-equal predicate.
    pub fn le(self, value: impl Into<Value>) -> RangeFilter<Record>
    where
        Value: RecordKey + Ord + Send + Sync + 'static,
    {
        self.range(value.into(), RangeOperator::LessOrEqual)
    }

    /// Builds a type-checked greater-than predicate.
    pub fn gt(self, value: impl Into<Value>) -> RangeFilter<Record>
    where
        Value: RecordKey + Ord + Send + Sync + 'static,
    {
        self.range(value.into(), RangeOperator::Greater)
    }

    /// Builds a type-checked greater-than-or-equal predicate.
    pub fn ge(self, value: impl Into<Value>) -> RangeFilter<Record>
    where
        Value: RecordKey + Ord + Send + Sync + 'static,
    {
        self.range(value.into(), RangeOperator::GreaterOrEqual)
    }

    #[allow(clippy::needless_pass_by_value)]
    fn range(self, bound: Value, operator: RangeOperator) -> RangeFilter<Record>
    where
        Value: RecordKey + Ord + Send + Sync + 'static,
    {
        let encoded_bound = bound.encode_key();
        let matches_bound = encoded_bound.clone();
        RangeFilter {
            field_id: self.field_id,
            operator,
            encoded_bound,
            matches: Arc::new(move |values| {
                let bound = Value::decode_key(matches_bound.as_deref().map_err(Clone::clone)?)?;
                values.iter().try_fold(false, |matched, encoded| {
                    let value = Value::decode_key(encoded)?;
                    let current = match operator {
                        RangeOperator::Less => value < bound,
                        RangeOperator::LessOrEqual => value <= bound,
                        RangeOperator::Greater => value > bound,
                        RangeOperator::GreaterOrEqual => value >= bound,
                    };
                    Ok(matched || current)
                })
            }),
            marker: PhantomData,
        }
    }
}

impl<Record, Value> Clone for TypedField<Record, Value> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Record, Value> Copy for TypedField<Record, Value> {}

/// A typed-record schema or canonical codec failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    /// The generated or hand-written schema is invalid.
    #[error(transparent)]
    Schema(#[from] SchemaError),
    /// A value could not be encoded.
    #[error("record encoding failed: {0}")]
    Encode(String),
    /// A value could not be decoded.
    #[error("record decoding failed: {0}")]
    Decode(String),
    /// Bytes followed an otherwise complete value.
    #[error("record contains trailing data")]
    TrailingData,
    /// The input was valid CBOR but not its unique canonical representation.
    #[error("record encoding is not canonical")]
    NonCanonicalEncoding,
    /// The record omitted a field required by its schema.
    #[error("record is missing field {0}")]
    MissingField(u32),
    /// A field ID appeared more than once.
    #[error("record repeats field {0}")]
    DuplicateField(u32),
    /// The record exceeded the field-count safety limit.
    #[error("record has too many fields: {0}")]
    TooManyFields(usize),
    /// One encoded field state exceeded the safety limit.
    #[error("field {field_id} state is too large: {size}")]
    FieldTooLarge {
        /// Stable numeric field identifier.
        field_id: u32,
        /// Encoded byte length.
        size: usize,
    },
    /// A replicated field rejected invalid or conflicting causal state.
    #[error(transparent)]
    Crdt(#[from] CrdtError),
    /// A hand-written record did not provide a deterministic merge adapter.
    #[error("record type does not provide a merge adapter")]
    MergeUnavailable,
}

/// Canonical application record identifier encoding.
pub trait RecordKey: Sized {
    /// Encodes this key into its unique durable representation.
    fn encode_key(&self) -> Result<Vec<u8>, RecordError>;

    /// Strictly decodes a key from its unique durable representation.
    fn decode_key(bytes: &[u8]) -> Result<Self, RecordError>;
}

impl<T> RecordKey for T
where
    T: Encode<()> + for<'bytes> Decode<'bytes, ()>,
{
    fn encode_key(&self) -> Result<Vec<u8>, RecordError> {
        encode_value(self)
    }

    fn decode_key(bytes: &[u8]) -> Result<Self, RecordError> {
        decode_value(bytes)
    }
}

/// Canonical state codec and schema metadata for a replicated field.
pub trait FieldState: Sized {
    /// The application value carried by this field strategy.
    type Value;

    /// The deterministic merge strategy.
    const CRDT_KIND: CrdtKind;

    /// Stable Rust logical value type used in schema compatibility checks.
    fn value_type_name() -> &'static str {
        type_name::<Self::Value>()
    }

    /// Encodes complete causal field state.
    fn encode_state(&self) -> Result<Vec<u8>, RecordError>;

    /// Strictly decodes complete causal field state.
    fn decode_state(bytes: &[u8]) -> Result<Self, RecordError>;

    /// Encodes each currently visible application value for filtering and indexes.
    fn visible_values(&self) -> Result<Vec<Vec<u8>>, RecordError>;

    /// Deterministically merges complete causal state from another replica.
    fn merge_state(&mut self, other: &Self) -> Result<(), RecordError>;
}

macro_rules! field_state {
    ($type:ident<$value:ident>, $kind:ident) => {
        impl<$value> FieldState for $type<$value>
        where
            $value: Clone + Eq + Encode<()> + for<'bytes> Decode<'bytes, ()>,
        {
            type Value = $value;

            const CRDT_KIND: CrdtKind = CrdtKind::$kind;

            fn encode_state(&self) -> Result<Vec<u8>, RecordError> {
                encode_value(self)
            }

            fn decode_state(bytes: &[u8]) -> Result<Self, RecordError> {
                decode_value(bytes)
            }

            fn visible_values(&self) -> Result<Vec<Vec<u8>>, RecordError> {
                self.values().map(encode_value).collect()
            }

            fn merge_state(&mut self, other: &Self) -> Result<(), RecordError> {
                Merge::merge(self, other).map_err(RecordError::from)
            }
        }
    };
}

impl<T> FieldState for Lww<T>
where
    T: Clone + Eq + Encode<()> + for<'bytes> Decode<'bytes, ()>,
{
    type Value = T;

    const CRDT_KIND: CrdtKind = CrdtKind::Lww;

    fn encode_state(&self) -> Result<Vec<u8>, RecordError> {
        encode_value(self)
    }

    fn decode_state(bytes: &[u8]) -> Result<Self, RecordError> {
        decode_value(bytes)
    }

    fn visible_values(&self) -> Result<Vec<Vec<u8>>, RecordError> {
        self.get().map(encode_value).into_iter().collect()
    }

    fn merge_state(&mut self, other: &Self) -> Result<(), RecordError> {
        Merge::merge(self, other).map_err(RecordError::from)
    }
}

field_state!(MultiValue<T>, MultiValue);
field_state!(Immutable<T>, Immutable);
field_state!(OrderedList<T>, OrderedList);

macro_rules! ordered_field_state {
    ($type:ident<$value:ident>, $kind:ident) => {
        impl<$value> FieldState for $type<$value>
        where
            $value: Clone + Ord + Encode<()> + for<'bytes> Decode<'bytes, ()>,
        {
            type Value = $value;

            const CRDT_KIND: CrdtKind = CrdtKind::$kind;

            fn encode_state(&self) -> Result<Vec<u8>, RecordError> {
                encode_value(self)
            }

            fn decode_state(bytes: &[u8]) -> Result<Self, RecordError> {
                decode_value(bytes)
            }

            fn visible_values(&self) -> Result<Vec<Vec<u8>>, RecordError> {
                self.values().map(encode_value).collect()
            }

            fn merge_state(&mut self, other: &Self) -> Result<(), RecordError> {
                Merge::merge(self, other).map_err(RecordError::from)
            }
        }
    };
}

ordered_field_state!(OrSet<T>, OrSet);
ordered_field_state!(GrowOnlySet<T>, GrowOnlySet);

impl FieldState for PnCounter {
    type Value = i128;

    const CRDT_KIND: CrdtKind = CrdtKind::PnCounter;

    fn encode_state(&self) -> Result<Vec<u8>, RecordError> {
        encode_value(self)
    }

    fn decode_state(bytes: &[u8]) -> Result<Self, RecordError> {
        decode_value(bytes)
    }

    fn visible_values(&self) -> Result<Vec<Vec<u8>>, RecordError> {
        Ok(vec![
            self.value()
                .map_err(|error| RecordError::Encode(error.to_string()))?
                .to_be_bytes()
                .to_vec(),
        ])
    }

    fn merge_state(&mut self, other: &Self) -> Result<(), RecordError> {
        Merge::merge(self, other).map_err(RecordError::from)
    }
}

/// Strongly typed record contract generated by `#[derive(IrohRecord)]`.
pub trait IrohRecord: Sized {
    /// Application-controlled primary-key type.
    type Id: RecordKey;

    /// Returns the validated durable schema descriptor.
    fn schema() -> Result<SchemaDescriptor, RecordError>;

    /// Borrows the primary key.
    fn id(&self) -> &Self::Id;

    /// Encodes all record fields in stable numeric-field order.
    fn encode_record(&self) -> Result<Vec<u8>, RecordError>;

    /// Strictly decodes a complete typed record.
    fn decode_record(bytes: &[u8]) -> Result<Self, RecordError>;

    /// Encodes the canonical primary key used by storage and indexes.
    fn record_id(&self) -> Result<Vec<u8>, RecordError> {
        self.id().encode_key()
    }

    /// Returns canonical visible values for one field, or an empty set if unknown.
    fn field_values(&self, field_id: u32) -> Result<Vec<Vec<u8>>, RecordError>;

    /// Merges every replicated field from another incarnation of the same record.
    fn merge_record(&mut self, _other: &Self) -> Result<(), RecordError> {
        Err(RecordError::MergeUnavailable)
    }
}

/// Strictly decoded stable field-state map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordFields {
    fields: BTreeMap<u32, Vec<u8>>,
}

impl RecordFields {
    /// Returns one field or a typed missing-field error.
    pub fn required(&self, field_id: u32) -> Result<&[u8], RecordError> {
        self.fields
            .get(&field_id)
            .map(Vec::as_slice)
            .ok_or(RecordError::MissingField(field_id))
    }
}

/// Encodes field states as a canonical CBOR map keyed by stable numeric IDs.
pub fn encode_record_fields(
    fields: impl IntoIterator<Item = (u32, Vec<u8>)>,
) -> Result<Vec<u8>, RecordError> {
    let mut canonical = BTreeMap::new();
    for (field_id, state) in fields {
        if state.len() > MAX_FIELD_STATE {
            return Err(RecordError::FieldTooLarge {
                field_id,
                size: state.len(),
            });
        }
        if canonical.insert(field_id, state).is_some() {
            return Err(RecordError::DuplicateField(field_id));
        }
        if canonical.len() > MAX_RECORD_FIELDS {
            return Err(RecordError::TooManyFields(canonical.len()));
        }
    }

    let mut encoder = Encoder::new(Vec::new());
    encoder
        .map(
            u64::try_from(canonical.len())
                .map_err(|error| RecordError::Encode(error.to_string()))?,
        )
        .map_err(encode_error)?;
    for (field_id, state) in canonical {
        encoder.u32(field_id).map_err(encode_error)?;
        encoder.bytes(&state).map_err(encode_error)?;
    }
    Ok(encoder.into_writer())
}

/// Strictly decodes a canonical stable field-state map.
pub fn decode_record_fields(bytes: &[u8]) -> Result<RecordFields, RecordError> {
    let mut decoder = Decoder::new(bytes);
    let count = decoder
        .map()
        .map_err(decode_error)?
        .ok_or_else(|| RecordError::Decode("indefinite record maps are forbidden".into()))?;
    let count = usize::try_from(count).map_err(|error| RecordError::Decode(error.to_string()))?;
    if count > MAX_RECORD_FIELDS {
        return Err(RecordError::TooManyFields(count));
    }

    let mut fields = BTreeMap::new();
    for _ in 0..count {
        let field_id = decoder.u32().map_err(decode_error)?;
        let state = decoder.bytes().map_err(decode_error)?;
        if state.len() > MAX_FIELD_STATE {
            return Err(RecordError::FieldTooLarge {
                field_id,
                size: state.len(),
            });
        }
        if fields.insert(field_id, state.to_vec()).is_some() {
            return Err(RecordError::DuplicateField(field_id));
        }
    }
    if decoder.position() != bytes.len() {
        return Err(RecordError::TrailingData);
    }

    let record_fields = RecordFields { fields };
    let canonical = encode_record_fields(
        record_fields
            .fields
            .iter()
            .map(|(&field_id, state)| (field_id, state.clone())),
    )?;
    if canonical != bytes {
        return Err(RecordError::NonCanonicalEncoding);
    }
    Ok(record_fields)
}

fn encode_value<T: Encode<()>>(value: &T) -> Result<Vec<u8>, RecordError> {
    minicbor::to_vec(value).map_err(|error| RecordError::Encode(error.to_string()))
}

fn decode_value<T>(bytes: &[u8]) -> Result<T, RecordError>
where
    T: Encode<()> + for<'value> Decode<'value, ()>,
{
    let mut decoder = Decoder::new(bytes);
    let value = decoder.decode::<T>().map_err(decode_error)?;
    if decoder.position() != bytes.len() {
        return Err(RecordError::TrailingData);
    }
    if encode_value(&value)? != bytes {
        return Err(RecordError::NonCanonicalEncoding);
    }
    Ok(value)
}

#[allow(clippy::needless_pass_by_value)]
fn encode_error(error: minicbor::encode::Error<Infallible>) -> RecordError {
    RecordError::Encode(error.to_string())
}

#[allow(clippy::needless_pass_by_value)]
fn decode_error(error: minicbor::decode::Error) -> RecordError {
    RecordError::Decode(error.to_string())
}
