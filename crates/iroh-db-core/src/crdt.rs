use std::collections::{BTreeMap, BTreeSet};

use crate::{AuthorId, Dot, VersionVector};

/// A deterministic CRDT operation or merge failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CrdtError {
    /// Distinct values claimed the same globally unique operation dot.
    #[error("one operation dot identifies conflicting values")]
    ConflictingDot,
    /// A multi-value read requires explicit conflict handling.
    #[error("value has {0} concurrent alternatives")]
    Conflict(usize),
    /// A write-once value was assigned again in its causal future.
    #[error("immutable value is already set")]
    ImmutableAlreadySet,
    /// A list insertion referenced an element that is not present.
    #[error("ordered-list predecessor is missing")]
    MissingPredecessor,
    /// A list removal referenced an element that is not present.
    #[error("ordered-list element is missing")]
    MissingElement,
    /// A list removal did not causally observe the referenced element.
    #[error("ordered-list removal does not observe the element")]
    InvalidRemoval,
    /// An arithmetic operation exceeded its durable integer range.
    #[error("counter overflow")]
    CounterOverflow,
}

/// Deterministically combines state from another replica.
pub trait Merge {
    /// Merges `other` into this value.
    fn merge(&mut self, other: &Self) -> Result<(), CrdtError>;
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
struct Assignment<T> {
    #[n(0)]
    value: T,
    #[n(1)]
    dot: Dot,
    #[n(2)]
    context: VersionVector,
}

/// A causal last-writer-wins register that never uses wall-clock time.
#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
pub struct Lww<T> {
    #[n(0)]
    assignment: Option<Assignment<T>>,
}

impl<T> Lww<T> {
    /// Constructs an empty register.
    pub const fn new() -> Self {
        Self { assignment: None }
    }

    /// Returns the current value, if assigned.
    pub fn get(&self) -> Option<&T> {
        self.assignment.as_ref().map(|entry| &entry.value)
    }
}

impl<T: Clone + Eq> Lww<T> {
    /// Applies an assignment using causal order, then dot order for concurrency.
    pub fn assign(&mut self, value: T, dot: Dot, context: VersionVector) -> Result<(), CrdtError> {
        merge_lww_assignment(
            &mut self.assignment,
            Assignment {
                value,
                dot,
                context,
            },
        )
    }

    /// Deterministically combines another replica's state.
    pub fn merge(&mut self, other: &Self) -> Result<(), CrdtError> {
        Merge::merge(self, other)
    }
}

impl<T> Default for Lww<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone + Eq> Merge for Lww<T> {
    fn merge(&mut self, other: &Self) -> Result<(), CrdtError> {
        if let Some(candidate) = &other.assignment {
            merge_lww_assignment(&mut self.assignment, candidate.clone())?;
        }
        Ok(())
    }
}

fn merge_lww_assignment<T: Eq>(
    current: &mut Option<Assignment<T>>,
    mut candidate: Assignment<T>,
) -> Result<(), CrdtError> {
    let Some(existing) = current else {
        *current = Some(candidate);
        return Ok(());
    };

    if candidate.dot == existing.dot {
        if candidate.value != existing.value {
            return Err(CrdtError::ConflictingDot);
        }
        existing.context.merge(&candidate.context);
        return Ok(());
    }

    let candidate_is_later = candidate.context.covers(&existing.dot);
    let existing_is_later = existing.context.covers(&candidate.dot);
    if candidate_is_later || (!existing_is_later && candidate.dot > existing.dot) {
        candidate.context.merge(&existing.context);
        *existing = candidate;
    }
    Ok(())
}

/// An add-wins observed-remove set.
#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
pub struct OrSet<T: Ord> {
    #[n(0)]
    adds: BTreeMap<T, BTreeSet<Dot>>,
    #[n(1)]
    removed: BTreeSet<Dot>,
}

impl<T: Ord> OrSet<T> {
    /// Constructs an empty set.
    pub const fn new() -> Self {
        Self {
            adds: BTreeMap::new(),
            removed: BTreeSet::new(),
        }
    }

    /// Returns whether a value has at least one live add dot.
    pub fn contains(&self, value: &T) -> bool
    where
        T: Ord,
    {
        self.adds.get(value).is_some_and(|dots| !dots.is_empty())
    }

    /// Iterates over live values in canonical value order.
    pub fn values(&self) -> impl Iterator<Item = &T> {
        self.adds.keys()
    }
}

impl<T: Clone + Ord> OrSet<T> {
    /// Adds a value under a globally unique operation dot.
    pub fn insert(&mut self, value: T, dot: Dot) -> Result<(), CrdtError> {
        for (existing_value, dots) in &self.adds {
            if dots.contains(&dot) && existing_value != &value {
                return Err(CrdtError::ConflictingDot);
            }
        }
        if !self.removed.contains(&dot) {
            self.adds.entry(value).or_default().insert(dot);
        }
        Ok(())
    }

    /// Removes only add operations visible in `context`.
    pub fn remove(&mut self, value: &T, context: &VersionVector) {
        let Some(dots) = self.adds.get_mut(value) else {
            return;
        };
        let observed: Vec<_> = dots
            .iter()
            .copied()
            .filter(|dot| context.covers(dot))
            .collect();
        for dot in observed {
            dots.remove(&dot);
            self.removed.insert(dot);
        }
        if dots.is_empty() {
            self.adds.remove(value);
        }
    }

    /// Deterministically combines another replica's state.
    pub fn merge(&mut self, other: &Self) -> Result<(), CrdtError> {
        Merge::merge(self, other)
    }
}

impl<T: Ord> Default for OrSet<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone + Ord> Merge for OrSet<T> {
    fn merge(&mut self, other: &Self) -> Result<(), CrdtError> {
        self.removed.extend(other.removed.iter().copied());
        for (value, dots) in &other.adds {
            for &dot in dots {
                self.insert(value.clone(), dot)?;
            }
        }
        for dots in self.adds.values_mut() {
            dots.retain(|dot| !self.removed.contains(dot));
        }
        self.adds.retain(|_, dots| !dots.is_empty());
        Ok(())
    }
}

/// A set whose only operation is insertion.
#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
pub struct GrowOnlySet<T: Ord> {
    #[n(0)]
    values: BTreeSet<T>,
}

impl<T: Ord> GrowOnlySet<T> {
    /// Constructs an empty set.
    pub const fn new() -> Self {
        Self {
            values: BTreeSet::new(),
        }
    }

    /// Iterates over values in canonical order.
    pub fn values(&self) -> impl Iterator<Item = &T> {
        self.values.iter()
    }
}

impl<T: Ord> GrowOnlySet<T> {
    /// Inserts a value and returns whether it was new.
    pub fn insert(&mut self, value: T) -> bool {
        self.values.insert(value)
    }

    /// Deterministically combines another replica's state.
    pub fn merge(&mut self, other: &Self) -> Result<(), CrdtError>
    where
        T: Clone,
    {
        Merge::merge(self, other)
    }
}

impl<T: Ord> Default for GrowOnlySet<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone + Ord> Merge for GrowOnlySet<T> {
    fn merge(&mut self, other: &Self) -> Result<(), CrdtError> {
        self.values.extend(other.values.iter().cloned());
        Ok(())
    }
}

/// A state-based positive/negative counter with per-author components.
#[derive(Debug, Clone, Default, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
pub struct PnCounter {
    #[n(0)]
    positive: BTreeMap<AuthorId, u64>,
    #[n(1)]
    negative: BTreeMap<AuthorId, u64>,
}

impl PnCounter {
    /// Constructs a zero counter.
    pub const fn new() -> Self {
        Self {
            positive: BTreeMap::new(),
            negative: BTreeMap::new(),
        }
    }

    /// Adds to an author's monotonic positive component.
    pub fn increment(&mut self, author: AuthorId, amount: u64) -> Result<(), CrdtError> {
        add_component(&mut self.positive, author, amount)
    }

    /// Adds to an author's monotonic negative component.
    pub fn decrement(&mut self, author: AuthorId, amount: u64) -> Result<(), CrdtError> {
        add_component(&mut self.negative, author, amount)
    }

    /// Computes the signed counter value with overflow checking.
    pub fn value(&self) -> Result<i128, CrdtError> {
        let positive = sum_components(&self.positive)?;
        let negative = sum_components(&self.negative)?;
        positive
            .checked_sub(negative)
            .ok_or(CrdtError::CounterOverflow)
    }

    /// Deterministically combines another replica's state.
    pub fn merge(&mut self, other: &Self) -> Result<(), CrdtError> {
        Merge::merge(self, other)
    }
}

impl Merge for PnCounter {
    fn merge(&mut self, other: &Self) -> Result<(), CrdtError> {
        merge_components(&mut self.positive, &other.positive);
        merge_components(&mut self.negative, &other.negative);
        self.value().map(|_| ())
    }
}

fn add_component(
    components: &mut BTreeMap<AuthorId, u64>,
    author: AuthorId,
    amount: u64,
) -> Result<(), CrdtError> {
    let value = components.entry(author).or_default();
    *value = value
        .checked_add(amount)
        .ok_or(CrdtError::CounterOverflow)?;
    Ok(())
}

fn merge_components(components: &mut BTreeMap<AuthorId, u64>, other: &BTreeMap<AuthorId, u64>) {
    for (&author, &other_value) in other {
        components
            .entry(author)
            .and_modify(|value| *value = (*value).max(other_value))
            .or_insert(other_value);
    }
}

fn sum_components(components: &BTreeMap<AuthorId, u64>) -> Result<i128, CrdtError> {
    components.values().try_fold(0_i128, |total, value| {
        total
            .checked_add(i128::from(*value))
            .ok_or(CrdtError::CounterOverflow)
    })
}

/// A register retaining every causally maximal assignment.
#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
pub struct MultiValue<T> {
    #[n(0)]
    entries: BTreeMap<Dot, Assignment<T>>,
}

impl<T> MultiValue<T> {
    /// Constructs an empty register.
    pub const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Iterates over concurrent values in canonical dot order.
    pub fn values(&self) -> impl Iterator<Item = &T> {
        self.entries.values().map(|entry| &entry.value)
    }

    /// Reads zero or one value, returning a typed conflict for concurrency.
    pub fn read_one(&self) -> Result<Option<&T>, CrdtError> {
        match self.entries.len() {
            0 => Ok(None),
            1 => Ok(self.entries.values().next().map(|entry| &entry.value)),
            count => Err(CrdtError::Conflict(count)),
        }
    }
}

impl<T: Clone + Eq> MultiValue<T> {
    /// Applies an assignment and removes only values it causally observes.
    pub fn assign(&mut self, value: T, dot: Dot, context: VersionVector) -> Result<(), CrdtError> {
        if let Some(existing) = self.entries.get_mut(&dot) {
            if existing.value != value {
                return Err(CrdtError::ConflictingDot);
            }
            existing.context.merge(&context);
            return Ok(());
        }
        if self
            .entries
            .values()
            .any(|existing| existing.context.covers(&dot))
        {
            return Ok(());
        }
        self.entries
            .retain(|_, existing| !context.covers(&existing.dot));
        self.entries.insert(
            dot,
            Assignment {
                value,
                dot,
                context,
            },
        );
        Ok(())
    }

    /// Deterministically combines another replica's state.
    pub fn merge(&mut self, other: &Self) -> Result<(), CrdtError> {
        Merge::merge(self, other)
    }
}

impl<T> Default for MultiValue<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone + Eq> Merge for MultiValue<T> {
    fn merge(&mut self, other: &Self) -> Result<(), CrdtError> {
        for (&dot, entry) in &other.entries {
            if let Some(existing) = self.entries.get_mut(&dot) {
                if existing.value != entry.value {
                    return Err(CrdtError::ConflictingDot);
                }
                existing.context.merge(&entry.context);
            } else {
                self.entries.insert(dot, entry.clone());
            }
        }

        let entries: Vec<_> = self.entries.values().cloned().collect();
        self.entries.retain(|dot, _| {
            !entries
                .iter()
                .any(|other| other.dot != *dot && other.context.covers(dot))
        });
        Ok(())
    }
}

/// A write-once register that retains unequal concurrent initial values.
#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
pub struct Immutable<T> {
    #[n(0)]
    values: MultiValue<T>,
}

impl<T> Immutable<T> {
    /// Constructs an unset immutable value.
    pub const fn new() -> Self {
        Self {
            values: MultiValue::new(),
        }
    }

    /// Reads the value, returning a typed error for concurrent initial values.
    pub fn get(&self) -> Result<Option<&T>, CrdtError> {
        self.values.read_one()
    }

    /// Iterates over all causally concurrent initial values in dot order.
    pub fn values(&self) -> impl Iterator<Item = &T> {
        self.values.values()
    }
}

impl<T: Clone + Eq> Immutable<T> {
    /// Sets an initial value, rejecting causal reassignment.
    pub fn set(&mut self, value: T, dot: Dot, context: VersionVector) -> Result<(), CrdtError> {
        if self
            .values
            .entries
            .values()
            .any(|existing| context.covers(&existing.dot))
        {
            return Err(CrdtError::ImmutableAlreadySet);
        }
        self.values.assign(value, dot, context)
    }

    /// Deterministically combines another replica's state.
    pub fn merge(&mut self, other: &Self) -> Result<(), CrdtError> {
        Merge::merge(self, other)
    }
}

impl<T> Default for Immutable<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone + Eq> Merge for Immutable<T> {
    fn merge(&mut self, other: &Self) -> Result<(), CrdtError> {
        for left in self.values.entries.values() {
            for right in other.values.entries.values() {
                if left.dot != right.dot
                    && (left.context.covers(&right.dot) || right.context.covers(&left.dot))
                {
                    return Err(CrdtError::ImmutableAlreadySet);
                }
            }
        }
        self.values.merge(&other.values)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
struct ListElement<T> {
    #[n(0)]
    parent: Option<Dot>,
    #[n(1)]
    value: T,
    #[n(2)]
    removed: bool,
}

/// A replicated growable ordered list with stable element dots.
#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
pub struct OrderedList<T> {
    #[n(0)]
    elements: BTreeMap<Dot, ListElement<T>>,
}

impl<T> OrderedList<T> {
    /// Constructs an empty list.
    pub const fn new() -> Self {
        Self {
            elements: BTreeMap::new(),
        }
    }

    /// Iterates over visible values in replicated list order.
    pub fn values(&self) -> impl Iterator<Item = &T> {
        let mut values = Vec::with_capacity(self.elements.len());
        self.collect_children(None, &mut values);
        values.into_iter()
    }

    fn collect_children<'a>(&'a self, parent: Option<Dot>, output: &mut Vec<&'a T>) {
        for (&dot, element) in self
            .elements
            .iter()
            .filter(|(_, element)| element.parent == parent)
        {
            if !element.removed {
                output.push(&element.value);
            }
            self.collect_children(Some(dot), output);
        }
    }
}

impl<T: Clone + Eq> OrderedList<T> {
    /// Inserts a stable element after `parent`, or at the replicated root.
    pub fn insert_after(
        &mut self,
        parent: Option<Dot>,
        dot: Dot,
        value: T,
    ) -> Result<(), CrdtError> {
        if parent.is_some_and(|parent| !self.elements.contains_key(&parent)) {
            return Err(CrdtError::MissingPredecessor);
        }
        if let Some(existing) = self.elements.get(&dot) {
            if existing.parent == parent && existing.value == value {
                return Ok(());
            }
            return Err(CrdtError::ConflictingDot);
        }
        self.elements.insert(
            dot,
            ListElement {
                parent,
                value,
                removed: false,
            },
        );
        Ok(())
    }

    /// Removes an element that is visible in `context`.
    pub fn remove(&mut self, dot: Dot, context: &VersionVector) -> Result<(), CrdtError> {
        let element = self
            .elements
            .get_mut(&dot)
            .ok_or(CrdtError::MissingElement)?;
        if !context.covers(&dot) {
            return Err(CrdtError::InvalidRemoval);
        }
        element.removed = true;
        Ok(())
    }

    /// Deterministically combines another replica's state.
    pub fn merge(&mut self, other: &Self) -> Result<(), CrdtError> {
        Merge::merge(self, other)
    }
}

impl<T> Default for OrderedList<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone + Eq> Merge for OrderedList<T> {
    fn merge(&mut self, other: &Self) -> Result<(), CrdtError> {
        for (&dot, other_element) in &other.elements {
            if let Some(element) = self.elements.get_mut(&dot) {
                if element.parent != other_element.parent || element.value != other_element.value {
                    return Err(CrdtError::ConflictingDot);
                }
                element.removed |= other_element.removed;
            } else {
                self.elements.insert(dot, other_element.clone());
            }
        }
        if self.elements.values().any(|element| {
            element
                .parent
                .is_some_and(|parent| !self.elements.contains_key(&parent))
        }) {
            return Err(CrdtError::MissingPredecessor);
        }
        Ok(())
    }
}
