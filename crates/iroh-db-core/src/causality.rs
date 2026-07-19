use std::{cmp::Ordering, collections::BTreeMap};

use crate::AuthorId;

/// The unique, deterministic identity of an operation in a domain.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, minicbor::Encode, minicbor::Decode,
)]
#[cbor(array)]
pub struct Dot {
    #[n(0)]
    author: AuthorId,
    #[n(1)]
    sequence: u64,
    #[n(2)]
    operation: u32,
}

impl Dot {
    /// Constructs an operation dot.
    pub const fn new(author: AuthorId, sequence: u64, operation: u32) -> Self {
        Self {
            author,
            sequence,
            operation,
        }
    }

    /// Returns the author that created this operation.
    pub const fn author(self) -> AuthorId {
        self.author
    }

    /// Returns the author's domain-local commit sequence.
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the operation index within the commit.
    pub const fn operation(self) -> u32 {
        self.operation
    }
}

/// The causal relationship between two histories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CausalRelation {
    /// Both histories contain the same author sequences.
    Equal,
    /// The left history is strictly contained in the right history.
    Before,
    /// The left history strictly contains the right history.
    After,
    /// Each history contains an event absent from the other.
    Concurrent,
}

/// A canonical summary of the highest observed commit sequence for each author.
#[derive(Debug, Clone, Default, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(transparent)]
pub struct VersionVector {
    #[n(0)]
    entries: BTreeMap<AuthorId, u64>,
}

impl VersionVector {
    /// Constructs an empty causal history.
    pub const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Records an observed operation and its containing commit.
    pub fn observe(&mut self, dot: Dot) {
        self.entries
            .entry(dot.author())
            .and_modify(|sequence| *sequence = (*sequence).max(dot.sequence()))
            .or_insert(dot.sequence());
    }

    /// Returns whether this history includes the commit containing `dot`.
    pub fn covers(&self, dot: &Dot) -> bool {
        self.entries
            .get(&dot.author())
            .is_some_and(|sequence| *sequence >= dot.sequence())
    }

    /// Adds all events represented by `other` to this history.
    pub fn merge(&mut self, other: &Self) {
        for (&author, &other_sequence) in &other.entries {
            self.entries
                .entry(author)
                .and_modify(|sequence| *sequence = (*sequence).max(other_sequence))
                .or_insert(other_sequence);
        }
    }

    /// Compares this history with another using vector-clock partial ordering.
    pub fn relation(&self, other: &Self) -> CausalRelation {
        let mut has_less = false;
        let mut has_greater = false;

        for author in self.entries.keys().chain(other.entries.keys()) {
            match self.entries.get(author).cmp(&other.entries.get(author)) {
                Ordering::Less => has_less = true,
                Ordering::Equal => {}
                Ordering::Greater => has_greater = true,
            }

            if has_less && has_greater {
                return CausalRelation::Concurrent;
            }
        }

        match (has_less, has_greater) {
            (false, false) => CausalRelation::Equal,
            (true, false) => CausalRelation::Before,
            (false, true) => CausalRelation::After,
            (true, true) => CausalRelation::Concurrent,
        }
    }

    /// Iterates over authors and sequences in canonical author order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&AuthorId, &u64)> {
        self.entries.iter()
    }
}
