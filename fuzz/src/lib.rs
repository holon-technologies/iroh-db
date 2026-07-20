#![forbid(unsafe_code)]

use std::fmt::Debug;

use iroh_db_core::{
    AuthorId, CapabilityId, CollectionId, CommitBody, CommitEnvelope, CommitHeader, CommitId,
    CommitSignature, CrdtKind, DomainId, Dot, FieldDescriptor, GrowOnlySet, Immutable, Lww, Merge,
    MultiValue, Operation, OperationKind, OrSet, OrderedList, PnCounter, SchemaDescriptor,
    SchemaId, TransactionId, VersionVector, decode_record_fields, encode_record_fields,
};
use iroh_db_security::{
    AuthorityCheckpoint, CapabilityCertificate, ConsistencyMode, ControlTransition,
    DomainDescriptor, Invitation, InvitationTicket, IrohSigner,
};
use iroh_db_store::{IndexValue, MaterializedRecord};
use iroh_db_sync::{GossipHint, MAX_CONTROL_FRAME, SyncFrame};

const VALID_COMMIT_ENVELOPE: &[u8] = b"valid:commit:envelope:";
const VALID_COMMIT_BODY: &[u8] = b"valid:commit:body:";
const VALID_SYNC_FRAME: &[u8] = b"valid:sync:frame:";
const VALID_GOSSIP_HINT: &[u8] = b"valid:sync:gossip:";
const VALID_DOMAIN_DESCRIPTOR: &[u8] = b"valid:security:descriptor:";
const VALID_SCHEMA: &[u8] = b"valid:state:schema:";
const VALID_RECORD_FIELDS: &[u8] = b"valid:state:fields:";
const VALID_MATERIALIZED_RECORD: &[u8] = b"valid:state:materialized:";

/// Exercises every canonical commit decoder and its successful round trip.
pub fn exercise_commit_decode(data: &[u8]) {
    let generated = valid_commit_seed(data);
    let data = generated.as_deref().unwrap_or(data);

    if let Ok(value) = CommitEnvelope::decode_canonical(data) {
        assert_eq!(value.encode_canonical(), data);
    }
    if let Ok(value) = CommitBody::decode_canonical(data) {
        assert_eq!(value.encode_canonical(), data);
    }
}

/// Exercises bounded sync and gossip decoders and their successful round trips.
pub fn exercise_sync_frame_decode(data: &[u8]) {
    let generated = valid_sync_seed(data);
    let data = generated.as_deref().unwrap_or(data);

    if let Ok(value) = SyncFrame::decode_canonical(data) {
        assert_eq!(value.encode_canonical().unwrap(), data);
    }
    if let Ok(value) = GossipHint::decode_canonical(data) {
        assert_eq!(value.encode_canonical().unwrap(), data);
    }
}

/// Exercises signed authority and invitation decoders at the trust boundary.
pub fn exercise_security_decode(data: &[u8]) {
    let generated = valid_security_seed(data);
    let data = generated.as_deref().unwrap_or(data);

    if let Ok(value) = DomainDescriptor::decode_canonical(data) {
        assert_eq!(value.encode_canonical().unwrap(), data);
    }
    if let Ok(value) = CapabilityCertificate::decode_canonical(data) {
        assert_eq!(value.encode_canonical().unwrap(), data);
    }
    if let Ok(value) = ControlTransition::decode_canonical(data) {
        assert_eq!(value.encode_canonical().unwrap(), data);
    }
    if let Ok(value) = AuthorityCheckpoint::decode_canonical(data) {
        assert_eq!(value.encode_canonical().unwrap(), data);
    }
    if let Ok(value) = Invitation::decode_canonical(data) {
        assert_eq!(value.encode_canonical().unwrap(), data);
    }
    if let Ok(value) = InvitationTicket::decode_canonical(data) {
        assert_eq!(value.encode_canonical().unwrap(), data);
    }
}

/// Exercises durable schema, record-field, and materialized-state decoders.
pub fn exercise_state_decode(data: &[u8]) {
    let generated = valid_state_seed(data);
    let data = generated.as_deref().unwrap_or(data);

    if let Ok(value) = SchemaDescriptor::decode_canonical(data) {
        assert_eq!(value.encode_canonical(), data);
    }
    let _ = decode_record_fields(data);
    if let Ok(value) = MaterializedRecord::decode_canonical(data) {
        assert_eq!(value.encode_canonical().unwrap(), data);
    }
}

/// Constructs valid arbitrary-byte replicas for every built-in CRDT family and
/// checks merge commutativity, associativity, and idempotence.
pub fn exercise_crdt_merge(data: &[u8]) {
    let authors = [author(1), author(2), author(3)];
    let dots = [
        Dot::new(authors[0], u64::from(input(data, 0)), 0),
        Dot::new(authors[1], u64::from(input(data, 1)), 0),
        Dot::new(authors[2], u64::from(input(data, 2)), 0),
    ];

    let lww: [Lww<u8>; 3] = std::array::from_fn(|index| {
        let mut value = Lww::new();
        value
            .assign(input(data, index + 3), dots[index], VersionVector::new())
            .unwrap();
        value
    });
    assert_merge_laws(&lww[0], &lww[1], &lww[2]);

    let mut or_sets: [OrSet<u8>; 3] = std::array::from_fn(|index| {
        let mut value = OrSet::new();
        value.insert(input(data, index + 6), dots[index]).unwrap();
        value
    });
    if input(data, 9) & 1 == 1 {
        let mut observed = VersionVector::new();
        observed.observe(dots[0]);
        or_sets[0].remove(&input(data, 6), &observed);
    }
    assert_merge_laws(&or_sets[0], &or_sets[1], &or_sets[2]);

    let grow_only: [GrowOnlySet<u8>; 3] = std::array::from_fn(|index| {
        let mut value = GrowOnlySet::new();
        value.insert(input(data, index + 10));
        value.insert(input(data, index + 13));
        value
    });
    assert_merge_laws(&grow_only[0], &grow_only[1], &grow_only[2]);

    let counters: [PnCounter; 3] = std::array::from_fn(|index| {
        let mut value = PnCounter::new();
        value
            .increment(authors[index], u64::from(input(data, index + 16)))
            .unwrap();
        value
            .decrement(authors[index], u64::from(input(data, index + 19)))
            .unwrap();
        value
    });
    assert_merge_laws(&counters[0], &counters[1], &counters[2]);

    let multi_values: [MultiValue<u8>; 3] = std::array::from_fn(|index| {
        let mut value = MultiValue::new();
        value
            .assign(input(data, index + 22), dots[index], VersionVector::new())
            .unwrap();
        value
    });
    assert_merge_laws(&multi_values[0], &multi_values[1], &multi_values[2]);

    let immutable: [Immutable<u8>; 3] = std::array::from_fn(|index| {
        let mut value = Immutable::new();
        value
            .set(input(data, index + 25), dots[index], VersionVector::new())
            .unwrap();
        value
    });
    assert_merge_laws(&immutable[0], &immutable[1], &immutable[2]);

    let ordered: [OrderedList<u8>; 3] = std::array::from_fn(|index| {
        let mut value = OrderedList::new();
        value
            .insert_after(None, dots[index], input(data, index + 28))
            .unwrap();
        value
            .insert_after(
                Some(dots[index]),
                Dot::new(authors[index], dots[index].sequence(), 1),
                input(data, index + 31),
            )
            .unwrap();
        value
    });
    assert_merge_laws(&ordered[0], &ordered[1], &ordered[2]);
}

fn assert_merge_laws<T>(first: &T, second: &T, third: &T)
where
    T: Clone + Debug + Eq + Merge,
{
    let mut left_associative = first.clone();
    left_associative.merge(second).unwrap();
    left_associative.merge(third).unwrap();

    let mut right_branch = second.clone();
    right_branch.merge(third).unwrap();
    let mut right_associative = first.clone();
    right_associative.merge(&right_branch).unwrap();

    let mut reversed = third.clone();
    reversed.merge(second).unwrap();
    reversed.merge(first).unwrap();

    let mut idempotent = left_associative.clone();
    idempotent.merge(&left_associative).unwrap();

    assert_eq!(left_associative, right_associative);
    assert_eq!(left_associative, reversed);
    assert_eq!(left_associative, idempotent);
}

fn author(byte: u8) -> AuthorId {
    AuthorId::from_bytes([byte; 32])
}

fn input(data: &[u8], index: usize) -> u8 {
    data.get(index).copied().unwrap_or(index as u8)
}

fn valid_commit_seed(data: &[u8]) -> Option<Vec<u8>> {
    if let Some(seed) = data.strip_prefix(VALID_COMMIT_ENVELOPE) {
        let header = CommitHeader::new(
            DomainId::from_bytes(seed_array(seed, 0)),
            seed_u64(seed, 32),
            AuthorId::from_bytes(seed_array(seed, 40)),
            seed_u64(seed, 72),
            vec![CommitId::from_bytes(seed_array(seed, 80))],
            CapabilityId::from_bytes(seed_array(seed, 112)),
            vec![SchemaId::from_bytes(seed_array(seed, 144))],
            seed_array(seed, 176),
        )
        .expect("the structured seed stays within commit bounds");
        let ciphertext = seed.iter().copied().take(256).collect();
        return Some(
            CommitEnvelope::new(
                header,
                ciphertext,
                CommitSignature::from_bytes(seed_array(seed, 200)),
            )
            .expect("the structured seed stays within envelope bounds")
            .encode_canonical(),
        );
    }

    data.strip_prefix(VALID_COMMIT_BODY).map(|seed| {
        let operation = Operation::new(
            CollectionId::for_name("fuzz-records"),
            seed.iter().copied().take(128).collect(),
            u32::from(input(seed, 128)),
            OperationKind::LwwAssign,
            seed.iter().copied().skip(128).take(256).collect(),
        )
        .expect("the structured seed stays within operation bounds");
        CommitBody::new(
            TransactionId::from_bytes(seed_array(seed, 384)),
            vec![operation],
        )
        .expect("the structured seed stays within body bounds")
        .encode_canonical()
    })
}

fn valid_sync_seed(data: &[u8]) -> Option<Vec<u8>> {
    if let Some(seed) = data.strip_prefix(VALID_SYNC_FRAME) {
        return Some(
            SyncFrame::Hello {
                nonce: seed_array(seed, 0),
                max_frame: u32::try_from(MAX_CONTROL_FRAME).unwrap(),
            }
            .encode_canonical()
            .expect("the structured frame is valid"),
        );
    }

    data.strip_prefix(VALID_GOSSIP_HINT).map(|seed| {
        let signer = IrohSigner::from_secret_bytes(seed_array(seed, 0));
        let unsigned = GossipHint::new(
            signer.author(),
            CommitId::from_bytes(seed_array(seed, 32)),
            seed_array(seed, 64),
            seed_u64(seed, 96),
            [0; 64],
        );
        let signature = signer.sign_gossip(
            &unsigned
                .signing_bytes()
                .expect("the structured gossip content is valid"),
        );
        GossipHint::new(
            unsigned.author(),
            unsigned.commit(),
            unsigned.frontier_digest(),
            unsigned.counter(),
            signature,
        )
        .encode_canonical()
        .expect("the structured gossip hint is valid")
    })
}

fn valid_security_seed(data: &[u8]) -> Option<Vec<u8>> {
    data.strip_prefix(VALID_DOMAIN_DESCRIPTOR).map(|seed| {
        let signer = IrohSigner::from_secret_bytes(seed_array(seed, 0));
        let mode = match input(seed, 32) % 3 {
            0 => ConsistencyMode::MultiWriter,
            1 => ConsistencyMode::SingleWriter,
            _ => ConsistencyMode::AppendOnly,
        };
        DomainDescriptor::issue(
            DomainId::from_bytes(seed_array(seed, 33)),
            mode,
            &signer,
            seed_array(seed, 65),
        )
        .expect("the structured descriptor is valid")
        .encode_canonical()
        .expect("the structured descriptor encodes")
    })
}

fn valid_state_seed(data: &[u8]) -> Option<Vec<u8>> {
    if let Some(seed) = data.strip_prefix(VALID_SCHEMA) {
        return Some(sample_schema(seed).encode_canonical());
    }
    if let Some(seed) = data.strip_prefix(VALID_RECORD_FIELDS) {
        return Some(
            encode_record_fields([
                (1, seed.iter().copied().take(256).collect()),
                (2, seed.iter().copied().skip(256).take(256).collect()),
            ])
            .expect("the structured record fields stay bounded"),
        );
    }

    data.strip_prefix(VALID_MATERIALIZED_RECORD).map(|seed| {
        let state = encode_record_fields([(1, seed.iter().copied().take(256).collect())])
            .expect("the structured record state stays bounded");
        MaterializedRecord::upsert(
            sample_schema(seed),
            seed.iter().copied().take(128).collect(),
            state,
            vec![IndexValue::new(
                2,
                seed.iter().copied().skip(128).take(128).collect(),
            )],
        )
        .expect("the structured materialized record stays bounded")
        .encode_canonical()
        .expect("the structured materialized record encodes")
    })
}

fn sample_schema(seed: &[u8]) -> SchemaDescriptor {
    SchemaDescriptor::new(
        "fuzz-records",
        u32::from_le_bytes(seed_array(seed, 0)),
        vec![
            FieldDescriptor::new(1, "id", CrdtKind::Immutable, "Vec<u8>").record_id(),
            FieldDescriptor::new(2, "value", CrdtKind::Lww, "Vec<u8>").indexed(),
        ],
    )
    .expect("the structured schema is valid")
}

fn seed_array<const N: usize>(data: &[u8], offset: usize) -> [u8; N] {
    std::array::from_fn(|index| input(data, offset + index))
}

fn seed_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(seed_array(data, offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_commit_seeds_reach_successful_decoders() {
        let envelope = valid_commit_seed(b"valid:commit:envelope:mutable").unwrap();
        CommitEnvelope::decode_canonical(&envelope).unwrap();

        let body = valid_commit_seed(b"valid:commit:body:mutable").unwrap();
        CommitBody::decode_canonical(&body).unwrap();
    }

    #[test]
    fn structured_sync_seeds_reach_successful_decoders() {
        let frame = valid_sync_seed(b"valid:sync:frame:mutable").unwrap();
        SyncFrame::decode_canonical(&frame).unwrap();

        let gossip = valid_sync_seed(b"valid:sync:gossip:mutable").unwrap();
        GossipHint::decode_canonical(&gossip).unwrap();
    }

    #[test]
    fn structured_security_seed_reaches_a_verified_decoder() {
        let descriptor = valid_security_seed(b"valid:security:descriptor:mutable").unwrap();
        DomainDescriptor::decode_canonical(&descriptor).unwrap();
    }

    #[test]
    fn structured_state_seeds_reach_successful_decoders() {
        let schema = valid_state_seed(b"valid:state:schema:mutable").unwrap();
        SchemaDescriptor::decode_canonical(&schema).unwrap();

        let fields = valid_state_seed(b"valid:state:fields:mutable").unwrap();
        decode_record_fields(&fields).unwrap();

        let materialized = valid_state_seed(b"valid:state:materialized:mutable").unwrap();
        MaterializedRecord::decode_canonical(&materialized).unwrap();
    }
}
