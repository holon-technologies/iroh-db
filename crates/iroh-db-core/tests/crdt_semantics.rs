use iroh_db_core::{
    AuthorId, CrdtError, Dot, GrowOnlySet, Immutable, Lww, MultiValue, OrSet, OrderedList,
    PnCounter, VersionVector,
};

fn author(byte: u8) -> AuthorId {
    AuthorId::from_bytes([byte; 32])
}

fn dot(author_byte: u8, sequence: u64, operation: u32) -> Dot {
    Dot::new(author(author_byte), sequence, operation)
}

fn context(dots: &[Dot]) -> VersionVector {
    let mut context = VersionVector::new();
    for &dot in dots {
        context.observe(dot);
    }
    context
}

#[test]
fn lww_prefers_causality_then_uses_dot_for_concurrent_writes() {
    let first = dot(9, 0, 0);
    let causally_later = dot(1, 1, 0);
    let concurrent_greater = dot(10, 0, 0);

    let mut register = Lww::new();
    register
        .assign("first", first, VersionVector::new())
        .unwrap();
    register
        .assign("later", causally_later, context(&[first]))
        .unwrap();
    assert_eq!(register.get(), Some(&"later"));

    register
        .assign("concurrent", concurrent_greater, VersionVector::new())
        .unwrap();
    assert_eq!(register.get(), Some(&"concurrent"));
}

#[test]
fn or_set_removes_only_observed_adds() {
    let observed = dot(1, 0, 0);
    let concurrent = dot(2, 0, 0);
    let mut left = OrSet::new();
    left.insert("trip-hop", observed).unwrap();

    let mut right = OrSet::new();
    right.insert("trip-hop", concurrent).unwrap();

    left.remove(&"trip-hop", &context(&[observed]));
    left.merge(&right).unwrap();

    assert!(left.contains(&"trip-hop"));
    assert_eq!(left.values().copied().collect::<Vec<_>>(), vec!["trip-hop"]);
}

#[test]
fn grow_only_set_is_a_union() {
    let mut left = GrowOnlySet::new();
    left.insert("one");
    let mut right = GrowOnlySet::new();
    right.insert("two");

    left.merge(&right).unwrap();

    assert_eq!(
        left.values().copied().collect::<Vec<_>>(),
        vec!["one", "two"]
    );
}

#[test]
fn pn_counter_merges_author_components_by_maximum() {
    let mut first_replica = PnCounter::new();
    first_replica.increment(author(1), 5).unwrap();
    first_replica.decrement(author(1), 2).unwrap();

    let mut stale_replica = first_replica.clone();
    first_replica.increment(author(1), 3).unwrap();
    stale_replica.increment(author(2), 4).unwrap();
    stale_replica.decrement(author(2), 1).unwrap();

    first_replica.merge(&stale_replica).unwrap();

    assert_eq!(first_replica.value().unwrap(), 9);
}

#[test]
fn multi_value_retains_concurrency_until_a_write_observes_it() {
    let first = dot(1, 0, 0);
    let second = dot(2, 0, 0);
    let resolution = dot(1, 1, 0);
    let mut values = MultiValue::new();
    values.assign("blue", first, VersionVector::new()).unwrap();
    values
        .assign("green", second, VersionVector::new())
        .unwrap();

    assert_eq!(values.read_one(), Err(CrdtError::Conflict(2)));
    assert_eq!(
        values.values().copied().collect::<Vec<_>>(),
        vec!["blue", "green"]
    );

    values
        .assign("teal", resolution, context(&[first, second]))
        .unwrap();
    assert_eq!(values.read_one(), Ok(Some(&"teal")));
}

#[test]
fn immutable_rejects_later_writes_but_preserves_concurrent_conflicts() {
    let first = dot(1, 0, 0);
    let concurrent = dot(2, 0, 0);
    let later = dot(1, 1, 0);
    let mut value = Immutable::new();
    value.set("original", first, VersionVector::new()).unwrap();

    assert_eq!(
        value.set("replacement", later, context(&[first])),
        Err(CrdtError::ImmutableAlreadySet)
    );

    value
        .set("concurrent", concurrent, VersionVector::new())
        .unwrap();
    assert_eq!(value.get(), Err(CrdtError::Conflict(2)));
}

#[test]
fn ordered_list_orders_concurrent_siblings_by_dot_and_keeps_descendants_of_tombstones() {
    let first = dot(1, 0, 0);
    let concurrent = dot(2, 0, 0);
    let child = dot(1, 1, 0);
    let mut list = OrderedList::new();
    list.insert_after(None, concurrent, "second").unwrap();
    list.insert_after(None, first, "first").unwrap();
    list.insert_after(Some(first), child, "child").unwrap();

    assert_eq!(
        list.values().copied().collect::<Vec<_>>(),
        vec!["first", "child", "second"]
    );

    list.remove(first, &context(&[first])).unwrap();
    assert_eq!(
        list.values().copied().collect::<Vec<_>>(),
        vec!["child", "second"]
    );
    assert_eq!(
        list.insert_after(Some(dot(9, 9, 9)), dot(3, 0, 0), "orphan"),
        Err(CrdtError::MissingPredecessor)
    );
}
