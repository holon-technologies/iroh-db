use iroh_db_core::{AuthorId, Dot, Lww, Merge, OrSet, VersionVector};
use proptest::prelude::*;

fn author(byte: u8) -> AuthorId {
    AuthorId::from_bytes([byte; 32])
}

fn concurrent_register(value: i32, author_byte: u8) -> Lww<i32> {
    let mut register = Lww::new();
    register
        .assign(
            value,
            Dot::new(author(author_byte), 0, 0),
            VersionVector::new(),
        )
        .unwrap();
    register
}

proptest! {
    #[test]
    fn lww_merge_is_commutative_associative_and_idempotent(
        first in any::<i32>(),
        second in any::<i32>(),
        third in any::<i32>(),
    ) {
        let a = concurrent_register(first, 1);
        let b = concurrent_register(second, 2);
        let c = concurrent_register(third, 3);

        let mut left_associative = a.clone();
        left_associative.merge(&b).unwrap();
        left_associative.merge(&c).unwrap();

        let mut right_branch = b.clone();
        right_branch.merge(&c).unwrap();
        let mut right_associative = a.clone();
        right_associative.merge(&right_branch).unwrap();

        let mut reversed = c.clone();
        reversed.merge(&b).unwrap();
        reversed.merge(&a).unwrap();

        let mut idempotent = left_associative.clone();
        Merge::merge(&mut idempotent, &left_associative).unwrap();

        prop_assert_eq!(&left_associative, &right_associative);
        prop_assert_eq!(&left_associative, &reversed);
        prop_assert_eq!(&left_associative, &idempotent);
        prop_assert_eq!(left_associative.get(), Some(&third));
    }

    #[test]
    fn or_set_merge_is_commutative_and_idempotent(value in any::<u16>()) {
        let first_dot = Dot::new(author(1), 0, 0);
        let second_dot = Dot::new(author(2), 0, 0);
        let mut first = OrSet::new();
        first.insert(value, first_dot).unwrap();
        let mut second = OrSet::new();
        second.insert(value, second_dot).unwrap();

        let mut removal_context = VersionVector::new();
        removal_context.observe(first_dot);
        first.remove(&value, &removal_context);

        let mut left = first.clone();
        left.merge(&second).unwrap();
        let mut right = second;
        right.merge(&first).unwrap();
        let mut idempotent = left.clone();
        idempotent.merge(&left).unwrap();

        prop_assert_eq!(&left, &right);
        prop_assert_eq!(&left, &idempotent);
        prop_assert!(left.contains(&value));
    }
}
