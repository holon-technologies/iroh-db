use std::str::FromStr;

use iroh_db_core::{
    AuthorId, CausalRelation, CollectionId, DomainId, Dot, FixedIdError, VersionVector,
};

fn author(byte: u8) -> AuthorId {
    AuthorId::from_bytes([byte; 32])
}

#[test]
fn collection_ids_are_stable_and_domain_separated() {
    let tracks = CollectionId::for_name("tracks");
    let tracks_again = CollectionId::for_name("tracks");
    let artists = CollectionId::for_name("artists");

    assert_eq!(tracks, tracks_again);
    assert_ne!(tracks, artists);
    assert_eq!(
        tracks.to_string(),
        "3d7d9e0d9969ffe4dfd2e91de8b39c482c0eceb1b3a6ab549e862b831f3b15db"
    );
}

#[test]
fn fixed_ids_have_strict_hex_parsing() {
    let id = DomainId::from_bytes([0xab; 32]);
    let encoded = id.to_string();

    assert_eq!(DomainId::from_str(&encoded), Ok(id));
    assert_eq!(
        DomainId::from_str("ab"),
        Err(FixedIdError::InvalidLength(1))
    );
    assert!(matches!(
        DomainId::from_str(&"zz".repeat(32)),
        Err(FixedIdError::InvalidHex(_))
    ));
}

#[test]
fn dots_have_a_total_canonical_order() {
    let first = Dot::new(author(1), 7, 0);
    let later_operation = Dot::new(author(1), 7, 1);
    let other_author = Dot::new(author(2), 7, 0);

    assert!(first < later_operation);
    assert!(later_operation < other_author);
}

#[test]
fn version_vectors_distinguish_causal_and_concurrent_history() {
    let mut left = VersionVector::new();
    left.observe(Dot::new(author(1), 0, 0));

    let mut right = VersionVector::new();
    right.observe(Dot::new(author(2), 0, 0));

    assert_eq!(left.relation(&right), CausalRelation::Concurrent);
    assert!(!left.covers(&Dot::new(author(2), 0, 0)));

    let mut merged = left.clone();
    merged.merge(&right);

    assert_eq!(left.relation(&merged), CausalRelation::Before);
    assert_eq!(merged.relation(&left), CausalRelation::After);
    assert_eq!(merged.relation(&merged), CausalRelation::Equal);
    assert!(merged.covers(&Dot::new(author(1), 0, 99)));
    assert!(merged.covers(&Dot::new(author(2), 0, 0)));
}
