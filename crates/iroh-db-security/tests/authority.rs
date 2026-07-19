use iroh_db_core::{AuthorId, CommitId, DomainId};
use iroh_db_security::{
    CapabilityCertificate, ConsistencyMode, ControlTransition, DomainDescriptor, IrohSigner,
    Permission, PermissionSet,
};

fn permissions(values: &[Permission]) -> PermissionSet {
    PermissionSet::from_permissions(values)
}

#[test]
fn descriptor_and_root_capability_are_signed_canonical_authority() {
    let owner = IrohSigner::from_secret_bytes([7; 32]);
    let domain = DomainId::from_bytes([9; 32]);
    let descriptor =
        DomainDescriptor::issue(domain, ConsistencyMode::MultiWriter, &owner, [3; 32]).unwrap();
    let encoded = descriptor.encode_canonical().unwrap();
    assert_eq!(
        DomainDescriptor::decode_canonical(&encoded).unwrap(),
        descriptor
    );
    descriptor.verify().unwrap();

    let all = PermissionSet::all();
    let root = CapabilityCertificate::issue_root(domain, all, &owner, [4; 32]).unwrap();
    root.verify_signature().unwrap();
    assert_eq!(root.subject(), owner.author());
    assert_eq!(root.permissions(), all);
    assert_eq!(root.delegation_permissions(), all);
    assert_eq!(
        CapabilityCertificate::decode_canonical(&root.encode_canonical().unwrap()).unwrap(),
        root
    );
}

#[test]
fn delegation_can_only_narrow_rights_epoch_and_depth() {
    let owner = IrohSigner::from_secret_bytes([1; 32]);
    let member = IrohSigner::from_secret_bytes([2; 32]);
    let reader = IrohSigner::from_secret_bytes([3; 32]);
    let domain = DomainId::from_bytes([5; 32]);
    let root =
        CapabilityCertificate::issue_root(domain, PermissionSet::all(), &owner, [6; 32]).unwrap();
    let member_cap = root
        .delegate(
            &owner,
            member.author(),
            permissions(&[Permission::Read, Permission::Write, Permission::Invite]),
            permissions(&[Permission::Read]),
            1,
            Some(3),
            [7; 32],
        )
        .unwrap();
    member_cap.validate_delegation(&root).unwrap();
    assert!(
        member_cap
            .delegate(
                &member,
                reader.author(),
                permissions(&[Permission::Write]),
                PermissionSet::empty(),
                1,
                Some(2),
                [8; 32],
            )
            .is_err()
    );
    let reader_cap = member_cap
        .delegate(
            &member,
            reader.author(),
            permissions(&[Permission::Read]),
            PermissionSet::empty(),
            1,
            Some(2),
            [9; 32],
        )
        .unwrap();
    reader_cap.validate_delegation(&member_cap).unwrap();
    assert_eq!(reader_cap.depth(), 2);
}

#[test]
fn tampering_wrong_issuer_and_unknown_permission_bits_fail_closed() {
    let owner = IrohSigner::from_secret_bytes([11; 32]);
    let impostor = IrohSigner::from_secret_bytes([12; 32]);
    let root = CapabilityCertificate::issue_root(
        DomainId::from_bytes([13; 32]),
        PermissionSet::all(),
        &owner,
        [14; 32],
    )
    .unwrap();
    let mut encoded = root.encode_canonical().unwrap();
    let last = encoded.len() - 1;
    encoded[last] ^= 1;
    assert!(CapabilityCertificate::decode_canonical(&encoded).is_err());
    assert!(
        root.delegate(
            &impostor,
            AuthorId::from_bytes([15; 32]),
            permissions(&[Permission::Read]),
            PermissionSet::empty(),
            0,
            None,
            [16; 32],
        )
        .is_err()
    );
    assert!(PermissionSet::from_bits(1 << 15).is_err());
}

#[test]
fn control_transition_is_canonical_signed_bounded_and_tamper_evident() {
    let owner = IrohSigner::from_secret_bytes([21; 32]);
    let domain = DomainId::from_bytes([22; 32]);
    let root =
        CapabilityCertificate::issue_root(domain, PermissionSet::all(), &owner, [23; 32]).unwrap();
    let transition = ControlTransition::issue(
        domain,
        1,
        None,
        0,
        vec![CommitId::from_bytes([1; 32]), CommitId::from_bytes([2; 32])],
        vec![AuthorId::from_bytes([3; 32])],
        owner.author(),
        [24; 32],
        root.id().unwrap(),
        [25; 32],
        &owner,
    )
    .unwrap();
    let encoded = transition.encode_canonical().unwrap();
    assert_eq!(
        ControlTransition::decode_canonical(&encoded).unwrap(),
        transition
    );
    transition.verify().unwrap();
    let mut tampered = encoded;
    *tampered.last_mut().unwrap() ^= 1;
    assert!(ControlTransition::decode_canonical(&tampered).is_err());
}
