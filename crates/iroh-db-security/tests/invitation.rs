use iroh_db_security::{
    CapabilityCertificate, ConsistencyMode, ControlTransition, DomainDescriptor, DomainSeed,
    Invitation, InvitationTicket, IrohSigner, Permission, PermissionSet,
};

#[test]
fn targeted_offline_ticket_round_trips_and_rejects_wrong_endpoint_or_secret() {
    let owner = IrohSigner::from_secret_bytes([21; 32]);
    let member = IrohSigner::from_secret_bytes([22; 32]);
    let stranger = IrohSigner::from_secret_bytes([23; 32]);
    let seed = DomainSeed::generate().unwrap();
    let descriptor = DomainDescriptor::issue(
        seed.domain_id(),
        ConsistencyMode::MultiWriter,
        &owner,
        [24; 32],
    )
    .unwrap();
    let root =
        CapabilityCertificate::issue_root(seed.domain_id(), PermissionSet::all(), &owner, [25; 32])
            .unwrap();
    let leaf = root
        .delegate(
            &owner,
            member.author(),
            PermissionSet::from_permissions(&[Permission::Read, Permission::Write]),
            PermissionSet::empty(),
            0,
            None,
            [26; 32],
        )
        .unwrap();
    let invitation =
        Invitation::issue(descriptor, vec![root, leaf], seed, member.author(), &owner).unwrap();
    let encoded = invitation.encode_canonical().unwrap();
    let decoded = Invitation::decode_canonical(&encoded).unwrap();
    assert_eq!(decoded.subject(), member.author());
    assert_eq!(format!("{decoded:?}"), "Invitation([redacted])");

    let (ticket, secret) = decoded.seal_offline().unwrap();
    let ticket = InvitationTicket::decode_canonical(&ticket.encode_canonical().unwrap()).unwrap();
    assert!(ticket.open(&secret, stranger.author()).is_err());
    let opened = ticket.open(&secret, member.author()).unwrap();
    assert_eq!(
        opened.domain_seed().domain_id(),
        opened.descriptor().domain_id()
    );
    assert_eq!(opened.capability_chain().len(), 2);

    let (_, wrong_secret) = opened.seal_offline().unwrap();
    assert!(ticket.open(&wrong_secret, member.author()).is_err());
    assert_eq!(format!("{secret:?}"), "InvitationSecret([redacted])");
}

#[test]
fn modified_online_invitation_fails_before_key_import() {
    let owner = IrohSigner::from_secret_bytes([31; 32]);
    let seed = DomainSeed::generate().unwrap();
    let descriptor = DomainDescriptor::issue(
        seed.domain_id(),
        ConsistencyMode::MultiWriter,
        &owner,
        [32; 32],
    )
    .unwrap();
    let root =
        CapabilityCertificate::issue_root(seed.domain_id(), PermissionSet::all(), &owner, [33; 32])
            .unwrap();
    let invitation =
        Invitation::issue(descriptor, vec![root], seed, owner.author(), &owner).unwrap();
    let mut encoded = invitation.encode_canonical().unwrap();
    let last = encoded.len() - 1;
    encoded[last] ^= 1;
    assert!(Invitation::decode_canonical(&encoded).is_err());
}

#[test]
fn rotated_invitation_rejects_epoch_key_not_bound_to_control() {
    let owner = IrohSigner::from_secret_bytes([41; 32]);
    let member = IrohSigner::from_secret_bytes([42; 32]);
    let initial_seed = DomainSeed::generate().unwrap();
    let invited_seed = initial_seed.next_epoch().unwrap();
    let descriptor = DomainDescriptor::issue(
        initial_seed.domain_id(),
        ConsistencyMode::MultiWriter,
        &owner,
        [43; 32],
    )
    .unwrap();
    let root = CapabilityCertificate::issue_root(
        initial_seed.domain_id(),
        PermissionSet::all(),
        &owner,
        [44; 32],
    )
    .unwrap();
    let control = ControlTransition::issue(
        initial_seed.domain_id(),
        1,
        None,
        0,
        Vec::new(),
        Vec::new(),
        owner.author(),
        owner.author(),
        root.id().unwrap(),
        [45; 32],
        root.id().unwrap(),
        [46; 32],
        &owner,
    )
    .unwrap();
    assert_ne!(
        invited_seed.distribution_digest(),
        control.key_distribution_digest()
    );
    let leaf = root
        .delegate_at_control(
            &owner,
            member.author(),
            PermissionSet::from_permissions(&[Permission::Read]),
            PermissionSet::empty(),
            1,
            Some(control.id().unwrap()),
            1,
            None,
            [47; 32],
        )
        .unwrap();

    assert!(
        Invitation::issue_at_checkpoint(
            descriptor,
            vec![root.clone(), leaf],
            vec![root.clone()],
            invited_seed,
            Some(control),
            Vec::new(),
            root.id().unwrap(),
            member.author(),
            &owner,
        )
        .is_err()
    );
}
