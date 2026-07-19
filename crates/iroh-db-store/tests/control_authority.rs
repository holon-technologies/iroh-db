use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

use iroh_db_core::{AuthorId, BlobHash, DomainId};
use iroh_db_security::{
    CapabilityCertificate, ConsistencyMode, ControlTransition, DomainDescriptor, DomainSeed,
    Invitation, IrohSigner, Permission, PermissionSet,
};
use iroh_db_store::{BlobStore, BlobStoreError, Store, StoreError};
use redb::TableDefinition;

#[derive(Default)]
struct MemoryBlobs(Mutex<BTreeMap<BlobHash, Vec<u8>>>);

impl BlobStore for MemoryBlobs {
    fn put<'a>(
        &'a self,
        bytes: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<BlobHash, BlobStoreError>> + Send + 'a>> {
        Box::pin(async move {
            let hash = BlobHash::from_bytes(*blake3::hash(&bytes).as_bytes());
            self.0.lock().unwrap().insert(hash, bytes);
            Ok(hash)
        })
    }

    fn get<'a>(
        &'a self,
        hash: BlobHash,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, BlobStoreError>> + Send + 'a>> {
        Box::pin(async move { Ok(self.0.lock().unwrap().get(&hash).cloned()) })
    }

    fn list<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<BlobHash>, BlobStoreError>> + Send + 'a>> {
        Box::pin(async move { Ok(self.0.lock().unwrap().keys().copied().collect()) })
    }
}

struct AuthorityFixture {
    owner: IrohSigner,
    delegate: IrohSigner,
    domain: DomainId,
    descriptor: DomainDescriptor,
    root: CapabilityCertificate,
    delegate_capability: CapabilityCertificate,
}

impl AuthorityFixture {
    fn new() -> Self {
        let owner = IrohSigner::from_secret_bytes([41; 32]);
        let delegate = IrohSigner::from_secret_bytes([42; 32]);
        let domain = DomainId::from_bytes([43; 32]);
        let descriptor =
            DomainDescriptor::issue(domain, ConsistencyMode::MultiWriter, &owner, [44; 32])
                .unwrap();
        let root =
            CapabilityCertificate::issue_root(domain, PermissionSet::all(), &owner, [45; 32])
                .unwrap();
        let delegate_capability = root
            .delegate(
                &owner,
                delegate.author(),
                PermissionSet::from_permissions(&[
                    Permission::Read,
                    Permission::Revoke,
                    Permission::Admin,
                ]),
                PermissionSet::empty(),
                0,
                None,
                [46; 32],
            )
            .unwrap();
        Self {
            owner,
            delegate,
            domain,
            descriptor,
            root,
            delegate_capability,
        }
    }

    fn bootstrap(&self, directory: &std::path::Path) -> Store {
        let store = Store::open(directory, Arc::new(MemoryBlobs::default())).unwrap();
        store
            .bootstrap_domain(&self.descriptor, &self.root)
            .unwrap();
        store.install_capability(&self.delegate_capability).unwrap();
        store
    }

    #[allow(clippy::too_many_arguments)]
    fn control(
        &self,
        signer: &IrohSigner,
        capability: &CapabilityCertificate,
        sequence: u64,
        predecessor: Option<[u8; 32]>,
        previous_epoch: u64,
        controller: AuthorId,
        nonce: u8,
    ) -> ControlTransition {
        let controller_capability = if controller == self.delegate.author() {
            self.delegate_capability.id().unwrap()
        } else {
            self.root.id().unwrap()
        };
        ControlTransition::issue(
            self.domain,
            sequence,
            predecessor,
            previous_epoch,
            Vec::new(),
            Vec::new(),
            self.owner.author(),
            controller,
            controller_capability,
            [nonce; 32],
            capability.id().unwrap(),
            [nonce.wrapping_add(1); 32],
            signer,
        )
        .unwrap()
    }
}

#[test]
fn successor_capability_and_control_advance_atomically() {
    let fixture = AuthorityFixture::new();
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path(), Arc::new(MemoryBlobs::default())).unwrap();
    store
        .bootstrap_domain(&fixture.descriptor, &fixture.root)
        .unwrap();
    let transfer = fixture.control(
        &fixture.owner,
        &fixture.root,
        1,
        None,
        0,
        fixture.delegate.author(),
        47,
    );

    store
        .apply_control_bundle(
            &transfer,
            &[fixture.root.clone(), fixture.delegate_capability.clone()],
        )
        .unwrap();

    assert_eq!(store.control_head(fixture.domain).unwrap(), Some(transfer));
    assert_eq!(
        store
            .active_capability(fixture.domain, fixture.delegate.author())
            .unwrap(),
        Some(fixture.delegate_capability.id().unwrap())
    );
}

#[test]
fn control_cannot_revoke_a_successor_capability_ancestor() {
    let fixture = AuthorityFixture::new();
    let directory = tempfile::tempdir().unwrap();
    let store = fixture.bootstrap(directory.path());
    let invalid = ControlTransition::issue(
        fixture.domain,
        1,
        None,
        0,
        Vec::new(),
        vec![fixture.owner.author()],
        fixture.owner.author(),
        fixture.delegate.author(),
        fixture.delegate_capability.id().unwrap(),
        [105; 32],
        fixture.root.id().unwrap(),
        [106; 32],
        &fixture.owner,
    )
    .unwrap();
    assert!(matches!(
        store.observe_control(&invalid),
        Err(StoreError::InvalidAuthority(_))
    ));
    assert!(store.control_head(fixture.domain).unwrap().is_none());

    let corrected = ControlTransition::issue(
        fixture.domain,
        1,
        None,
        0,
        Vec::new(),
        Vec::new(),
        fixture.owner.author(),
        fixture.delegate.author(),
        fixture.delegate_capability.id().unwrap(),
        [107; 32],
        fixture.root.id().unwrap(),
        [108; 32],
        &fixture.owner,
    )
    .unwrap();
    store.apply_control(&corrected).unwrap();
    assert_eq!(store.control_head(fixture.domain).unwrap(), Some(corrected));
}

#[test]
fn rejected_control_bundle_leaves_capability_and_head_unchanged() {
    let fixture = AuthorityFixture::new();
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path(), Arc::new(MemoryBlobs::default())).unwrap();
    store
        .bootstrap_domain(&fixture.descriptor, &fixture.root)
        .unwrap();
    let invalid = fixture.control(
        &fixture.owner,
        &fixture.root,
        1,
        None,
        1,
        fixture.delegate.author(),
        48,
    );

    assert!(matches!(
        store.apply_control_bundle(
            &invalid,
            &[fixture.root.clone(), fixture.delegate_capability.clone()],
        ),
        Err(StoreError::InvalidAuthority(_))
    ));
    assert!(store.control_head(fixture.domain).unwrap().is_none());
    assert!(
        store
            .capability(fixture.delegate_capability.id().unwrap())
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .active_capability(fixture.domain, fixture.delegate.author())
            .unwrap()
            .is_none()
    );
}

#[test]
fn invitation_authority_import_is_atomic_and_activates_only_root_and_leaf() {
    let fixture = AuthorityFixture::new();
    let invalid_directory = tempfile::tempdir().unwrap();
    let invalid_store =
        Store::open(invalid_directory.path(), Arc::new(MemoryBlobs::default())).unwrap();
    let sibling_signer = IrohSigner::from_secret_bytes([47; 32]);
    let sibling = fixture
        .root
        .delegate(
            &fixture.owner,
            sibling_signer.author(),
            PermissionSet::from_permissions(&[Permission::Read]),
            PermissionSet::empty(),
            0,
            None,
            [48; 32],
        )
        .unwrap();
    assert!(matches!(
        invalid_store.import_domain_authority_atomic(
            &fixture.descriptor,
            &[
                fixture.root.clone(),
                fixture.delegate_capability.clone(),
                sibling,
            ],
        ),
        Err(StoreError::InvalidAuthority(_))
    ));
    assert!(
        invalid_store
            .domain_descriptor(fixture.domain)
            .unwrap()
            .is_none()
    );
    assert!(
        invalid_store
            .capability(fixture.root.id().unwrap())
            .unwrap()
            .is_none()
    );

    let valid_directory = tempfile::tempdir().unwrap();
    let valid_store =
        Store::open(valid_directory.path(), Arc::new(MemoryBlobs::default())).unwrap();
    valid_store
        .import_domain_authority_atomic(
            &fixture.descriptor,
            &[fixture.root.clone(), fixture.delegate_capability.clone()],
        )
        .unwrap();
    assert_eq!(
        valid_store
            .active_capability(fixture.domain, fixture.delegate.author())
            .unwrap(),
        Some(fixture.delegate_capability.id().unwrap())
    );
    assert_eq!(
        valid_store
            .active_capability(fixture.domain, fixture.owner.author())
            .unwrap(),
        Some(fixture.root.id().unwrap())
    );
    assert!(
        valid_store
            .is_author_trusted(fixture.domain, fixture.owner.author())
            .unwrap()
    );
    assert!(
        valid_store
            .is_author_trusted(fixture.domain, fixture.delegate.author())
            .unwrap()
    );
}

#[test]
fn revoking_an_issuer_invalidates_its_active_descendants() {
    let fixture = AuthorityFixture::new();
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path(), Arc::new(MemoryBlobs::default())).unwrap();
    store
        .bootstrap_domain(&fixture.descriptor, &fixture.root)
        .unwrap();
    let issuer = IrohSigner::from_secret_bytes([91; 32]);
    let child = IrohSigner::from_secret_bytes([92; 32]);
    let issuer_capability = fixture
        .root
        .delegate(
            &fixture.owner,
            issuer.author(),
            PermissionSet::from_permissions(&[
                Permission::Read,
                Permission::Write,
                Permission::Invite,
            ]),
            PermissionSet::from_permissions(&[Permission::Read, Permission::Write]),
            0,
            None,
            [93; 32],
        )
        .unwrap();
    let child_capability = issuer_capability
        .delegate(
            &issuer,
            child.author(),
            PermissionSet::from_permissions(&[Permission::Read, Permission::Write]),
            PermissionSet::empty(),
            0,
            None,
            [94; 32],
        )
        .unwrap();
    store.install_capability(&issuer_capability).unwrap();
    store.install_capability(&child_capability).unwrap();
    assert!(
        store
            .authorize_capability(
                fixture.domain,
                child.author(),
                child_capability.id().unwrap(),
                Permission::Write,
                0,
            )
            .unwrap()
    );
    let revocation = ControlTransition::issue(
        fixture.domain,
        1,
        None,
        0,
        Vec::new(),
        vec![issuer.author()],
        fixture.owner.author(),
        fixture.owner.author(),
        fixture.root.id().unwrap(),
        [95; 32],
        fixture.root.id().unwrap(),
        [96; 32],
        &fixture.owner,
    )
    .unwrap();
    store.apply_control(&revocation).unwrap();

    assert!(
        !store
            .authorize_capability(
                fixture.domain,
                child.author(),
                child_capability.id().unwrap(),
                Permission::Write,
                1,
            )
            .unwrap()
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn subject_revocation_blocks_historical_replay_but_allows_fresh_anchor() {
    let fixture = AuthorityFixture::new();
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path(), Arc::new(MemoryBlobs::default())).unwrap();
    store
        .bootstrap_domain(&fixture.descriptor, &fixture.root)
        .unwrap();
    let subject = IrohSigner::from_secret_bytes([97; 32]);
    let historical_child = IrohSigner::from_secret_bytes([111; 32]);
    let permissions = PermissionSet::from_permissions(&[Permission::Read, Permission::Write]);
    let historical = fixture
        .root
        .delegate(
            &fixture.owner,
            subject.author(),
            permissions,
            PermissionSet::from_permissions(&[Permission::Read]),
            0,
            None,
            [98; 32],
        )
        .unwrap();
    let historical_descendant = historical
        .delegate(
            &subject,
            historical_child.author(),
            PermissionSet::from_permissions(&[Permission::Read]),
            PermissionSet::empty(),
            0,
            None,
            [112; 32],
        )
        .unwrap();
    let selected = fixture
        .root
        .delegate(
            &fixture.owner,
            subject.author(),
            permissions,
            PermissionSet::empty(),
            0,
            None,
            [99; 32],
        )
        .unwrap();
    let preissued_future = fixture
        .root
        .delegate_at_control(
            &fixture.owner,
            subject.author(),
            permissions,
            PermissionSet::empty(),
            1,
            Some([104; 32]),
            1,
            None,
            [105; 32],
        )
        .unwrap();
    store.install_capability(&selected).unwrap();
    assert!(
        store
            .install_capability_chain_atomic(&[fixture.root.clone(), historical.clone()])
            .is_err()
    );
    assert_eq!(
        store
            .active_capability(fixture.domain, subject.author())
            .unwrap(),
        Some(selected.id().unwrap())
    );
    store
        .install_capability_chain_atomic(&[
            fixture.root.clone(),
            historical.clone(),
            historical_descendant,
        ])
        .unwrap();
    let revocation = ControlTransition::issue(
        fixture.domain,
        1,
        None,
        0,
        Vec::new(),
        vec![subject.author()],
        fixture.owner.author(),
        fixture.owner.author(),
        fixture.root.id().unwrap(),
        [100; 32],
        fixture.root.id().unwrap(),
        [101; 32],
        &fixture.owner,
    )
    .unwrap();
    store.apply_control(&revocation).unwrap();

    assert!(
        store
            .install_capability_chain_atomic(&[fixture.root.clone(), historical])
            .is_err()
    );
    assert!(
        store
            .install_capability_chain_atomic(&[fixture.root.clone(), preissued_future])
            .is_err()
    );
    let fresh = fixture
        .root
        .delegate_at_control(
            &fixture.owner,
            subject.author(),
            permissions,
            PermissionSet::empty(),
            1,
            Some(revocation.id().unwrap()),
            1,
            None,
            [102; 32],
        )
        .unwrap();
    store
        .install_capability_chain_atomic(&[fixture.root.clone(), fresh.clone()])
        .unwrap();
    assert!(
        store
            .authorize_capability(
                fixture.domain,
                subject.author(),
                fresh.id().unwrap(),
                Permission::Write,
                1,
            )
            .unwrap()
    );
    let future = fixture
        .root
        .delegate_at_control(
            &fixture.owner,
            subject.author(),
            permissions,
            PermissionSet::empty(),
            2,
            Some([109; 32]),
            1,
            None,
            [110; 32],
        )
        .unwrap();
    assert!(
        store
            .install_capability_chain_atomic(&[fixture.root.clone(), future])
            .is_err()
    );
    assert_eq!(
        store
            .active_capability(fixture.domain, subject.author())
            .unwrap(),
        Some(fresh.id().unwrap())
    );
}

#[test]
fn corrupt_subject_revocation_index_fails_closed_and_repairs_from_control() {
    const SUBJECT_REVOCATIONS: TableDefinition<'static, &[u8], u64> =
        TableDefinition::new("subject_revocations_v1");
    let fixture = AuthorityFixture::new();
    let directory = tempfile::tempdir().unwrap();
    let store = fixture.bootstrap(directory.path());
    let historical = fixture
        .root
        .delegate(
            &fixture.owner,
            fixture.delegate.author(),
            PermissionSet::from_permissions(&[Permission::Read]),
            PermissionSet::empty(),
            0,
            None,
            [106; 32],
        )
        .unwrap();
    let revocation = ControlTransition::issue(
        fixture.domain,
        1,
        None,
        0,
        Vec::new(),
        vec![fixture.delegate.author()],
        fixture.owner.author(),
        fixture.owner.author(),
        fixture.root.id().unwrap(),
        [104; 32],
        fixture.root.id().unwrap(),
        [105; 32],
        &fixture.owner,
    )
    .unwrap();
    store.apply_control(&revocation).unwrap();
    assert!(
        store
            .subject_revocations_consistent(fixture.domain)
            .unwrap()
    );
    drop(store);

    let database = redb::Database::create(directory.path().join("meta.redb")).unwrap();
    let write = database.begin_write().unwrap();
    {
        let mut table = write.open_table(SUBJECT_REVOCATIONS).unwrap();
        let mut key = [0_u8; 64];
        key[..32].copy_from_slice(fixture.domain.as_bytes());
        key[32..].copy_from_slice(fixture.delegate.author().as_bytes());
        table.remove(key.as_slice()).unwrap();
    }
    write.commit().unwrap();
    drop(database);

    let reopened = Store::open(directory.path(), Arc::new(MemoryBlobs::default())).unwrap();
    assert!(
        !reopened
            .subject_revocations_consistent(fixture.domain)
            .unwrap()
    );
    assert!(matches!(
        reopened.install_capability_chain_atomic(&[fixture.root.clone(), historical]),
        Err(StoreError::CorruptDerivedMetadata(_))
    ));
    reopened.repair_subject_revocations(fixture.domain).unwrap();
    assert!(
        reopened
            .subject_revocations_consistent(fixture.domain)
            .unwrap()
    );
    assert!(
        !reopened
            .authorize_capability(
                fixture.domain,
                fixture.delegate.author(),
                fixture.delegate_capability.id().unwrap(),
                Permission::Read,
                1,
            )
            .unwrap()
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn only_designated_controller_can_advance_and_transfer_control() {
    let fixture = AuthorityFixture::new();
    let directory = tempfile::tempdir().unwrap();
    let store = fixture.bootstrap(directory.path());
    assert_eq!(
        store.current_controller(fixture.domain).unwrap(),
        fixture.owner.author()
    );

    let unauthorized = fixture.control(
        &fixture.delegate,
        &fixture.delegate_capability,
        1,
        None,
        0,
        fixture.delegate.author(),
        50,
    );
    assert!(matches!(
        store.apply_control(&unauthorized),
        Err(StoreError::InvalidAuthority(_))
    ));
    assert!(store.control_head(fixture.domain).unwrap().is_none());

    let missing_successor = fixture.control(
        &fixture.owner,
        &fixture.root,
        1,
        None,
        0,
        AuthorId::from_bytes([99; 32]),
        49,
    );
    assert!(matches!(
        store.apply_control(&missing_successor),
        Err(StoreError::InvalidAuthority(_))
    ));
    assert!(store.control_head(fixture.domain).unwrap().is_none());

    let expiring = IrohSigner::from_secret_bytes([48; 32]);
    let expiring_capability = fixture
        .root
        .delegate(
            &fixture.owner,
            expiring.author(),
            PermissionSet::from_permissions(&[Permission::Admin]),
            PermissionSet::empty(),
            0,
            Some(0),
            [49; 32],
        )
        .unwrap();
    store.install_capability(&expiring_capability).unwrap();
    let stranded_transfer = fixture.control(
        &fixture.owner,
        &fixture.root,
        1,
        None,
        0,
        expiring.author(),
        48,
    );
    assert!(matches!(
        store.apply_control(&stranded_transfer),
        Err(StoreError::InvalidAuthority(_))
    ));
    assert!(store.control_head(fixture.domain).unwrap().is_none());

    let transfer = fixture.control(
        &fixture.owner,
        &fixture.root,
        1,
        None,
        0,
        fixture.delegate.author(),
        51,
    );
    store.apply_control(&transfer).unwrap();
    assert_eq!(
        store.current_controller(fixture.domain).unwrap(),
        fixture.delegate.author()
    );

    let predecessor = Some(transfer.id().unwrap());
    let former_controller = fixture.control(
        &fixture.owner,
        &fixture.root,
        2,
        predecessor,
        1,
        fixture.delegate.author(),
        52,
    );
    assert!(matches!(
        store.apply_control(&former_controller),
        Err(StoreError::InvalidAuthority(_))
    ));
    let next = fixture.control(
        &fixture.delegate,
        &fixture.delegate_capability,
        2,
        predecessor,
        1,
        fixture.delegate.author(),
        53,
    );
    store.apply_control(&next).unwrap();
    assert_eq!(store.current_epoch(fixture.domain).unwrap(), 2);
    assert_eq!(
        store.accepted_control_chain(fixture.domain).unwrap(),
        vec![transfer, next]
    );
}

#[test]
fn controller_equivocation_freezes_both_receipt_orders_durably() {
    let fixture = AuthorityFixture::new();
    let first_dir = tempfile::tempdir().unwrap();
    let second_dir = tempfile::tempdir().unwrap();
    let first_store = fixture.bootstrap(first_dir.path());
    let second_store = fixture.bootstrap(second_dir.path());
    let left = fixture.control(
        &fixture.owner,
        &fixture.root,
        1,
        None,
        0,
        fixture.owner.author(),
        60,
    );
    let right = fixture.control(
        &fixture.owner,
        &fixture.root,
        1,
        None,
        0,
        fixture.owner.author(),
        61,
    );

    first_store.apply_control(&left).unwrap();
    second_store.apply_control(&right).unwrap();
    assert!(matches!(
        first_store.apply_control(&right),
        Err(StoreError::ControlFork { .. })
    ));
    assert!(matches!(
        second_store.apply_control(&left),
        Err(StoreError::ControlFork { .. })
    ));
    assert!(matches!(
        first_store.current_epoch(fixture.domain),
        Err(StoreError::ControlFork { .. })
    ));
    assert!(matches!(
        second_store.current_epoch(fixture.domain),
        Err(StoreError::ControlFork { .. })
    ));
    assert!(matches!(
        first_store.control_head(fixture.domain),
        Err(StoreError::ControlFork { .. })
    ));
    assert!(matches!(
        first_store.authorize_capability(
            fixture.domain,
            fixture.owner.author(),
            fixture.root.id().unwrap(),
            Permission::Admin,
            1,
        ),
        Err(StoreError::ControlFork { .. })
    ));

    drop(first_store);
    let reopened = Store::open(first_dir.path(), Arc::new(MemoryBlobs::default())).unwrap();
    assert!(matches!(
        reopened.current_epoch(fixture.domain),
        Err(StoreError::ControlFork { .. })
    ));
}

#[test]
fn checkpoint_head_equivocation_freezes_without_retained_predecessor() {
    let fixture = AuthorityFixture::new();
    let member = IrohSigner::from_secret_bytes([121; 32]);
    let seed = DomainSeed::from_epoch_key(fixture.domain, 2, [122; 32]);
    let head = ControlTransition::issue(
        fixture.domain,
        2,
        Some([123; 32]),
        1,
        Vec::new(),
        Vec::new(),
        fixture.owner.author(),
        fixture.owner.author(),
        fixture.root.id().unwrap(),
        seed.distribution_digest(),
        fixture.root.id().unwrap(),
        [124; 32],
        &fixture.owner,
    )
    .unwrap();
    let leaf = fixture
        .root
        .delegate_at_control(
            &fixture.owner,
            member.author(),
            PermissionSet::from_permissions(&[Permission::Read]),
            PermissionSet::empty(),
            2,
            Some(head.id().unwrap()),
            2,
            None,
            [125; 32],
        )
        .unwrap();
    let invitation = Invitation::issue_at_checkpoint(
        fixture.descriptor.clone(),
        vec![fixture.root.clone(), leaf],
        vec![fixture.root.clone()],
        seed,
        Some(head.clone()),
        Vec::new(),
        fixture.root.id().unwrap(),
        member.author(),
        &fixture.owner,
    )
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path(), Arc::new(MemoryBlobs::default())).unwrap();
    store
        .import_authority_checkpoint_atomic(&invitation)
        .unwrap();
    let conflicting = ControlTransition::issue(
        fixture.domain,
        2,
        Some([123; 32]),
        1,
        Vec::new(),
        Vec::new(),
        fixture.owner.author(),
        fixture.owner.author(),
        fixture.root.id().unwrap(),
        [126; 32],
        fixture.root.id().unwrap(),
        [127; 32],
        &fixture.owner,
    )
    .unwrap();

    assert!(matches!(
        store.observe_control(&conflicting),
        Err(StoreError::ControlFork { .. })
    ));
    assert!(matches!(
        store.current_epoch(fixture.domain),
        Err(StoreError::ControlFork { .. })
    ));
    drop(store);
    let reopened = Store::open(directory.path(), Arc::new(MemoryBlobs::default())).unwrap();
    assert!(matches!(
        reopened.current_epoch(fixture.domain),
        Err(StoreError::ControlFork { .. })
    ));
}

#[test]
fn checkpoint_rejects_omitted_sequence_zero_capability_replay() {
    let fixture = AuthorityFixture::new();
    let member = IrohSigner::from_secret_bytes([131; 32]);
    let omitted = IrohSigner::from_secret_bytes([132; 32]);
    let seed = DomainSeed::from_epoch_key(fixture.domain, 2, [133; 32]);
    let head = ControlTransition::issue(
        fixture.domain,
        2,
        Some([134; 32]),
        1,
        Vec::new(),
        Vec::new(),
        fixture.owner.author(),
        fixture.owner.author(),
        fixture.root.id().unwrap(),
        seed.distribution_digest(),
        fixture.root.id().unwrap(),
        [135; 32],
        &fixture.owner,
    )
    .unwrap();
    let leaf = fixture
        .root
        .delegate_at_control(
            &fixture.owner,
            member.author(),
            PermissionSet::from_permissions(&[Permission::Read]),
            PermissionSet::empty(),
            2,
            Some(head.id().unwrap()),
            2,
            None,
            [136; 32],
        )
        .unwrap();
    let invitation = Invitation::issue_at_checkpoint(
        fixture.descriptor.clone(),
        vec![fixture.root.clone(), leaf],
        vec![fixture.root.clone()],
        seed,
        Some(head),
        Vec::new(),
        fixture.root.id().unwrap(),
        member.author(),
        &fixture.owner,
    )
    .unwrap();
    let omitted_capability = fixture
        .root
        .delegate(
            &fixture.owner,
            omitted.author(),
            PermissionSet::from_permissions(&[Permission::Read]),
            PermissionSet::empty(),
            0,
            None,
            [137; 32],
        )
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path(), Arc::new(MemoryBlobs::default())).unwrap();
    store
        .import_authority_checkpoint_atomic(&invitation)
        .unwrap();

    assert!(
        store
            .install_capability_chain_atomic(&[fixture.root.clone(), omitted_capability])
            .is_err()
    );
}

#[test]
fn post_checkpoint_control_can_nominate_omitted_historical_admin() {
    let fixture = AuthorityFixture::new();
    let member = IrohSigner::from_secret_bytes([141; 32]);
    let seed = DomainSeed::from_epoch_key(fixture.domain, 2, [142; 32]);
    let head = ControlTransition::issue(
        fixture.domain,
        2,
        Some([143; 32]),
        1,
        Vec::new(),
        Vec::new(),
        fixture.owner.author(),
        fixture.owner.author(),
        fixture.root.id().unwrap(),
        seed.distribution_digest(),
        fixture.root.id().unwrap(),
        [144; 32],
        &fixture.owner,
    )
    .unwrap();
    let leaf = fixture
        .root
        .delegate_at_control(
            &fixture.owner,
            member.author(),
            PermissionSet::from_permissions(&[Permission::Read]),
            PermissionSet::empty(),
            2,
            Some(head.id().unwrap()),
            2,
            None,
            [145; 32],
        )
        .unwrap();
    let invitation = Invitation::issue_at_checkpoint(
        fixture.descriptor.clone(),
        vec![fixture.root.clone(), leaf],
        vec![fixture.root.clone()],
        seed,
        Some(head.clone()),
        Vec::new(),
        fixture.root.id().unwrap(),
        member.author(),
        &fixture.owner,
    )
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path(), Arc::new(MemoryBlobs::default())).unwrap();
    store
        .import_authority_checkpoint_atomic(&invitation)
        .unwrap();
    let transfer = ControlTransition::issue(
        fixture.domain,
        3,
        Some(head.id().unwrap()),
        2,
        Vec::new(),
        Vec::new(),
        fixture.owner.author(),
        fixture.delegate.author(),
        fixture.delegate_capability.id().unwrap(),
        [146; 32],
        fixture.root.id().unwrap(),
        [147; 32],
        &fixture.owner,
    )
    .unwrap();

    store
        .apply_control_bundle(
            &transfer,
            &[fixture.root.clone(), fixture.delegate_capability.clone()],
        )
        .unwrap();
    assert_eq!(
        store.current_controller(fixture.domain).unwrap(),
        fixture.delegate.author()
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn checkpoint_preserves_newer_active_owner_leaf_instead_of_reactivating_root() {
    let fixture = AuthorityFixture::new();
    let source_dir = tempfile::tempdir().unwrap();
    let source = fixture.bootstrap(source_dir.path());
    let first = fixture.control(
        &fixture.owner,
        &fixture.root,
        1,
        None,
        0,
        fixture.delegate.author(),
        151,
    );
    source.apply_control(&first).unwrap();
    let seed = DomainSeed::from_epoch_key(fixture.domain, 2, [152; 32]);
    let second = ControlTransition::issue(
        fixture.domain,
        2,
        Some(first.id().unwrap()),
        1,
        Vec::new(),
        Vec::new(),
        fixture.owner.author(),
        fixture.delegate.author(),
        fixture.delegate_capability.id().unwrap(),
        seed.distribution_digest(),
        fixture.delegate_capability.id().unwrap(),
        [153; 32],
        &fixture.delegate,
    )
    .unwrap();
    source.apply_control(&second).unwrap();
    let refreshed_owner = fixture
        .root
        .delegate_at_control(
            &fixture.owner,
            fixture.owner.author(),
            PermissionSet::all(),
            PermissionSet::all(),
            2,
            Some(second.id().unwrap()),
            2,
            None,
            [154; 32],
        )
        .unwrap();
    source.install_capability(&refreshed_owner).unwrap();
    let target = IrohSigner::from_secret_bytes([155; 32]);
    let target_capability = refreshed_owner
        .delegate(
            &fixture.owner,
            target.author(),
            PermissionSet::from_permissions(&[Permission::Read]),
            PermissionSet::empty(),
            2,
            None,
            [156; 32],
        )
        .unwrap();
    source.install_capability(&target_capability).unwrap();
    let target_chain = source
        .capability_chain(target_capability.id().unwrap())
        .unwrap();
    let controller_chain = source
        .capability_chain(fixture.delegate_capability.id().unwrap())
        .unwrap();
    let active_chains = source
        .active_capabilities(fixture.domain)
        .unwrap()
        .into_iter()
        .map(|id| source.capability_chain(id).unwrap())
        .collect::<Vec<_>>();

    let invitation = Invitation::issue_at_checkpoint_with_evidence(
        fixture.descriptor.clone(),
        target_chain,
        controller_chain,
        &active_chains,
        seed,
        Some(second),
        Vec::new(),
        refreshed_owner.id().unwrap(),
        target.author(),
        &fixture.owner,
    )
    .unwrap();
    let target_dir = tempfile::tempdir().unwrap();
    let imported = Store::open(target_dir.path(), Arc::new(MemoryBlobs::default())).unwrap();
    imported
        .import_authority_checkpoint_atomic(&invitation)
        .unwrap();

    assert_eq!(
        imported
            .active_capability(fixture.domain, fixture.owner.author())
            .unwrap(),
        Some(refreshed_owner.id().unwrap())
    );
    assert_ne!(
        imported
            .active_capability(fixture.domain, fixture.owner.author())
            .unwrap(),
        Some(fixture.root.id().unwrap())
    );
}

#[test]
fn sibling_detection_does_not_depend_on_first_arrival_revocations() {
    let fixture = AuthorityFixture::new();
    let first_dir = tempfile::tempdir().unwrap();
    let second_dir = tempfile::tempdir().unwrap();
    let first_store = fixture.bootstrap(first_dir.path());
    let second_store = fixture.bootstrap(second_dir.path());
    let revoking = ControlTransition::issue(
        fixture.domain,
        1,
        None,
        0,
        Vec::new(),
        vec![fixture.delegate.author()],
        fixture.owner.author(),
        fixture.owner.author(),
        fixture.root.id().unwrap(),
        [70; 32],
        fixture.root.id().unwrap(),
        [71; 32],
        &fixture.owner,
    )
    .unwrap();
    let transferring = fixture.control(
        &fixture.owner,
        &fixture.root,
        1,
        None,
        0,
        fixture.delegate.author(),
        72,
    );

    first_store.apply_control(&revoking).unwrap();
    second_store.apply_control(&transferring).unwrap();
    assert!(matches!(
        first_store.apply_control(&transferring),
        Err(StoreError::ControlFork { .. })
    ));
    assert!(matches!(
        second_store.apply_control(&revoking),
        Err(StoreError::ControlFork { .. })
    ));
}

#[test]
fn observed_siblings_freeze_before_either_is_applied() {
    let fixture = AuthorityFixture::new();
    let directory = tempfile::tempdir().unwrap();
    let store = fixture.bootstrap(directory.path());
    let left = fixture.control(
        &fixture.owner,
        &fixture.root,
        1,
        None,
        0,
        fixture.owner.author(),
        80,
    );
    let right = fixture.control(
        &fixture.owner,
        &fixture.root,
        1,
        None,
        0,
        fixture.owner.author(),
        81,
    );

    store.observe_control(&left).unwrap();
    assert!(matches!(
        store.observe_control(&right),
        Err(StoreError::ControlFork { .. })
    ));
    assert!(matches!(
        store.control_head(fixture.domain),
        Err(StoreError::ControlFork { .. })
    ));
    assert!(matches!(
        store.current_epoch(fixture.domain),
        Err(StoreError::ControlFork { .. })
    ));
}
