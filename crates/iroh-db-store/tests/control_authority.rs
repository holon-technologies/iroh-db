use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

use iroh_db_core::{AuthorId, BlobHash, DomainId};
use iroh_db_security::{
    CapabilityCertificate, ConsistencyMode, ControlTransition, DomainDescriptor, IrohSigner,
    Permission, PermissionSet,
};
use iroh_db_store::{BlobStore, BlobStoreError, Store, StoreError};

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
