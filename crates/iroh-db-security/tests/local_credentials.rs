use iroh_db_security::{LocalCredentials, SecurityError};

#[test]
fn encrypted_local_credentials_are_stable_and_tamper_evident() {
    let directory = tempfile::tempdir().unwrap();
    let first = LocalCredentials::load_or_create(directory.path()).unwrap();
    let reopened = LocalCredentials::load_or_create(directory.path()).unwrap();
    assert_eq!(first.domain_id(), reopened.domain_id());
    assert_eq!(first.signer().author(), reopened.signer().author());
    assert_eq!(format!("{first:?}"), "LocalCredentials([redacted])");

    let path = directory.path().join("credentials.v1");
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[40] ^= 1;
    std::fs::write(path, bytes).unwrap();
    assert_eq!(
        LocalCredentials::load_or_create(directory.path()).unwrap_err(),
        SecurityError::InvalidKeyProviderData
    );
}

#[cfg(unix)]
#[test]
fn local_credentials_reject_group_readable_master_keys() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir().unwrap();
    LocalCredentials::load_or_create(directory.path()).unwrap();
    let master = directory.path().join("master.key");
    std::fs::set_permissions(&master, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        LocalCredentials::load_or_create(directory.path()).unwrap_err(),
        SecurityError::InsecureKeyPermissions
    );
}
