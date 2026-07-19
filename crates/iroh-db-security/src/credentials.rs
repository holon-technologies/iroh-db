use std::{
    fs::OpenOptions,
    io::Write as _,
    path::{Path, PathBuf},
};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead as _, KeyInit as _, Payload},
};
use hkdf::Hkdf;
use iroh_db_core::DomainId;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{DomainKey, IrohSigner, SecurityError};

const MASTER_FILE: &str = "master.key";
const CREDENTIALS_FILE: &str = "credentials.v1";
const MAGIC: &[u8; 8] = b"IDBKEY01";
const DOMAIN_MAGIC: &[u8; 8] = b"IDBDOM01";
const PLAINTEXT_LEN: usize = 96;
const DOMAIN_PLAINTEXT_LEN: usize = 72;
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Sensitive bootstrap material for adding a new device to an encrypted domain.
#[derive(Clone)]
pub struct DomainSeed {
    domain_id: DomainId,
    epoch: u64,
    domain_key: DomainKey,
}

impl DomainSeed {
    /// Creates a fresh encrypted domain seed.
    pub fn generate() -> Result<Self, SecurityError> {
        let mut domain_id = [0_u8; 32];
        getrandom::fill(&mut domain_id).map_err(|_| SecurityError::RandomnessUnavailable)?;
        Ok(Self {
            domain_id: DomainId::from_bytes(domain_id),
            epoch: 0,
            domain_key: DomainKey::generate()?,
        })
    }

    /// Returns the stable domain identifier.
    pub const fn domain_id(&self) -> DomainId {
        self.domain_id
    }

    /// Returns the active encryption epoch represented by this seed.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the epoch-zero key for a trusted local key provider.
    pub fn domain_key(&self) -> DomainKey {
        self.domain_key.clone()
    }

    /// Exposes key bytes only to an authenticated epoch-distribution protocol.
    #[doc(hidden)]
    pub const fn epoch_key_bytes(&self) -> [u8; 32] {
        *self.domain_key.as_bytes()
    }

    /// Creates the next epoch for this stable domain using a fresh random key.
    pub fn next_epoch(&self) -> Result<Self, SecurityError> {
        Ok(Self {
            domain_id: self.domain_id,
            epoch: self
                .epoch
                .checked_add(1)
                .ok_or(SecurityError::InvalidKeyProviderData)?,
            domain_key: DomainKey::generate()?,
        })
    }

    /// Returns a non-secret commitment used to bind targeted key distribution to control.
    pub fn distribution_digest(&self) -> [u8; 32] {
        let mut input = Vec::with_capacity(72);
        input.extend_from_slice(self.domain_id.as_bytes());
        input.extend_from_slice(&self.epoch.to_be_bytes());
        input.extend_from_slice(self.domain_key.as_bytes());
        *blake3::hash(&input).as_bytes()
    }

    pub(crate) const fn from_parts(domain_id: DomainId, epoch: u64, domain_key: DomainKey) -> Self {
        Self {
            domain_id,
            epoch,
            domain_key,
        }
    }

    /// Reconstructs a digest-verified epoch grant received over authenticated transport.
    #[doc(hidden)]
    pub const fn from_epoch_key(domain_id: DomainId, epoch: u64, key: [u8; 32]) -> Self {
        Self::from_parts(domain_id, epoch, DomainKey::from_bytes(key))
    }
}

impl std::fmt::Debug for DomainSeed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DomainSeed([redacted])")
    }
}

/// Persistent private-domain identity and epoch-zero key material.
#[derive(Clone)]
pub struct LocalCredentials {
    signer: IrohSigner,
    domain_key: DomainKey,
    domain_id: DomainId,
    root: PathBuf,
}

impl LocalCredentials {
    /// Loads or creates an owner-only encrypted local key vault.
    pub fn load_or_create(root: impl AsRef<Path>) -> Result<Self, SecurityError> {
        let root = root.as_ref();
        std::fs::create_dir_all(root).map_err(io_error)?;
        let master_path = root.join(MASTER_FILE);
        let master = load_or_create_master(&master_path)?;
        let credentials_path = root.join(CREDENTIALS_FILE);
        if credentials_path.exists() {
            check_owner_only(&credentials_path)?;
            let bytes = std::fs::read(credentials_path).map_err(io_error)?;
            let mut credentials = decode_credentials(&bytes, &master)?;
            credentials.root = root.to_path_buf();
            Ok(credentials)
        } else {
            let credentials = Self::generate(root.to_path_buf())?;
            let bytes = encode_credentials(&credentials, &master)?;
            write_owner_only(&credentials_path, &bytes)?;
            Ok(credentials)
        }
    }

    /// Creates a new device identity in an existing trusted domain.
    pub fn create_for_domain(
        root: impl AsRef<Path>,
        seed: &DomainSeed,
    ) -> Result<Self, SecurityError> {
        let root = root.as_ref();
        std::fs::create_dir_all(root).map_err(io_error)?;
        let master = load_or_create_master(&root.join(MASTER_FILE))?;
        let credentials_path = root.join(CREDENTIALS_FILE);
        if credentials_path.exists() {
            return Err(SecurityError::InvalidKeyProviderData);
        }
        let credentials = Self {
            signer: IrohSigner::generate(),
            domain_key: seed.domain_key(),
            domain_id: seed.domain_id(),
            root: root.to_path_buf(),
        };
        write_owner_only(
            &credentials_path,
            &encode_credentials(&credentials, &master)?,
        )?;
        Ok(credentials)
    }

    /// Returns the iroh endpoint signer used by this database.
    pub fn signer(&self) -> IrohSigner {
        self.signer.clone()
    }

    /// Returns the epoch-zero private-domain key.
    pub fn domain_key(&self) -> DomainKey {
        self.domain_key.clone()
    }

    /// Returns the stable default private-domain ID.
    pub const fn domain_id(&self) -> DomainId {
        self.domain_id
    }

    /// Exports sensitive domain bootstrap material for a trusted invitation flow.
    pub fn domain_seed(&self) -> DomainSeed {
        DomainSeed {
            domain_id: self.domain_id,
            epoch: 0,
            domain_key: self.domain_key.clone(),
        }
    }

    /// Persists a domain seed in the owner-only encrypted device catalog.
    pub fn store_domain(&self, seed: &DomainSeed) -> Result<(), SecurityError> {
        let directory = self.root.join("domains");
        std::fs::create_dir_all(&directory).map_err(io_error)?;
        let path = directory.join(format!("{}.v1", seed.domain_id));
        if path.exists() {
            let existing = self.load_domain(seed.domain_id)?;
            if existing.epoch == seed.epoch
                && existing.domain_key.as_bytes() == seed.domain_key.as_bytes()
            {
                return Ok(());
            }
            return Err(SecurityError::InvalidKeyProviderData);
        }
        let master = load_or_create_master(&self.root.join(MASTER_FILE))?;
        let bytes = encode_domain_seed(seed, &master)?;
        store_epoch_archive(&directory, seed, &master)?;
        write_owner_only(&path, &bytes)
    }

    /// Atomically advances a catalog domain while retaining both epoch keys locally.
    pub fn replace_domain(&self, seed: &DomainSeed) -> Result<(), SecurityError> {
        let current = self.load_domain(seed.domain_id)?;
        if seed.epoch
            != current
                .epoch
                .checked_add(1)
                .ok_or(SecurityError::InvalidKeyProviderData)?
        {
            return Err(SecurityError::InvalidKeyProviderData);
        }
        let directory = self.root.join("domains");
        std::fs::create_dir_all(&directory).map_err(io_error)?;
        let master = load_or_create_master(&self.root.join(MASTER_FILE))?;
        store_epoch_archive(&directory, &current, &master)?;
        store_epoch_archive(&directory, seed, &master)?;
        let bytes = encode_domain_seed(seed, &master)?;
        write_owner_only_replace(&directory.join(format!("{}.v1", seed.domain_id)), &bytes)
    }

    /// Durably archives the next epoch key without changing the active catalog entry.
    #[doc(hidden)]
    pub fn stage_domain(&self, seed: &DomainSeed) -> Result<(), SecurityError> {
        let current = self.load_domain(seed.domain_id)?;
        if seed.epoch == current.epoch
            && seed.domain_key.as_bytes() == current.domain_key.as_bytes()
        {
            return Ok(());
        }
        if seed.epoch
            != current
                .epoch
                .checked_add(1)
                .ok_or(SecurityError::InvalidKeyProviderData)?
        {
            return Err(SecurityError::InvalidKeyProviderData);
        }
        let directory = self.root.join("domains");
        std::fs::create_dir_all(&directory).map_err(io_error)?;
        let master = load_or_create_master(&self.root.join(MASTER_FILE))?;
        store_epoch_archive(&directory, seed, &master)
    }

    /// Selects a retained epoch as active, including rotation rollback after metadata failure.
    #[doc(hidden)]
    pub fn activate_domain(&self, seed: &DomainSeed) -> Result<(), SecurityError> {
        let directory = self.root.join("domains");
        std::fs::create_dir_all(&directory).map_err(io_error)?;
        let master = load_or_create_master(&self.root.join(MASTER_FILE))?;
        store_epoch_archive(&directory, seed, &master)?;
        write_owner_only_replace(
            &directory.join(format!("{}.v1", seed.domain_id)),
            &encode_domain_seed(seed, &master)?,
        )
    }

    /// Loads one domain seed from the encrypted device catalog.
    pub fn load_domain(&self, domain_id: DomainId) -> Result<DomainSeed, SecurityError> {
        if domain_id == self.domain_id {
            let catalog = self.root.join("domains").join(format!("{domain_id}.v1"));
            if !catalog.exists() {
                return Ok(self.domain_seed());
            }
        }
        let path = self.root.join("domains").join(format!("{domain_id}.v1"));
        check_owner_only(&path)?;
        let master = load_or_create_master(&self.root.join(MASTER_FILE))?;
        let bytes = std::fs::read(path).map_err(io_error)?;
        let seed = decode_domain_seed(&bytes, &master)?;
        if seed.domain_id != domain_id {
            return Err(SecurityError::InvalidKeyProviderData);
        }
        Ok(seed)
    }

    /// Loads a retained historical epoch key without changing the active catalog entry.
    pub fn load_domain_epoch(
        &self,
        domain_id: DomainId,
        epoch: u64,
    ) -> Result<DomainSeed, SecurityError> {
        let current = self.load_domain(domain_id)?;
        if current.epoch == epoch {
            return Ok(current);
        }
        if domain_id == self.domain_id && epoch == 0 {
            return Ok(self.domain_seed());
        }
        let path = self
            .root
            .join("domains")
            .join(format!("{domain_id}.epoch-{epoch}.v1"));
        check_owner_only(&path)?;
        let master = load_or_create_master(&self.root.join(MASTER_FILE))?;
        let bytes = std::fs::read(path).map_err(io_error)?;
        let seed = decode_domain_seed(&bytes, &master)?;
        if seed.domain_id != domain_id || seed.epoch != epoch {
            return Err(SecurityError::InvalidKeyProviderData);
        }
        Ok(seed)
    }

    /// Lists every domain available to this device.
    pub fn domains(&self) -> Result<Vec<DomainId>, SecurityError> {
        let mut domains = vec![self.domain_id];
        let directory = self.root.join("domains");
        if directory.exists() {
            for entry in std::fs::read_dir(directory).map_err(io_error)? {
                let entry = entry.map_err(io_error)?;
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                let Some(id) = name.strip_suffix(".v1") else {
                    continue;
                };
                let Ok(id) = id.parse() else {
                    continue;
                };
                domains.push(id);
            }
        }
        domains.sort_unstable();
        domains.dedup();
        Ok(domains)
    }

    /// Returns the same secret identity used to authenticate the iroh endpoint.
    pub fn endpoint_secret_key(&self) -> iroh_base::SecretKey {
        iroh_base::SecretKey::from_bytes(&self.signer.secret_bytes())
    }

    fn generate(root: PathBuf) -> Result<Self, SecurityError> {
        let mut signer = [0_u8; 32];
        let mut domain_key = [0_u8; 32];
        let mut domain_id = [0_u8; 32];
        getrandom::fill(&mut signer).map_err(|_| SecurityError::RandomnessUnavailable)?;
        getrandom::fill(&mut domain_key).map_err(|_| SecurityError::RandomnessUnavailable)?;
        getrandom::fill(&mut domain_id).map_err(|_| SecurityError::RandomnessUnavailable)?;
        Ok(Self {
            signer: IrohSigner::from_secret_bytes(signer),
            domain_key: DomainKey::from_bytes(domain_key),
            domain_id: DomainId::from_bytes(domain_id),
            root,
        })
    }
}

impl std::fmt::Debug for LocalCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LocalCredentials([redacted])")
    }
}

fn load_or_create_master(path: &Path) -> Result<Zeroizing<[u8; 32]>, SecurityError> {
    if path.exists() {
        check_owner_only(path)?;
        let bytes = std::fs::read(path).map_err(io_error)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| SecurityError::InvalidKeyProviderData)?;
        return Ok(Zeroizing::new(bytes));
    }
    let mut bytes = Zeroizing::new([0_u8; 32]);
    getrandom::fill(&mut *bytes).map_err(|_| SecurityError::RandomnessUnavailable)?;
    write_owner_only(path, &*bytes)?;
    Ok(bytes)
}

fn encode_credentials(
    credentials: &LocalCredentials,
    master: &[u8; 32],
) -> Result<Vec<u8>, SecurityError> {
    let mut nonce = [0_u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| SecurityError::RandomnessUnavailable)?;
    let mut plaintext = Zeroizing::new(Vec::with_capacity(PLAINTEXT_LEN));
    plaintext.extend_from_slice(&credentials.signer.secret_bytes());
    plaintext.extend_from_slice(credentials.domain_key.as_bytes());
    plaintext.extend_from_slice(credentials.domain_id.as_bytes());
    let key = vault_key(master)?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &plaintext,
                aad: MAGIC,
            },
        )
        .map_err(|_| SecurityError::EncryptionFailed)?;
    let mut encoded = Vec::with_capacity(MAGIC.len() + nonce.len() + ciphertext.len());
    encoded.extend_from_slice(MAGIC);
    encoded.extend_from_slice(&nonce);
    encoded.extend_from_slice(&ciphertext);
    Ok(encoded)
}

fn decode_credentials(bytes: &[u8], master: &[u8; 32]) -> Result<LocalCredentials, SecurityError> {
    if bytes.len() != MAGIC.len() + 24 + PLAINTEXT_LEN + 16 || &bytes[..MAGIC.len()] != MAGIC {
        return Err(SecurityError::InvalidKeyProviderData);
    }
    let nonce: [u8; 24] = bytes[8..32]
        .try_into()
        .map_err(|_| SecurityError::InvalidKeyProviderData)?;
    let key = vault_key(master)?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &bytes[32..],
                    aad: MAGIC,
                },
            )
            .map_err(|_| SecurityError::InvalidKeyProviderData)?,
    );
    if plaintext.len() != PLAINTEXT_LEN {
        return Err(SecurityError::InvalidKeyProviderData);
    }
    let signer = plaintext[..32]
        .try_into()
        .map_err(|_| SecurityError::InvalidKeyProviderData)?;
    let domain_key = plaintext[32..64]
        .try_into()
        .map_err(|_| SecurityError::InvalidKeyProviderData)?;
    let domain_id = plaintext[64..]
        .try_into()
        .map_err(|_| SecurityError::InvalidKeyProviderData)?;
    Ok(LocalCredentials {
        signer: IrohSigner::from_secret_bytes(signer),
        domain_key: DomainKey::from_bytes(domain_key),
        domain_id: DomainId::from_bytes(domain_id),
        root: PathBuf::new(),
    })
}

fn encode_domain_seed(seed: &DomainSeed, master: &[u8; 32]) -> Result<Vec<u8>, SecurityError> {
    let mut nonce = [0_u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| SecurityError::RandomnessUnavailable)?;
    let mut plaintext = Zeroizing::new(Vec::with_capacity(DOMAIN_PLAINTEXT_LEN));
    plaintext.extend_from_slice(seed.domain_id.as_bytes());
    plaintext.extend_from_slice(&seed.epoch.to_be_bytes());
    plaintext.extend_from_slice(seed.domain_key.as_bytes());
    let key = vault_key(master)?;
    let ciphertext = XChaCha20Poly1305::new((&*key).into())
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &plaintext,
                aad: DOMAIN_MAGIC,
            },
        )
        .map_err(|_| SecurityError::EncryptionFailed)?;
    let mut encoded = Vec::with_capacity(32 + ciphertext.len());
    encoded.extend_from_slice(DOMAIN_MAGIC);
    encoded.extend_from_slice(&nonce);
    encoded.extend_from_slice(&ciphertext);
    Ok(encoded)
}

fn decode_domain_seed(bytes: &[u8], master: &[u8; 32]) -> Result<DomainSeed, SecurityError> {
    if bytes.len() != 32 + DOMAIN_PLAINTEXT_LEN + 16 || &bytes[..8] != DOMAIN_MAGIC {
        return Err(SecurityError::InvalidKeyProviderData);
    }
    let nonce: [u8; 24] = bytes[8..32]
        .try_into()
        .map_err(|_| SecurityError::InvalidKeyProviderData)?;
    let key = vault_key(master)?;
    let plaintext = Zeroizing::new(
        XChaCha20Poly1305::new((&*key).into())
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &bytes[32..],
                    aad: DOMAIN_MAGIC,
                },
            )
            .map_err(|_| SecurityError::InvalidKeyProviderData)?,
    );
    let domain_id = plaintext[..32]
        .try_into()
        .map_err(|_| SecurityError::InvalidKeyProviderData)?;
    let epoch = u64::from_be_bytes(
        plaintext[32..40]
            .try_into()
            .map_err(|_| SecurityError::InvalidKeyProviderData)?,
    );
    let domain_key = plaintext[40..]
        .try_into()
        .map_err(|_| SecurityError::InvalidKeyProviderData)?;
    Ok(DomainSeed {
        domain_id: DomainId::from_bytes(domain_id),
        epoch,
        domain_key: DomainKey::from_bytes(domain_key),
    })
}

fn vault_key(master: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, SecurityError> {
    let hkdf = Hkdf::<Sha256>::new(Some(b"iroh-db/local-key-vault/v1"), master);
    let mut key = Zeroizing::new([0_u8; 32]);
    hkdf.expand(b"credentials/v1", &mut *key)
        .map_err(|_| SecurityError::KeyDerivationFailed)?;
    Ok(key)
}

fn store_epoch_archive(
    directory: &Path,
    seed: &DomainSeed,
    master: &[u8; 32],
) -> Result<(), SecurityError> {
    let path = directory.join(format!("{}.epoch-{}.v1", seed.domain_id, seed.epoch));
    if path.exists() {
        let bytes = std::fs::read(&path).map_err(io_error)?;
        let existing = decode_domain_seed(&bytes, master)?;
        if existing.domain_id == seed.domain_id
            && existing.epoch == seed.epoch
            && existing.domain_key.as_bytes() == seed.domain_key.as_bytes()
        {
            return Ok(());
        }
        return Err(SecurityError::InvalidKeyProviderData);
    }
    write_owner_only_replace(&path, &encode_domain_seed(seed, master)?)
}

fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<(), SecurityError> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(io_error)?;
    file.write_all(bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)
}

fn write_owner_only_replace(path: &Path, bytes: &[u8]) -> Result<(), SecurityError> {
    let mut suffix = [0_u8; 8];
    getrandom::fill(&mut suffix).map_err(|_| SecurityError::RandomnessUnavailable)?;
    let mut encoded_suffix = String::with_capacity(16);
    for byte in suffix {
        encoded_suffix.push(HEX[usize::from(byte >> 4)] as char);
        encoded_suffix.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    let temporary = path.with_extension(format!("tmp-{encoded_suffix}"));
    write_owner_only(&temporary, bytes)?;
    std::fs::rename(&temporary, path).map_err(io_error)?;
    if let Some(parent) = path.parent() {
        OpenOptions::new()
            .read(true)
            .open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(io_error)?;
    }
    Ok(())
}

#[cfg(unix)]
fn check_owner_only(path: &Path) -> Result<(), SecurityError> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(path)
        .map_err(io_error)?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(SecurityError::InsecureKeyPermissions);
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_owner_only(_path: &Path) -> Result<(), SecurityError> {
    Ok(())
}

#[allow(clippy::needless_pass_by_value)]
fn io_error(error: std::io::Error) -> SecurityError {
    SecurityError::KeyProviderIo(error.to_string())
}
