use iroh_db_blobs::{BlobEngine, BlobRef};
use iroh_db_core::{AuthorId, CommitId};
use iroh_db_security::verify_snapshot_signature;
use iroh_db_store::MaterializedRecord;
use tokio::io::AsyncReadExt as _;

use crate::{DbError, IrohDb};

const SNAPSHOT_VERSION: u16 = 1;

/// An immutable encrypted local snapshot and its verified state root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    blob: BlobRef,
    state_root: [u8; 32],
}

impl Snapshot {
    /// Reconstructs an out-of-band snapshot reference after authorization metadata exchange.
    pub const fn from_parts(blob: BlobRef, state_root: [u8; 32]) -> Self {
        Self { blob, state_root }
    }

    /// Returns the encrypted snapshot blob reference.
    pub const fn blob_ref(self) -> BlobRef {
        self.blob
    }

    /// Returns the BLAKE3 root of canonical captured state.
    pub const fn state_root(self) -> [u8; 32] {
        self.state_root
    }
}

#[derive(minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
struct SnapshotContent {
    #[n(0)]
    version: u16,
    #[n(1)]
    domain_id: iroh_db_core::DomainId,
    #[n(2)]
    frontier: Vec<CommitId>,
    #[n(3)]
    records: Vec<Vec<u8>>,
    #[n(4)]
    covered_commits: Vec<CommitId>,
    #[n(5)]
    author_sequences: Vec<(AuthorId, u64)>,
}

#[derive(minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
struct SignedSnapshot {
    #[n(0)]
    content: Vec<u8>,
    #[n(1)]
    state_root: [u8; 32],
    #[n(2)]
    author: AuthorId,
    #[n(3)]
    signature: [u8; 64],
}

impl IrohDb {
    /// Captures canonical materialized state and frontier in a signed encrypted blob.
    pub async fn snapshot(&self) -> Result<Snapshot, DbError> {
        let _writer = self.inner.writer.lock().await;
        let domain_id = self.domain_id();
        let records = self.inner.store.export_materialized(domain_id)?;
        let content = SnapshotContent {
            version: SNAPSHOT_VERSION,
            domain_id,
            frontier: self.inner.store.frontier(domain_id)?,
            records: encode_records(&records)?,
            covered_commits: self.inner.store.list_commit_ids(domain_id)?,
            author_sequences: self.inner.store.author_sequences(domain_id)?,
        };
        let content = minicbor::to_vec(content).map_err(snapshot_codec)?;
        let state_root = state_root(&records)?;
        let signer = self.inner.credentials.signer();
        let signing_bytes = snapshot_signing_bytes(&content, &state_root, signer.author())?;
        let envelope = SignedSnapshot {
            content,
            state_root,
            author: signer.author(),
            signature: signer.sign_snapshot(&signing_bytes),
        };
        let bytes = minicbor::to_vec(envelope).map_err(snapshot_codec)?;
        let blob = blob_engine(self).import_bytes(bytes, None).await?;
        Ok(Snapshot { blob, state_root })
    }

    /// Verifies and atomically installs a local snapshot's derived state.
    pub async fn install_snapshot(&self, snapshot: Snapshot) -> Result<(), DbError> {
        let _writer = self.inner.writer.lock().await;
        let mut stream = blob_engine(self).open(&snapshot.blob).await?;
        let mut bytes = Vec::new();
        stream
            .read_to_end(&mut bytes)
            .await
            .map_err(|error| DbError::InvalidSnapshot(error.to_string()))?;
        let envelope: SignedSnapshot = decode_canonical(&bytes)?;
        if envelope.state_root != snapshot.state_root {
            return Err(DbError::InvalidSnapshot("state root mismatch".into()));
        }
        let signing_bytes =
            snapshot_signing_bytes(&envelope.content, &envelope.state_root, envelope.author)?;
        verify_snapshot_signature(envelope.author, &signing_bytes, &envelope.signature)?;
        if !self
            .inner
            .store
            .is_author_trusted(self.domain_id(), envelope.author)?
        {
            return Err(DbError::UnauthorizedDevice);
        }
        let content: SnapshotContent = decode_canonical(&envelope.content)?;
        if content.version != SNAPSHOT_VERSION || content.domain_id != self.domain_id() {
            return Err(DbError::InvalidSnapshot(
                "unsupported version or wrong domain".into(),
            ));
        }
        let records = decode_records(&content.records)?;
        if state_root(&records)? != envelope.state_root {
            return Err(DbError::InvalidSnapshot("state root mismatch".into()));
        }
        self.inner.store.install_snapshot(
            content.domain_id,
            &records,
            &content.covered_commits,
            &content.frontier,
            &content.author_sequences,
        )?;
        Ok(())
    }

    /// Rebuilds all derived records and indexes from validated immutable commits.
    pub async fn rebuild(&self) -> Result<[u8; 32], DbError> {
        let _writer = self.inner.writer.lock().await;
        let domain_id = self.domain_id();
        let mutations = self.rebuild_mutations().await?;
        self.inner
            .store
            .replace_materialized(domain_id, &mutations)?;
        state_root(&mutations)
    }

    /// Computes the canonical root of current materialized state.
    pub fn state_root(&self) -> Result<[u8; 32], DbError> {
        let records = self.inner.store.export_materialized(self.domain_id())?;
        state_root(&records)
    }
}

fn blob_engine(db: &IrohDb) -> BlobEngine {
    BlobEngine::new_at_epoch(
        db.inner.blobs.clone(),
        db.domain_id(),
        db.epoch(),
        db.domain_key(),
    )
}

fn encode_records(records: &[MaterializedRecord]) -> Result<Vec<Vec<u8>>, DbError> {
    records
        .iter()
        .map(|record| record.encode_canonical().map_err(DbError::from))
        .collect()
}

fn decode_records(records: &[Vec<u8>]) -> Result<Vec<MaterializedRecord>, DbError> {
    records
        .iter()
        .map(|record| MaterializedRecord::decode_canonical(record).map_err(DbError::from))
        .collect()
}

fn state_root(records: &[MaterializedRecord]) -> Result<[u8; 32], DbError> {
    let bytes = minicbor::to_vec(encode_records(records)?).map_err(snapshot_codec)?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

fn snapshot_signing_bytes(
    content: &[u8],
    state_root: &[u8; 32],
    author: AuthorId,
) -> Result<Vec<u8>, DbError> {
    minicbor::to_vec((content, state_root, author)).map_err(snapshot_codec)
}

fn decode_canonical<T>(bytes: &[u8]) -> Result<T, DbError>
where
    T: minicbor::Encode<()> + for<'value> minicbor::Decode<'value, ()>,
{
    let mut decoder = minicbor::Decoder::new(bytes);
    let value = decoder.decode().map_err(snapshot_codec)?;
    if decoder.position() != bytes.len()
        || minicbor::to_vec(&value).map_err(snapshot_codec)? != bytes
    {
        return Err(DbError::InvalidSnapshot("non-canonical encoding".into()));
    }
    Ok(value)
}

#[allow(clippy::needless_pass_by_value)]
fn snapshot_codec(error: impl std::fmt::Display) -> DbError {
    DbError::InvalidSnapshot(error.to_string())
}
