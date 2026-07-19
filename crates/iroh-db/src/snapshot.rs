use iroh_db_blobs::BlobRef;
use iroh_db_core::{AuthorId, CapabilityId, CommitId};
use iroh_db_security::{CapabilityCertificate, Permission, verify_snapshot_signature};
use iroh_db_store::{MaterializedRecord, SnapshotBaseline, StoreError};
use tokio::io::AsyncReadExt as _;

use crate::{DbError, IrohDb};

const SNAPSHOT_VERSION: u16 = 2;

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
    #[n(6)]
    epoch: u64,
    #[n(7)]
    control_head: Option<[u8; 32]>,
    #[n(8)]
    capability_id: CapabilityId,
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
        let _control_reader = self.inner.control_gate.read().await;
        let _writer = self.inner.writer.lock().await;
        let domain_id = self.domain_id();
        let active_epoch = self.inner.store.current_epoch(domain_id)?;
        if self.epoch() != active_epoch {
            return Err(DbError::StaleEpoch {
                handle: self.epoch(),
                active: active_epoch,
            });
        }
        let capability_id =
            self.capability_for_permission(self.author_id(), Permission::Snapshot, active_epoch)?;
        let records = self.inner.store.export_materialized(domain_id)?;
        let content = SnapshotContent {
            version: SNAPSHOT_VERSION,
            domain_id,
            frontier: self.inner.store.frontier(domain_id)?,
            records: encode_records(&records)?,
            covered_commits: self.inner.store.list_commit_ids(domain_id)?,
            author_sequences: self.inner.store.author_sequences(domain_id)?,
            epoch: active_epoch,
            control_head: control_head_id(self)?,
            capability_id,
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
        let blob = self.blob_engine().import_bytes(bytes, None).await?;
        Ok(Snapshot { blob, state_root })
    }

    /// Verifies and atomically installs a local snapshot's derived state.
    pub async fn install_snapshot(&self, snapshot: Snapshot) -> Result<(), DbError> {
        let _control_reader = self.inner.control_gate.read().await;
        let _writer = self.inner.writer.lock().await;
        let (envelope, content, records) = self.decode_snapshot(snapshot).await?;
        let active_epoch = self.inner.store.current_epoch(self.domain_id())?;
        if content.epoch != active_epoch || self.epoch() != active_epoch {
            return Err(DbError::InvalidSnapshot(
                "snapshot epoch does not match active authority".into(),
            ));
        }
        if content.control_head != control_head_id(self)? {
            return Err(DbError::InvalidSnapshot(
                "snapshot control head does not match active authority".into(),
            ));
        }
        let capability_id =
            self.capability_for_permission(envelope.author, Permission::Snapshot, content.epoch)?;
        if content.capability_id != capability_id {
            return Err(DbError::UnauthorizedDevice);
        }
        let baseline = SnapshotBaseline::new(
            content.domain_id,
            content.epoch,
            snapshot.blob.manifest_hash(),
            envelope.state_root,
            content.frontier.clone(),
            content.author_sequences.clone(),
        )?;
        if let Err(error) = self.inner.store.install_snapshot(
            content.domain_id,
            &records,
            &content.covered_commits,
            &content.frontier,
            &content.author_sequences,
            &baseline,
        ) {
            return match error {
                StoreError::InvalidSnapshotMetadata(message) => {
                    Err(DbError::InvalidSnapshot(message))
                }
                error => Err(DbError::Store(error)),
            };
        }
        Ok(())
    }

    pub(crate) async fn verified_snapshot_baseline_records(
        &self,
    ) -> Result<Option<Vec<MaterializedRecord>>, DbError> {
        let Some(baseline) = self.inner.store.snapshot_baseline(self.domain_id())? else {
            if self.inner.store.has_snapshot_coverage(self.domain_id())? {
                return Err(DbError::InvalidSnapshot(
                    "snapshot coverage has no durable recovery baseline".into(),
                ));
            }
            return Ok(None);
        };
        let snapshot = Snapshot::from_parts(
            BlobRef::new(
                baseline.domain_id(),
                baseline.epoch(),
                baseline.manifest_hash(),
            ),
            baseline.state_root(),
        );
        let (envelope, content, records) = self.decode_snapshot(snapshot).await?;
        if content.epoch != baseline.epoch()
            || content.frontier != baseline.frontier()
            || content.author_sequences != baseline.author_sequences()
        {
            return Err(DbError::InvalidSnapshot(
                "retained snapshot differs from its recovery baseline".into(),
            ));
        }
        let coverage = self.inner.store.snapshot_coverage(self.domain_id())?;
        if coverage
            .iter()
            .any(|commit_id| content.covered_commits.binary_search(commit_id).is_err())
        {
            return Err(DbError::InvalidSnapshot(
                "snapshot coverage contains an unsigned commit".into(),
            ));
        }
        for commit_id in &content.covered_commits {
            if !self
                .inner
                .store
                .contains_commit(self.domain_id(), *commit_id)?
                && !self.inner.store.is_commit_quarantined(*commit_id)?
            {
                return Err(DbError::InvalidSnapshot(
                    "signed snapshot coverage is incomplete".into(),
                ));
            }
        }
        self.verify_historical_snapshot_authority(&envelope, &content)?;
        Ok(Some(records))
    }

    async fn decode_snapshot(
        &self,
        snapshot: Snapshot,
    ) -> Result<(SignedSnapshot, SnapshotContent, Vec<MaterializedRecord>), DbError> {
        if snapshot.blob.domain_id() != self.domain_id() {
            return Err(DbError::InvalidSnapshot(
                "snapshot blob belongs to another domain".into(),
            ));
        }
        let mut stream = self
            .blob_engine_for_epoch(snapshot.blob.epoch())?
            .open(&snapshot.blob)
            .await?;
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
        let content: SnapshotContent = decode_canonical(&envelope.content)?;
        if content.version != SNAPSHOT_VERSION
            || content.domain_id != self.domain_id()
            || content.epoch != snapshot.blob.epoch()
        {
            return Err(DbError::InvalidSnapshot(
                "unsupported version, wrong domain, or wrong epoch".into(),
            ));
        }
        validate_snapshot_metadata(&content)?;
        let records = decode_records(&content.records)?;
        if state_root(&records)? != envelope.state_root {
            return Err(DbError::InvalidSnapshot("state root mismatch".into()));
        }
        Ok((envelope, content, records))
    }

    fn verify_historical_snapshot_authority(
        &self,
        envelope: &SignedSnapshot,
        content: &SnapshotContent,
    ) -> Result<(), DbError> {
        let Some(descriptor) = self.inner.store.domain_descriptor(content.domain_id)? else {
            if content.capability_id != crate::db::private_capability(content.domain_id) {
                return Err(DbError::UnauthorizedDevice);
            }
            return Ok(());
        };
        let snapshot_control_sequence = match content.control_head {
            Some(control_id) => {
                let control = self
                    .inner
                    .store
                    .control_transition(content.domain_id, control_id)?
                    .ok_or_else(|| {
                        DbError::InvalidSnapshot("snapshot authority anchor is not retained".into())
                    })?;
                if control.id()? != control_id || control.new_epoch() != content.epoch {
                    return Err(DbError::InvalidSnapshot(
                        "snapshot authority anchor does not authorize its epoch".into(),
                    ));
                }
                if self
                    .inner
                    .store
                    .accepted_control_at_sequence(content.domain_id, control.sequence())?
                    .as_ref()
                    .map(iroh_db_security::ControlTransition::id)
                    .transpose()?
                    != Some(control_id)
                {
                    return Err(DbError::InvalidSnapshot(
                        "snapshot authority anchor was not accepted".into(),
                    ));
                }
                control.sequence()
            }
            None if content.epoch == 0 => 0,
            None => {
                return Err(DbError::InvalidSnapshot(
                    "snapshot epoch has no authority anchor".into(),
                ));
            }
        };
        let chain = self.inner.store.capability_chain(content.capability_id)?;
        let Some(root) = chain.first() else {
            return Err(DbError::UnauthorizedDevice);
        };
        let Some(leaf) = chain.last() else {
            return Err(DbError::UnauthorizedDevice);
        };
        if root.domain_id() != content.domain_id
            || root.subject() != descriptor.owner()
            || leaf.subject() != envelope.author
            || !leaf.permits(Permission::Snapshot, content.epoch)
        {
            return Err(DbError::UnauthorizedDevice);
        }
        if !self.historical_capability_anchors_accepted(
            content.domain_id,
            &chain,
            snapshot_control_sequence,
        )? {
            return Err(DbError::UnauthorizedDevice);
        }
        let revocations: std::collections::BTreeMap<_, _> = self
            .inner
            .store
            .subject_revocations(content.domain_id)?
            .into_iter()
            .collect();
        if chain.iter().any(|capability| {
            revocations
                .get(&capability.subject())
                .is_some_and(|revoked_at| {
                    *revoked_at > capability.issued_control_sequence()
                        && *revoked_at <= snapshot_control_sequence
                })
        }) {
            return Err(DbError::UnauthorizedDevice);
        }
        Ok(())
    }

    fn historical_capability_anchors_accepted(
        &self,
        domain_id: iroh_db_core::DomainId,
        chain: &[CapabilityCertificate],
        snapshot_control_sequence: u64,
    ) -> Result<bool, DbError> {
        let checkpoint = self.inner.store.authority_checkpoint(domain_id)?;
        let checkpoint_sequence = checkpoint
            .as_ref()
            .and_then(iroh_db_security::AuthorityCheckpoint::head)
            .map(iroh_db_security::ControlTransition::sequence);
        for capability in chain {
            let sequence = capability.issued_control_sequence();
            if sequence > snapshot_control_sequence {
                return Ok(false);
            }
            let before_checkpoint = checkpoint_sequence.is_some_and(|cut| sequence < cut);
            let anchor_is_accepted = if before_checkpoint {
                let capability_id = capability.id()?;
                checkpoint
                    .as_ref()
                    .is_some_and(|checkpoint| checkpoint.capability_ids().contains(&capability_id))
            } else if sequence == 0 {
                capability.issued_control_head().is_none()
            } else {
                let Some(control) = self
                    .inner
                    .store
                    .accepted_control_at_sequence(domain_id, sequence)?
                else {
                    return Ok(false);
                };
                capability.issued_control_head() == Some(control.id()?)
            };
            if !anchor_is_accepted {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Rebuilds all derived records and indexes from validated immutable commits.
    pub async fn rebuild(&self) -> Result<[u8; 32], DbError> {
        let _control_reader = self.inner.control_gate.read().await;
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

fn validate_snapshot_metadata(content: &SnapshotContent) -> Result<(), DbError> {
    if !strictly_sorted(&content.frontier)
        || !strictly_sorted(&content.covered_commits)
        || !content
            .author_sequences
            .windows(2)
            .all(|pair| pair[0].0 < pair[1].0)
        || content
            .frontier
            .iter()
            .any(|commit_id| content.covered_commits.binary_search(commit_id).is_err())
        || content.covered_commits.is_empty() != content.frontier.is_empty()
        || content.covered_commits.is_empty() != content.author_sequences.is_empty()
    {
        return Err(DbError::InvalidSnapshot(
            "snapshot causal metadata is malformed".into(),
        ));
    }
    Ok(())
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn control_head_id(db: &IrohDb) -> Result<Option<[u8; 32]>, DbError> {
    db.inner
        .store
        .control_head(db.domain_id())?
        .as_ref()
        .map(iroh_db_security::ControlTransition::id)
        .transpose()
        .map_err(DbError::from)
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
