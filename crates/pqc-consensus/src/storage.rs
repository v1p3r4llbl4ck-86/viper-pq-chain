// SPDX-License-Identifier: BUSL-1.1
//! Disk-backed canonical chain persistence for the single-node prototype.
//!
//! The durable source of truth is the committed block history plus minimal
//! metadata required to rebuild indexes and verify replay. Mutable state is not
//! persisted here as authoritative data; recovery always derives it from
//! genesis plus chain history.

use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{BufReader, BufWriter},
    path::{Path, PathBuf},
};

use pqc_crypto::{registry::phase1_registry, AlgId, Lifecycle, SigClass};
use pqc_state::StateStore;
use pqc_tx::{
    codec::{decode_tx, encode_tx},
    compute_tx_hash,
    validate::FeeParams,
    TxError,
};
use pqc_types::{
    account::{Account, Address},
    attestation::{Attestation, AttestationId, AttestationRevocation, AttestationStatus},
    block::{Block, BlockHash, BlockHeader, CommitSig},
    governance::{
        GovernanceProposalType, GovernanceReceipt, PendingProposal, PendingUpgrade, ProposalEffect,
        ProposalStatus,
    },
    keyset::{KeyEntry, KeySet, KeyStatus},
    transaction::TxHash,
    validator::{ValidatorRecord, ValidatorStatus},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

use crate::{
    commit::{validate_block_commit_quorum, CommitQuorumPolicy, CommitValidationError},
    recover_tip as recover_from_chain,
    recovery::replay_blocks_from_state,
    BlockExecutionResult, BlockMetadata, ChainError, ChainStore, ReplayError, ReplayResult,
    StoredBlock,
};

const BLOCKS_DIR: &str = "blocks";
const HASHES_DIR: &str = "hashes";
const STAGING_DIR: &str = "staging";
const CHECKPOINTS_DIR: &str = "checkpoints";
const CHECKPOINT_FILE: &str = "trusted-checkpoint.cbor";
const TIP_FILE: &str = "tip.cbor";

/// State format version compiled into this binary (ADR-030 / TASK-101).
///
/// This version is persisted in every `TrustedCheckpointRecord` written by this binary
/// and checked on boot.  Increment this constant whenever the checkpoint schema, leaf hash
/// domain string, sort order, or any serialised state struct changes in a way that would
/// make an existing checkpoint unreadable or produce a different state root.
///
/// Boot fail-fast rules:
/// - `disk_version < STATE_FORMAT_VERSION` → `StateFormatUpgradeRequired` (need migration)
/// - `disk_version > STATE_FORMAT_VERSION` → `BinaryTooOld` (need newer binary)
///
/// **Changelog**:
/// - v1: initial format (accounts, attestations, governance receipts, alg registry,
///   validators, fee market, pending proposals).
/// - v2: adds `pending_upgrades` (ADR-031 / TASK-102).  The `state_root()` now
///   includes the upgrade leaf section.  Old v1 checkpoints are migrated
///   automatically on first boot by `RocksDbChainStore::apply_upgrade_chain`.
/// - v3: validator leaf hash now includes `tombstoned` field (F-001 audit fix).
///   State roots computed under v2 are incompatible with v3.
pub const STATE_FORMAT_VERSION: u16 = 3;

#[derive(Debug)]
pub struct DiskChainStore {
    root: PathBuf,
    chain: ChainStore,
    commit_policy: Option<CommitQuorumPolicy>,
    /// The anchor hash passed to `open()` — used for disk-based full replay when the
    /// in-memory ChainStore only holds tail blocks (ADR-028 checkpoint-bounded open).
    genesis_anchor: BlockHash,
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("{operation} failed for {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to encode {path}: {detail}")]
    Encode { path: PathBuf, detail: String },
    #[error("failed to decode {path}: {detail}")]
    Decode { path: PathBuf, detail: String },
    #[error(transparent)]
    Chain(#[from] ChainError),
    #[error(transparent)]
    Commit(#[from] CommitValidationError),
    #[error(transparent)]
    Replay(#[from] ReplayError),
    #[error("INCOMPLETE_WRITE_DETECTED: staging directory is not empty")]
    IncompleteWriteDetected,
    #[error("TIP_MISSING_WITH_EXISTING_DATA: persisted data exists but tip file is missing")]
    TipMissingWithExistingData,
    #[error("MISSING_BLOCK_FILE: expected persisted block for height {height}")]
    MissingBlockFile { height: u64 },
    #[error("UNEXPECTED_BLOCK_FILE: found unexpected block file {name}")]
    UnexpectedBlockFile { name: String },
    #[error("MISSING_HASH_INDEX: expected persisted hash index for block {hash}")]
    MissingHashIndex { hash: String },
    #[error("UNEXPECTED_HASH_INDEX: found unexpected hash index file {name}")]
    UnexpectedHashIndex { name: String },
    #[error("HASH_INDEX_MISMATCH: block {hash} should point to height {expected_height}, got {got_height}")]
    HashIndexMismatch {
        hash: String,
        expected_height: u64,
        got_height: u64,
    },
    #[error("TIP_HEIGHT_MISMATCH: tip file says height {expected}, rebuilt chain height is {got}")]
    TipHeightMismatch { expected: u64, got: u64 },
    #[error("TIP_HASH_MISMATCH: tip file says {expected:?}, rebuilt chain tip is {got:?}")]
    TipHashMismatch { expected: BlockHash, got: BlockHash },
    #[error("INVALID_PERSISTED_VALUE: {0}")]
    InvalidPersistedValue(&'static str),
    /// Policy P-COMPAT-001 §(3) — chain_id pre-flight guard (ADR-052).
    /// The configured chain_id for this binary does not match the
    /// chain_id persisted in the on-disk store. Refusing to start
    /// avoids the 2026-04-24 rc1 failure mode (running a binary
    /// built for chain X against a data directory from chain Y).
    #[error(
        "CHAIN_ID_MISMATCH (P-COMPAT-001): on-disk chain_id=0x{got} but binary is configured for \
         chain_id=0x{expected}. Move the data directory aside or run the binary built for the \
         on-disk chain. See ADR-052."
    )]
    ChainIdMismatch { expected: String, got: String },
    #[error("INVALID_PERSISTED_ALG_ID: 0x{0:04x}")]
    InvalidPersistedAlgId(u16),
    /// RocksDB engine error (ADR-032).
    #[error("ROCKSDB_ERROR: {0}")]
    RocksDb(String),
    #[error("TX_ENCODE_FAILED at height {height}, index {tx_index}: {source}")]
    TxEncodeFailed {
        height: u64,
        tx_index: usize,
        #[source]
        source: TxError,
    },
    #[error("TX_DECODE_FAILED at height {height}, index {tx_index}: {source}")]
    TxDecodeFailed {
        height: u64,
        tx_index: usize,
        #[source]
        source: TxError,
    },
    #[error("TX_BODY_HASH_MISMATCH at height {height}, index {tx_index}: expected {expected:?}, got {got:?}")]
    TxBodyHashMismatch {
        height: u64,
        tx_index: usize,
        expected: TxHash,
        got: TxHash,
    },
    #[error("CHECKPOINT_HEIGHT_MISMATCH: expected canonical state height {expected}, got {got}")]
    CheckpointHeightMismatch { expected: u64, got: u64 },
    #[error("CHECKPOINT_TIP_HASH_MISMATCH: expected {expected:?}, got {got:?}")]
    CheckpointTipHashMismatch { expected: BlockHash, got: BlockHash },
    #[error("CHECKPOINT_STATE_ROOT_MISMATCH: expected {expected:?}, got {got:?}")]
    CheckpointStateRootMismatch { expected: BlockHash, got: BlockHash },
    #[error("CHECKPOINT_REGISTRY_MISMATCH: {0}")]
    CheckpointRegistryMismatch(&'static str),
    #[error("INVALID_SNAPSHOT: {0}")]
    InvalidSnapshot(&'static str),
    /// TASK-187a — pre-flight guard for `RocksDbChainStore::prune_blocks_below`.
    /// Refused because the requested cutoff would either delete the genesis
    /// block (cutoff == 0), exceed the current tip (cutoff > tip), or leave the
    /// store with no trusted checkpoint at height ≥ cutoff (the node would be
    /// unable to bootstrap on next start). The follower-prune subcommand maps
    /// this error to a non-zero exit + a `prune.log` line so the operator
    /// knows the run was a no-op.
    #[error("INVALID_PRUNE_CUTOFF: {0}")]
    InvalidPruneCutoff(&'static str),
    /// Disk checkpoint was written by an older binary (disk_version < compiled STATE_FORMAT_VERSION).
    /// A migration is required before the node can start.  See TASK-102 for the
    /// `UpgradeHandler` migration path.
    #[error(
        "STATE_FORMAT_UPGRADE_REQUIRED: checkpoint version {disk_version} is older than \
             this binary's STATE_FORMAT_VERSION {binary_version}. \
             A migration handler must be run before the node can start."
    )]
    StateFormatUpgradeRequired {
        disk_version: u16,
        binary_version: u16,
    },
    /// Disk checkpoint was written by a newer binary (disk_version > compiled STATE_FORMAT_VERSION).
    /// This binary is too old to read the checkpoint; upgrade the binary.
    #[error(
        "BINARY_TOO_OLD: checkpoint version {disk_version} is newer than \
             this binary's STATE_FORMAT_VERSION {binary_version}. \
             Upgrade the node binary before starting."
    )]
    BinaryTooOld {
        disk_version: u16,
        binary_version: u16,
    },
    /// The checkpoint file is present but failed validation (e.g. produced by
    /// an older binary that omitted validator state from the snapshot), so the
    /// full-replay path was taken.  However, `open_internal` loaded only the
    /// checkpoint tail into the in-memory ChainStore (blocks after the
    /// checkpoint height), meaning a full replay from genesis is impossible
    /// without re-opening the store.  The operator must wipe the chain data
    /// directory so the node can start fresh.
    #[error("PARTIAL_CHAIN_CANNOT_FULL_REPLAY: checkpoint at height {checkpoint_height} failed validation but only blocks from height {first_block_height} are in memory. Wipe the chain data directory ({data_dir}) and restart to start fresh.")]
    PartialChainCannotFullReplay {
        checkpoint_height: u64,
        first_block_height: u64,
        data_dir: PathBuf,
    },
    /// A state migration handler chain was found but failed during execution.
    #[error("MIGRATION_FAILED: {0}")]
    MigrationFailed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedCheckpointMetadata {
    pub height: u64,
    pub tip_hash: BlockHash,
    pub state_root: BlockHash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoverySource {
    FullReplay,
    TrustedCheckpoint,
}

#[derive(Debug)]
pub struct CheckpointRecoveryResult {
    pub replay: ReplayResult,
    pub source: RecoverySource,
    pub checkpoint: Option<TrustedCheckpointMetadata>,
}

impl DiskChainStore {
    pub fn open(root: impl AsRef<Path>, anchor_prev_hash: BlockHash) -> Result<Self, StorageError> {
        Self::open_internal(root, anchor_prev_hash, None)
    }

    pub fn open_with_commit_policy(
        root: impl AsRef<Path>,
        anchor_prev_hash: BlockHash,
        commit_policy: CommitQuorumPolicy,
    ) -> Result<Self, StorageError> {
        Self::open_internal(root, anchor_prev_hash, Some(commit_policy))
    }

    fn open_internal(
        root: impl AsRef<Path>,
        anchor_prev_hash: BlockHash,
        commit_policy: Option<CommitQuorumPolicy>,
    ) -> Result<Self, StorageError> {
        let root = root.as_ref().to_path_buf();
        ensure_dir(&root)?;
        let blocks_dir = root.join(BLOCKS_DIR);
        let hashes_dir = root.join(HASHES_DIR);
        let staging_dir = root.join(STAGING_DIR);
        let checkpoints_dir = root.join(CHECKPOINTS_DIR);
        ensure_dir(&blocks_dir)?;
        ensure_dir(&hashes_dir)?;
        ensure_dir(&staging_dir)?;
        ensure_dir(&checkpoints_dir)?;

        if !dir_entries(&staging_dir)?.is_empty() {
            return Err(StorageError::IncompleteWriteDetected);
        }

        let checkpoint_path = checkpoints_dir.join(CHECKPOINT_FILE);

        // Detect snapshot-bootstrapped stores: if block 1 is absent but a checkpoint
        // with height > 0 exists, this store was cold-started from a distributed snapshot
        // and pre-snapshot block files are intentionally absent.
        let first_block_path = blocks_dir.join(block_file_name(1));
        let snapshot_base = if !first_block_path.exists() {
            read_snapshot_base_if_present(&checkpoint_path)?
        } else {
            None
        };
        let start_height: u64 = snapshot_base.as_ref().map(|(h, _)| h + 1).unwrap_or(1);
        let (chain_anchor, base_height) = match &snapshot_base {
            Some((h, tip_hash)) => (tip_hash.clone(), *h),
            None => (anchor_prev_hash.clone(), 0),
        };

        // If a locally-written checkpoint exists on a full-history store (block 1 is present),
        // use it to bound which blocks are loaded into the in-memory ChainStore. Blocks before
        // the checkpoint height are read from disk during startup for inventory validation but
        // are not retained in memory. This prevents unbounded RSS growth: ChainStore holds only
        // the tail (checkpoint_height+1 .. tip), while the full history stays on disk and is
        // served to followers via read_stored_block_from_disk when needed.
        let checkpoint_window = if snapshot_base.is_none() {
            let window = read_snapshot_base_if_present(&checkpoint_path)?;
            match &window {
                Some((ckpt_h, ckpt_tip)) => {
                    // Validate checkpoint integrity before using it as the chain anchor.
                    // The block at ckpt_h+1 must exist and its prev_hash must equal the
                    // checkpoint's tip_hash. If not (corrupt checkpoint, wrong tip_hash,
                    // or non-canonical height), discard the window and load the full chain
                    // from genesis so recovery can still work.
                    let next_path = blocks_dir.join(block_file_name(ckpt_h + 1));
                    let is_valid = next_path.exists()
                        && read_cbor::<StoredBlockRecord>(&next_path)
                            .map(|r| r.header.prev_hash == ckpt_tip.0)
                            .unwrap_or(false);
                    if is_valid {
                        window
                    } else {
                        None
                    }
                }
                None => None,
            }
        } else {
            None
        };
        let (chain_anchor, base_height) = match &checkpoint_window {
            Some((ckpt_h, ckpt_tip)) => (ckpt_tip.clone(), *ckpt_h),
            None => (chain_anchor, base_height),
        };
        // First height that will be retained in the in-memory ChainStore.
        let memory_load_from = checkpoint_window
            .as_ref()
            .map(|(h, _)| h + 1)
            .unwrap_or(start_height);

        let tip_path = root.join(TIP_FILE);
        let mut chain = ChainStore::new_with_base(chain_anchor, base_height);

        if !tip_path.exists() {
            if !dir_entries(&blocks_dir)?.is_empty() || !dir_entries(&hashes_dir)?.is_empty() {
                return Err(StorageError::TipMissingWithExistingData);
            }

            return Ok(Self {
                root,
                chain,
                commit_policy,
                genesis_anchor: anchor_prev_hash,
            });
        }

        let tip = read_cbor::<TipRecord>(&tip_path)?;
        let mut expected_block_files = BTreeSet::new();
        let mut expected_hash_files = BTreeSet::new();

        for height in start_height..=tip.height {
            let block_file = block_file_name(height);
            expected_block_files.insert(block_file.clone());
            let block_path = blocks_dir.join(&block_file);
            if !block_path.exists() {
                return Err(StorageError::MissingBlockFile { height });
            }

            let record = read_cbor::<StoredBlockRecord>(&block_path)?;
            // Extract the block hash before deciding whether to retain this block.
            // The record is deserialized in full for validation, then dropped if
            // height < memory_load_from to keep memory bounded.
            let block_hash = BlockHash(record.metadata.block_hash);
            let hash_name = hash_index_file_name(&block_hash);
            expected_hash_files.insert(hash_name.clone());

            let hash_path = hashes_dir.join(&hash_name);
            if !hash_path.exists() {
                return Err(StorageError::MissingHashIndex {
                    hash: hex::encode(block_hash.0),
                });
            }

            let hash_index = read_cbor::<HashIndexRecord>(&hash_path)?;
            if hash_index.height != height {
                return Err(StorageError::HashIndexMismatch {
                    hash: hex::encode(block_hash.0),
                    expected_height: height,
                    got_height: hash_index.height,
                });
            }

            if height >= memory_load_from {
                // Tail block: deserialize fully and retain in the in-memory ChainStore.
                let stored = record_into_stored_block(record, height)?;
                if let Some(policy) = &commit_policy {
                    validate_block_commit_quorum(&stored.block, policy)?;
                }
                chain.append_stored_block(stored)?;
            }
            // Pre-checkpoint blocks: record is dropped here, freeing the allocation.
            // The checkpoint provides integrity proof for all pre-checkpoint history.
        }

        ensure_inventory_exact(&blocks_dir, &expected_block_files, |name| {
            StorageError::UnexpectedBlockFile { name }
        })?;
        ensure_inventory_exact(&hashes_dir, &expected_hash_files, |name| {
            StorageError::UnexpectedHashIndex { name }
        })?;

        if chain.height() != tip.height {
            return Err(StorageError::TipHeightMismatch {
                expected: tip.height,
                got: chain.height(),
            });
        }

        // Use the chain's own anchor as the fallback tip hash (handles snapshot-bootstrapped
        // stores where the anchor is the snapshot tip, not the genesis anchor).
        let actual_tip = chain
            .tip_hash()
            .cloned()
            .unwrap_or_else(|| chain.anchor_prev_hash().clone());
        let expected_tip = BlockHash(tip.block_hash);
        if actual_tip != expected_tip {
            return Err(StorageError::TipHashMismatch {
                expected: expected_tip,
                got: actual_tip,
            });
        }

        Ok(Self {
            root,
            chain,
            commit_policy,
            genesis_anchor: anchor_prev_hash,
        })
    }

    pub fn append_block(
        &mut self,
        execution: &BlockExecutionResult,
    ) -> Result<BlockMetadata, StorageError> {
        self.validate_commit_proof(&execution.block)?;
        self.append_block_inner(execution)
    }

    /// Append a locally-produced block without re-validating commit signatures.
    ///
    /// Use this when the caller is the block producer and has already attached
    /// valid commit signatures — the signatures were just computed and do not
    /// need a round-trip verification through the verifier.
    pub fn append_block_trusted(
        &mut self,
        execution: &BlockExecutionResult,
    ) -> Result<BlockMetadata, StorageError> {
        self.append_block_inner(execution)
    }

    fn append_block_inner(
        &mut self,
        execution: &BlockExecutionResult,
    ) -> Result<BlockMetadata, StorageError> {
        let mut trial = self.chain.clone();
        let metadata = trial.append_block(execution)?;
        let stored = trial
            .tip()
            .expect("append_block must produce a chain tip")
            .clone();

        self.persist_stored_block(&stored)?;
        self.chain = trial;

        tracing::info!(
            height = metadata.height,
            included = metadata.included_count,
            tip_hash = %hex::encode(metadata.block_hash.0),
            "block persisted",
        );

        Ok(metadata)
    }

    pub fn append_stored_block(
        &mut self,
        stored: StoredBlock,
    ) -> Result<BlockMetadata, StorageError> {
        self.validate_commit_proof(&stored.block)?;
        let mut trial = self.chain.clone();
        let metadata = trial.append_stored_block(stored.clone())?;
        self.persist_stored_block(&stored)?;
        self.chain = trial;

        tracing::info!(
            height = metadata.height,
            included = metadata.included_count,
            tip_hash = %hex::encode(metadata.block_hash.0),
            "remote block persisted",
        );

        Ok(metadata)
    }

    pub fn chain(&self) -> &ChainStore {
        &self.chain
    }

    pub fn tip_hash(&self) -> Option<&BlockHash> {
        self.chain.tip_hash()
    }

    pub fn height(&self) -> u64 {
        self.chain.height()
    }

    /// Read a stored block by height — tries in-memory chain first, falls back to disk.
    /// Returns `Ok(None)` if the height does not exist.
    pub fn read_stored_block_at_height(
        &self,
        height: u64,
    ) -> Result<Option<StoredBlock>, StorageError> {
        if let Some(stored) = self.chain.get_stored_block_by_height(height) {
            return Ok(Some(stored.clone()));
        }
        self.read_stored_block_from_disk(height)
    }

    pub fn export_block_bytes(&self, height: u64) -> Result<Option<Vec<u8>>, StorageError> {
        // Fast path: block is in the in-memory window.
        if let Some(stored) = self.chain.get_stored_block_by_height(height) {
            return Self::encode_block_bytes(stored).map(Some);
        }
        // Disk fallback: block predates the checkpoint window (no longer in memory).
        // Read from disk and serialize without retaining in memory.
        self.read_stored_block_from_disk(height)
            .and_then(|opt| opt.map(|s| Self::encode_block_bytes(&s)).transpose())
    }

    /// Read a single block from disk by height without loading it into the in-memory ChainStore.
    /// Used for P2P block export of pre-checkpoint blocks that have been evicted from RAM.
    fn read_stored_block_from_disk(
        &self,
        height: u64,
    ) -> Result<Option<StoredBlock>, StorageError> {
        let block_path = self.blocks_dir().join(block_file_name(height));
        if !block_path.exists() {
            return Ok(None);
        }
        let record = read_cbor::<StoredBlockRecord>(&block_path)?;
        record_into_stored_block(record, height).map(Some)
    }

    pub fn encode_block_bytes(stored: &StoredBlock) -> Result<Vec<u8>, StorageError> {
        encode_stored_block_bytes(stored)
    }

    pub fn decode_block_bytes(bytes: &[u8]) -> Result<StoredBlock, StorageError> {
        let record = decode_cbor_slice::<StoredBlockRecord>(bytes, "<p2p-block>")?;
        let height = record.header.height;
        record_into_stored_block(record, height)
    }

    pub fn recover_tip(
        &self,
        genesis_state: &StateStore,
        fee_params: FeeParams,
        fee_dist: pqc_state::FeeDistributionParams,
        validator_pool: Vec<pqc_types::account::Address>,
    ) -> Result<ReplayResult, StorageError> {
        // If the in-memory chain is tail-only (ADR-028 checkpoint-bounded open), block files
        // before the checkpoint height are absent from memory but present on disk. Read all
        // blocks from disk for a full genesis-to-tip replay, using the genesis anchor that
        // was supplied to open().
        let chain_start = self
            .chain
            .blocks_in_order()
            .first()
            .map(|b| b.metadata.height)
            .unwrap_or(1);
        if chain_start > 1 {
            let tip_path = self.root.join(TIP_FILE);
            if !tip_path.exists() {
                return Err(StorageError::Replay(ReplayError::HeightGap {
                    expected: 1,
                    got: chain_start,
                }));
            }
            let tip = read_cbor::<TipRecord>(&tip_path).map_err(|e| StorageError::Decode {
                path: tip_path.clone(),
                detail: e.to_string(),
            })?;
            let mut blocks = Vec::with_capacity(tip.height as usize);
            for h in 1..=tip.height {
                let block = self
                    .read_stored_block_from_disk(h)?
                    .ok_or(StorageError::MissingBlockFile { height: h })?;
                blocks.push(block);
            }
            return replay_blocks_from_state(
                genesis_state,
                &self.genesis_anchor,
                &blocks,
                fee_params,
                fee_dist,
                validator_pool,
            )
            .map_err(StorageError::Replay);
        }
        recover_from_chain(
            &self.chain,
            genesis_state,
            fee_params,
            fee_dist,
            validator_pool,
        )
        .map_err(StorageError::Replay)
    }

    pub fn write_trusted_checkpoint(
        &self,
        state: &StateStore,
    ) -> Result<TrustedCheckpointMetadata, StorageError> {
        let expected_height = self.height();
        let got_height = state.block_height();
        if got_height != expected_height {
            return Err(StorageError::CheckpointHeightMismatch {
                expected: expected_height,
                got: got_height,
            });
        }

        let expected_tip_hash = self
            .tip_hash()
            .cloned()
            .unwrap_or_else(|| self.chain.anchor_prev_hash().clone());
        let got_tip_hash = if got_height == 0 {
            self.chain.anchor_prev_hash().clone()
        } else {
            self.chain
                .get_metadata_by_height(got_height)
                .map(|metadata| metadata.block_hash.clone())
                .unwrap_or_else(|| self.chain.anchor_prev_hash().clone())
        };
        if got_tip_hash != expected_tip_hash {
            return Err(StorageError::CheckpointTipHashMismatch {
                expected: expected_tip_hash,
                got: got_tip_hash,
            });
        }

        let actual_state_root = BlockHash(state.state_root());
        let expected_state_root = if got_height == 0 {
            actual_state_root.clone()
        } else {
            self.chain
                .get_metadata_by_height(got_height)
                .map(|metadata| metadata.state_root.clone())
                .unwrap_or_else(|| actual_state_root.clone())
        };
        if actual_state_root != expected_state_root {
            return Err(StorageError::CheckpointStateRootMismatch {
                expected: expected_state_root,
                got: actual_state_root,
            });
        }

        let metadata = TrustedCheckpointMetadata {
            height: got_height,
            tip_hash: expected_tip_hash,
            state_root: expected_state_root,
        };
        let record = TrustedCheckpointRecord {
            version: STATE_FORMAT_VERSION,
            metadata: TrustedCheckpointMetadataRecord {
                height: metadata.height,
                tip_hash: metadata.tip_hash.0,
                state_root: metadata.state_root.0,
            },
            state: state_into_record(state),
        };
        let stage = self.staging_dir().join("trusted-checkpoint.tmp");
        let checkpoint_path = self.checkpoint_path();
        write_cbor(&stage, &record)?;
        rename(&stage, &checkpoint_path)?;

        Ok(metadata)
    }

    /// Decode only the height and tip_hash from raw snapshot bytes (without full state deserialization).
    ///
    /// Used by the cold-start logic to determine the snapshot height before persisting it,
    /// so the correct number of tail blocks can be fetched.
    pub fn decode_snapshot_metadata(bytes: &[u8]) -> Result<(u64, BlockHash), StorageError> {
        let record = decode_cbor_slice::<TrustedCheckpointRecord>(bytes, "<snapshot>")?;
        check_state_format_version(record.version)?;
        Ok((record.metadata.height, BlockHash(record.metadata.tip_hash)))
    }

    /// Return the raw CBOR bytes of the current trusted checkpoint, or `None` if none exists.
    ///
    /// Used to serve snapshots to peers via the P2P snapshot endpoint.
    pub fn export_checkpoint_bytes(&self) -> Result<Option<Vec<u8>>, StorageError> {
        let path = self.checkpoint_path();
        if !path.exists() {
            return Ok(None);
        }
        fs::read(&path)
            .map(Some)
            .map_err(|source| StorageError::Io {
                operation: "read checkpoint",
                path,
                source,
            })
    }

    /// Return `true` if a trusted checkpoint file exists on disk.
    pub fn has_checkpoint(&self) -> bool {
        self.checkpoint_path().exists()
    }

    /// Import an externally-obtained snapshot as the trusted checkpoint (CLI/operator path).
    ///
    /// Validates the CBOR structure, version, and state_root internal consistency, then
    /// writes the bytes atomically to `checkpoints/trusted-checkpoint.cbor`.
    ///
    /// **Trust boundary:** the caller (operator) vouches for the snapshot source.
    /// This method validates: CBOR decode, `version == 1`, `state.block_height == metadata.height`,
    /// `state_root` computed from state equals `metadata.state_root`. It does NOT re-execute
    /// blocks or cross-check against peer signatures. Corrupted or inconsistent inputs fail closed.
    ///
    /// The in-memory chain is NOT updated. Call this on a stopped node's data directory;
    /// the store will be re-opened on next start with `open` / `open_with_commit_policy`.
    pub fn import_external_snapshot(
        &self,
        bytes: &[u8],
        chain_id: &[u8],
    ) -> Result<TrustedCheckpointMetadata, StorageError> {
        let record = decode_cbor_slice::<TrustedCheckpointRecord>(bytes, "<snapshot>")?;
        check_state_format_version(record.version)?;
        let metadata = TrustedCheckpointMetadata {
            height: record.metadata.height,
            tip_hash: BlockHash(record.metadata.tip_hash),
            state_root: BlockHash(record.metadata.state_root),
        };
        let state = record_into_state(record.state, chain_id)?;
        if state.block_height() != metadata.height {
            return Err(StorageError::InvalidSnapshot(
                "snapshot state height does not match metadata",
            ));
        }
        let actual_root = BlockHash(state.state_root());
        if actual_root != metadata.state_root {
            return Err(StorageError::InvalidSnapshot(
                "snapshot state_root does not match metadata",
            ));
        }
        let stage = self.staging_dir().join("trusted-checkpoint.tmp");
        write_raw_bytes(&stage, bytes)?;
        rename(&stage, &self.checkpoint_path())?;
        tracing::info!(
            height = metadata.height,
            tip_hash = %hex::encode(metadata.tip_hash.0),
            "external snapshot imported as trusted checkpoint",
        );
        Ok(metadata)
    }

    /// Cold-start bootstrap from an externally-obtained snapshot plus optional tail blocks.
    ///
    /// Used when a follower node starts with an empty data directory and downloads a
    /// snapshot from a trusted peer via the P2P snapshot endpoint. The caller is responsible
    /// for fetching the snapshot bytes and any tail block bytes from the peer.
    ///
    /// After return:
    /// - The checkpoint file is written at `snapshot_height`.
    /// - Tail blocks `(snapshot_height+1)..P` are persisted to disk.
    /// - The in-memory chain is updated to reflect the new tip at height `P`.
    ///
    /// **Trust boundary:** the snapshot source is trusted by the operator. The state_root is
    /// validated for internal consistency but blocks before `snapshot_height` are not
    /// re-executed. Tail blocks go through commit-quorum validation (if a policy is set).
    /// Corrupt or inconsistent inputs fail closed with no partial writes retained.
    ///
    /// Requires the store to be empty (`height() == 0`).
    pub fn bootstrap_from_external_snapshot(
        &mut self,
        snapshot_bytes: &[u8],
        tail_block_bytes: &[Vec<u8>],
        chain_id: &[u8],
    ) -> Result<TrustedCheckpointMetadata, StorageError> {
        if self.chain.height() != 0 {
            return Err(StorageError::InvalidSnapshot(
                "cold bootstrap requires an empty disk store (height must be 0)",
            ));
        }

        // --- Step 1: decode and validate snapshot ---
        let record = decode_cbor_slice::<TrustedCheckpointRecord>(snapshot_bytes, "<snapshot>")?;
        check_state_format_version(record.version)?;
        let metadata = TrustedCheckpointMetadata {
            height: record.metadata.height,
            tip_hash: BlockHash(record.metadata.tip_hash),
            state_root: BlockHash(record.metadata.state_root),
        };
        let state = record_into_state(record.state, chain_id)?;
        if state.block_height() != metadata.height {
            return Err(StorageError::InvalidSnapshot(
                "snapshot state height does not match metadata",
            ));
        }
        let actual_root = BlockHash(state.state_root());
        if actual_root != metadata.state_root {
            return Err(StorageError::InvalidSnapshot(
                "snapshot state_root does not match metadata",
            ));
        }

        // --- Step 2: validate tail blocks in a temporary chain anchored at snapshot tip ---
        let mut tail_chain = ChainStore::new_with_base(metadata.tip_hash.clone(), metadata.height);
        let mut tail_stored: Vec<StoredBlock> = Vec::with_capacity(tail_block_bytes.len());
        for bytes in tail_block_bytes {
            let stored = Self::decode_block_bytes(bytes)?;
            self.validate_commit_proof(&stored.block)?;
            let mut trial = tail_chain.clone();
            trial.append_stored_block(stored.clone())?;
            tail_chain = trial;
            tail_stored.push(stored);
        }

        // --- Step 3: write checkpoint atomically ---
        let stage = self.staging_dir().join("trusted-checkpoint.tmp");
        write_raw_bytes(&stage, snapshot_bytes)?;
        rename(&stage, &self.checkpoint_path())?;

        // --- Step 4: persist tail blocks to disk ---
        for stored in &tail_stored {
            self.persist_stored_block(stored)?;
        }

        // --- Step 5: update the in-memory chain ---
        self.chain = tail_chain;

        tracing::info!(
            snapshot_height = metadata.height,
            tail_blocks = tail_stored.len(),
            final_height = self.chain.height(),
            tip_hash = %hex::encode(
                self.chain.tip_hash().unwrap_or(&metadata.tip_hash).0
            ),
            "cold bootstrap from external snapshot complete",
        );
        Ok(metadata)
    }

    pub fn recover_tip_with_checkpoint(
        &self,
        genesis_state: &StateStore,
        fee_params: FeeParams,
        fee_dist: pqc_state::FeeDistributionParams,
        validator_pool: Vec<pqc_types::account::Address>,
    ) -> Result<CheckpointRecoveryResult, StorageError> {
        if let Some((metadata, checkpoint_state)) =
            self.load_valid_checkpoint(genesis_state.chain_id())?
        {
            let tail: Vec<StoredBlock> = self
                .chain
                .blocks_in_order()
                .into_iter()
                .filter(|stored| stored.metadata.height > metadata.height)
                .cloned()
                .collect();

            tracing::info!(
                source = "trusted_checkpoint",
                checkpoint_height = metadata.height,
                tail_blocks = tail.len(),
                "recovering from checkpoint",
            );

            let replay = replay_blocks_from_state(
                &checkpoint_state,
                &metadata.tip_hash,
                &tail,
                fee_params.clone(),
                fee_dist.clone(),
                validator_pool.clone(),
            )
            .map_err(StorageError::Replay)?;

            tracing::info!(
                source = "trusted_checkpoint",
                height = replay.height,
                tip_hash = %hex::encode(replay.tip_hash.0),
                "recovery complete",
            );

            return Ok(CheckpointRecoveryResult {
                replay,
                source: RecoverySource::TrustedCheckpoint,
                checkpoint: Some(metadata),
            });
        }

        tracing::info!(
            source = "full_replay",
            "no valid checkpoint found, replaying from genesis"
        );

        // recover_tip reads all blocks from disk when the in-memory chain is tail-only
        // (ADR-028), so no PartialChainCannotFullReplay guard is needed here.
        let replay = self.recover_tip(genesis_state, fee_params, fee_dist, validator_pool)?;

        tracing::info!(
            source = "full_replay",
            height = replay.height,
            tip_hash = %hex::encode(replay.tip_hash.0),
            "recovery complete",
        );

        Ok(CheckpointRecoveryResult {
            replay,
            source: RecoverySource::FullReplay,
            checkpoint: None,
        })
    }

    fn persist_stored_block(&self, stored: &StoredBlock) -> Result<(), StorageError> {
        let height = stored.metadata.height;
        let block_path = self.blocks_dir().join(block_file_name(height));
        let hash_path = self
            .hashes_dir()
            .join(hash_index_file_name(&stored.metadata.block_hash));
        let tip_path = self.tip_path();

        let block_stage = self
            .staging_dir()
            .join(format!("{}.block.tmp", format_height(height)));
        let hash_stage = self.staging_dir().join(format!(
            "{}.hash.tmp",
            hex::encode(stored.metadata.block_hash.0)
        ));
        let tip_stage = self.staging_dir().join("tip.tmp");

        write_cbor(&block_stage, &stored_block_into_record(stored)?)?;
        write_cbor(
            &hash_stage,
            &HashIndexRecord {
                height: stored.metadata.height,
            },
        )?;
        write_cbor(
            &tip_stage,
            &TipRecord {
                height: stored.metadata.height,
                block_hash: stored.metadata.block_hash.0,
            },
        )?;

        rename(&block_stage, &block_path)?;
        rename(&hash_stage, &hash_path)?;
        rename(&tip_stage, &tip_path)?;

        Ok(())
    }

    fn blocks_dir(&self) -> PathBuf {
        self.root.join(BLOCKS_DIR)
    }

    fn hashes_dir(&self) -> PathBuf {
        self.root.join(HASHES_DIR)
    }

    fn staging_dir(&self) -> PathBuf {
        self.root.join(STAGING_DIR)
    }

    fn checkpoints_dir(&self) -> PathBuf {
        self.root.join(CHECKPOINTS_DIR)
    }

    fn checkpoint_path(&self) -> PathBuf {
        self.checkpoints_dir().join(CHECKPOINT_FILE)
    }

    fn tip_path(&self) -> PathBuf {
        self.root.join(TIP_FILE)
    }

    fn load_valid_checkpoint(
        &self,
        chain_id: &[u8],
    ) -> Result<Option<(TrustedCheckpointMetadata, StateStore)>, StorageError> {
        let checkpoint_path = self.checkpoint_path();
        if !checkpoint_path.exists() {
            return Ok(None);
        }

        let record = match read_cbor::<TrustedCheckpointRecord>(&checkpoint_path) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(path = %checkpoint_path.display(), error = %e, "checkpoint CBOR decode failed — falling back to full replay");
                return Ok(None);
            }
        };
        // ADR-030 / TASK-101: fail-fast on STATE_FORMAT_VERSION mismatch.
        if record.version < STATE_FORMAT_VERSION {
            return Err(StorageError::StateFormatUpgradeRequired {
                disk_version: record.version,
                binary_version: STATE_FORMAT_VERSION,
            });
        }
        if record.version > STATE_FORMAT_VERSION {
            return Err(StorageError::BinaryTooOld {
                disk_version: record.version,
                binary_version: STATE_FORMAT_VERSION,
            });
        }

        let metadata = TrustedCheckpointMetadata {
            height: record.metadata.height,
            tip_hash: BlockHash(record.metadata.tip_hash),
            state_root: BlockHash(record.metadata.state_root),
        };
        let state = match record_into_state(record.state, chain_id) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(checkpoint_height = metadata.height, error = %e, "checkpoint state deserialization failed — falling back to full replay");
                return Ok(None);
            }
        };
        if state.block_height() != metadata.height {
            tracing::warn!(
                state_height = state.block_height(),
                checkpoint_height = metadata.height,
                "checkpoint height mismatch — falling back to full replay"
            );
            return Ok(None);
        }

        let actual_state_root = BlockHash(state.state_root());
        if actual_state_root != metadata.state_root {
            tracing::warn!(
                checkpoint_height = metadata.height,
                stored_root = %hex::encode(metadata.state_root.0),
                computed_root = %hex::encode(actual_state_root.0),
                "checkpoint state_root mismatch — checkpoint written by an older binary that omitted validator state; falling back to full replay. Wipe chain data to write a fresh checkpoint."
            );
            return Ok(None);
        }

        if metadata.height == 0 {
            if metadata.tip_hash != *self.chain.anchor_prev_hash() {
                tracing::warn!(
                    "checkpoint tip_hash mismatch at height 0 — falling back to full replay"
                );
                return Ok(None);
            }
        } else {
            // Cross-check with canonical chain if the checkpoint height is within our known
            // block history. For snapshot-bootstrapped stores the pre-snapshot blocks are
            // intentionally absent; in that case trust the checkpoint — state_root was
            // verified above and the operator vouches for the snapshot source.
            if let Some(canonical) = self.chain.get_metadata_by_height(metadata.height) {
                if canonical.block_hash != metadata.tip_hash
                    || canonical.state_root != metadata.state_root
                {
                    tracing::warn!(checkpoint_height = metadata.height, "checkpoint metadata does not match canonical chain — falling back to full replay");
                    return Ok(None);
                }
            }
        }

        Ok(Some((metadata, state)))
    }

    fn validate_commit_proof(&self, block: &Block) -> Result<(), StorageError> {
        if let Some(policy) = &self.commit_policy {
            validate_block_commit_quorum(block, policy)?;
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct TipRecord {
    height: u64,
    block_hash: [u8; 32],
}

#[derive(Serialize, Deserialize)]
pub(crate) struct TrustedCheckpointRecord {
    pub(crate) version: u16,
    pub(crate) metadata: TrustedCheckpointMetadataRecord,
    pub(crate) state: StateSnapshotRecord,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct TrustedCheckpointMetadataRecord {
    pub(crate) height: u64,
    pub(crate) tip_hash: [u8; 32],
    pub(crate) state_root: [u8; 32],
}

#[derive(Serialize, Deserialize)]
pub(crate) struct HashIndexRecord {
    pub(crate) height: u64,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct StoredBlockRecord {
    pub(crate) header: BlockHeaderRecord,
    pub(crate) tx_hashes: Vec<[u8; 32]>,
    pub(crate) tx_bodies: Vec<Vec<u8>>,
    pub(crate) metadata: BlockMetadataRecord,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct BlockHeaderRecord {
    /// ADR-053 §T1.1 — `header_version: u16` is the first field and
    /// gates every future decoder dispatch. `#[serde(default)]` allows
    /// pre-ADR-053 records to decode as version 0 (i.e. "legacy");
    /// viper-pq-1 genesis ships with value 1.
    #[serde(default)]
    pub(crate) header_version: u16,
    pub(crate) height: u64,
    pub(crate) prev_hash: [u8; 32],
    pub(crate) state_root: [u8; 32],
    pub(crate) tx_root: [u8; 32],
    pub(crate) timestamp: u64,
    pub(crate) proposer: Vec<u8>,
    pub(crate) commit_signatures: Vec<CommitSigRecord>,
    /// ADR-053 §T1.1 — `extension_root` commits to a future
    /// key→value map of optional block-header extensions. At v1 this
    /// is always `empty_extension_root()`. `#[serde(default)]` decodes
    /// pre-ADR-053 records as the all-zeros sentinel (distinct from
    /// `empty_extension_root()` — the zero value is never emitted by
    /// a viper-pq-1 producer).
    #[serde(default)]
    pub(crate) extension_root: [u8; 32],
}

#[derive(Serialize, Deserialize)]
pub(crate) struct CommitSigRecord {
    pub(crate) validator_address: Vec<u8>,
    pub(crate) sig_alg_id: u16,
    pub(crate) signature: Vec<u8>,
    /// BFT round (ADR-051 / TASK-171 / SPEC-CONSENSUS-001 §8.4 §10.1).
    /// `#[serde(default)]` so legacy blocks written before this field
    /// was added still decode cleanly (round defaults to 0 — matching
    /// the single-round prototype slice that was always in effect
    /// when those blocks were produced).
    #[serde(default)]
    pub(crate) round: u32,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct BlockMetadataRecord {
    pub(crate) block_hash: [u8; 32],
    pub(crate) height: u64,
    pub(crate) prev_hash: [u8; 32],
    pub(crate) state_root: [u8; 32],
    pub(crate) tx_root: [u8; 32],
    pub(crate) timestamp: u64,
    pub(crate) bytes_used: u64,
    pub(crate) included_count: u64,
    pub(crate) deferred_count: u64,
    pub(crate) skipped_count: u64,
    pub(crate) vc_budget_consumed: u64,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct StateSnapshotRecord {
    block_height: u64,
    accounts: Vec<AccountRecord>,
    attestations: Vec<AttestationRecord>,
    governance_receipts: Vec<GovernanceReceiptRecord>,
    alg_registry: Vec<AlgRegistryRecord>,
    /// Added in checkpoint format v2. Old checkpoints without this field
    /// deserialize with an empty Vec (via serde default). Those checkpoints
    /// will fail the state_root cross-check and trigger a full replay — the
    /// correct fallback until the chain data is wiped and a fresh checkpoint
    /// (with validators) is written at the next CHECKPOINT_INTERVAL.
    #[serde(default)]
    validators: Vec<ValidatorSnapshotRecord>,
    /// Added for SPEC-FEE-002 AIMD fee market. Old checkpoints deserialize
    /// with default values and will fail the state_root cross-check, triggering
    /// a full replay — the correct fallback behaviour.
    #[serde(default)]
    fee_market_base_fee: u64,
    #[serde(default)]
    fee_market_block_gas_limit: u64,
    #[serde(default)]
    fee_market_burn_rate_bps: u16,
    /// Added for multi-step governance (TASK-100). Old checkpoints without
    /// this field deserialize with an empty Vec and will fail the state_root
    /// cross-check, triggering a full replay — the correct fallback.
    #[serde(default)]
    pending_proposals: Vec<PendingProposalRecord>,
    /// Added in STATE_FORMAT_VERSION=2 (ADR-031 / TASK-102). Old checkpoints
    /// deserialize with an empty Vec.  The v1→v2 migration handler rewrites the
    /// checkpoint so the state_root reflects the new computation (which includes
    /// an empty upgrade-leaf section).
    #[serde(default)]
    pending_upgrades: Vec<PendingUpgradeRecord>,
}

/// Flat serialization record for a pending governance proposal (TASK-100).
///
/// `effect_type` encodes which effect variant is present:
/// 1 = RegistryUpdate, 2 = BurnRateUpdate, 3 = FeeParamUpdate.
/// Fields that do not apply to the active variant are set to 0 / false.
#[derive(Serialize, Deserialize)]
pub(crate) struct PendingProposalRecord {
    proposal_id: [u8; 32],
    proposal_type: u8,
    proposer: [u8; 32],
    voting_deadline: u64,
    execute_after: u64,
    rationale_hash: [u8; 32],
    status: u8,
    // Effect discriminant: 1=RegistryUpdate, 2=BurnRateUpdate, 3=FeeParamUpdate.
    effect_type: u8,
    // RegistryUpdate fields:
    effect_alg_id: u16,
    effect_has_lifecycle: bool,
    effect_lifecycle: u8,
    effect_has_min_fee: bool,
    effect_min_fee: u64,
    // BurnRateUpdate field:
    effect_burn_rate_bps: u16,
    // FeeParamUpdate field:
    effect_block_gas_limit: u64,
    // Votes: sorted list of (address_bytes, yes).
    votes: Vec<([u8; 32], bool)>,
    // SoftwareUpgrade fields (effect_type == 4, ADR-053 §T2.3):
    effect_activate_at_timestamp_ns: u64,
    effect_expected_version: u16,
}

/// Serialization record for a pending binary upgrade (ADR-031 / TASK-102,
/// ADR-053 §T2.3 switched `activate_at_*` from height to timestamp_ns).
#[derive(Serialize, Deserialize)]
pub(crate) struct PendingUpgradeRecord {
    proposal_id: [u8; 32],
    activate_at_timestamp_ns: u64,
    expected_version: u16,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ValidatorSnapshotRecord {
    operator: [u8; 32],
    node_id: String,
    consensus_alg_id: u16,
    consensus_pk: Vec<u8>,
    self_bond: u128,
    /// Encoded ValidatorStatus: 0=Candidate, 1=Active, 2=Jailed,
    /// 3=Unbonding (unbonding_start_height stored separately), 4=Exited.
    status: u8,
    /// Non-zero only when status==3 (Unbonding).
    unbonding_start_height: u64,
    registered_height: u64,
    /// Tombstone flag: true after equivocation slashing (SPEC-SLASH-001 §9 Step 5).
    /// Defaults to false for records serialized before TASK-097.
    #[serde(default)]
    tombstoned: bool,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct AccountRecord {
    address: [u8; 32],
    balance: u128,
    nonce: u64,
    keys: Vec<KeyRecord>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct KeyRecord {
    alg_id: u16,
    pk_bytes: Vec<u8>,
    key_version: u32,
    valid_from_height: u64,
    status: u8,
    allowed_tx_types: u32,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct AlgRegistryRecord {
    alg_id: u16,
    spec_ref: String,
    pk_size: u64,
    sig_size: u64,
    sig_class: Option<u8>,
    min_fee: u64,
    lifecycle: u8,
    benchmark_verify_per_sec: u32,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct GovernanceReceiptRecord {
    proposal_id: [u8; 32],
    proposal_type: u8,
    proposer: [u8; 32],
    target_alg_id: u16,
    lifecycle_before: u8,
    lifecycle_after: u8,
    min_fee_before: u64,
    min_fee_after: u64,
    rationale_hash: [u8; 32],
    executed_at_height: u64,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct AttestationRecord {
    attestation_id: [u8; 32],
    attester: [u8; 32],
    subject: [u8; 32],
    attestation_type: u16,
    content_hash: [u8; 32],
    schema_id: [u8; 32],
    metadata_hash: Option<[u8; 32]>,
    anchor_height: u64,
    expires_at_height: Option<u64>,
    status: u8,
    revocation: Option<AttestationRevocationRecord>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct AttestationRevocationRecord {
    revoked_at_height: u64,
    revoker: [u8; 32],
    revocation_reason_hash: Option<[u8; 32]>,
}

pub(crate) fn stored_block_into_record(
    stored: &StoredBlock,
) -> Result<StoredBlockRecord, StorageError> {
    let tx_bodies = stored
        .included_transactions
        .iter()
        .enumerate()
        .map(|(tx_index, tx)| {
            encode_tx(tx).map_err(|source| StorageError::TxEncodeFailed {
                height: stored.metadata.height,
                tx_index,
                source,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(StoredBlockRecord {
        header: BlockHeaderRecord {
            header_version: stored.block.header.header_version,
            height: stored.block.header.height,
            prev_hash: stored.block.header.prev_hash.0,
            state_root: stored.block.header.state_root.0,
            tx_root: stored.block.header.tx_root.0,
            timestamp: stored.block.header.timestamp,
            proposer: stored.block.header.proposer.clone(),
            extension_root: stored.block.header.extension_root,
            commit_signatures: stored
                .block
                .commit_signatures
                .iter()
                .map(|sig| CommitSigRecord {
                    validator_address: sig.validator_address.clone(),
                    sig_alg_id: sig.sig_alg_id.as_u16(),
                    signature: sig.signature.clone(),
                    round: sig.round,
                })
                .collect(),
        },
        tx_hashes: stored.block.tx_hashes.iter().map(|hash| hash.0).collect(),
        tx_bodies,
        metadata: BlockMetadataRecord {
            block_hash: stored.metadata.block_hash.0,
            height: stored.metadata.height,
            prev_hash: stored.metadata.prev_hash.0,
            state_root: stored.metadata.state_root.0,
            tx_root: stored.metadata.tx_root.0,
            timestamp: stored.metadata.timestamp,
            bytes_used: stored.metadata.bytes_used as u64,
            included_count: stored.metadata.included_count as u64,
            deferred_count: stored.metadata.deferred_count as u64,
            skipped_count: stored.metadata.skipped_count as u64,
            vc_budget_consumed: stored.metadata.vc_budget_consumed as u64,
        },
    })
}

pub(crate) fn record_into_stored_block(
    record: StoredBlockRecord,
    expected_height: u64,
) -> Result<StoredBlock, StorageError> {
    if record.tx_hashes.len() != record.tx_bodies.len() {
        return Err(StorageError::InvalidPersistedValue(
            "tx_hashes and tx_bodies length mismatch",
        ));
    }

    let included_transactions = record
        .tx_bodies
        .iter()
        .enumerate()
        .map(|(tx_index, raw)| {
            let expected_hash = TxHash(record.tx_hashes[tx_index]);
            let actual_hash = TxHash(compute_tx_hash(raw));
            if actual_hash != expected_hash {
                return Err(StorageError::TxBodyHashMismatch {
                    height: expected_height,
                    tx_index,
                    expected: expected_hash,
                    got: actual_hash,
                });
            }

            decode_tx(raw).map_err(|source| StorageError::TxDecodeFailed {
                height: expected_height,
                tx_index,
                source,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let commit_signatures = record
        .header
        .commit_signatures
        .into_iter()
        .map(|sig| {
            let sig_alg_id = AlgId::from_u16(sig.sig_alg_id)
                .ok_or(StorageError::InvalidPersistedAlgId(sig.sig_alg_id))?;
            Ok(CommitSig {
                validator_address: sig.validator_address,
                sig_alg_id,
                signature: sig.signature,
                round: sig.round,
            })
        })
        .collect::<Result<Vec<_>, StorageError>>()?;

    Ok(StoredBlock {
        block: Block {
            header: BlockHeader {
                header_version: record.header.header_version,
                height: record.header.height,
                prev_hash: BlockHash(record.header.prev_hash),
                state_root: BlockHash(record.header.state_root),
                tx_root: BlockHash(record.header.tx_root),
                timestamp: record.header.timestamp,
                proposer: record.header.proposer,
                extension_root: record.header.extension_root,
            },
            tx_hashes: record.tx_hashes.into_iter().map(TxHash).collect(),
            commit_signatures,
        },
        metadata: BlockMetadata {
            block_hash: BlockHash(record.metadata.block_hash),
            height: record.metadata.height,
            prev_hash: BlockHash(record.metadata.prev_hash),
            state_root: BlockHash(record.metadata.state_root),
            tx_root: BlockHash(record.metadata.tx_root),
            timestamp: record.metadata.timestamp,
            bytes_used: usize::try_from(record.metadata.bytes_used).map_err(|_| {
                StorageError::InvalidPersistedValue("bytes_used does not fit usize")
            })?,
            included_count: usize::try_from(record.metadata.included_count).map_err(|_| {
                StorageError::InvalidPersistedValue("included_count does not fit usize")
            })?,
            deferred_count: usize::try_from(record.metadata.deferred_count).map_err(|_| {
                StorageError::InvalidPersistedValue("deferred_count does not fit usize")
            })?,
            skipped_count: usize::try_from(record.metadata.skipped_count).map_err(|_| {
                StorageError::InvalidPersistedValue("skipped_count does not fit usize")
            })?,
            vc_budget_consumed: usize::try_from(record.metadata.vc_budget_consumed).map_err(
                |_| StorageError::InvalidPersistedValue("vc_budget_consumed does not fit usize"),
            )?,
        },
        included_transactions,
    })
}

pub(crate) fn encode_stored_block_bytes(stored: &StoredBlock) -> Result<Vec<u8>, StorageError> {
    let record = stored_block_into_record(stored)?;
    let mut out = Vec::new();
    ciborium::into_writer(&record, &mut out).map_err(|err| StorageError::Encode {
        path: PathBuf::from("<p2p-block>"),
        detail: err.to_string(),
    })?;
    Ok(out)
}

pub(crate) fn decode_cbor_slice<T: DeserializeOwned>(
    bytes: &[u8],
    label: &'static str,
) -> Result<T, StorageError> {
    ciborium::from_reader(bytes).map_err(|err| StorageError::Decode {
        path: PathBuf::from(label),
        detail: err.to_string(),
    })
}

/// Encode a value to CBOR bytes (used by `apply_upgrade_chain` migration path).
pub(crate) fn encode_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, StorageError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|err| StorageError::Encode {
        path: PathBuf::from("<cbor>"),
        detail: err.to_string(),
    })?;
    Ok(buf)
}

pub(crate) fn state_into_record(state: &StateStore) -> StateSnapshotRecord {
    StateSnapshotRecord {
        block_height: state.block_height(),
        accounts: state
            .accounts_in_order()
            .into_iter()
            .map(|account| AccountRecord {
                address: account.address.0,
                balance: account.balance,
                nonce: account.nonce,
                keys: account
                    .keys
                    .0
                    .iter()
                    .map(|key| KeyRecord {
                        alg_id: key.alg_id.as_u16(),
                        pk_bytes: key.pk_bytes.to_vec(),
                        key_version: key.key_version,
                        valid_from_height: key.valid_from_height,
                        status: encode_key_status(key.status),
                        allowed_tx_types: key.allowed_tx_types,
                    })
                    .collect(),
            })
            .collect(),
        attestations: state
            .attestations_in_order()
            .into_iter()
            .map(|attestation| AttestationRecord {
                attestation_id: attestation.attestation_id.0,
                attester: attestation.attester.0,
                subject: attestation.subject,
                attestation_type: attestation.attestation_type,
                content_hash: attestation.content_hash,
                schema_id: attestation.schema_id,
                metadata_hash: attestation.metadata_hash,
                anchor_height: attestation.anchor_height,
                expires_at_height: attestation.expires_at_height,
                status: encode_attestation_status(attestation.status),
                revocation: attestation.revocation.as_ref().map(|revocation| {
                    AttestationRevocationRecord {
                        revoked_at_height: revocation.revoked_at_height,
                        revoker: revocation.revoker.0,
                        revocation_reason_hash: revocation.revocation_reason_hash,
                    }
                }),
            })
            .collect(),
        governance_receipts: state
            .governance_receipts_in_order()
            .into_iter()
            .map(|receipt| GovernanceReceiptRecord {
                proposal_id: receipt.proposal_id.0,
                proposal_type: receipt.proposal_type.as_u8(),
                proposer: receipt.proposer.0,
                target_alg_id: receipt.target_alg_id.as_u16(),
                lifecycle_before: encode_lifecycle(receipt.lifecycle_before),
                lifecycle_after: encode_lifecycle(receipt.lifecycle_after),
                min_fee_before: receipt.min_fee_before,
                min_fee_after: receipt.min_fee_after,
                rationale_hash: receipt.rationale_hash,
                executed_at_height: receipt.executed_at_height,
            })
            .collect(),
        alg_registry: state
            .alg_entries_in_order()
            .into_iter()
            .map(|entry| AlgRegistryRecord {
                alg_id: entry.alg_id.as_u16(),
                spec_ref: entry.spec_ref.to_string(),
                pk_size: entry.pk_size as u64,
                sig_size: entry.sig_size as u64,
                sig_class: entry.sig_class.map(encode_sig_class),
                min_fee: entry.min_fee,
                lifecycle: encode_lifecycle(entry.lifecycle),
                benchmark_verify_per_sec: entry.benchmark_verify_per_sec,
            })
            .collect(),
        validators: state
            .validators_in_order()
            .into_iter()
            .map(|v| {
                let (status, unbonding_start_height) = encode_validator_status(&v.status);
                ValidatorSnapshotRecord {
                    operator: v.operator.0,
                    node_id: v.node_id.clone(),
                    consensus_alg_id: v.consensus_alg_id.as_u16(),
                    consensus_pk: v.consensus_pk.clone(),
                    self_bond: v.self_bond,
                    status,
                    unbonding_start_height,
                    registered_height: v.registered_height,
                    tombstoned: v.tombstoned,
                }
            })
            .collect(),
        // ADR-053 §T2.1: snapshot schema captures the compute dimension
        // only. Storage/witness/contention are reserved (target = 0,
        // base_fee at floor) at launch; a future STATE_FORMAT_VERSION
        // bump extends the schema when they activate.
        fee_market_base_fee: state.fee_market.compute.base_fee,
        fee_market_block_gas_limit: state.fee_market.compute.limit,
        fee_market_burn_rate_bps: state.fee_market.burn_rate_bps,
        pending_proposals: state
            .pending_proposals_in_order()
            .into_iter()
            .map(|p| {
                let status = match p.status {
                    ProposalStatus::Voting => 0,
                    ProposalStatus::Executed => 1,
                    ProposalStatus::Expired => 2,
                    ProposalStatus::Rejected => 3,
                    ProposalStatus::ExecutionFailed => 4,
                };
                let (
                    effect_type,
                    effect_alg_id,
                    effect_has_lifecycle,
                    effect_lifecycle,
                    effect_has_min_fee,
                    effect_min_fee,
                    effect_burn_rate_bps,
                    effect_block_gas_limit,
                    effect_activate_at_timestamp_ns,
                    effect_expected_version,
                ) = match &p.effect {
                    ProposalEffect::RegistryUpdate {
                        alg_id,
                        target_lifecycle,
                        new_min_fee,
                    } => (
                        1u8,
                        alg_id.as_u16(),
                        target_lifecycle.is_some(),
                        target_lifecycle.map(encode_lifecycle).unwrap_or(0),
                        new_min_fee.is_some(),
                        new_min_fee.unwrap_or(0),
                        0u16,
                        0u64,
                        0u64,
                        0u16,
                    ),
                    ProposalEffect::BurnRateUpdate { new_burn_rate_bps } => (
                        2u8,
                        0,
                        false,
                        0,
                        false,
                        0,
                        *new_burn_rate_bps,
                        0u64,
                        0u64,
                        0u16,
                    ),
                    ProposalEffect::FeeParamUpdate {
                        new_block_gas_limit,
                    } => (
                        3u8,
                        0,
                        false,
                        0,
                        false,
                        0,
                        0u16,
                        *new_block_gas_limit,
                        0u64,
                        0u16,
                    ),
                    ProposalEffect::SoftwareUpgrade {
                        activate_at_timestamp_ns,
                        expected_version,
                    } => (
                        4u8,
                        0,
                        false,
                        0,
                        false,
                        0,
                        0u16,
                        0u64,
                        *activate_at_timestamp_ns,
                        *expected_version,
                    ),
                    // ADR-049 AddAlgorithm / ADR-050 AddSlashingVerifier:
                    // the legacy PendingProposalRecord schema cannot represent
                    // their full payload (spec_ref is a variable-length
                    // string). Snapshot serialization encodes only the
                    // effect_type discriminant; restore rejects the record
                    // with `InvalidPersistedValue`.  Expanding the record
                    // schema is a STATE_FORMAT_VERSION bump, tracked as a
                    // follow-up to ADR-049/050 (the present commit lands the
                    // type + apply + state-root wiring; snapshot support
                    // comes when the first governance-added algorithm or
                    // slashing verifier actually lives past a checkpoint).
                    ProposalEffect::AddAlgorithm(_) => {
                        (5u8, 0, false, 0, false, 0, 0u16, 0u64, 0u64, 0u16)
                    }
                    ProposalEffect::AddSlashingVerifier(_) => {
                        (6u8, 0, false, 0, false, 0, 0u16, 0u64, 0u64, 0u16)
                    }
                    // ADR-053 §T1.4 AddHash: same legacy-record constraint as
                    // AddAlgorithm above — spec_ref is variable-length, so the
                    // snapshot schema encodes only the effect_type discriminant
                    // and restore rejects the record with `InvalidPersistedValue`.
                    // Full AddHash snapshot support is a STATE_FORMAT_VERSION bump.
                    ProposalEffect::AddHash(_) => {
                        (7u8, 0, false, 0, false, 0, 0u16, 0u64, 0u64, 0u16)
                    }
                    // ADR-053 §T3.5 AddAuthTemplate: same legacy-record
                    // constraint — apply-side dispatch + on-chain registry +
                    // snapshot field-expansion all land together in the
                    // follow-up STATE_FORMAT_VERSION bump.
                    ProposalEffect::AddAuthTemplate(_) => {
                        (8u8, 0, false, 0, false, 0, 0u16, 0u64, 0u64, 0u16)
                    }
                };
                let mut votes: Vec<([u8; 32], bool)> =
                    p.votes.iter().map(|(addr, &yes)| (addr.0, yes)).collect();
                votes.sort_by_key(|(addr, _)| *addr);
                PendingProposalRecord {
                    proposal_id: p.proposal_id.0,
                    proposal_type: p.proposal_type.as_u8(),
                    proposer: p.proposer.0,
                    voting_deadline: p.voting_deadline,
                    execute_after: p.execute_after,
                    rationale_hash: p.rationale_hash,
                    status,
                    effect_type,
                    effect_alg_id,
                    effect_has_lifecycle,
                    effect_lifecycle,
                    effect_has_min_fee,
                    effect_min_fee,
                    effect_burn_rate_bps,
                    effect_block_gas_limit,
                    effect_activate_at_timestamp_ns,
                    effect_expected_version,
                    votes,
                }
            })
            .collect(),
        pending_upgrades: state
            .pending_upgrades_in_order()
            .into_iter()
            .map(|u| PendingUpgradeRecord {
                proposal_id: u.proposal_id.0,
                activate_at_timestamp_ns: u.activate_at_timestamp_ns,
                expected_version: u.expected_version,
            })
            .collect(),
    }
}

pub(crate) fn record_into_state(
    record: StateSnapshotRecord,
    chain_id: &[u8],
) -> Result<StateStore, StorageError> {
    let alg_registry = validate_registry_snapshot(&record.alg_registry)?;

    let accounts = record
        .accounts
        .into_iter()
        .map(|account| {
            let keys = account
                .keys
                .into_iter()
                .map(|key| {
                    let alg_id = AlgId::from_u16(key.alg_id)
                        .ok_or(StorageError::InvalidPersistedAlgId(key.alg_id))?;
                    Ok(KeyEntry {
                        alg_id,
                        pk_bytes: key.pk_bytes.into(),
                        key_version: key.key_version,
                        valid_from_height: key.valid_from_height,
                        status: decode_key_status(key.status).ok_or(
                            StorageError::InvalidPersistedValue("unknown checkpoint key status"),
                        )?,
                        allowed_tx_types: key.allowed_tx_types,
                    })
                })
                .collect::<Result<Vec<_>, StorageError>>()?;

            Ok(Account {
                address: Address(account.address),
                balance: account.balance,
                nonce: account.nonce,
                keys: KeySet(keys),
                policy_version: 0,
                policy_hash: None,
                verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
                auth_data: Vec::new(),
            })
        })
        .collect::<Result<Vec<_>, StorageError>>()?;

    let attestations = record
        .attestations
        .into_iter()
        .map(|attestation| {
            Ok(Attestation {
                attestation_id: AttestationId(attestation.attestation_id),
                attester: Address(attestation.attester),
                subject: attestation.subject,
                attestation_type: attestation.attestation_type,
                content_hash: attestation.content_hash,
                schema_id: attestation.schema_id,
                metadata_hash: attestation.metadata_hash,
                anchor_height: attestation.anchor_height,
                expires_at_height: attestation.expires_at_height,
                status: decode_attestation_status(attestation.status).ok_or(
                    StorageError::InvalidPersistedValue("unknown checkpoint attestation status"),
                )?,
                revocation: attestation
                    .revocation
                    .map(|revocation| AttestationRevocation {
                        revoked_at_height: revocation.revoked_at_height,
                        revoker: Address(revocation.revoker),
                        revocation_reason_hash: revocation.revocation_reason_hash,
                    }),
            })
        })
        .collect::<Result<Vec<_>, StorageError>>()?;

    let governance_receipts = record
        .governance_receipts
        .into_iter()
        .map(|receipt| {
            let proposal_type = GovernanceProposalType::from_u8(receipt.proposal_type).ok_or(
                StorageError::InvalidPersistedValue("unknown checkpoint governance proposal type"),
            )?;
            let target_alg_id = AlgId::from_u16(receipt.target_alg_id)
                .ok_or(StorageError::InvalidPersistedAlgId(receipt.target_alg_id))?;
            Ok(GovernanceReceipt {
                proposal_id: TxHash(receipt.proposal_id),
                proposal_type,
                proposer: Address(receipt.proposer),
                target_alg_id,
                lifecycle_before: decode_lifecycle(receipt.lifecycle_before).ok_or(
                    StorageError::InvalidPersistedValue(
                        "unknown checkpoint governance lifecycle_before",
                    ),
                )?,
                lifecycle_after: decode_lifecycle(receipt.lifecycle_after).ok_or(
                    StorageError::InvalidPersistedValue(
                        "unknown checkpoint governance lifecycle_after",
                    ),
                )?,
                min_fee_before: receipt.min_fee_before,
                min_fee_after: receipt.min_fee_after,
                rationale_hash: receipt.rationale_hash,
                executed_at_height: receipt.executed_at_height,
            })
        })
        .collect::<Result<Vec<_>, StorageError>>()?;

    let validators = record
        .validators
        .into_iter()
        .map(|v| {
            let alg_id = AlgId::from_u16(v.consensus_alg_id)
                .ok_or(StorageError::InvalidPersistedAlgId(v.consensus_alg_id))?;
            let status = decode_validator_status(v.status, v.unbonding_start_height).ok_or(
                StorageError::InvalidPersistedValue("unknown checkpoint validator status"),
            )?;
            Ok(ValidatorRecord {
                operator: Address(v.operator),
                node_id: v.node_id,
                consensus_alg_id: alg_id,
                consensus_pk: v.consensus_pk,
                self_bond: v.self_bond,
                status,
                registered_height: v.registered_height,
                tombstoned: v.tombstoned,
            })
        })
        .collect::<Result<Vec<_>, StorageError>>()?;

    let mut state = StateStore::from_snapshot_full(
        accounts,
        attestations,
        governance_receipts,
        alg_registry,
        record.block_height,
        chain_id.to_vec(),
    );
    for validator in validators {
        state.insert_validator(validator);
    }
    // Restore AIMD fee market state — SPEC-FEE-002. Old checkpoints (before
    // fee_market fields were added) deserialize fee_market_block_gas_limit=0.
    // A zero gas_limit is always invalid; use it as the sentinel for old format.
    // In that case the defaults from StateStore::new() remain — the state_root
    // mismatch in load_valid_checkpoint will trigger a full replay.
    if record.fee_market_block_gas_limit > 0 {
        // ADR-053 §T2.1: snapshot carries compute-dim scalars only;
        // storage/witness/contention keep their `reserved_default`
        // shape until a future STATE_FORMAT_VERSION bump.
        let mut fm = pqc_state::FeeMarketState::default();
        fm.compute.base_fee = record.fee_market_base_fee;
        fm.compute.limit = record.fee_market_block_gas_limit;
        fm.burn_rate_bps = record.fee_market_burn_rate_bps;
        state.restore_fee_market(fm);
    }

    // Restore pending governance proposals — TASK-100.
    for rec in record.pending_proposals {
        let proposal_type = GovernanceProposalType::from_u8(rec.proposal_type).ok_or(
            StorageError::InvalidPersistedValue("unknown pending_proposal proposal_type"),
        )?;
        let status = match rec.status {
            0 => ProposalStatus::Voting,
            1 => ProposalStatus::Executed,
            2 => ProposalStatus::Expired,
            3 => ProposalStatus::Rejected,
            4 => ProposalStatus::ExecutionFailed,
            _ => {
                return Err(StorageError::InvalidPersistedValue(
                    "unknown pending_proposal status",
                ))
            }
        };
        let effect = match rec.effect_type {
            1 => {
                let alg_id = AlgId::from_u16(rec.effect_alg_id)
                    .ok_or(StorageError::InvalidPersistedAlgId(rec.effect_alg_id))?;
                let target_lifecycle = if rec.effect_has_lifecycle {
                    Some(decode_lifecycle(rec.effect_lifecycle).ok_or(
                        StorageError::InvalidPersistedValue("unknown pending_proposal lifecycle"),
                    )?)
                } else {
                    None
                };
                let new_min_fee = if rec.effect_has_min_fee {
                    Some(rec.effect_min_fee)
                } else {
                    None
                };
                ProposalEffect::RegistryUpdate {
                    alg_id,
                    target_lifecycle,
                    new_min_fee,
                }
            }
            2 => ProposalEffect::BurnRateUpdate {
                new_burn_rate_bps: rec.effect_burn_rate_bps,
            },
            3 => ProposalEffect::FeeParamUpdate {
                new_block_gas_limit: rec.effect_block_gas_limit,
            },
            4 => ProposalEffect::SoftwareUpgrade {
                activate_at_timestamp_ns: rec.effect_activate_at_timestamp_ns,
                expected_version: rec.effect_expected_version,
            },
            _ => {
                return Err(StorageError::InvalidPersistedValue(
                    "unknown pending_proposal effect_type",
                ))
            }
        };
        let votes: std::collections::HashMap<Address, bool> = rec
            .votes
            .into_iter()
            .map(|(addr_bytes, yes)| (Address(addr_bytes), yes))
            .collect();
        state.insert_pending_proposal(PendingProposal {
            proposal_id: TxHash(rec.proposal_id),
            proposal_type,
            proposer: Address(rec.proposer),
            voting_deadline: rec.voting_deadline,
            execute_after: rec.execute_after,
            rationale_hash: rec.rationale_hash,
            status,
            effect,
            votes,
        });
    }

    // Restore pending software upgrades — ADR-031 / ADR-053 §T2.3.
    for rec in record.pending_upgrades {
        state.insert_pending_upgrade(PendingUpgrade {
            proposal_id: TxHash(rec.proposal_id),
            activate_at_timestamp_ns: rec.activate_at_timestamp_ns,
            expected_version: rec.expected_version,
        });
    }

    Ok(state)
}

pub(crate) fn validate_registry_snapshot(
    records: &[AlgRegistryRecord],
) -> Result<Vec<pqc_crypto::registry::AlgEntry>, StorageError> {
    let expected = phase1_registry();
    if records.len() != expected.len() {
        return Err(StorageError::CheckpointRegistryMismatch(
            "registry length does not match the local phase-1 baseline",
        ));
    }

    // Build a lookup map keyed by alg_id so ordering differences between the
    // checkpoint serialization (sorted by alg_id numeric value) and the
    // phase1_registry() declaration order don't cause spurious mismatches.
    let expected_by_id: std::collections::HashMap<u16, &pqc_crypto::registry::AlgEntry> =
        expected.iter().map(|e| (e.alg_id.as_u16(), e)).collect();

    let mut restored = Vec::with_capacity(records.len());

    for record in records.iter() {
        let entry =
            expected_by_id
                .get(&record.alg_id)
                .ok_or(StorageError::CheckpointRegistryMismatch(
                    "checkpoint contains unknown alg_id not in local phase-1 baseline",
                ))?;
        if record.spec_ref != entry.spec_ref
            || record.pk_size != entry.pk_size as u64
            || record.sig_size != entry.sig_size as u64
            || record.sig_class != entry.sig_class.map(encode_sig_class)
            || record.benchmark_verify_per_sec != entry.benchmark_verify_per_sec
        {
            return Err(StorageError::CheckpointRegistryMismatch(
                "registry contents do not match the local phase-1 baseline",
            ));
        }

        let lifecycle = decode_lifecycle(record.lifecycle).ok_or(
            StorageError::CheckpointRegistryMismatch("registry lifecycle is invalid"),
        )?;
        let mut restored_entry = (*entry).clone();
        restored_entry.lifecycle = lifecycle;
        restored_entry.min_fee = record.min_fee;
        restored.push(restored_entry);
    }

    Ok(restored)
}

pub(crate) fn encode_attestation_status(status: AttestationStatus) -> u8 {
    match status {
        AttestationStatus::Active => 0,
        AttestationStatus::Revoked => 1,
    }
}

pub(crate) fn decode_attestation_status(status: u8) -> Option<AttestationStatus> {
    match status {
        0 => Some(AttestationStatus::Active),
        1 => Some(AttestationStatus::Revoked),
        _ => None,
    }
}

pub(crate) fn encode_key_status(status: KeyStatus) -> u8 {
    match status {
        KeyStatus::Pending => 0,
        KeyStatus::Active => 1,
        KeyStatus::Revoked => 2,
    }
}

pub(crate) fn decode_key_status(encoded: u8) -> Option<KeyStatus> {
    match encoded {
        0 => Some(KeyStatus::Pending),
        1 => Some(KeyStatus::Active),
        2 => Some(KeyStatus::Revoked),
        _ => None,
    }
}

pub(crate) fn encode_lifecycle(lifecycle: Lifecycle) -> u8 {
    match lifecycle {
        Lifecycle::Active => 0,
        Lifecycle::Discouraged => 1,
        Lifecycle::Deprecated => 2,
        Lifecycle::Banned => 3,
    }
}

pub(crate) fn decode_lifecycle(encoded: u8) -> Option<Lifecycle> {
    match encoded {
        0 => Some(Lifecycle::Active),
        1 => Some(Lifecycle::Discouraged),
        2 => Some(Lifecycle::Deprecated),
        3 => Some(Lifecycle::Banned),
        _ => None,
    }
}

pub(crate) fn encode_sig_class(sig_class: SigClass) -> u8 {
    match sig_class {
        SigClass::Reduced => 0,
        SigClass::Standard => 1,
        SigClass::Premium => 2,
    }
}

/// Returns `(status_byte, unbonding_start_height)`. For all non-Unbonding
/// statuses `unbonding_start_height` is 0. Encoding: 0=Candidate, 1=Active,
/// 2=Jailed, 3=Unbonding, 4=Exited.
pub(crate) fn encode_validator_status(status: &ValidatorStatus) -> (u8, u64) {
    match status {
        ValidatorStatus::Candidate => (0, 0),
        ValidatorStatus::Active => (1, 0),
        ValidatorStatus::Jailed => (2, 0),
        ValidatorStatus::Unbonding { start_height } => (3, *start_height),
        ValidatorStatus::Exited => (4, 0),
    }
}

pub(crate) fn decode_validator_status(
    encoded: u8,
    unbonding_start_height: u64,
) -> Option<ValidatorStatus> {
    match encoded {
        0 => Some(ValidatorStatus::Candidate),
        1 => Some(ValidatorStatus::Active),
        2 => Some(ValidatorStatus::Jailed),
        3 => Some(ValidatorStatus::Unbonding {
            start_height: unbonding_start_height,
        }),
        4 => Some(ValidatorStatus::Exited),
        _ => None,
    }
}

fn ensure_dir(path: &Path) -> Result<(), StorageError> {
    fs::create_dir_all(path).map_err(|source| StorageError::Io {
        operation: "create_dir_all",
        path: path.to_path_buf(),
        source,
    })
}

fn rename(from: &Path, to: &Path) -> Result<(), StorageError> {
    fs::rename(from, to).map_err(|source| StorageError::Io {
        operation: "rename",
        path: to.to_path_buf(),
        source,
    })
}

fn read_cbor<T: DeserializeOwned>(path: &Path) -> Result<T, StorageError> {
    let file = File::open(path).map_err(|source| StorageError::Io {
        operation: "open",
        path: path.to_path_buf(),
        source,
    })?;
    ciborium::from_reader(BufReader::new(file)).map_err(|err| StorageError::Decode {
        path: path.to_path_buf(),
        detail: err.to_string(),
    })
}

fn write_cbor<T: Serialize>(path: &Path, value: &T) -> Result<(), StorageError> {
    let file = File::create(path).map_err(|source| StorageError::Io {
        operation: "create",
        path: path.to_path_buf(),
        source,
    })?;
    ciborium::into_writer(value, BufWriter::new(file)).map_err(|err| StorageError::Encode {
        path: path.to_path_buf(),
        detail: err.to_string(),
    })
}

fn dir_entries(path: &Path) -> Result<Vec<String>, StorageError> {
    let mut entries = fs::read_dir(path)
        .map_err(|source| StorageError::Io {
            operation: "read_dir",
            path: path.to_path_buf(),
            source,
        })?
        .map(|entry| {
            entry
                .map_err(|source| StorageError::Io {
                    operation: "read_dir_entry",
                    path: path.to_path_buf(),
                    source,
                })
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort();
    Ok(entries)
}

fn ensure_inventory_exact<F>(
    dir: &Path,
    expected: &BTreeSet<String>,
    map_error: F,
) -> Result<(), StorageError>
where
    F: Fn(String) -> StorageError,
{
    let actual: BTreeSet<String> = dir_entries(dir)?.into_iter().collect();
    if actual == *expected {
        return Ok(());
    }

    if let Some(extra) = actual.difference(expected).next() {
        return Err(map_error(extra.clone()));
    }

    if let Some(missing) = expected.difference(&actual).next() {
        return Err(map_error(missing.clone()));
    }

    Ok(())
}

fn format_height(height: u64) -> String {
    format!("{height:020}")
}

fn block_file_name(height: u64) -> String {
    format!("{}.cbor", format_height(height))
}

fn hash_index_file_name(block_hash: &BlockHash) -> String {
    format!("{}.cbor", hex::encode(block_hash.0))
}

/// Write raw bytes to a file, wrapping IO errors in `StorageError::Io`.
fn write_raw_bytes(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    fs::write(path, bytes).map_err(|source| StorageError::Io {
        operation: "write",
        path: path.to_path_buf(),
        source,
    })
}

/// Read the snapshot base from a checkpoint file without full state deserialization.
///
/// Returns `Some((height, tip_hash))` if the checkpoint exists, has `version == 1`,
/// and records a non-zero height (indicating blocks before that height are absent).
/// Returns `None` in all other cases (file absent, parse error, or height == 0).
/// Fail-fast version check for checkpoint records (ADR-030 / TASK-101).
///
/// Returns `Ok(())` if `disk_version == STATE_FORMAT_VERSION`.
/// Returns `Err(StateFormatUpgradeRequired)` if the disk checkpoint is older.
/// Returns `Err(BinaryTooOld)` if the disk checkpoint is newer (binary needs upgrade).
pub(crate) fn check_state_format_version(disk_version: u16) -> Result<(), StorageError> {
    if disk_version < STATE_FORMAT_VERSION {
        return Err(StorageError::StateFormatUpgradeRequired {
            disk_version,
            binary_version: STATE_FORMAT_VERSION,
        });
    }
    if disk_version > STATE_FORMAT_VERSION {
        return Err(StorageError::BinaryTooOld {
            disk_version,
            binary_version: STATE_FORMAT_VERSION,
        });
    }
    Ok(())
}

fn read_snapshot_base_if_present(
    checkpoint_path: &Path,
) -> Result<Option<(u64, BlockHash)>, StorageError> {
    if !checkpoint_path.exists() {
        return Ok(None);
    }
    let record = match read_cbor::<TrustedCheckpointRecord>(checkpoint_path) {
        Ok(r) => r,
        Err(_) => return Ok(None), // CBOR decode failure → no snapshot base
    };
    // ADR-030 / TASK-101: fail-fast on version mismatch.
    check_state_format_version(record.version)?;
    if record.metadata.height == 0 {
        return Ok(None);
    }
    Ok(Some((
        record.metadata.height,
        BlockHash(record.metadata.tip_hash),
    )))
}

#[cfg(test)]
mod tests;
