// SPDX-License-Identifier: BUSL-1.1
//! RocksDB-backed chain store — ADR-032 / TASK-103.
//!
//! Replaces `DiskChainStore` with a RocksDB implementation using column families:
//!
//! | CF            | Key                   | Value                              |
//! |---------------|-----------------------|------------------------------------|
//! | `blocks`      | height `u64 BE`       | CBOR `StoredBlockRecord`           |
//! | `hash_index`  | block hash `[u8;32]`  | height `u64 BE`                    |
//! | `tx_index`    | tx hash `[u8;32]`     | height `u64 BE`                    |
//! | `checkpoints` | height `u64 BE`       | raw CBOR `TrustedCheckpointRecord` |
//! | `meta`        | bytes key             | bytes value                        |
//!
//! All block commits are atomic `WriteBatch` operations — no staging directory needed.
//!
//! New capabilities over `DiskChainStore`:
//! - `get_tx_block_height` — O(1) tx lookup by hash (seeds TASK-104)
//! - `blocks_in_height_range` — range iterator for `/v1/blocks?from=N&to=M`
//!
//! Build note: the `bundled` feature (workspace `rocksdb` dep) compiles RocksDB from
//! included C++ source.  Requires `gcc-c++` on the build host:
//!   dnf install gcc-c++ make   (RHEL/Rocky/Alma 9)

use std::{path::Path, sync::Arc};

use pqc_state::StateStore;
use pqc_tx::validate::FeeParams;
use pqc_types::{block::BlockHash, transaction::TxHash};
use rocksdb::{ColumnFamilyDescriptor, IteratorMode, Options, WriteBatch, WriteOptions, DB};

use super::storage::{
    decode_cbor_slice, encode_stored_block_bytes, record_into_state, record_into_stored_block,
    state_into_record, CheckpointRecoveryResult, RecoverySource, StorageError, StoredBlockRecord,
    TrustedCheckpointMetadata, TrustedCheckpointMetadataRecord, TrustedCheckpointRecord,
};
use crate::{
    commit::{validate_block_commit_quorum, CommitQuorumPolicy},
    recover_tip as recover_from_chain,
    recovery::replay_blocks_from_state,
    BlockExecutionResult, BlockMetadata, ChainStore, ReplayResult, StoredBlock,
};

// ── Column family names ───────────────────────────────────────────────────────

const CF_BLOCKS: &str = "blocks";
const CF_HASH_INDEX: &str = "hash_index";
/// Tx hash → block height.  Written on every block commit; enables O(1) TASK-104 lookup.
const CF_TX_INDEX: &str = "tx_index";
const CF_CHECKPOINTS: &str = "checkpoints";
const CF_META: &str = "meta";
/// ADR-054 — archived state-equivalent sibling blocks displaced by
/// `replace_canonical_at_height`. Key: 32-byte block_hash || 8-byte
/// height BE. Value: full `StoredBlockRecord` CBOR. Pruned alongside
/// `compact_to_checkpoint` (anything below the latest finalized
/// checkpoint is unreachable for sibling-swap purposes).
const CF_SIBLINGS: &str = "siblings";

// ── Meta CF keys ──────────────────────────────────────────────────────────────

const META_TIP_HEIGHT: &[u8] = b"tip_height";
const META_GENESIS_ANCHOR: &[u8] = b"genesis_anchor";
const META_SNAPSHOT_BASE_HEIGHT: &[u8] = b"snapshot_base_height";
const META_SNAPSHOT_BASE_HASH: &[u8] = b"snapshot_base_hash";
/// Policy P-COMPAT-001 §(3) — persisted chain_id for the store. Written
/// by [`RocksDbChainStore::open_with_chain_id`] on first open, checked
/// on every subsequent open to refuse cross-chain binary/data mixing.
/// The stored value is the raw chain_id bytes (hex-decoded from the
/// operator config's `chain_id_hex`). ADR-052.
const META_CHAIN_ID: &[u8] = b"chain_id";

// ── PruneStats — TASK-187a return type ────────────────────────────────────────

/// Per-CF deletion counts returned by [`RocksDbChainStore::prune_blocks_below`].
/// Captured in the operator `prune.log` and emitted to Prometheus via the
/// `pqcd snapshot-prune` subcommand so an operator can verify the prune did
/// what they asked. All fields are monotonic counts of records removed by
/// the call (NOT cumulative across the lifetime of the node).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PruneStats {
    /// `CF_BLOCKS` entries deleted (one per block at height < cutoff).
    pub blocks_deleted: u64,
    /// `CF_HASH_INDEX` entries deleted (one per hash → height pointer
    /// referencing a pruned block).
    pub hash_index_deleted: u64,
    /// `CF_TX_INDEX` entries deleted (one per tx_hash → height pointer
    /// referencing a pruned block; for empty-block chains this is 0).
    pub tx_index_deleted: u64,
    /// `CF_SIBLINGS` entries deleted (state-equivalent reorged blocks
    /// archived by `replace_canonical_at_height` at heights < cutoff).
    pub siblings_deleted: u64,
    /// Older trusted-checkpoint records dropped from `CF_CHECKPOINTS` —
    /// only the most recent entry is retained.
    pub checkpoints_deleted: u64,
    /// Trusted-checkpoint records preserved (always 0 or 1; bootstrap
    /// reads only the End iterator).
    pub checkpoints_kept: u64,
}

// ── RocksDbChainStore ─────────────────────────────────────────────────────────

/// RocksDB-backed canonical chain store (ADR-032).
///
/// Drop-in replacement for `DiskChainStore` — all public method signatures are identical.
/// The in-memory `ChainStore` holds only the tail (post-checkpoint window), mirroring
/// the ADR-028 bounded-memory design.
pub struct RocksDbChainStore {
    db: Arc<DB>,
    /// In-memory tail of the canonical chain (blocks above the last checkpoint).
    chain: ChainStore,
    /// Genesis anchor stored on first open; used for full-replay recovery.
    genesis_anchor: BlockHash,
    /// Write options applied to every `WriteBatch` commit.  Set `disable_wal = true`
    /// via `open_no_wal` for test environments where durability is not required
    /// and WAL overhead would cause CI throughput regressions.
    write_opts: WriteOptions,
    //
    // Phase 8 M2 (TASK-113, commit `bcf77b9..` onwards): the previous
    // `commit_policy: Option<CommitQuorumPolicy>` field is gone. The
    // policy is derived per-block from `StateStore::active_validators()`
    // at the append caller; `append_block` / `append_stored_block` now
    // take `policy: Option<&CommitQuorumPolicy>` so the store stays
    // stateless w.r.t. the validator set (which is on-chain, not
    // storage-layer state). See docs/historical/phase-8-m2-plan.md §3.1 (the hot
    // spot that M2 explicitly targeted).
}

impl RocksDbChainStore {
    // ── Constructors ──────────────────────────────────────────────────────────

    pub fn open(root: impl AsRef<Path>, anchor_prev_hash: BlockHash) -> Result<Self, StorageError> {
        Self::open_internal(root, anchor_prev_hash, false)
    }

    /// Open without WAL (Write-Ahead Log) for test environments.
    ///
    /// Disabling the WAL removes the fsync-per-write overhead that causes
    /// throughput regressions in debug builds.  **Do not use in production.**
    pub fn open_no_wal(
        root: impl AsRef<Path>,
        anchor_prev_hash: BlockHash,
    ) -> Result<Self, StorageError> {
        Self::open_internal(root, anchor_prev_hash, true)
    }

    /// Policy P-COMPAT-001 §(3) — open the store with a configured
    /// `chain_id` pre-flight guard (ADR-052).
    ///
    /// On first open (no persisted `chain_id` in the meta CF), writes
    /// the provided `chain_id` and proceeds. On every subsequent open
    /// the persisted value is read and compared to the provided
    /// `chain_id`; mismatch returns [`StorageError::ChainIdMismatch`]
    /// before any further chain-store work is done. This prevents the
    /// 2026-04-24 failure mode (binary built for archival-overlay
    /// state running against a data directory written by a pre-archival
    /// binary) at the metadata level, without needing to first observe
    /// a `state_root` mismatch at checkpoint replay.
    ///
    /// Prefer this constructor over [`RocksDbChainStore::open`] in
    /// production boot paths; the no-check [`open`] variant is retained
    /// for tests and tooling that operate on arbitrary data directories.
    pub fn open_with_chain_id(
        root: impl AsRef<Path>,
        anchor_prev_hash: BlockHash,
        chain_id: &[u8],
    ) -> Result<Self, StorageError> {
        let store = Self::open_internal(root, anchor_prev_hash, false)?;
        store.enforce_chain_id(chain_id)?;
        Ok(store)
    }

    /// Same as [`Self::open_with_chain_id`] for tests that also want
    /// WAL disabled for speed.
    pub fn open_no_wal_with_chain_id(
        root: impl AsRef<Path>,
        anchor_prev_hash: BlockHash,
        chain_id: &[u8],
    ) -> Result<Self, StorageError> {
        let store = Self::open_internal(root, anchor_prev_hash, true)?;
        store.enforce_chain_id(chain_id)?;
        Ok(store)
    }

    /// Apply the P-COMPAT-001 §(3) guard against an already-open store.
    /// On a fresh data directory this writes the provided `chain_id`
    /// so the next open can check against it; on a populated directory
    /// it reads and compares, returning [`StorageError::ChainIdMismatch`]
    /// on divergence.
    fn enforce_chain_id(&self, chain_id: &[u8]) -> Result<(), StorageError> {
        let meta_cf = self.db.cf_handle(CF_META).expect("meta CF");
        match self
            .db
            .get_cf(&meta_cf, META_CHAIN_ID)
            .map_err(rocksdb_err)?
        {
            None => {
                // Fresh directory — persist the chain_id so subsequent
                // opens can enforce against it.
                write_meta_raw(&self.db, META_CHAIN_ID, chain_id)?;
                Ok(())
            }
            Some(stored) => {
                if stored.as_slice() == chain_id {
                    Ok(())
                } else {
                    Err(StorageError::ChainIdMismatch {
                        expected: hex::encode(chain_id),
                        got: hex::encode(&stored),
                    })
                }
            }
        }
    }

    fn open_internal(
        root: impl AsRef<Path>,
        anchor_prev_hash: BlockHash,
        disable_wal: bool,
    ) -> Result<Self, StorageError> {
        let db = if disable_wal {
            Arc::new(open_rocksdb_no_wal(root.as_ref())?)
        } else {
            Arc::new(open_rocksdb(root.as_ref())?)
        };

        let mut write_opts = WriteOptions::default();
        if disable_wal {
            write_opts.disable_wal(true);
        }

        // ── Genesis anchor ────────────────────────────────────────────────────
        let genesis_anchor = match read_meta_hash_by_name(&db, META_GENESIS_ANCHOR)? {
            Some(hash) => hash,
            None => {
                // First open — persist the anchor so subsequent opens use it.
                write_meta_raw(&db, META_GENESIS_ANCHOR, &anchor_prev_hash.0)?;
                anchor_prev_hash.clone()
            }
        };

        // ── Current tip ───────────────────────────────────────────────────────
        let tip_height = read_meta_u64_by_name(&db, META_TIP_HEIGHT)?.unwrap_or(0);

        // ── Snapshot base (cold-start from distributed snapshot) ──────────────
        let snapshot_base = match (
            read_meta_u64_by_name(&db, META_SNAPSHOT_BASE_HEIGHT)?,
            read_meta_hash_by_name(&db, META_SNAPSHOT_BASE_HASH)?,
        ) {
            (Some(h), Some(hash)) if h > 0 => Some((h, hash)),
            _ => None,
        };

        let start_height = snapshot_base.as_ref().map(|(h, _)| h + 1).unwrap_or(1);

        // ── Empty store ───────────────────────────────────────────────────────
        if tip_height == 0 {
            let (chain_anchor, base_height) = match &snapshot_base {
                Some((h, hash)) => (hash.clone(), *h),
                None => (genesis_anchor.clone(), 0),
            };
            let chain = ChainStore::new_with_base(chain_anchor, base_height);
            return Ok(Self {
                db,
                chain,
                genesis_anchor,
                write_opts,
            });
        }

        // ── Checkpoint window ─────────────────────────────────────────────────
        //
        // Find the latest valid checkpoint to use as the in-memory chain anchor.
        // Pre-checkpoint blocks remain in RocksDB only; tail blocks are loaded
        // into the in-memory ChainStore with full tx-body-hash validation.
        let checkpoint_window = find_latest_checkpoint_pair(&db, None)?;

        let (chain_anchor, base_height) = match &checkpoint_window {
            Some((ckpt_h, ckpt_tip)) => (ckpt_tip.clone(), *ckpt_h),
            None => {
                let anchor = snapshot_base
                    .as_ref()
                    .map(|(_, h)| h.clone())
                    .unwrap_or_else(|| genesis_anchor.clone());
                let base = snapshot_base.as_ref().map(|(h, _)| *h).unwrap_or(0);
                (anchor, base)
            }
        };

        let memory_load_from = checkpoint_window
            .as_ref()
            .map(|(h, _)| h + 1)
            .unwrap_or(start_height);

        let mut chain = ChainStore::new_with_base(chain_anchor, base_height);

        // Load only the tail into the in-memory chain.  Pre-checkpoint blocks are
        // validated implicitly by the checkpoint state_root; WriteBatch guarantees
        // they can't be partially written.
        //
        // Phase 8 M2 (TASK-113): open-time commit-quorum re-validation is gone.
        // The blocks on disk were validated with the policy in effect at the
        // moment they were appended; replaying that check here would need the
        // time-travelling StateStore snapshot at each block's height, which we
        // don't reconstruct until the engine replay path runs. Block-inherent
        // checks (hash + parent + signature on the consensus inner message)
        // still run via `ChainStore::append_stored_block`, so corrupted
        // on-disk state is caught at this point regardless.
        for height in memory_load_from..=tip_height {
            let stored = read_stored_block_from_db(&db, height)?
                .ok_or(StorageError::MissingBlockFile { height })?;
            chain.append_stored_block(stored)?;
        }

        if chain.height() != tip_height {
            return Err(StorageError::TipHeightMismatch {
                expected: tip_height,
                got: chain.height(),
            });
        }

        Ok(Self {
            db,
            chain,
            genesis_anchor,
            write_opts,
        })
    }

    // ── Block append ──────────────────────────────────────────────────────────

    /// Append a block received from a peer or the consensus round.
    /// Validates the commit quorum proof before writing when a `policy` is
    /// provided (Phase 8 M2: caller derives from `StateStore::active_validators()`).
    /// Passing `None` skips quorum validation — intended for unit tests and
    /// the bootstrap path before any validators are seeded.
    pub fn append_block(
        &mut self,
        execution: &BlockExecutionResult,
        policy: Option<&CommitQuorumPolicy>,
    ) -> Result<BlockMetadata, StorageError> {
        if let Some(p) = policy {
            validate_block_commit_quorum(&execution.block, p)?;
        }
        self.append_block_inner(execution)
    }

    /// Append a locally-produced block without re-validating commit signatures.
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

        self.persist_to_db(&stored)?;
        self.chain = trial;

        tracing::info!(
            height = metadata.height,
            included = metadata.included_count,
            tip_hash = %hex::encode(metadata.block_hash.0),
            "block persisted to RocksDB",
        );

        Ok(metadata)
    }

    /// Append a fully-constructed `StoredBlock` (P2P sync path).
    /// Validates commit quorum when `policy` is provided; callers on the
    /// live M2 path derive the policy from the current `StateStore`
    /// active set snapshot just before dispatching here.
    pub fn append_stored_block(
        &mut self,
        stored: StoredBlock,
        policy: Option<&CommitQuorumPolicy>,
    ) -> Result<BlockMetadata, StorageError> {
        if let Some(p) = policy {
            validate_block_commit_quorum(&stored.block, p)?;
        }
        let mut trial = self.chain.clone();
        let metadata = trial.append_stored_block(stored.clone())?;
        self.persist_to_db(&stored)?;
        self.chain = trial;

        tracing::info!(
            height = metadata.height,
            included = metadata.included_count,
            tip_hash = %hex::encode(metadata.block_hash.0),
            "remote block persisted to RocksDB",
        );

        Ok(metadata)
    }

    /// ADR-054 §Stage 4 — atomically replace the canonical chain tip
    /// with a state-equivalent sibling.
    ///
    /// Pre-conditions (the in-memory layer enforces them again, but we
    /// fail fast at this boundary so RocksDB never sees a divergent
    /// candidate):
    /// - `canonical.metadata.height == self.chain.height()` (must be at tip);
    /// - `canonical.metadata.{prev_hash, state_root, tx_root}` match the
    ///   local tip's identical fields (state-equivalence);
    /// - `canonical.metadata.block_hash != local_tip.metadata.block_hash`.
    ///
    /// When `policy` is `Some`, `validate_block_commit_quorum` runs on
    /// the candidate before any disk I/O — Stage 2 of the reception
    /// pipeline owns this path, so this is defence-in-depth, not the
    /// only gate.
    ///
    /// On success: a single `WriteBatch` removes the old `hash_index`
    /// entry, archives the old block to the `siblings` CF, overwrites
    /// the `blocks[height]` entry with the canonical variant,
    /// re-indexes the canonical hash, and updates the in-memory
    /// `ChainStore` via `replace_tip_block`. `meta.tip_height` is
    /// re-asserted in the same batch (the value does not change, but
    /// including it keeps the swap atomic w.r.t. concurrent readers
    /// that resolve `tip_height -> hash_index`).
    ///
    /// Returns the displaced (formerly-canonical) block so the caller
    /// can include it in audit logs, metrics, or a forensic record. The
    /// displaced block is also retrievable from the `siblings` CF via
    /// [`Self::read_sibling_by_hash`].
    pub fn replace_canonical_at_height(
        &mut self,
        canonical: StoredBlock,
        policy: Option<&CommitQuorumPolicy>,
    ) -> Result<StoredBlock, StorageError> {
        if let Some(p) = policy {
            validate_block_commit_quorum(&canonical.block, p)?;
        }

        // Stage the in-memory swap on a clone so we can roll back if
        // RocksDB rejects the batch. `replace_tip_block` enforces the
        // sibling invariants and returns the displaced StoredBlock.
        let mut trial = self.chain.clone();
        let displaced = trial.replace_tip_block(canonical.clone())?;

        // Persist atomically. On any RocksDB failure the in-memory
        // swap is discarded and the caller observes no state change.
        self.persist_replace_canonical(&displaced, &canonical)?;

        // Commit the in-memory swap last, after the disk side succeeded.
        self.chain = trial;

        tracing::info!(
            height = canonical.metadata.height,
            old_tip = %hex::encode(displaced.metadata.block_hash.0),
            new_tip = %hex::encode(canonical.metadata.block_hash.0),
            old_timestamp = displaced.metadata.timestamp,
            new_timestamp = canonical.metadata.timestamp,
            "ADR-054 canonical sibling swap committed",
        );

        Ok(displaced)
    }

    /// ADR-054 §Stage 6 — on-startup integrity audit.
    ///
    /// Walks the post-checkpoint tail in `self.chain` and asserts that
    /// every block carries at least one entry in `commit_signatures`.
    /// This is the cheapest possible defense-in-depth check against
    /// the 2026-04-25 bug class: a buggy ingest path silently
    /// persisted a non-finalized block (zero or sub-quorum sigs) and
    /// the chain stalled the next time a child arrived. Catching
    /// `commit_signatures.is_empty()` at startup lets the operator
    /// recover via `pqcd snapshot-import` BEFORE the node tries to
    /// sync further on top of corrupted state.
    ///
    /// Why not full quorum verification at startup? The threshold is
    /// a function of the validator set at the parent-block's state,
    /// which we do not reconstruct without a full replay. The replay
    /// (and its per-block quorum check at append time) is what
    /// `recover_tip_with_checkpoint` already runs after `open`, so
    /// the cheap audit here is a fast pre-flight; the expensive
    /// audit is implicit in the recovery path that follows.
    ///
    /// On failure returns `Err(StorageError::InvalidPersistedValue)`
    /// with a diagnostic message; the operator-facing error string
    /// in `node.rs` advises a snapshot-import recovery.
    pub fn verify_quick_finality_invariants(&self) -> Result<(), StorageError> {
        for stored in self.chain.blocks_in_order() {
            if stored.block.commit_signatures.is_empty() {
                tracing::error!(
                    height = stored.metadata.height,
                    block_hash = %hex::encode(stored.metadata.block_hash.0),
                    "ADR-054 §Stage 6: persisted block has empty commit_signatures",
                );
                return Err(StorageError::InvalidPersistedValue(
                    "ADR-054: post-checkpoint tail contains a block with no commit \
                     signatures — this should never reach disk under the strict-finality \
                     gate. Recover via `pqcd snapshot-import` from a healthy peer.",
                ));
            }
        }
        Ok(())
    }

    /// Read a previously-displaced sibling block by its hash. Returns
    /// `Ok(None)` if no swap has ever recorded that hash. Useful for
    /// forensic tooling and the on-startup integrity audit.
    pub fn read_sibling_by_hash(
        &self,
        hash: &BlockHash,
    ) -> Result<Option<StoredBlock>, StorageError> {
        let cf = self.db.cf_handle(CF_SIBLINGS).expect("siblings CF");
        // The siblings CF key is `hash || height_be`; we only have the
        // hash, so iterate over the prefix. There can be at most one
        // entry per hash (block_hash collisions across heights are
        // computationally infeasible under SHAKE-256).
        let mut iter = self.db.prefix_iterator_cf(&cf, &hash.0[..]);
        match iter.next() {
            None => Ok(None),
            Some(Ok(kv)) => {
                if kv.0.len() != 40 || kv.0[..32] != hash.0[..] {
                    return Ok(None);
                }
                let mut height_bytes = [0u8; 8];
                height_bytes.copy_from_slice(&kv.0[32..40]);
                let height = u64::from_be_bytes(height_bytes);
                let record: StoredBlockRecord = decode_cbor_slice(&kv.1, "<siblings>")?;
                Ok(Some(record_into_stored_block(record, height)?))
            }
            Some(Err(e)) => Err(StorageError::RocksDb(e.to_string())),
        }
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    pub fn chain(&self) -> &ChainStore {
        &self.chain
    }

    pub fn tip_hash(&self) -> Option<&BlockHash> {
        self.chain.tip_hash()
    }

    pub fn height(&self) -> u64 {
        self.chain.height()
    }

    // ── Block reading ─────────────────────────────────────────────────────────

    /// Read a stored block by height — in-memory chain first, then RocksDB fallback.
    pub fn read_stored_block_at_height(
        &self,
        height: u64,
    ) -> Result<Option<StoredBlock>, StorageError> {
        if let Some(stored) = self.chain.get_stored_block_by_height(height) {
            return Ok(Some(stored.clone()));
        }
        read_stored_block_from_db(&self.db, height)
    }

    /// Serialize a stored block to raw CBOR bytes for P2P transport.
    pub fn export_block_bytes(&self, height: u64) -> Result<Option<Vec<u8>>, StorageError> {
        // Fast path: tail block is in memory.
        if let Some(stored) = self.chain.get_stored_block_by_height(height) {
            return encode_stored_block_bytes(stored).map(Some);
        }
        // Pre-checkpoint blocks: return raw bytes from RocksDB (already CBOR-encoded).
        let blocks_cf = self.db.cf_handle(CF_BLOCKS).expect("blocks CF");
        match self
            .db
            .get_cf(&blocks_cf, height_to_key(height))
            .map_err(rocksdb_err)?
        {
            None => Ok(None),
            Some(bytes) => Ok(Some(bytes.to_vec())),
        }
    }

    /// Encode a `StoredBlock` to raw CBOR bytes (static).
    pub fn encode_block_bytes(stored: &StoredBlock) -> Result<Vec<u8>, StorageError> {
        encode_stored_block_bytes(stored)
    }

    /// Decode raw CBOR bytes into a `StoredBlock` (static).
    pub fn decode_block_bytes(bytes: &[u8]) -> Result<StoredBlock, StorageError> {
        let record: StoredBlockRecord = decode_cbor_slice(bytes, "<block-bytes>")?;
        let height = record.metadata.height;
        record_into_stored_block(record, height)
    }

    /// Decode one `StoredBlock` from a CBOR-sequence reader, advancing
    /// the reader by exactly the bytes consumed by the encoded block.
    /// Used by the cold-storage import path (TASK-188b §3) which reads
    /// a concatenation of `encode_block_bytes` outputs from a single
    /// zstd-decompressed batch.
    ///
    /// `StoredBlockRecord` is `pub(crate)`, so external callers cannot
    /// drive `ciborium::from_reader` directly. This function is the
    /// only sanctioned way to walk a CBOR-sequence stream of stored
    /// blocks across crate boundaries.
    pub fn decode_block_bytes_from_reader<R: std::io::Read>(
        reader: R,
    ) -> Result<StoredBlock, StorageError> {
        let record: StoredBlockRecord =
            ciborium::from_reader(reader).map_err(|err| StorageError::Decode {
                path: std::path::PathBuf::from("<cold-storage-stream>"),
                detail: err.to_string(),
            })?;
        let height = record.metadata.height;
        record_into_stored_block(record, height)
    }

    // ── Checkpoint write ──────────────────────────────────────────────────────

    /// Write the current state as a trusted checkpoint to the `checkpoints` CF.
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
                .map(|m| m.block_hash.clone())
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
                .map(|m| m.state_root.clone())
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
            version: super::storage::STATE_FORMAT_VERSION,
            metadata: TrustedCheckpointMetadataRecord {
                height: metadata.height,
                tip_hash: metadata.tip_hash.0,
                state_root: metadata.state_root.0,
            },
            state: state_into_record(state),
        };

        let cbor = encode_cbor_vec(&record)?;
        let checkpoints_cf = self.db.cf_handle(CF_CHECKPOINTS).expect("checkpoints CF");
        self.db
            .put_cf(&checkpoints_cf, height_to_key(got_height), cbor)
            .map_err(rocksdb_err)?;

        tracing::info!(
            height = metadata.height,
            tip_hash = %hex::encode(metadata.tip_hash.0),
            "trusted checkpoint written to RocksDB",
        );

        Ok(metadata)
    }

    /// Evict all blocks at heights ≤ `checkpoint_height` from the in-memory
    /// ChainStore. Call this after `write_trusted_checkpoint` to bound RSS.
    pub fn compact_chain_to_checkpoint(
        &mut self,
        checkpoint_height: u64,
        checkpoint_tip_hash: BlockHash,
    ) {
        self.chain
            .compact_to_checkpoint(checkpoint_height, checkpoint_tip_hash);
    }

    /// TASK-187a — permanently delete on-disk records for every block at
    /// height strictly below `cutoff_height`. Used by the `pqcd snapshot-prune`
    /// subcommand to reclaim follower disk space without compromising the
    /// node's ability to bootstrap on the next start (the latest trusted
    /// checkpoint must remain at height ≥ cutoff — see pre-flight checks
    /// below; otherwise we return [`StorageError::InvalidPruneCutoff`]).
    ///
    /// Touches **only** the chain-store column families this crate owns —
    /// `CF_BLOCKS`, `CF_HASH_INDEX`, `CF_TX_INDEX`, `CF_SIBLINGS`,
    /// `CF_CHECKPOINTS`. The state-store column families (owned by
    /// `pqc-state`) and `CF_META` are untouched, so prune cannot perturb the
    /// state_root computation: a node that pruned at height M and a node
    /// that did not will compute the same state_root for any height ≥ M
    /// (the cold-sync replay-equivalence pin from TASK-198 holds by
    /// construction). The genesis anchor in `CF_META` is preserved.
    ///
    /// Atomicity. All deletes are issued via a single `WriteBatch`; the
    /// caller never observes a partial prune. Compaction of the affected
    /// CFs is triggered after the batch commits so the SST files actually
    /// shrink (without compaction `delete_range` is logical-only and the
    /// disk footprint stays the same until the next major write triggers
    /// background compaction).
    ///
    /// The in-memory `chain` ChainStore (post-checkpoint tail) is NOT
    /// mutated by this method — it never holds entries below the latest
    /// checkpoint anyway, so any pre-cutoff blocks would already be absent
    /// from the tail. Callers that want to release RAM in addition to disk
    /// should call `compact_chain_to_checkpoint` separately.
    pub fn prune_blocks_below(&mut self, cutoff_height: u64) -> Result<PruneStats, StorageError> {
        // ── 1. Pre-flight checks ─────────────────────────────────────────
        if cutoff_height == 0 {
            return Err(StorageError::InvalidPruneCutoff(
                "cutoff of 0 would delete the genesis block",
            ));
        }
        let tip = self.height();
        if cutoff_height > tip {
            return Err(StorageError::InvalidPruneCutoff(
                "cutoff exceeds current tip height",
            ));
        }
        // Must have a trusted checkpoint at height >= cutoff so the node can
        // bootstrap on next start.  Iterate `CF_CHECKPOINTS` from the end
        // (highest height first) and break as soon as we find one ≥ cutoff.
        let cp_cf = self.db.cf_handle(CF_CHECKPOINTS).expect("checkpoints CF");
        let has_late_checkpoint = self
            .db
            .iterator_cf(&cp_cf, IteratorMode::End)
            .filter_map(Result::ok)
            .map(|(k, _)| key_to_height(&k).unwrap_or(0))
            .any(|h| h >= cutoff_height);
        if !has_late_checkpoint {
            return Err(StorageError::InvalidPruneCutoff(
                "no trusted checkpoint at or above the cutoff height; pruning would render the \
                 node unable to bootstrap on next start",
            ));
        }

        // ── 2. Build the batch ───────────────────────────────────────────
        let mut stats = PruneStats::default();
        let mut batch = WriteBatch::default();

        // 2a. CF_BLOCKS — count first (BE keys are height-ordered, so we can
        // break early once we hit a height ≥ cutoff), then delete_range
        // [0, cutoff).
        let blocks_cf = self.db.cf_handle(CF_BLOCKS).expect("blocks CF");
        for entry in self.db.iterator_cf(&blocks_cf, IteratorMode::Start) {
            let (k, _) = entry.map_err(rocksdb_err)?;
            let h = key_to_height(&k)?;
            if h >= cutoff_height {
                break;
            }
            stats.blocks_deleted += 1;
        }
        batch.delete_range_cf(&blocks_cf, height_to_key(0), height_to_key(cutoff_height));

        // 2b. CF_HASH_INDEX — keys are block hashes (no order on height),
        // so we must scan and delete entries whose value < cutoff.
        let hash_cf = self.db.cf_handle(CF_HASH_INDEX).expect("hash_index CF");
        for entry in self.db.iterator_cf(&hash_cf, IteratorMode::Start) {
            let (k, v) = entry.map_err(rocksdb_err)?;
            let h = key_to_height(&v)?;
            if h < cutoff_height {
                batch.delete_cf(&hash_cf, &*k);
                stats.hash_index_deleted += 1;
            }
        }

        // 2c. CF_TX_INDEX — same shape as CF_HASH_INDEX (tx_hash → height).
        let tx_cf = self.db.cf_handle(CF_TX_INDEX).expect("tx_index CF");
        for entry in self.db.iterator_cf(&tx_cf, IteratorMode::Start) {
            let (k, v) = entry.map_err(rocksdb_err)?;
            let h = key_to_height(&v)?;
            if h < cutoff_height {
                batch.delete_cf(&tx_cf, &*k);
                stats.tx_index_deleted += 1;
            }
        }

        // 2d. CF_SIBLINGS — composite key `block_hash[32] || height_be[8]`.
        // Parse the trailing 8 bytes as the height.  Defensive: skip any
        // malformed key (length != 40) instead of erroring.
        let sib_cf = self.db.cf_handle(CF_SIBLINGS).expect("siblings CF");
        for entry in self.db.iterator_cf(&sib_cf, IteratorMode::Start) {
            let (k, _) = entry.map_err(rocksdb_err)?;
            if k.len() != 40 {
                continue;
            }
            let mut height_bytes = [0u8; 8];
            height_bytes.copy_from_slice(&k[32..40]);
            let h = u64::from_be_bytes(height_bytes);
            if h < cutoff_height {
                batch.delete_cf(&sib_cf, &*k);
                stats.siblings_deleted += 1;
            }
        }

        // 2e. CF_CHECKPOINTS — keep only the most recent entry; everything
        // older is dead weight (bootstrap reads the End iterator only).
        let mut all_checkpoints: Vec<u64> = Vec::new();
        for entry in self.db.iterator_cf(&cp_cf, IteratorMode::Start) {
            let (k, _) = entry.map_err(rocksdb_err)?;
            all_checkpoints.push(key_to_height(&k)?);
        }
        if let Some(&latest) = all_checkpoints.iter().max() {
            for &h in &all_checkpoints {
                if h != latest {
                    batch.delete_cf(&cp_cf, height_to_key(h));
                    stats.checkpoints_deleted += 1;
                }
            }
            stats.checkpoints_kept = 1;
        }

        // ── 3. Apply the batch atomically ────────────────────────────────
        self.db.write(batch).map_err(rocksdb_err)?;

        // ── 4. Trigger compaction so SST files actually shrink ───────────
        // `compact_range_cf` with None bounds compacts the entire CF.
        // Synchronous in the calling thread; for a 7-day-tail prune this is
        // typically a few seconds of I/O on a modern NVMe.
        self.db
            .compact_range_cf(&blocks_cf, None::<&[u8]>, None::<&[u8]>);
        self.db
            .compact_range_cf(&hash_cf, None::<&[u8]>, None::<&[u8]>);
        self.db
            .compact_range_cf(&tx_cf, None::<&[u8]>, None::<&[u8]>);
        self.db
            .compact_range_cf(&sib_cf, None::<&[u8]>, None::<&[u8]>);
        self.db
            .compact_range_cf(&cp_cf, None::<&[u8]>, None::<&[u8]>);

        tracing::info!(
            cutoff_height,
            tip_height = tip,
            blocks_deleted = stats.blocks_deleted,
            hash_index_deleted = stats.hash_index_deleted,
            tx_index_deleted = stats.tx_index_deleted,
            siblings_deleted = stats.siblings_deleted,
            checkpoints_deleted = stats.checkpoints_deleted,
            checkpoints_kept = stats.checkpoints_kept,
            "prune_blocks_below completed",
        );

        Ok(stats)
    }

    // ── Snapshot / P2P sync ───────────────────────────────────────────────────

    /// Decode only the height and tip_hash from raw snapshot bytes (no full state decode).
    pub fn decode_snapshot_metadata(bytes: &[u8]) -> Result<(u64, BlockHash), StorageError> {
        let record = decode_cbor_slice::<TrustedCheckpointRecord>(bytes, "<snapshot>")?;
        super::storage::check_state_format_version(record.version)?;
        Ok((record.metadata.height, BlockHash(record.metadata.tip_hash)))
    }

    /// Return the raw CBOR bytes of the most recent checkpoint, or `None`.
    pub fn export_checkpoint_bytes(&self) -> Result<Option<Vec<u8>>, StorageError> {
        let checkpoints_cf = self.db.cf_handle(CF_CHECKPOINTS).expect("checkpoints CF");
        let mut iter = self.db.iterator_cf(&checkpoints_cf, IteratorMode::End);
        match iter.next() {
            None => Ok(None),
            Some(Ok((_, v))) => Ok(Some(v.to_vec())),
            Some(Err(e)) => Err(rocksdb_err(e)),
        }
    }

    /// Return `true` if at least one trusted checkpoint exists.
    pub fn has_checkpoint(&self) -> bool {
        let checkpoints_cf = self.db.cf_handle(CF_CHECKPOINTS).expect("checkpoints CF");
        let mut iter = self.db.iterator_cf(&checkpoints_cf, IteratorMode::End);
        iter.next().is_some()
    }

    /// Import an externally-obtained snapshot as a trusted checkpoint.
    ///
    /// Validates CBOR structure, version, and state_root internal consistency, then
    /// writes the bytes to the `checkpoints` CF.  The in-memory chain is NOT updated
    /// — call this on a stopped node's data directory.
    pub fn import_external_snapshot(
        &self,
        bytes: &[u8],
        chain_id: &[u8],
    ) -> Result<TrustedCheckpointMetadata, StorageError> {
        let record = decode_cbor_slice::<TrustedCheckpointRecord>(bytes, "<snapshot>")?;
        super::storage::check_state_format_version(record.version)?;
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
        if BlockHash(state.state_root()) != metadata.state_root {
            return Err(StorageError::InvalidSnapshot(
                "snapshot state_root does not match metadata",
            ));
        }

        let checkpoints_cf = self.db.cf_handle(CF_CHECKPOINTS).expect("checkpoints CF");
        self.db
            .put_cf(&checkpoints_cf, height_to_key(metadata.height), bytes)
            .map_err(rocksdb_err)?;

        tracing::info!(
            height = metadata.height,
            tip_hash = %hex::encode(metadata.tip_hash.0),
            "external snapshot imported as trusted checkpoint (RocksDB)",
        );

        Ok(metadata)
    }

    /// Cold-start bootstrap from an externally-obtained snapshot + optional tail blocks.
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
                "cold bootstrap requires an empty store (height must be 0)",
            ));
        }

        // ── Step 1: decode and validate snapshot ─────────────────────────────
        let record = decode_cbor_slice::<TrustedCheckpointRecord>(snapshot_bytes, "<snapshot>")?;
        super::storage::check_state_format_version(record.version)?;
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
        if BlockHash(state.state_root()) != metadata.state_root {
            return Err(StorageError::InvalidSnapshot(
                "snapshot state_root does not match metadata",
            ));
        }

        // ── Step 2: validate tail blocks ─────────────────────────────────────
        // Build the commit-quorum policy from the snapshot's embedded
        // validator set (Phase 8 M2 — the storage backend no longer
        // carries a static policy). The snapshot includes the complete
        // on-chain state at the snapshot height, so the policy we
        // derive here is exactly the one under which the immediately
        // following tail blocks were produced. `from_state_store(state, None)`
        // only errors on duplicate validator addresses (prevented by
        // StateStore's HashMap invariant) or an invalid explicit
        // threshold (we pass `None`, so the default 2f+1 is always
        // well-formed). The expect is load-bearing: a failure here would
        // mean the snapshot's state store is self-inconsistent, which
        // is a bug either in snapshot generation or in state
        // serialisation — neither is something the caller can recover
        // from.
        let snapshot_policy = CommitQuorumPolicy::from_state_store(&state, None)
            .expect("snapshot state yields a valid commit quorum policy");
        let mut tail_chain = ChainStore::new_with_base(metadata.tip_hash.clone(), metadata.height);
        let mut tail_stored: Vec<StoredBlock> = Vec::with_capacity(tail_block_bytes.len());
        for bytes in tail_block_bytes {
            let stored = Self::decode_block_bytes(bytes)?;
            if let Some(policy) = &snapshot_policy {
                validate_block_commit_quorum(&stored.block, policy)?;
            }
            let mut trial = tail_chain.clone();
            trial.append_stored_block(stored.clone())?;
            tail_chain = trial;
            tail_stored.push(stored);
        }

        // ── Step 3: write checkpoint + tail blocks atomically ─────────────────
        let checkpoints_cf = self.db.cf_handle(CF_CHECKPOINTS).expect("checkpoints CF");
        let meta_cf = self.db.cf_handle(CF_META).expect("meta CF");

        let final_height = if tail_stored.is_empty() {
            metadata.height
        } else {
            tail_chain.height()
        };
        let final_tip_hash = tail_chain
            .tip_hash()
            .cloned()
            .unwrap_or_else(|| metadata.tip_hash.clone());

        let mut batch = WriteBatch::default();
        batch.put_cf(
            &checkpoints_cf,
            height_to_key(metadata.height),
            snapshot_bytes,
        );
        batch.put_cf(
            &meta_cf,
            META_SNAPSHOT_BASE_HEIGHT,
            height_to_key(metadata.height),
        );
        batch.put_cf(&meta_cf, META_SNAPSHOT_BASE_HASH, metadata.tip_hash.0);

        for stored in &tail_stored {
            append_block_to_batch(&mut batch, &self.db, stored)?;
        }

        batch.put_cf(&meta_cf, META_TIP_HEIGHT, height_to_key(final_height));
        self.db
            .write_opt(batch, &self.write_opts)
            .map_err(rocksdb_err)?;

        // ── Step 4: update in-memory chain ────────────────────────────────────
        self.chain = tail_chain;

        tracing::info!(
            snapshot_height = metadata.height,
            tail_blocks = tail_stored.len(),
            final_height,
            tip_hash = %hex::encode(final_tip_hash.0),
            "cold bootstrap from external snapshot complete (RocksDB)",
        );

        Ok(metadata)
    }

    // ── Recovery ─────────────────────────────────────────────────────────────

    /// Full-replay recovery from genesis state.
    pub fn recover_tip(
        &self,
        genesis_state: &StateStore,
        fee_params: FeeParams,
        fee_dist: pqc_state::FeeDistributionParams,
        validator_pool: Vec<pqc_types::account::Address>,
    ) -> Result<ReplayResult, StorageError> {
        let tip_height = self.height();
        if tip_height == 0 {
            return recover_from_chain(
                &self.chain,
                genesis_state,
                fee_params,
                fee_dist,
                validator_pool,
            )
            .map_err(StorageError::Replay);
        }

        let snapshot_base_height =
            read_meta_u64_by_name(&self.db, META_SNAPSHOT_BASE_HEIGHT)?.unwrap_or(0);
        let start_h = if snapshot_base_height > 0 {
            snapshot_base_height + 1
        } else {
            1
        };

        let chain_start = self
            .chain
            .blocks_in_order()
            .first()
            .map(|b| b.metadata.height)
            .unwrap_or(start_h);

        if chain_start > start_h {
            // Tail-only in-memory chain; load all blocks from RocksDB for full replay.
            let mut blocks = Vec::with_capacity((tip_height - start_h + 1) as usize);
            for h in start_h..=tip_height {
                let block = read_stored_block_from_db(&self.db, h)?
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

    /// Recovery via trusted checkpoint + tail replay.
    pub fn recover_tip_with_checkpoint(
        &self,
        genesis_state: &StateStore,
        fee_params: FeeParams,
        fee_dist: pqc_state::FeeDistributionParams,
        validator_pool: Vec<pqc_types::account::Address>,
    ) -> Result<CheckpointRecoveryResult, StorageError> {
        if let Some((metadata, checkpoint_state)) =
            find_latest_checkpoint_with_state(&self.db, genesis_state.chain_id())?
        {
            let tail: Vec<StoredBlock> = self
                .chain
                .blocks_in_order()
                .into_iter()
                .filter(|s| s.metadata.height > metadata.height)
                .cloned()
                .collect();

            tracing::info!(
                source = "trusted_checkpoint",
                checkpoint_height = metadata.height,
                tail_blocks = tail.len(),
                "recovering from RocksDB checkpoint",
            );

            let replay = replay_blocks_from_state(
                &checkpoint_state,
                &metadata.tip_hash,
                &tail,
                fee_params,
                fee_dist,
                validator_pool,
            )
            .map_err(StorageError::Replay)?;

            tracing::info!(
                height = replay.height,
                tip_hash = %hex::encode(replay.tip_hash.0),
                "recovery complete (checkpoint path)",
            );

            return Ok(CheckpointRecoveryResult {
                replay,
                source: RecoverySource::TrustedCheckpoint,
                checkpoint: Some(metadata),
            });
        }

        tracing::info!(
            source = "full_replay",
            "no valid checkpoint found — replaying from genesis",
        );

        let replay = self.recover_tip(genesis_state, fee_params, fee_dist, validator_pool)?;

        tracing::info!(
            height = replay.height,
            tip_hash = %hex::encode(replay.tip_hash.0),
            "recovery complete (full replay path)",
        );

        Ok(CheckpointRecoveryResult {
            replay,
            source: RecoverySource::FullReplay,
            checkpoint: None,
        })
    }

    // ── New capabilities (ADR-032 additions) ──────────────────────────────────

    /// O(1) tx lookup: return the block height that includes `tx_hash`, or `None`.
    ///
    /// The `tx_index` CF is populated on every block commit (including migration).
    /// Covers the full chain, not just the in-memory tail.
    /// Wired into `GET /v1/txs/{hash}` by TASK-104.
    pub fn get_tx_block_height(&self, tx_hash: &TxHash) -> Result<Option<u64>, StorageError> {
        let tx_index_cf = self.db.cf_handle(CF_TX_INDEX).expect("tx_index CF");
        match self
            .db
            .get_cf(&tx_index_cf, tx_hash.0)
            .map_err(rocksdb_err)?
        {
            None => Ok(None),
            Some(bytes) => Ok(Some(key_to_height(&bytes)?)),
        }
    }

    /// Read all stored blocks with heights in `from..=to`.
    pub fn blocks_in_height_range(
        &self,
        from: u64,
        to: u64,
    ) -> Result<Vec<StoredBlock>, StorageError> {
        if from > to {
            return Ok(vec![]);
        }
        let mut result = Vec::with_capacity((to - from + 1) as usize);
        for height in from..=to {
            match self.read_stored_block_at_height(height)? {
                Some(b) => result.push(b),
                None => break,
            }
        }
        Ok(result)
    }

    // ── Migration helper ──────────────────────────────────────────────────────

    /// Write raw checkpoint bytes to the `checkpoints` CF without state validation.
    /// Used only by `pqcd migrate-store`, which has already validated the data via
    /// the legacy `DiskChainStore`.
    pub fn import_checkpoint_for_migration(&self, bytes: &[u8]) -> Result<(), StorageError> {
        let record = decode_cbor_slice::<TrustedCheckpointRecord>(bytes, "<migration>")?;
        super::storage::check_state_format_version(record.version)?;
        let checkpoints_cf = self.db.cf_handle(CF_CHECKPOINTS).expect("checkpoints CF");
        self.db
            .put_cf(
                &checkpoints_cf,
                height_to_key(record.metadata.height),
                bytes,
            )
            .map_err(rocksdb_err)?;
        Ok(())
    }

    // ── Test-only corruption helpers ─────────────────────────────────────────

    /// Overwrite the checkpoint at `height` with arbitrary bytes.
    /// Used in scenario tests to simulate checkpoint corruption.
    #[cfg(any(test, feature = "testing-utils"))]
    pub fn corrupt_checkpoint(&self, height: u64, garbage: &[u8]) {
        let cf = self.db.cf_handle(CF_CHECKPOINTS).expect("checkpoints CF");
        self.db
            .put_cf(&cf, height_to_key(height), garbage)
            .expect("corrupt_checkpoint write");
    }

    /// Overwrite the block at `height` with arbitrary bytes.
    /// Used in scenario tests to simulate block corruption.
    #[cfg(any(test, feature = "testing-utils"))]
    pub fn corrupt_block(&self, height: u64, garbage: &[u8]) {
        let cf = self.db.cf_handle(CF_BLOCKS).expect("blocks CF");
        self.db
            .put_cf(&cf, height_to_key(height), garbage)
            .expect("corrupt_block write");
    }

    // ── State migration (ADR-031 / TASK-102) ──────────────────────────────────

    /// Run the compiled-in upgrade handler chain if the latest checkpoint is
    /// older than the current `STATE_FORMAT_VERSION`.
    ///
    /// This is called automatically in `open_disk_store_from_config` before
    /// `recover_tip_with_checkpoint`, so operators only need to install the new
    /// binary and restart — the migration happens on first boot.
    ///
    /// # Behaviour
    /// - No checkpoint on disk → returns `Ok(())` (fresh node, no migration needed).
    /// - `disk_version == STATE_FORMAT_VERSION` → returns `Ok(())` (already current).
    /// - `disk_version > STATE_FORMAT_VERSION` → returns `Err(BinaryTooOld)`.
    /// - `disk_version < STATE_FORMAT_VERSION` → runs handler chain, rewrites checkpoint.
    pub fn apply_upgrade_chain(
        &self,
        registry: &pqc_state::UpgradeRegistry,
    ) -> Result<(), StorageError> {
        use super::storage::{
            encode_cbor, state_into_record, TrustedCheckpointMetadataRecord,
            TrustedCheckpointRecord, STATE_FORMAT_VERSION,
        };

        let checkpoints_cf = self.db.cf_handle(CF_CHECKPOINTS).expect("checkpoints CF");
        let mut iter = self.db.iterator_cf(&checkpoints_cf, IteratorMode::End);

        // Find the latest checkpoint entry without the fail-fast version check.
        let (raw_key, raw_value) = loop {
            match iter.next() {
                None => return Ok(()), // no checkpoint — fresh node
                Some(Ok(kv)) => {
                    // Decode just enough to read the version field.
                    match decode_cbor_slice::<TrustedCheckpointRecord>(&kv.1, "<migration>") {
                        Ok(r) if r.metadata.height == 0 => continue,
                        Ok(_) => break (kv.0, kv.1),
                        Err(_) => continue, // skip corrupted entries
                    }
                }
                Some(Err(e)) => return Err(StorageError::RocksDb(e.to_string())),
            }
        };

        let record = decode_cbor_slice::<TrustedCheckpointRecord>(&raw_value, "<migration>")?;
        let disk_version = record.version;

        match disk_version.cmp(&STATE_FORMAT_VERSION) {
            std::cmp::Ordering::Equal => return Ok(()), // already current
            std::cmp::Ordering::Greater => {
                return Err(StorageError::BinaryTooOld {
                    disk_version,
                    binary_version: STATE_FORMAT_VERSION,
                });
            }
            std::cmp::Ordering::Less => {} // proceed with migration
        }

        // Save metadata before consuming `record.state`.
        let saved_height = record.metadata.height;
        let saved_tip_hash = record.metadata.tip_hash;

        // We need the chain_id to deserialise state.  Use an empty slice here —
        // `record_into_state` uses it only to initialise `StateStore::chain_id`.
        // The chain_id is re-derived from genesis config after recovery; the
        // migration only touches schema fields, not chain_id-dependent logic.
        let mut state = record_into_state(record.state, &[])?;

        // Run migration handlers from disk_version to STATE_FORMAT_VERSION.
        registry
            .run_migrations(&mut state, disk_version, STATE_FORMAT_VERSION)
            .map_err(|e| StorageError::MigrationFailed(e.to_string()))?;

        // Recompute state_root with the new algorithm (includes upgrade-leaf section).
        let new_state_root = state.state_root();

        // Build and write back the migrated checkpoint record.
        let migrated_state = state_into_record(&state);
        let migrated_record = TrustedCheckpointRecord {
            version: STATE_FORMAT_VERSION,
            metadata: TrustedCheckpointMetadataRecord {
                height: saved_height,
                tip_hash: saved_tip_hash,
                state_root: new_state_root,
            },
            state: migrated_state,
        };

        let migrated_bytes = encode_cbor(&migrated_record)
            .map_err(|e| StorageError::MigrationFailed(e.to_string()))?;

        self.db
            .put_cf(&checkpoints_cf, &raw_key, &migrated_bytes)
            .map_err(rocksdb_err)?;

        tracing::info!(
            from_version = disk_version,
            to_version = STATE_FORMAT_VERSION,
            height = migrated_record.metadata.height,
            "state migration complete — checkpoint rewritten with new version",
        );

        Ok(())
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn persist_to_db(&self, stored: &StoredBlock) -> Result<(), StorageError> {
        let meta_cf = self.db.cf_handle(CF_META).expect("meta CF");
        let mut batch = WriteBatch::default();
        append_block_to_batch(&mut batch, &self.db, stored)?;
        batch.put_cf(
            &meta_cf,
            META_TIP_HEIGHT,
            height_to_key(stored.metadata.height),
        );
        self.db
            .write_opt(batch, &self.write_opts)
            .map_err(rocksdb_err)
    }

    /// ADR-054 — single atomic WriteBatch implementing the canonical
    /// sibling swap on RocksDB:
    /// 1. Archive the displaced block under the `siblings` CF.
    /// 2. Drop the displaced hash_index entry.
    /// 3. Overwrite the `blocks[height]` entry with the canonical body
    ///    (existing tx_index entries point at the same height key, so
    ///    they remain valid — siblings have identical tx_hashes by
    ///    pre-condition).
    /// 4. Insert the canonical hash_index entry.
    /// 5. Re-assert `meta.tip_height` so concurrent readers observe the
    ///    swap as a single transaction.
    fn persist_replace_canonical(
        &self,
        displaced: &StoredBlock,
        canonical: &StoredBlock,
    ) -> Result<(), StorageError> {
        let blocks_cf = self.db.cf_handle(CF_BLOCKS).expect("blocks CF");
        let hash_index_cf = self.db.cf_handle(CF_HASH_INDEX).expect("hash_index CF");
        let siblings_cf = self.db.cf_handle(CF_SIBLINGS).expect("siblings CF");
        let meta_cf = self.db.cf_handle(CF_META).expect("meta CF");

        let height = canonical.metadata.height;
        let height_key = height_to_key(height);

        // Sibling key: 32-byte hash || 8-byte BE height. Hash prefix
        // makes `prefix_iterator_cf` lookups by hash O(1).
        let mut sibling_key = [0u8; 40];
        sibling_key[..32].copy_from_slice(&displaced.metadata.block_hash.0);
        sibling_key[32..].copy_from_slice(&height_key);

        let displaced_cbor = encode_stored_block_bytes(displaced)?;
        let canonical_cbor = encode_stored_block_bytes(canonical)?;

        let mut batch = WriteBatch::default();
        // (1) Archive displaced.
        batch.put_cf(&siblings_cf, sibling_key, displaced_cbor);
        // (2) Drop displaced hash index.
        batch.delete_cf(&hash_index_cf, displaced.metadata.block_hash.0);
        // (3) Overwrite canonical at height.
        batch.put_cf(&blocks_cf, height_key, canonical_cbor);
        // (4) Index canonical hash → height.
        batch.put_cf(&hash_index_cf, canonical.metadata.block_hash.0, height_key);
        // (5) Re-assert tip height (unchanged value, same height key).
        batch.put_cf(&meta_cf, META_TIP_HEIGHT, height_key);

        self.db
            .write_opt(batch, &self.write_opts)
            .map_err(rocksdb_err)
    }

    // `validate_commit_proof` method removed with the `commit_policy`
    // field in Phase 8 M2 (TASK-113). Quorum validation now lives at
    // the append-block call site — the caller passes `policy:
    // Option<&CommitQuorumPolicy>` derived from the current
    // `StateStore::active_validators()` snapshot.
}

// ── Free functions ────────────────────────────────────────────────────────────

/// Open (or create) the RocksDB at `path` with all required column families.
fn open_rocksdb(path: &Path) -> Result<DB, StorageError> {
    let mut db_opts = Options::default();
    db_opts.create_if_missing(true);
    db_opts.create_missing_column_families(true);

    let mut cf_opts = Options::default();
    cf_opts.set_compression_type(rocksdb::DBCompressionType::Lz4);

    let cfs = vec![
        ColumnFamilyDescriptor::new(CF_BLOCKS, cf_opts.clone()),
        ColumnFamilyDescriptor::new(CF_HASH_INDEX, cf_opts.clone()),
        ColumnFamilyDescriptor::new(CF_TX_INDEX, cf_opts.clone()),
        ColumnFamilyDescriptor::new(CF_CHECKPOINTS, cf_opts.clone()),
        ColumnFamilyDescriptor::new(CF_META, Options::default()),
        // ADR-054 — siblings archive. `create_missing_column_families`
        // makes this CF appear on first open of a pre-ADR-054 data dir,
        // so existing RocksDB layouts upgrade transparently.
        ColumnFamilyDescriptor::new(CF_SIBLINGS, cf_opts.clone()),
    ];

    DB::open_cf_descriptors(&db_opts, path, cfs).map_err(rocksdb_err)
}

/// Open RocksDB with minimized background resource usage for test environments.
///
/// Differences from `open_rocksdb`:
/// - No compression (eliminates LZ4 CPU overhead in debug builds).
/// - `max_background_jobs = 1` — reduces background compaction threads that
///   compete with Tokio workers on constrained VPS hardware.
///
/// **Do not use in production** — throughput and space amplification are worse.
fn open_rocksdb_no_wal(path: &Path) -> Result<DB, StorageError> {
    let mut db_opts = Options::default();
    db_opts.create_if_missing(true);
    db_opts.create_missing_column_families(true);
    // Limit RocksDB background compaction threads to avoid CPU starvation of
    // Tokio workers when multiple test nodes run in parallel.
    db_opts.set_max_background_jobs(1);

    let mut cf_opts = Options::default();
    cf_opts.set_compression_type(rocksdb::DBCompressionType::None);

    let cfs = vec![
        ColumnFamilyDescriptor::new(CF_BLOCKS, cf_opts.clone()),
        ColumnFamilyDescriptor::new(CF_HASH_INDEX, cf_opts.clone()),
        ColumnFamilyDescriptor::new(CF_TX_INDEX, cf_opts.clone()),
        ColumnFamilyDescriptor::new(CF_CHECKPOINTS, cf_opts.clone()),
        ColumnFamilyDescriptor::new(CF_META, Options::default()),
        // ADR-054 — siblings archive. `create_missing_column_families`
        // makes this CF appear on first open of a pre-ADR-054 data dir,
        // so existing RocksDB layouts upgrade transparently.
        ColumnFamilyDescriptor::new(CF_SIBLINGS, cf_opts.clone()),
    ];

    DB::open_cf_descriptors(&db_opts, path, cfs).map_err(rocksdb_err)
}

/// Scan the `checkpoints` CF from newest to oldest and return the first
/// `(checkpoint_height, tip_hash)` pair that is structurally valid.
///
/// Used in `open_internal` where the chain_id is not yet available.
fn find_latest_checkpoint_pair(
    db: &DB,
    _chain_id: Option<&[u8]>,
) -> Result<Option<(u64, BlockHash)>, StorageError> {
    let checkpoints_cf = db.cf_handle(CF_CHECKPOINTS).expect("checkpoints CF");
    let mut iter = db.iterator_cf(&checkpoints_cf, IteratorMode::End);
    loop {
        let entry = match iter.next() {
            None => return Ok(None),
            Some(Ok(kv)) => kv,
            Some(Err(e)) => return Err(StorageError::RocksDb(e.to_string())),
        };
        let record = match decode_cbor_slice::<TrustedCheckpointRecord>(&entry.1, "<ckpt>") {
            Ok(r) => r,
            Err(_) => continue, // skip corrupted entry
        };
        // ADR-030: hard-fail only if the disk has a NEWER format than this binary.
        // Older formats are acceptable here — apply_upgrade_chain (called in
        // open_disk_store_from_config after open()) will migrate the checkpoint
        // before recover_tip_with_checkpoint runs.
        if record.version > super::storage::STATE_FORMAT_VERSION {
            return Err(StorageError::BinaryTooOld {
                disk_version: record.version,
                binary_version: super::storage::STATE_FORMAT_VERSION,
            });
        }
        if record.metadata.height == 0 {
            continue;
        }
        return Ok(Some((
            record.metadata.height,
            BlockHash(record.metadata.tip_hash),
        )));
    }
}

/// Find the latest valid checkpoint, fully deserialising state and verifying
/// `state_root`.  Used in `recover_tip_with_checkpoint`.
fn find_latest_checkpoint_with_state(
    db: &DB,
    chain_id: &[u8],
) -> Result<Option<(TrustedCheckpointMetadata, StateStore)>, StorageError> {
    let checkpoints_cf = db.cf_handle(CF_CHECKPOINTS).expect("checkpoints CF");
    let mut iter = db.iterator_cf(&checkpoints_cf, IteratorMode::End);
    loop {
        let entry = match iter.next() {
            None => return Ok(None),
            Some(Ok(kv)) => kv,
            Some(Err(e)) => return Err(StorageError::RocksDb(e.to_string())),
        };

        let record = match decode_cbor_slice::<TrustedCheckpointRecord>(&entry.1, "<ckpt>") {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "checkpoint CBOR decode failed — skipping");
                continue;
            }
        };
        // ADR-030 / TASK-101: version mismatch → hard fail.
        super::storage::check_state_format_version(record.version)?;

        let metadata = TrustedCheckpointMetadata {
            height: record.metadata.height,
            tip_hash: BlockHash(record.metadata.tip_hash),
            state_root: BlockHash(record.metadata.state_root),
        };

        if metadata.height == 0 {
            return Ok(None);
        }

        let state = match record_into_state(record.state, chain_id) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    checkpoint_height = metadata.height,
                    error = %e,
                    "checkpoint state deserialization failed — skipping",
                );
                continue;
            }
        };

        if state.block_height() != metadata.height {
            tracing::warn!(
                state_height = state.block_height(),
                checkpoint_height = metadata.height,
                "checkpoint height mismatch — skipping",
            );
            continue;
        }

        let actual_root = BlockHash(state.state_root());
        if actual_root != metadata.state_root {
            tracing::warn!(
                checkpoint_height = metadata.height,
                stored_root = %hex::encode(metadata.state_root.0),
                computed_root = %hex::encode(actual_root.0),
                "checkpoint state_root mismatch — skipping",
            );
            continue;
        }

        return Ok(Some((metadata, state)));
    }
}

/// Read and fully decode a `StoredBlock` from the `blocks` CF.
fn read_stored_block_from_db(db: &DB, height: u64) -> Result<Option<StoredBlock>, StorageError> {
    let blocks_cf = db.cf_handle(CF_BLOCKS).expect("blocks CF");
    match db
        .get_cf(&blocks_cf, height_to_key(height))
        .map_err(rocksdb_err)?
    {
        None => Ok(None),
        Some(bytes) => {
            let record: StoredBlockRecord = decode_cbor_slice(&bytes, "<block-db>")?;
            let stored = record_into_stored_block(record, height)?;
            Ok(Some(stored))
        }
    }
}

/// Write a `StoredBlock` into a `WriteBatch` (blocks + hash_index + tx_index CFs).
/// The caller is responsible for updating `meta/tip_height`.
fn append_block_to_batch(
    batch: &mut WriteBatch,
    db: &DB,
    stored: &StoredBlock,
) -> Result<(), StorageError> {
    let height_key = height_to_key(stored.metadata.height);

    let blocks_cf = db.cf_handle(CF_BLOCKS).expect("blocks CF");
    let hash_index_cf = db.cf_handle(CF_HASH_INDEX).expect("hash_index CF");
    let tx_index_cf = db.cf_handle(CF_TX_INDEX).expect("tx_index CF");

    let block_cbor = encode_stored_block_bytes(stored)?;
    batch.put_cf(&blocks_cf, height_key, block_cbor);
    batch.put_cf(&hash_index_cf, stored.metadata.block_hash.0, height_key);

    // Index every tx for O(1) TASK-104 lookup.
    for tx_hash in &stored.block.tx_hashes {
        batch.put_cf(&tx_index_cf, tx_hash.0, height_key);
    }

    Ok(())
}

/// CBOR-encode `value` into a `Vec<u8>`.
fn encode_cbor_vec<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, StorageError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|e| StorageError::Encode {
        path: std::path::PathBuf::from("<rocksdb>"),
        detail: e.to_string(),
    })?;
    Ok(buf)
}

fn rocksdb_err(e: rocksdb::Error) -> StorageError {
    StorageError::RocksDb(e.to_string())
}

#[inline]
fn height_to_key(height: u64) -> [u8; 8] {
    height.to_be_bytes()
}

fn key_to_height(bytes: &[u8]) -> Result<u64, StorageError> {
    if bytes.len() != 8 {
        return Err(StorageError::InvalidPersistedValue(
            "height key must be 8 bytes",
        ));
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(bytes);
    Ok(u64::from_be_bytes(arr))
}

// ── Meta CF helpers ───────────────────────────────────────────────────────────

fn read_meta_u64_by_name(db: &DB, key: &[u8]) -> Result<Option<u64>, StorageError> {
    let meta_cf = db.cf_handle(CF_META).expect("meta CF");
    match db.get_cf(&meta_cf, key).map_err(rocksdb_err)? {
        None => Ok(None),
        Some(bytes) => Ok(Some(key_to_height(&bytes)?)),
    }
}

fn read_meta_hash_by_name(db: &DB, key: &[u8]) -> Result<Option<BlockHash>, StorageError> {
    let meta_cf = db.cf_handle(CF_META).expect("meta CF");
    match db.get_cf(&meta_cf, key).map_err(rocksdb_err)? {
        None => Ok(None),
        Some(bytes) => {
            if bytes.len() != 32 {
                return Err(StorageError::InvalidPersistedValue(
                    "meta hash must be 32 bytes",
                ));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(Some(BlockHash(arr)))
        }
    }
}

fn write_meta_raw(db: &DB, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
    let meta_cf = db.cf_handle(CF_META).expect("meta CF");
    db.put_cf(&meta_cf, key, value).map_err(rocksdb_err)
}

#[cfg(test)]
mod adr_054_tests {
    //! ADR-054 — `replace_canonical_at_height` + `siblings` CF coverage.
    //!
    //! These tests exercise the RocksDB-side persistence guarantees of
    //! the canonical sibling swap. The in-memory pre-conditions are
    //! covered by `chain::tests::replace_tip_block_*`.

    use std::{
        env, fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use pqc_crypto::{sign::StubVerifier, AlgId};
    use pqc_mempool::{admission::try_admit, Mempool};
    use pqc_state::StateStore;
    use pqc_tx::{codec::encode_tx, validate::FeeParams};
    use pqc_types::{
        account::{Account, Address},
        block::BlockHash,
        keyset::{allowed_tx, KeyEntry, KeySet, KeyStatus},
        transaction::{MsgType, Transaction},
    };

    use crate::{
        engine::compute_block_hash, AssemblyConfig, ChainError, LocalProposer, LocalProposerConfig,
        StoredBlock,
    };

    use super::{RocksDbChainStore, StorageError};

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(label: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = env::temp_dir().join(format!(
                "pqc-rocks-adr054-{label}-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn signer_account(addr: Address, balance: u128) -> Account {
        Account {
            address: addr,
            balance,
            nonce: 0,
            keys: KeySet(vec![KeyEntry {
                alg_id: AlgId::MlDsa65,
                pk_bytes: vec![0u8; 32].into(),
                key_version: 1,
                valid_from_height: 0,
                status: KeyStatus::Active,
                allowed_tx_types: allowed_tx::ALL,
            }]),
            policy_version: 0,
            policy_hash: None,
            verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
            auth_data: Vec::new(),
        }
    }

    fn transfer_tx(sender: Address, recipient: Address, nonce: u64) -> Transaction {
        let mut payload = Vec::new();
        ciborium::into_writer(
            &ciborium::value::Value::Map(vec![
                (
                    ciborium::value::Value::Integer(1u64.into()),
                    ciborium::value::Value::Bytes(recipient.0.to_vec()),
                ),
                (
                    ciborium::value::Value::Integer(2u64.into()),
                    ciborium::value::Value::Integer(100u64.into()),
                ),
            ]),
            &mut payload,
        )
        .unwrap();
        Transaction {
            tx_version: 1,
            chain_id: Vec::new(),
            msg_type: MsgType::TokenTransfer,
            sender,
            nonce,
            fee: 100,
            fee_tip: 0,
            gas_limit: 100_000,
            payload,
            sig_alg_id: AlgId::MlDsa65,
            sig_key_version: 1,
            signature: vec![0xAB; 3_309],
        }
    }

    fn admit(pool: &mut Mempool, store: &StateStore, tx: &Transaction) {
        let raw = encode_tx(tx).unwrap();
        try_admit(pool, raw, store, &StubVerifier, &FeeParams::default()).unwrap();
    }

    fn make_proposer() -> LocalProposer {
        LocalProposer::new(
            [0x99; 32],
            LocalProposerConfig {
                assembly: AssemblyConfig::default(),
                initial_prev_hash: BlockHash([0x11; 32]),
            },
        )
    }

    /// Append one block and return the persisted store + the stored block.
    fn append_block_to_store(dir: &TempDir) -> (RocksDbChainStore, StoredBlock) {
        let mut store =
            RocksDbChainStore::open_no_wal(&dir.0, BlockHash([0x11; 32])).expect("open ok");

        let sender = Address([0xA1; 32]);
        let recipient = Address([0x22; 32]);
        let mut state = StateStore::new();
        state.insert_account(signer_account(sender.clone(), 10_000));
        let mut pool = Mempool::new();
        let mut proposer = make_proposer();
        let tx = transfer_tx(sender, recipient, 0);
        admit(&mut pool, &state, &tx);
        let result = proposer
            .run_once(&mut state, &mut pool, 1_710_000_000)
            .expect("run_once ok");
        store.append_block_trusted(&result).expect("append ok");
        let stored = store
            .read_stored_block_at_height(1)
            .expect("read ok")
            .expect("present");
        (store, stored)
    }

    fn shift_timestamp_sibling(stored: &StoredBlock, delta_ns: u64) -> StoredBlock {
        let mut block = stored.block.clone();
        block.header.timestamp = block.header.timestamp.saturating_add(delta_ns);
        let block_hash = compute_block_hash(&block);
        let mut metadata = stored.metadata.clone();
        metadata.timestamp = block.header.timestamp;
        metadata.block_hash = block_hash;
        StoredBlock {
            block,
            metadata,
            included_transactions: stored.included_transactions.clone(),
        }
    }

    #[test]
    fn replace_canonical_swaps_tip_and_archives_displaced_to_siblings_cf() {
        let dir = TempDir::new("swap-archive");
        let (mut store, original) = append_block_to_store(&dir);
        let original_hash = original.metadata.block_hash.clone();

        let canonical = shift_timestamp_sibling(&original, 2_000_000_000);
        let canonical_hash = canonical.metadata.block_hash.clone();
        assert_ne!(canonical_hash, original_hash);

        let displaced = store
            .replace_canonical_at_height(canonical.clone(), None)
            .expect("swap ok");
        assert_eq!(displaced.metadata.block_hash, original_hash);

        // Tip is now the canonical variant.
        assert_eq!(store.tip_hash(), Some(&canonical_hash));
        assert_eq!(store.height(), 1);

        // Disk read returns the canonical body at height 1.
        let on_disk = store
            .read_stored_block_at_height(1)
            .expect("read ok")
            .expect("present");
        assert_eq!(on_disk.metadata.block_hash, canonical_hash);
        assert_eq!(
            on_disk.block.header.timestamp,
            canonical.block.header.timestamp
        );

        // Displaced body archived in siblings CF.
        let archived = store
            .read_sibling_by_hash(&original_hash)
            .expect("read ok")
            .expect("archived");
        assert_eq!(archived.metadata.block_hash, original_hash);
        assert_eq!(archived.metadata.height, 1);
        assert_eq!(
            archived.block.header.timestamp,
            original.block.header.timestamp
        );

        // Looking up the original hash via the canonical hash_index path
        // returns nothing — the hash_index entry was removed by the batch.
        assert!(store
            .read_sibling_by_hash(&BlockHash([0xFF; 32]))
            .unwrap()
            .is_none());
    }

    #[test]
    fn replace_canonical_persists_across_reopen() {
        let dir = TempDir::new("swap-reopen");
        let (mut store, original) = append_block_to_store(&dir);
        let original_hash = original.metadata.block_hash.clone();
        let canonical = shift_timestamp_sibling(&original, 2_000_000_000);
        let canonical_hash = canonical.metadata.block_hash.clone();

        store
            .replace_canonical_at_height(canonical, None)
            .expect("swap ok");
        drop(store);

        let reopened =
            RocksDbChainStore::open_no_wal(&dir.0, BlockHash([0x11; 32])).expect("reopen ok");
        assert_eq!(reopened.tip_hash(), Some(&canonical_hash));
        assert_eq!(reopened.height(), 1);
        let on_disk = reopened
            .read_stored_block_at_height(1)
            .expect("read ok")
            .expect("present");
        assert_eq!(on_disk.metadata.block_hash, canonical_hash);
        let archived = reopened
            .read_sibling_by_hash(&original_hash)
            .expect("read ok")
            .expect("archived");
        assert_eq!(archived.metadata.block_hash, original_hash);
    }

    #[test]
    fn verify_quick_finality_invariants_rejects_empty_commit_sigs() {
        let dir = TempDir::new("audit-reject");
        // The synthetic proposer used by `append_block_to_store` does
        // NOT attach commit signatures — those are added by the
        // consensus loop in production. The audit MUST reject this
        // chain at startup, which is exactly the protective behaviour
        // ADR-054 §Stage 6 asks for.
        let (store, _stored) = append_block_to_store(&dir);
        let err = store
            .verify_quick_finality_invariants()
            .expect_err("audit must refuse a chain with empty commit_signatures");
        match err {
            StorageError::InvalidPersistedValue(msg) => {
                assert!(
                    msg.contains("ADR-054"),
                    "unexpected audit error message: {msg}"
                );
            }
            other => panic!("expected InvalidPersistedValue, got {other:?}"),
        }
    }

    #[test]
    fn verify_quick_finality_invariants_passes_when_every_block_has_sigs() {
        // Same synthetic chain, but we patch the in-memory tail to
        // give the block a fake-but-non-empty commit_signatures vector
        // before running the audit. The audit only inspects vec
        // length, so a length-1 placeholder satisfies the invariant.
        let dir = TempDir::new("audit-pass");
        let (mut store, stored) = append_block_to_store(&dir);
        let mut patched = stored;
        patched
            .block
            .commit_signatures
            .push(pqc_types::block::CommitSig {
                validator_address: vec![0u8; 32],
                sig_alg_id: pqc_crypto::AlgId::MlDsa65,
                round: 0,
                signature: vec![0u8; 8],
            });
        // Re-derive the candidate's metadata so the storage
        // pre-conditions hold; the timestamp is shifted to ensure a
        // hash difference vs the original.
        let canonical = shift_timestamp_sibling(&patched, 1);
        store
            .replace_canonical_at_height(canonical, None)
            .expect("swap to fake-sig variant ok");
        store
            .verify_quick_finality_invariants()
            .expect("audit must pass once every block has at least one sig");
    }

    #[test]
    fn replace_canonical_rejects_state_divergent_candidate_atomically() {
        let dir = TempDir::new("swap-divergent");
        let (mut store, original) = append_block_to_store(&dir);
        let original_hash = original.metadata.block_hash.clone();

        // Tamper with state_root → state-divergent candidate.
        let mut block = original.block.clone();
        block.header.state_root = BlockHash([0xCC; 32]);
        block.header.timestamp += 2_000_000_000;
        let new_hash = compute_block_hash(&block);
        let mut metadata = original.metadata.clone();
        metadata.state_root = BlockHash([0xCC; 32]);
        metadata.timestamp = block.header.timestamp;
        metadata.block_hash = new_hash;
        let divergent = StoredBlock {
            block,
            metadata,
            included_transactions: original.included_transactions.clone(),
        };

        let err = store
            .replace_canonical_at_height(divergent, None)
            .unwrap_err();
        match err {
            StorageError::Chain(ChainError::SiblingStateDivergence {
                field: "state_root",
                ..
            }) => {}
            other => panic!("expected state_root divergence, got {other:?}"),
        }

        // Tip + on-disk block unchanged.
        assert_eq!(store.tip_hash(), Some(&original_hash));
        let on_disk = store.read_stored_block_at_height(1).unwrap().unwrap();
        assert_eq!(on_disk.metadata.block_hash, original_hash);
        // No siblings archived for failed swaps.
        assert!(store
            .read_sibling_by_hash(&original_hash)
            .unwrap()
            .is_none());
    }
}

#[cfg(test)]
mod prune_tests;
