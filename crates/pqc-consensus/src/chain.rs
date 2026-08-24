// SPDX-License-Identifier: BUSL-1.1
//! Linear in-memory block store for the single-node prototype.
//!
//! This layer records committed blocks, indexes them by height and hash, and
//! enforces the minimal invariants needed for deterministic replay and future
//! persistence work.

use std::collections::{BTreeMap, HashMap};

use pqc_types::block::{Block, BlockHash};
use pqc_types::transaction::Transaction;
use thiserror::Error;

use crate::engine::{compute_block_hash, BlockExecutionResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockMetadata {
    pub block_hash: BlockHash,
    pub height: u64,
    pub prev_hash: BlockHash,
    pub state_root: BlockHash,
    pub tx_root: BlockHash,
    pub timestamp: u64,
    pub bytes_used: usize,
    pub included_count: usize,
    pub deferred_count: usize,
    pub skipped_count: usize,
    pub vc_budget_consumed: usize,
}

#[derive(Debug, Clone)]
pub struct StoredBlock {
    pub block: Block,
    pub metadata: BlockMetadata,
    pub included_transactions: Vec<Transaction>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChainError {
    #[error("DUPLICATE_BLOCK_HASH: block hash already exists in active chain")]
    DuplicateBlockHash,
    #[error("DUPLICATE_BLOCK_HEIGHT: active chain already contains height {0}")]
    DuplicateBlockHeight(u64),
    #[error("INVALID_BLOCK_HEIGHT: expected next height {expected}, got {got}")]
    InvalidBlockHeight { expected: u64, got: u64 },
    #[error("PARENT_HASH_MISMATCH: block parent does not match current tip")]
    ParentHashMismatch { expected: BlockHash, got: BlockHash },
    #[error("EXECUTION_HEIGHT_MISMATCH: block header height {block_height} != execution new height {execution_height}")]
    ExecutionHeightMismatch {
        block_height: u64,
        execution_height: u64,
    },
    #[error("EXECUTION_ROOT_MISMATCH: execution roots do not match block header roots")]
    ExecutionRootMismatch,
    #[error("STORED_BLOCK_HASH_MISMATCH: stored metadata hash does not match the block header and tx set")]
    StoredBlockHashMismatch,
    #[error("STORED_BLOCK_METADATA_MISMATCH: {0}")]
    StoredBlockMetadataMismatch(&'static str),
    #[error("STORED_BLOCK_BODY_COUNT_MISMATCH: tx body count does not match tx_hash count")]
    StoredBlockBodyCountMismatch,
    /// ADR-054 — sibling tip-replacement attempted but the local tip is
    /// not at the height the caller asked to replace. The caller must
    /// re-read `tip()` and resubmit; replacement is permitted at the tip
    /// only (no rewriting of finalised history).
    #[error("REPLACE_NOT_AT_TIP: replace requested for height {requested}, but tip is at {tip}")]
    ReplaceNotAtTip { requested: u64, tip: u64 },
    /// ADR-054 — sibling tip-replacement attempted with no current tip.
    /// Empty chains have nothing to replace; the caller should append.
    #[error("REPLACE_EMPTY_CHAIN: cannot replace tip on an empty chain")]
    ReplaceEmptyChain,
    /// ADR-054 — sibling tip-replacement attempted but the candidate
    /// block is structurally not a sibling of the local tip. Sibling
    /// status requires identical `prev_hash + state_root + tx_root`;
    /// any divergence is a state-effect difference and triggers the
    /// equivocation-evidence path at the caller, not a swap.
    #[error("SIBLING_STATE_DIVERGENCE: candidate block at height {height} is not a state-equivalent sibling of the local tip ({field} differs)")]
    SiblingStateDivergence { height: u64, field: &'static str },
    /// ADR-054 — sibling tip-replacement attempted with the same hash
    /// as the local tip. The caller should treat this as a duplicate
    /// rather than attempting a swap.
    #[error("SIBLING_HASH_COLLISION: candidate block_hash equals the local tip hash; nothing to replace")]
    SiblingHashCollision,
}

#[derive(Debug, Clone)]
pub struct ChainStore {
    anchor_prev_hash: BlockHash,
    by_hash: HashMap<BlockHash, StoredBlock>,
    by_height: BTreeMap<u64, BlockHash>,
    tip_hash: Option<BlockHash>,
    /// Virtual base height for snapshot-bootstrapped chains.
    ///
    /// When a node cold-starts from a distributed snapshot (TASK-050), it does not
    /// have block files for heights 1..snapshot_height. Setting `base_height` allows
    /// the chain to report the correct absolute height and accept the first post-snapshot
    /// block without requiring sequential history from genesis.
    ///
    /// For nodes with full history from genesis this is always 0.
    base_height: u64,
}

impl ChainStore {
    pub fn new(anchor_prev_hash: BlockHash) -> Self {
        Self {
            anchor_prev_hash,
            by_hash: HashMap::new(),
            by_height: BTreeMap::new(),
            tip_hash: None,
            base_height: 0,
        }
    }

    /// Construct a chain anchored at `anchor_prev_hash` with a non-zero virtual base height.
    ///
    /// Used for snapshot-bootstrapped nodes where blocks before `base_height` are not
    /// present on disk. The first block that can be appended must have height
    /// `base_height + 1` and `prev_hash == anchor_prev_hash`.
    pub fn new_with_base(anchor_prev_hash: BlockHash, base_height: u64) -> Self {
        Self {
            anchor_prev_hash,
            by_hash: HashMap::new(),
            by_height: BTreeMap::new(),
            tip_hash: None,
            base_height,
        }
    }

    pub fn height(&self) -> u64 {
        self.tip()
            .map(|stored| stored.metadata.height)
            .unwrap_or(self.base_height)
    }

    pub fn tip_hash(&self) -> Option<&BlockHash> {
        self.tip_hash.as_ref()
    }

    pub fn anchor_prev_hash(&self) -> &BlockHash {
        &self.anchor_prev_hash
    }

    pub fn tip(&self) -> Option<&StoredBlock> {
        self.tip_hash
            .as_ref()
            .and_then(|hash| self.by_hash.get(hash))
    }

    pub fn get_block_by_height(&self, height: u64) -> Option<&Block> {
        self.by_height
            .get(&height)
            .and_then(|hash| self.by_hash.get(hash))
            .map(|stored| &stored.block)
    }

    pub fn get_stored_block_by_height(&self, height: u64) -> Option<&StoredBlock> {
        self.by_height
            .get(&height)
            .and_then(|hash| self.by_hash.get(hash))
    }

    pub fn get_block_by_hash(&self, block_hash: &BlockHash) -> Option<&Block> {
        self.by_hash.get(block_hash).map(|stored| &stored.block)
    }

    pub fn get_metadata_by_height(&self, height: u64) -> Option<&BlockMetadata> {
        self.by_height
            .get(&height)
            .and_then(|hash| self.by_hash.get(hash))
            .map(|stored| &stored.metadata)
    }

    pub fn get_metadata_by_hash(&self, block_hash: &BlockHash) -> Option<&BlockMetadata> {
        self.by_hash.get(block_hash).map(|stored| &stored.metadata)
    }

    pub fn blocks_in_order(&self) -> Vec<&StoredBlock> {
        self.by_height
            .values()
            .filter_map(|hash| self.by_hash.get(hash))
            .collect()
    }

    pub fn metadata_in_order(&self) -> Vec<BlockMetadata> {
        self.blocks_in_order()
            .into_iter()
            .map(|stored| stored.metadata.clone())
            .collect()
    }

    pub fn append_block(
        &mut self,
        execution: &BlockExecutionResult,
    ) -> Result<BlockMetadata, ChainError> {
        self.validate_execution(execution)?;

        let block_hash = compute_block_hash(&execution.block);
        let metadata = BlockMetadata {
            block_hash: block_hash.clone(),
            height: execution.block.header.height,
            prev_hash: execution.block.header.prev_hash.clone(),
            state_root: execution.state_root.clone(),
            tx_root: execution.tx_root.clone(),
            timestamp: execution.block.header.timestamp,
            bytes_used: execution.bytes_used,
            included_count: execution.included.len(),
            deferred_count: execution.deferred.len(),
            skipped_count: execution.skipped.len(),
            vc_budget_consumed: execution.vc_budget_consumed,
        };

        self.append_stored_block(StoredBlock {
            block: execution.block.clone(),
            metadata,
            included_transactions: execution.included_transactions.clone(),
        })
    }

    /// Evict all blocks at heights ≤ `checkpoint_height` from the in-memory
    /// maps and advance the anchor to the checkpoint tip hash.
    /// Called after writing a trusted checkpoint to bound RSS during long runs.
    pub fn compact_to_checkpoint(
        &mut self,
        checkpoint_height: u64,
        checkpoint_tip_hash: BlockHash,
    ) {
        let evict_heights: Vec<u64> = self
            .by_height
            .range(..=checkpoint_height)
            .map(|(h, _)| *h)
            .collect();
        for h in evict_heights {
            if let Some(hash) = self.by_height.remove(&h) {
                self.by_hash.remove(&hash);
            }
        }
        self.anchor_prev_hash = checkpoint_tip_hash;
        self.base_height = checkpoint_height;
    }

    pub fn append_stored_block(
        &mut self,
        stored: StoredBlock,
    ) -> Result<BlockMetadata, ChainError> {
        self.validate_stored_block(&stored)?;

        let block_hash = stored.metadata.block_hash.clone();
        let metadata = stored.metadata.clone();
        self.by_height.insert(metadata.height, block_hash.clone());
        self.by_hash.insert(block_hash.clone(), stored);
        self.tip_hash = Some(block_hash);

        Ok(metadata)
    }

    /// ADR-054 §Stage 4 — atomic sibling swap at the chain tip.
    ///
    /// Replaces the current tip with `canonical`, returning the previous
    /// tip's `StoredBlock` so the caller can archive it (siblings CF in
    /// the RocksDB layer). The candidate MUST be a *state-equivalent*
    /// sibling of the local tip: same `prev_hash`, `state_root`, and
    /// `tx_root`. Differences in `timestamp`, `commit_signatures`, or
    /// any other field that ends up in `block_hash` are permitted and
    /// are exactly the case the swap exists to resolve.
    ///
    /// Pre-condition guards (return `ChainError::*` without mutation):
    /// - chain must have a tip (`ReplaceEmptyChain`);
    /// - tip height must equal `canonical.metadata.height` (`ReplaceNotAtTip`);
    /// - tip hash must differ from `canonical.metadata.block_hash`
    ///   (`SiblingHashCollision` — caller should treat duplicates idempotently);
    /// - tip's `prev_hash`/`state_root`/`tx_root` must match the candidate's
    ///   (`SiblingStateDivergence` with the offending field — caller emits
    ///   equivocation evidence per ADR-054 §Stage 4 (c)).
    ///
    /// On success, the returned `StoredBlock` is the *previous* tip — its
    /// `metadata.block_hash` and `metadata.timestamp` will reflect the
    /// variant that was just removed from the canonical chain.
    pub fn replace_tip_block(&mut self, canonical: StoredBlock) -> Result<StoredBlock, ChainError> {
        let tip_hash = self
            .tip_hash
            .as_ref()
            .ok_or(ChainError::ReplaceEmptyChain)?
            .clone();
        let tip = self
            .by_hash
            .get(&tip_hash)
            .expect("tip_hash points into by_hash by invariant")
            .clone();

        if tip.metadata.height != canonical.metadata.height {
            return Err(ChainError::ReplaceNotAtTip {
                requested: canonical.metadata.height,
                tip: tip.metadata.height,
            });
        }
        if tip.metadata.block_hash == canonical.metadata.block_hash {
            return Err(ChainError::SiblingHashCollision);
        }
        if tip.metadata.prev_hash != canonical.metadata.prev_hash {
            return Err(ChainError::SiblingStateDivergence {
                height: tip.metadata.height,
                field: "prev_hash",
            });
        }
        if tip.metadata.state_root != canonical.metadata.state_root {
            return Err(ChainError::SiblingStateDivergence {
                height: tip.metadata.height,
                field: "state_root",
            });
        }
        if tip.metadata.tx_root != canonical.metadata.tx_root {
            return Err(ChainError::SiblingStateDivergence {
                height: tip.metadata.height,
                field: "tx_root",
            });
        }

        // Verify the candidate's metadata internally agrees with its
        // body before we touch the maps. This catches malformed inputs
        // that would otherwise leave the maps consistent with bogus data.
        let candidate_block_hash = compute_block_hash(&canonical.block);
        if canonical.metadata.block_hash != candidate_block_hash {
            return Err(ChainError::StoredBlockHashMismatch);
        }
        if canonical.metadata.height != canonical.block.header.height
            || canonical.metadata.prev_hash != canonical.block.header.prev_hash
            || canonical.metadata.state_root != canonical.block.header.state_root
            || canonical.metadata.tx_root != canonical.block.header.tx_root
        {
            return Err(ChainError::StoredBlockMetadataMismatch(
                "candidate metadata does not match its block header",
            ));
        }
        if canonical.block.tx_hashes.len() != canonical.included_transactions.len() {
            return Err(ChainError::StoredBlockBodyCountMismatch);
        }

        // Atomic swap on the maps. by_height entry is overwritten
        // (single-canonical-per-height invariant preserved); by_hash
        // entry for the prior variant is removed; by_hash entry for the
        // canonical variant is inserted; tip_hash advanced.
        let new_hash = canonical.metadata.block_hash.clone();
        self.by_height
            .insert(canonical.metadata.height, new_hash.clone());
        self.by_hash.remove(&tip_hash);
        self.by_hash.insert(new_hash.clone(), canonical);
        self.tip_hash = Some(new_hash);

        Ok(tip)
    }

    fn validate_execution(&self, execution: &BlockExecutionResult) -> Result<(), ChainError> {
        if execution.block.header.height != execution.new_height {
            return Err(ChainError::ExecutionHeightMismatch {
                block_height: execution.block.header.height,
                execution_height: execution.new_height,
            });
        }

        if execution.block.header.state_root != execution.state_root
            || execution.block.header.tx_root != execution.tx_root
        {
            return Err(ChainError::ExecutionRootMismatch);
        }

        let block_hash = compute_block_hash(&execution.block);
        if self.by_hash.contains_key(&block_hash) {
            return Err(ChainError::DuplicateBlockHash);
        }

        let height = execution.block.header.height;
        if self.by_height.contains_key(&height) {
            return Err(ChainError::DuplicateBlockHeight(height));
        }

        let expected_height = self.height().saturating_add(1);
        if height != expected_height {
            return Err(ChainError::InvalidBlockHeight {
                expected: expected_height,
                got: height,
            });
        }

        let expected_prev_hash = self
            .tip_hash
            .clone()
            .unwrap_or_else(|| self.anchor_prev_hash.clone());
        if execution.block.header.prev_hash != expected_prev_hash {
            return Err(ChainError::ParentHashMismatch {
                expected: expected_prev_hash,
                got: execution.block.header.prev_hash.clone(),
            });
        }

        Ok(())
    }

    fn validate_stored_block(&self, stored: &StoredBlock) -> Result<(), ChainError> {
        if stored.metadata.height != stored.block.header.height {
            return Err(ChainError::StoredBlockMetadataMismatch(
                "metadata height does not match block header",
            ));
        }
        if stored.metadata.prev_hash != stored.block.header.prev_hash {
            return Err(ChainError::StoredBlockMetadataMismatch(
                "metadata prev_hash does not match block header",
            ));
        }
        if stored.metadata.state_root != stored.block.header.state_root {
            return Err(ChainError::StoredBlockMetadataMismatch(
                "metadata state_root does not match block header",
            ));
        }
        if stored.metadata.tx_root != stored.block.header.tx_root {
            return Err(ChainError::StoredBlockMetadataMismatch(
                "metadata tx_root does not match block header",
            ));
        }
        if stored.metadata.included_count != stored.block.tx_hashes.len() {
            return Err(ChainError::StoredBlockMetadataMismatch(
                "metadata included_count does not match tx_hash count",
            ));
        }
        if stored.block.tx_hashes.len() != stored.included_transactions.len() {
            return Err(ChainError::StoredBlockBodyCountMismatch);
        }

        let block_hash = compute_block_hash(&stored.block);
        if stored.metadata.block_hash != block_hash {
            return Err(ChainError::StoredBlockHashMismatch);
        }

        if self.by_hash.contains_key(&block_hash) {
            return Err(ChainError::DuplicateBlockHash);
        }

        let height = stored.block.header.height;
        if self.by_height.contains_key(&height) {
            return Err(ChainError::DuplicateBlockHeight(height));
        }

        let expected_height = self.height().saturating_add(1);
        if height != expected_height {
            return Err(ChainError::InvalidBlockHeight {
                expected: expected_height,
                got: height,
            });
        }

        let expected_prev_hash = self
            .tip_hash
            .clone()
            .unwrap_or_else(|| self.anchor_prev_hash.clone());
        if stored.block.header.prev_hash != expected_prev_hash {
            return Err(ChainError::ParentHashMismatch {
                expected: expected_prev_hash,
                got: stored.block.header.prev_hash.clone(),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests;
