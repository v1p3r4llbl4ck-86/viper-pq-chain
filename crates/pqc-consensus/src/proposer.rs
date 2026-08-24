// SPDX-License-Identifier: BUSL-1.1
//! Local single-node proposer loop for the current prototype milestone.
//!
//! This module intentionally stays small: it builds the next block against
//! cloned state and mempool snapshots, then commits the prepared result in one
//! explicit step. No networking, leader election, or multi-node coordination is
//! introduced here.

use pqc_mempool::Mempool;
use pqc_state::StateStore;
use pqc_types::block::{Block, BlockHash};
use thiserror::Error;

use crate::engine::{
    assemble_block, compute_block_hash, AssembleError, AssemblyConfig, AssemblyContext,
    BlockExecutionResult,
};

#[derive(Debug, Clone)]
pub struct LocalProposerConfig {
    pub assembly: AssemblyConfig,
    pub initial_prev_hash: BlockHash,
}

impl Default for LocalProposerConfig {
    fn default() -> Self {
        Self {
            assembly: AssemblyConfig::default(),
            initial_prev_hash: BlockHash([0u8; 32]),
        }
    }
}

pub struct ProposedBlock {
    pub execution: BlockExecutionResult,
    pub block_hash: BlockHash,
    next_state: StateStore,
    next_pool: Mempool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProposerError {
    #[error(transparent)]
    Assemble(#[from] AssembleError),
    #[error("STALE_PROPOSAL_HEIGHT: expected next height {expected}, got {got}")]
    StaleProposalHeight { expected: u64, got: u64 },
    #[error("STALE_PROPOSAL_PREV_HASH: proposal was built against an old chain tip")]
    StaleProposalPrevHash,
}

pub struct LocalProposer {
    proposer: [u8; 32],
    config: LocalProposerConfig,
    tip_hash: BlockHash,
    committed_blocks: Vec<Block>,
}

impl LocalProposer {
    pub fn new(proposer: [u8; 32], config: LocalProposerConfig) -> Self {
        Self {
            proposer,
            tip_hash: config.initial_prev_hash.clone(),
            config,
            committed_blocks: Vec::new(),
        }
    }

    pub fn build_next_block(
        &self,
        store: &StateStore,
        pool: &Mempool,
        timestamp: u64,
    ) -> Result<ProposedBlock, ProposerError> {
        let mut next_state = store.clone();
        let mut next_pool = pool.clone();
        let execution = assemble_block(
            &mut next_state,
            &mut next_pool,
            &AssemblyContext {
                height: store.block_height().saturating_add(1),
                prev_hash: self.tip_hash.clone(),
                timestamp,
                proposer: self.proposer.to_vec(),
            },
            self.config.assembly.clone(),
        )?;
        let block_hash = compute_block_hash(&execution.block);

        Ok(ProposedBlock {
            execution,
            block_hash,
            next_state,
            next_pool,
        })
    }

    pub fn commit_block(
        &mut self,
        store: &mut StateStore,
        pool: &mut Mempool,
        proposal: ProposedBlock,
    ) -> Result<BlockExecutionResult, ProposerError> {
        let expected_height = store.block_height().saturating_add(1);
        let proposal_height = proposal.execution.block.header.height;
        if proposal_height != expected_height {
            return Err(ProposerError::StaleProposalHeight {
                expected: expected_height,
                got: proposal_height,
            });
        }

        if proposal.execution.block.header.prev_hash != self.tip_hash {
            return Err(ProposerError::StaleProposalPrevHash);
        }

        let height = proposal.execution.new_height;
        let included = proposal.execution.included.len();
        let skipped = proposal.execution.skipped.len();
        let bytes_used = proposal.execution.bytes_used;
        let tip_hash = hex::encode(proposal.block_hash.0);

        *store = proposal.next_state;
        *pool = proposal.next_pool;
        self.tip_hash = proposal.block_hash.clone();
        self.committed_blocks.push(proposal.execution.block.clone());

        tracing::info!(
            height,
            included,
            skipped,
            bytes_used,
            tip_hash = %tip_hash,
            "block committed",
        );

        Ok(proposal.execution)
    }

    /// Commit block state WITHOUT replacing the mempool.
    ///
    /// This is used by the 3-phase devnet producer loop, where the pool may have
    /// received new transactions via `inject_tx` between phase 1 (build/clone)
    /// and phase 3 (commit). Replacing the pool with the phase-1 clone would
    /// silently evict those injected transactions.
    ///
    /// Callers are responsible for applying the pool diff from the returned
    /// `BlockExecutionResult` (evicting included + skipped tx hashes and calling
    /// `evict_stale` for each included sender).
    pub fn commit_block_preserve_pool(
        &mut self,
        store: &mut StateStore,
        proposal: ProposedBlock,
    ) -> Result<BlockExecutionResult, ProposerError> {
        let expected_height = store.block_height().saturating_add(1);
        let proposal_height = proposal.execution.block.header.height;
        if proposal_height != expected_height {
            return Err(ProposerError::StaleProposalHeight {
                expected: expected_height,
                got: proposal_height,
            });
        }

        if proposal.execution.block.header.prev_hash != self.tip_hash {
            return Err(ProposerError::StaleProposalPrevHash);
        }

        let height = proposal.execution.new_height;
        let included = proposal.execution.included.len();
        let skipped = proposal.execution.skipped.len();
        let bytes_used = proposal.execution.bytes_used;
        let tip_hash = hex::encode(proposal.block_hash.0);

        *store = proposal.next_state;
        // Do NOT replace pool — callers apply the diff.
        self.tip_hash = proposal.block_hash.clone();
        self.committed_blocks.push(proposal.execution.block.clone());

        tracing::info!(
            height,
            included,
            skipped,
            bytes_used,
            tip_hash = %tip_hash,
            "block committed (pool preserved)",
        );

        Ok(proposal.execution)
    }

    pub fn run_once(
        &mut self,
        store: &mut StateStore,
        pool: &mut Mempool,
        timestamp: u64,
    ) -> Result<BlockExecutionResult, ProposerError> {
        let proposal = self.build_next_block(store, pool, timestamp)?;
        self.commit_block(store, pool, proposal)
    }

    /// Update the proposer address used when building the next block.
    ///
    /// Used by the BFT consensus loop (TASK-084) to implement proposer rotation:
    /// before each height the loop calls `select_proposer(validators, height, round)`
    /// and sets the result here, so the assembled block header carries the correct
    /// rotating proposer address.
    pub fn set_proposer(&mut self, address: [u8; 32]) {
        self.proposer = address;
    }

    /// Advance this proposer's internal `tip_hash` to a new value.
    ///
    /// Used when a block arrives from a PEER (via gossip / snapshot /
    /// block-fetch) and is persisted through `import_remote_block`
    /// rather than through this node's own `commit_block` path. Without
    /// this update, the next call to `build_next_block` would construct
    /// a proposal whose `prev_hash` points to the stale pre-import
    /// tip, causing a `ChainError::ParentHashMismatch` when the block
    /// is appended to the shared chain store (ADR-051 / TASK-167 /
    /// TASK-170 — discovered while validating the 3-node distributed-
    /// signing test).
    ///
    /// Callers MUST pass the block_hash of the most recently-imported
    /// block. No internal validation is performed beyond a bare copy.
    pub fn advance_tip(&mut self, new_tip: BlockHash) {
        self.tip_hash = new_tip;
    }

    pub fn tip_hash(&self) -> &BlockHash {
        &self.tip_hash
    }

    pub fn committed_blocks(&self) -> &[Block] {
        &self.committed_blocks
    }
}

#[cfg(test)]
mod tests;
