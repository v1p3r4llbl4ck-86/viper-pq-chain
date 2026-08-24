// SPDX-License-Identifier: BUSL-1.1
//! Deterministic replay and recovery helpers for the single-node prototype.
//!
//! The current prototype keeps an active linear chain in memory. This module
//! replays that history from a genesis state snapshot and verifies that the
//! final state, roots, and tip hash are fully derivable from committed block
//! data alone.

use pqc_state::{
    apply::{apply_tx, distribute_block_fees, ExecutionContext, FeeDistributionParams},
    process_governance_tallies, ApplyError, StateStore,
};
use pqc_tx::{codec::encode_tx, compute_tx_hash, validate::FeeParams, TxError};
use pqc_types::{account::Address, block::BlockHash, transaction::TxHash};
use thiserror::Error;

use crate::{
    chain::{ChainStore, StoredBlock},
    engine::{compute_block_hash, compute_tx_root},
};

#[derive(Debug)]
pub struct ReplayResult {
    pub state: StateStore,
    pub tip_hash: BlockHash,
    pub height: u64,
    pub state_root: BlockHash,
}

#[derive(Debug, Error)]
pub enum ReplayError {
    #[error("HEIGHT_GAP: expected height {expected}, got {got}")]
    HeightGap { expected: u64, got: u64 },
    #[error("PARENT_HASH_MISMATCH at height {height}: expected {expected:?}, got {got:?}")]
    ParentHashMismatch {
        height: u64,
        expected: BlockHash,
        got: BlockHash,
    },
    #[error("TIP_HASH_MISMATCH: expected {expected:?}, got {got:?}")]
    TipHashMismatch { expected: BlockHash, got: BlockHash },
    #[error("BLOCK_HASH_MISMATCH at height {height}: expected {expected:?}, got {got:?}")]
    BlockHashMismatch {
        height: u64,
        expected: BlockHash,
        got: BlockHash,
    },
    #[error(
        "BODY_COUNT_MISMATCH at height {height}: {body_count} tx bodies for {hash_count} tx hashes"
    )]
    BodyCountMismatch {
        height: u64,
        body_count: usize,
        hash_count: usize,
    },
    #[error(
        "TX_HASH_MISMATCH at height {height}, index {tx_index}: expected {expected:?}, got {got:?}"
    )]
    TxHashMismatch {
        height: u64,
        tx_index: usize,
        expected: TxHash,
        got: TxHash,
    },
    #[error("TX_ENCODING_FAILED at height {height}, index {tx_index}: {source}")]
    TxEncodingFailed {
        height: u64,
        tx_index: usize,
        #[source]
        source: TxError,
    },
    #[error("TX_APPLY_FAILED at height {height}, index {tx_index}: {source}")]
    ApplyFailed {
        height: u64,
        tx_index: usize,
        #[source]
        source: ApplyError,
    },
    #[error("TX_ROOT_MISMATCH at height {height}: expected {expected:?}, got {got:?}")]
    TxRootMismatch {
        height: u64,
        expected: BlockHash,
        got: BlockHash,
    },
    #[error("STATE_ROOT_MISMATCH at height {height}: expected {expected:?}, got {got:?}")]
    StateRootMismatch {
        height: u64,
        expected: BlockHash,
        got: BlockHash,
    },
    #[error("METADATA_MISMATCH at height {height}: {detail}")]
    MetadataMismatch { height: u64, detail: &'static str },
}

pub fn verify_chain_consistency(chain: &ChainStore) -> Result<(), ReplayError> {
    let blocks = chain.blocks_in_order();
    verify_stored_blocks_structure(1, chain.anchor_prev_hash(), blocks.iter().copied())?;

    let expected_tip = blocks
        .last()
        .map(|stored| stored.metadata.block_hash.clone())
        .unwrap_or_else(|| chain.anchor_prev_hash().clone());
    let actual_tip = chain
        .tip_hash()
        .cloned()
        .unwrap_or_else(|| chain.anchor_prev_hash().clone());

    if actual_tip != expected_tip {
        return Err(ReplayError::TipHashMismatch {
            expected: expected_tip,
            got: actual_tip,
        });
    }

    Ok(())
}

pub fn replay_blocks_from_genesis(
    genesis_state: &StateStore,
    anchor_prev_hash: &BlockHash,
    blocks: &[StoredBlock],
    fee_params: FeeParams,
    fee_dist: FeeDistributionParams,
    validator_pool: Vec<Address>,
) -> Result<ReplayResult, ReplayError> {
    replay_blocks_from_state(
        genesis_state,
        anchor_prev_hash,
        blocks,
        fee_params,
        fee_dist,
        validator_pool,
    )
}

/// Replay a committed tail starting from an already trusted state snapshot.
///
/// This is used for checkpoint-tail recovery and for live follower catch-up in
/// the local multi-node devnet path. The supplied `anchor_prev_hash` must be
/// the hash that immediately precedes `blocks[0]`, or the current chain anchor
/// when replaying a full history from height 1.
///
/// `fee_dist` and `validator_pool` MUST match the values used during original
/// block production; a mismatch causes a `STATE_ROOT_MISMATCH` replay error.
pub fn replay_blocks_from_state(
    base_state: &StateStore,
    anchor_prev_hash: &BlockHash,
    blocks: &[StoredBlock],
    fee_params: FeeParams,
    fee_dist: FeeDistributionParams,
    validator_pool: Vec<Address>,
) -> Result<ReplayResult, ReplayError> {
    verify_stored_blocks_structure(
        base_state.block_height().saturating_add(1),
        anchor_prev_hash,
        blocks.iter(),
    )?;

    let mut state = base_state.clone();
    let mut tip_hash = anchor_prev_hash.clone();
    let mut state_root = BlockHash(state.state_root());

    for stored in blocks {
        let mut fees_collected: u128 = 0;
        let mut block_gas_used: u64 = 0;

        // Mirror engine.rs: wire the current AIMD adaptive base fee into each
        // block's ExecutionContext so actual_fee_breakdown matches production.
        let mut block_fee_params = fee_params.clone();
        block_fee_params.base_fee_dynamic = state.base_fee_dynamic();

        for (tx_index, (tx, expected_hash)) in stored
            .included_transactions
            .iter()
            .zip(stored.block.tx_hashes.iter())
            .enumerate()
        {
            let raw = encode_tx(tx).map_err(|source| ReplayError::TxEncodingFailed {
                height: stored.metadata.height,
                tx_index,
                source,
            })?;
            let actual_hash = TxHash(compute_tx_hash(&raw));
            if &actual_hash != expected_hash {
                return Err(ReplayError::TxHashMismatch {
                    height: stored.metadata.height,
                    tx_index,
                    expected: expected_hash.clone(),
                    got: actual_hash,
                });
            }

            let execution = apply_tx(
                &mut state,
                tx,
                ExecutionContext {
                    tx_bytes_len: raw.len(),
                    fee_params: block_fee_params.clone(),
                },
            )
            .map_err(|source| ReplayError::ApplyFailed {
                height: stored.metadata.height,
                tx_index,
                source,
            })?;
            fees_collected = fees_collected
                .saturating_add(u128::from(execution.fee_charged))
                .saturating_add(u128::from(tx.fee_tip));
            block_gas_used = block_gas_used.saturating_add(execution.gas_used);
        }

        // Distribute fees — MUST use the same params as the production path in assemble_block.
        if stored.block.header.proposer.len() == 32 {
            let proposer_bytes: [u8; 32] = stored
                .block
                .header
                .proposer
                .as_slice()
                .try_into()
                .map_err(|_| ReplayError::MetadataMismatch {
                    height: stored.metadata.height,
                    detail: "proposer address is not 32 bytes despite length check",
                })?;
            let proposer_addr = Address(proposer_bytes);
            // Phase 8 M2 (TASK-113) — replay must mirror the live
            // apply path: prefer `state.active_validators()` over the
            // static `validator_pool` argument so fee credits resolve
            // to the same addresses on recovery as they did at block
            // production time. State at this point reflects everything
            // applied up to (but not including) this block, same
            // ordering guarantee as in `engine::apply_block`. Fallback
            // to the passed-in pool only when state is empty (pre-
            // genesis-seed bootstrap window in unit tests).
            let state_pool: Vec<Address> = state
                .active_validators()
                .iter()
                .map(|v| v.operator.clone())
                .collect();
            let pool_slice: &[Address] = if state_pool.is_empty() {
                &validator_pool
            } else {
                &state_pool
            };
            distribute_block_fees(
                &mut state,
                &proposer_addr,
                fees_collected,
                pool_slice,
                &fee_dist,
            );
        }

        // Apply AIMD adaptive base fee update — SPEC-FEE-002 §6.2.
        // Must mirror the call in engine.rs assemble_block (before advance_height).
        state.apply_aimd_update(block_gas_used);

        // Tally governance proposals — must mirror engine.rs assemble_block (TASK-100).
        process_governance_tallies(&mut state, stored.block.header.height);

        // Process Unbonding → Exited transitions — must mirror engine.rs assemble_block.
        let exited = state.process_validator_unbonding_expirations(stored.block.header.height);
        for (operator, bond) in exited {
            if let Some(account) = state.get_account_mut(&operator) {
                account.balance = account.balance.saturating_add(bond);
            }
            state.commit_account_mutation(&operator);
        }

        // TASK-223 — replay-side mirror of engine.rs::assemble_block: activate
        // pending consensus-key rotations whose `rotation_start_height` has
        // been reached. MUST stay in lockstep with engine.rs or replayed
        // state-root will diverge from the live one at the activation block.
        let _ = state.activate_pending_consensus_key_rotations(stored.block.header.height);

        state.advance_height();

        let actual_tx_root = BlockHash(compute_tx_root(&stored.block.tx_hashes));
        if actual_tx_root != stored.block.header.tx_root {
            return Err(ReplayError::TxRootMismatch {
                height: stored.metadata.height,
                expected: stored.block.header.tx_root.clone(),
                got: actual_tx_root,
            });
        }

        let actual_state_root = BlockHash(state.state_root());
        if actual_state_root != stored.block.header.state_root {
            return Err(ReplayError::StateRootMismatch {
                height: stored.metadata.height,
                expected: stored.block.header.state_root.clone(),
                got: actual_state_root,
            });
        }

        let actual_block_hash = compute_block_hash(&stored.block);
        if actual_block_hash != stored.metadata.block_hash {
            return Err(ReplayError::BlockHashMismatch {
                height: stored.metadata.height,
                expected: stored.metadata.block_hash.clone(),
                got: actual_block_hash,
            });
        }

        tip_hash = stored.metadata.block_hash.clone();
        state_root = actual_state_root;
    }

    Ok(ReplayResult {
        height: state.block_height(),
        state,
        tip_hash,
        state_root,
    })
}

pub fn recover_tip(
    chain: &ChainStore,
    genesis_state: &StateStore,
    fee_params: FeeParams,
    fee_dist: FeeDistributionParams,
    validator_pool: Vec<Address>,
) -> Result<ReplayResult, ReplayError> {
    verify_chain_consistency(chain)?;
    let blocks: Vec<StoredBlock> = chain.blocks_in_order().into_iter().cloned().collect();
    replay_blocks_from_state(
        genesis_state,
        chain.anchor_prev_hash(),
        &blocks,
        fee_params,
        fee_dist,
        validator_pool,
    )
}

fn verify_stored_blocks_structure<'a>(
    expected_start_height: u64,
    anchor_prev_hash: &BlockHash,
    blocks: impl IntoIterator<Item = &'a StoredBlock>,
) -> Result<(), ReplayError> {
    let mut expected_prev_hash = anchor_prev_hash.clone();

    for (expected_height, stored) in (expected_start_height..).zip(blocks) {
        let height = stored.block.header.height;
        if height != expected_height {
            return Err(ReplayError::HeightGap {
                expected: expected_height,
                got: height,
            });
        }

        if stored.block.header.prev_hash != expected_prev_hash {
            return Err(ReplayError::ParentHashMismatch {
                height,
                expected: expected_prev_hash,
                got: stored.block.header.prev_hash.clone(),
            });
        }

        if stored.block.tx_hashes.len() != stored.included_transactions.len() {
            return Err(ReplayError::BodyCountMismatch {
                height,
                body_count: stored.included_transactions.len(),
                hash_count: stored.block.tx_hashes.len(),
            });
        }

        if stored.metadata.height != stored.block.header.height {
            return Err(ReplayError::MetadataMismatch {
                height,
                detail: "metadata height does not match block header",
            });
        }
        if stored.metadata.prev_hash != stored.block.header.prev_hash {
            return Err(ReplayError::MetadataMismatch {
                height,
                detail: "metadata prev_hash does not match block header",
            });
        }
        if stored.metadata.state_root != stored.block.header.state_root {
            return Err(ReplayError::MetadataMismatch {
                height,
                detail: "metadata state_root does not match block header",
            });
        }
        if stored.metadata.tx_root != stored.block.header.tx_root {
            return Err(ReplayError::MetadataMismatch {
                height,
                detail: "metadata tx_root does not match block header",
            });
        }
        if stored.metadata.included_count != stored.block.tx_hashes.len() {
            return Err(ReplayError::MetadataMismatch {
                height,
                detail: "metadata included_count does not match block tx hashes",
            });
        }

        let actual_block_hash = compute_block_hash(&stored.block);
        if stored.metadata.block_hash != actual_block_hash {
            return Err(ReplayError::BlockHashMismatch {
                height,
                expected: stored.metadata.block_hash.clone(),
                got: actual_block_hash,
            });
        }

        expected_prev_hash = stored.metadata.block_hash.clone();
    }

    Ok(())
}

#[cfg(test)]
mod tests;
