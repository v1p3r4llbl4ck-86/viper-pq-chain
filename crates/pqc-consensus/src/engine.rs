// SPDX-License-Identifier: BUSL-1.1
//! Deterministic block assembly for the Phase 1 proposer path.
//!
//! The block assembler consumes admitted mempool entries, orders them with a
//! deterministic policy, applies state transitions in sequence, and produces a
//! block candidate plus the resulting state root.

use std::cmp::Ordering;

use crate::epoch::{is_epoch_boundary, EpochConfig};
use pqc_crypto::TaggedHasher;
use pqc_mempool::{pool::PendingEntry, Mempool};
use pqc_state::{
    apply::{
        apply_tx, distribute_block_fees, ExecutionContext, ExecutionStatus, FeeDistributionParams,
    },
    process_governance_tallies, ApplyError, StateStore,
};
use pqc_tx::validate::FeeParams;
use pqc_types::account::Address;
use pqc_types::{
    block::{Block, BlockHash, BlockHeader},
    transaction::{Transaction, TxHash},
};
use thiserror::Error;

/// Metadata required to assemble a block candidate.
#[derive(Debug, Clone)]
pub struct AssemblyContext {
    pub height: u64,
    pub prev_hash: BlockHash,
    pub timestamp: u64,
    /// Validator address bytes. Phase 1 uses 32-byte operator addresses.
    pub proposer: Vec<u8>,
}

/// Block assembly limits and fee distribution configuration.
#[derive(Debug, Clone)]
pub struct AssemblyConfig {
    /// Current implementation counts canonical transaction bytes only.
    /// Header and commit material accounting will be added in later phases.
    pub max_block_bytes: usize,
    pub fee_params: FeeParams,
    /// All active validator addresses participating in the fee pool.
    ///
    /// Phase 3 bootstrap path: set from `config.devnet.validators`. Phase 8
    /// M2 (TASK-113) switches fee distribution to read the active set from
    /// `StateStore::active_validators()` per block — so this field becomes
    /// a FALLBACK only: engine's `apply_block` prefers the state-driven set
    /// whenever the store has any Active validator, and falls back to this
    /// field only when the store is empty (genesis-seeding, isolated unit
    /// tests with no validators installed).
    ///
    /// Step 2 of the M2 plan removes this field entirely once every
    /// `AssemblyConfig` construction path reliably ships validators via
    /// state at construction time (see `docs/historical/phase-8-m2-plan.md` §4).
    pub validator_pool: Vec<Address>,
    /// Controls proposer priority share vs. pool split.
    pub fee_dist: FeeDistributionParams,
    /// Epoch configuration — controls epoch duration and unbonding period (ADR-042).
    pub epoch_config: EpochConfig,
}

impl Default for AssemblyConfig {
    fn default() -> Self {
        Self {
            max_block_bytes: usize::MAX,
            fee_params: FeeParams::default(),
            validator_pool: Vec::new(),
            fee_dist: FeeDistributionParams::default(),
            epoch_config: EpochConfig::default(),
        }
    }
}

/// Why a pending transaction was not included in the assembled block.
#[derive(Debug, PartialEq, Eq)]
pub enum SkipReason {
    BlockSizeLimit,
    ApplyFailed(ApplyError),
}

/// A skipped transaction plus its reason.
#[derive(Debug, PartialEq, Eq)]
pub struct SkippedTx {
    pub tx_hash: TxHash,
    pub reason: SkipReason,
}

/// Output of a successful assembly run.
#[derive(Debug)]
pub struct BlockExecutionResult {
    pub block: Block,
    pub included: Vec<TxHash>,
    pub included_transactions: Vec<Transaction>,
    pub deferred: Vec<TxHash>,
    pub new_height: u64,
    pub state_root: BlockHash,
    pub tx_root: BlockHash,
    pub bytes_used: usize,
    pub vc_budget_consumed: usize,
    pub skipped: Vec<SkippedTx>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AssembleError {
    #[error("INVALID_HEIGHT: expected next height {expected}, got {got}")]
    InvalidHeight { expected: u64, got: u64 },
    #[error("INVALID_PROPOSER: proposer address must be 32 bytes, got {got}")]
    InvalidProposer { got: usize },
}

/// Assemble a block from currently admitted mempool transactions.
///
/// The ordering policy is deterministic and intentionally small:
/// higher fee first, then higher tip, then sender bytes, nonce, and tx_hash.
/// This matches the current admission model, which permits only one pending
/// nonce per sender against the finalized state snapshot.
pub fn assemble_block(
    store: &mut StateStore,
    pool: &mut Mempool,
    ctx: &AssemblyContext,
    config: AssemblyConfig,
) -> Result<BlockExecutionResult, AssembleError> {
    let expected_height = store.block_height().saturating_add(1);
    if ctx.height != expected_height {
        return Err(AssembleError::InvalidHeight {
            expected: expected_height,
            got: ctx.height,
        });
    }

    if ctx.proposer.len() != 32 {
        return Err(AssembleError::InvalidProposer {
            got: ctx.proposer.len(),
        });
    }

    let mut pending: Vec<PendingEntry> = pool.all_pending().cloned().collect();
    pending.sort_by(compare_pending_entries);

    let mut included_hashes = Vec::new();
    let mut included_transactions = Vec::new();
    let mut deferred = Vec::new();
    let mut bytes_used = 0usize;
    let mut skipped = Vec::new();
    let vc_budget_consumed = pool.vc_admitted_count();
    let mut fees_collected: u128 = 0;
    // Accumulate total gas_used across all included transactions for the AIMD update.
    let mut block_gas_used: u64 = 0;

    for entry in pending {
        let next_size = bytes_used.saturating_add(entry.raw_bytes.len());
        if next_size > config.max_block_bytes {
            deferred.push(TxHash(entry.tx_hash));
            continue;
        }

        // Wire the current AIMD adaptive base fee into the ExecutionContext fee_params
        // so the lane-adjusted effective base fee (SPEC-FEE-002 §7) is used.
        let mut exec_fee_params = config.fee_params.clone();
        exec_fee_params.base_fee_dynamic = store.base_fee_dynamic();

        match apply_tx(
            store,
            &entry.tx,
            ExecutionContext {
                tx_bytes_len: entry.raw_bytes.len(),
                fee_params: exec_fee_params,
            },
        ) {
            Ok(execution) => {
                fees_collected = fees_collected
                    .saturating_add(u128::from(execution.fee_charged))
                    .saturating_add(u128::from(entry.tx.fee_tip));
                bytes_used = next_size;
                block_gas_used = block_gas_used.saturating_add(execution.gas_used);
                included_hashes.push(TxHash(entry.tx_hash));
                included_transactions.push(entry.tx.clone());
                pool.evict(&entry.tx_hash);
                if matches!(
                    execution.status,
                    ExecutionStatus::Applied | ExecutionStatus::RevertedOutOfGas
                ) {
                    pool.evict_stale(&entry.tx.sender.0, entry.tx.nonce.saturating_add(1));
                }
            }
            Err(err) => {
                pool.evict(&entry.tx_hash);
                skipped.push(SkippedTx {
                    tx_hash: TxHash(entry.tx_hash),
                    reason: SkipReason::ApplyFailed(err),
                });
            }
        }
    }

    // Distribute collected fees: proposer priority share + validator pool split.
    let proposer_bytes: [u8; 32] =
        ctx.proposer
            .as_slice()
            .try_into()
            .map_err(|_| AssembleError::InvalidProposer {
                got: ctx.proposer.len(),
            })?;
    let proposer_addr = Address(proposer_bytes);

    // Phase 8 M2 (TASK-113) — prefer the on-chain Active validator set
    // over the static config list. `active_validators()` already sorts
    // deterministically by operator address, and its snapshot reflects
    // the state BEFORE this block's validator-set mutations run
    // (`process_epoch_transitions` executes later in the apply path), so
    // a validator registered in this block is not paid for this block —
    // the invariant the M2 plan §5 pins.
    //
    // Fallback to `config.validator_pool` only when the store has no
    // Active validators yet (covers isolated unit tests and the pre-
    // genesis-seed bootstrap window where the state map is empty).
    let state_pool: Vec<Address> = store
        .active_validators()
        .iter()
        .map(|v| v.operator.clone())
        .collect();
    let pool_slice: &[Address] = if state_pool.is_empty() {
        &config.validator_pool
    } else {
        &state_pool
    };
    distribute_block_fees(
        store,
        &proposer_addr,
        fees_collected,
        pool_slice,
        &config.fee_dist,
    );

    // Apply AIMD adaptive base fee update — SPEC-FEE-002 §6.2.
    // Must run after fee distribution and before advance_height().
    store.apply_aimd_update(block_gas_used);

    // Tally governance proposals whose voting window closed at this height — TASK-100.
    process_governance_tallies(store, ctx.height);

    // Process Unbonding → Exited transitions for validators whose unbonding period elapsed.
    // Returns stake to operator accounts (SPEC-VAL-001 §5.3.7, TASK-064).
    let exited = store.process_validator_unbonding_expirations(ctx.height);
    for (operator, bond) in exited {
        if let Some(account) = store.get_account_mut(&operator) {
            account.balance = account.balance.saturating_add(bond);
        }
        store.commit_account_mutation(&operator);
    }

    // TASK-223 — activate any pending consensus-key rotations whose
    // `rotation_start_height` has been reached. Atomic per-block; replaces
    // the operator's `consensus_alg_id + consensus_pk` in the validator
    // record. The replay path mirrors this call (see recovery.rs); cold-
    // sync replay (TASK-198) holds the byte-stability invariant for
    // chains that include rotation activations.
    let activations = store.activate_pending_consensus_key_rotations(ctx.height);
    if !activations.is_empty() {
        tracing::info!(
            count = activations.len(),
            height = ctx.height,
            "consensus-key rotations activated"
        );
    }

    pool.reset_vc_count();
    store.advance_height();

    // Process epoch boundary validator set transitions — ADR-042.
    if is_epoch_boundary(ctx.height, config.epoch_config.epoch_duration) {
        store.process_epoch_transitions(
            ctx.height,
            config.epoch_config.epoch_duration,
            config.epoch_config.unbonding_period,
            &config.epoch_config.churn,
        );
    }

    let state_root = BlockHash(store.state_root());
    let tx_root = BlockHash(compute_tx_root(&included_hashes));

    let block = Block {
        header: BlockHeader {
            // ADR-053 §T1.1 — every produced block at viper-pq-1 genesis
            // onwards ships `header_version = HEADER_VERSION_V1` and an
            // empty `extension_root`. Future P-COMPAT-001 upgrades bump
            // the version or populate the extension map.
            header_version: pqc_types::block::HEADER_VERSION_V1,
            height: ctx.height,
            prev_hash: ctx.prev_hash.clone(),
            state_root: state_root.clone(),
            tx_root: tx_root.clone(),
            timestamp: ctx.timestamp,
            proposer: ctx.proposer.clone(),
            extension_root: pqc_types::block::empty_extension_root(),
        },
        tx_hashes: included_hashes.clone(),
        commit_signatures: Vec::new(),
    };

    Ok(BlockExecutionResult {
        block,
        included: included_hashes,
        included_transactions,
        deferred,
        new_height: store.block_height(),
        state_root,
        tx_root,
        bytes_used,
        vc_budget_consumed,
        skipped,
    })
}

fn compare_pending_entries(left: &PendingEntry, right: &PendingEntry) -> Ordering {
    right
        .fee
        .cmp(&left.fee)
        .then_with(|| right.fee_tip.cmp(&left.fee_tip))
        .then_with(|| left.tx.sender.0.cmp(&right.tx.sender.0))
        .then_with(|| left.tx.nonce.cmp(&right.tx.nonce))
        .then_with(|| left.tx_hash.cmp(&right.tx_hash))
}

pub(crate) fn compute_tx_root(tx_hashes: &[TxHash]) -> [u8; 32] {
    let mut digest = TaggedHasher::new(b"PQC-TX-ROOT-V1");
    digest.push_u64(tx_hashes.len() as u64);
    for tx_hash in tx_hashes {
        digest.push_chunk(&tx_hash.0);
    }
    digest.finish()
}

pub fn compute_block_hash(block: &Block) -> BlockHash {
    // ADR-053 §T1.1 — domain tagged `"VIPER-BLOCK-HASH-V1"` (upgraded
    // from the legacy `"PQC-BLOCK-HASH-V1"` at viper-pq-1 launch; the
    // tag MUST change when the header layout changes, per
    // P-COMPAT-001, so every viper-pq-1 block_hash is cryptographically
    // distinct from every legacy devnet-2 block_hash even if the other
    // inputs coincide). `header_version` is absorbed first so future
    // versions never collide with v1 block hashes, and `extension_root`
    // at the end ensures future extension commitments are included.
    let mut digest = TaggedHasher::new(b"VIPER-BLOCK-HASH-V1");
    digest.push_u64(block.header.header_version as u64);
    digest.push_u64(block.header.height);
    digest.push_chunk(&block.header.prev_hash.0);
    digest.push_chunk(&block.header.state_root.0);
    digest.push_chunk(&block.header.tx_root.0);
    digest.push_u64(block.header.timestamp);
    digest.push_chunk(&block.header.proposer);
    digest.push_chunk(&block.header.extension_root);
    digest.push_u64(block.tx_hashes.len() as u64);
    for tx_hash in &block.tx_hashes {
        digest.push_chunk(&tx_hash.0);
    }
    BlockHash(digest.finish())
}

#[cfg(test)]
mod tests;
