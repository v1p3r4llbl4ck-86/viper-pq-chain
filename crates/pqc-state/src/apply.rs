// SPDX-License-Identifier: BUSL-1.1
//! State transition execution — SPEC-OPS-001.
//!
//! Each public function applies one validated operation to the StateStore.
//! Preconditions are checked here; the transaction validation pipeline
//! (pqc-tx) handles envelope-level checks before reaching apply.

pub mod archival;
pub mod attestation;
pub mod consensus_rotate;
pub mod governance;
pub mod key_mgmt;
pub mod proof_anchor;
pub mod slashing;
#[cfg(feature = "token_economics")]
pub mod transfer;
pub mod validator;
pub mod vault;

use crate::{error::ApplyError, gas_schedule::scheduled_gas_for_tx, store::StateStore};
use pqc_tx::validate::{actual_fee_breakdown, FeeParams};
use pqc_types::{
    account::{Account, Address},
    keyset::KeySet,
    transaction::Transaction,
};

/// Passthrough verifier for devnet builds without the `pq-verifier` feature.
///
/// Accepts any signature for any public key — NEVER use in production.
/// In production builds (`pq-verifier` feature enabled), `pqc_crypto::PqVerifier` is used instead.
#[cfg(not(feature = "pq-verifier"))]
struct DevnetPassthroughVerifier;

#[cfg(not(feature = "pq-verifier"))]
impl pqc_crypto::sign::SignatureVerifier for DevnetPassthroughVerifier {
    fn verify(
        &self,
        _pk: &pqc_crypto::sign::PublicKey,
        _message: &[u8],
        _sig: &pqc_crypto::sign::Signature,
    ) -> Result<(), pqc_crypto::CryptoError> {
        Ok(())
    }
}

/// Fee distribution parameters for block reward allocation.
///
/// Controls the split between the block proposer's priority share and the
/// validator pool. The proposer receives `proposer_share_bps / 10_000` of
/// the total collected fees; the remainder is split equally among all
/// `pool_validators` passed to `distribute_block_fees`.
///
/// When `pool_validators` is empty, 100 % goes to the proposer regardless of
/// `proposer_share_bps` (backward-compatible empty-set fallback; also used by
/// tests that do not wire a validator set).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeDistributionParams {
    /// Proposer's exclusive priority share in basis points (0–10 000).
    /// Remaining `10_000 − proposer_share_bps` bps are split among the pool.
    pub proposer_share_bps: u16,
}

impl Default for FeeDistributionParams {
    fn default() -> Self {
        // Phase 3 default: 50 % proposer priority share, 50 % validator pool.
        // With an empty pool the full amount still goes to the proposer.
        Self {
            proposer_share_bps: 5_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStatus {
    Applied,
    RevertedOutOfGas,
}

#[derive(Debug, Clone)]
pub struct ExecutionContext {
    pub tx_bytes_len: usize,
    pub fee_params: FeeParams,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionResult {
    pub status: ExecutionStatus,
    pub gas_used: u64,
    pub fee_charged: u64,
    pub fee_refund: u64,
}

/// Apply a validated transaction to state.
///
/// The transaction MUST have already passed the full validation pipeline
/// (SPEC-TX-001 §8) before calling this function. This function does not
/// re-verify signatures; it applies payload state, computes actual execution
/// cost, settles fee and tip, and increments the sender nonce on inclusion.
pub fn apply_tx(
    store: &mut StateStore,
    tx: &Transaction,
    exec_ctx: ExecutionContext,
) -> Result<ExecutionResult, ApplyError> {
    let scheduled_gas = scheduled_gas_for_tx(tx)?;
    let registry_min_fee = store.alg_min_fee(tx.sig_alg_id).unwrap_or(0);

    if tx.gas_limit < scheduled_gas {
        settle_sender(store, tx, tx.fee)?;
        return Ok(ExecutionResult {
            status: ExecutionStatus::RevertedOutOfGas,
            gas_used: tx.gas_limit,
            fee_charged: tx.fee,
            fee_refund: 0,
        });
    }

    let mut working = store.clone();

    apply_payload(&mut working, tx)?;

    let actual_fee = actual_fee_breakdown(
        tx,
        exec_ctx.tx_bytes_len,
        scheduled_gas,
        &exec_ctx.fee_params,
        registry_min_fee,
    )
    .total();
    settle_sender(&mut working, tx, actual_fee)?;

    *store = working;

    Ok(ExecutionResult {
        status: ExecutionStatus::Applied,
        gas_used: scheduled_gas,
        fee_charged: actual_fee,
        fee_refund: tx.fee.saturating_sub(actual_fee),
    })
}

fn apply_payload(store: &mut StateStore, tx: &Transaction) -> Result<(), ApplyError> {
    use pqc_types::transaction::MsgType;

    match tx.msg_type {
        MsgType::VaultCreate => vault::apply_vault_create(store, tx),
        MsgType::VaultPolicyUpdate => vault::apply_vault_policy_update(store, tx),
        MsgType::AttestationCreate => attestation::apply_attestation_create(store, tx),
        MsgType::AttestationRevoke => attestation::apply_attestation_revoke(store, tx),
        MsgType::ProofAnchor => proof_anchor::apply_proof_anchor(store, tx),
        #[cfg(feature = "token_economics")]
        MsgType::TokenTransfer => transfer::apply_token_transfer(store, tx),
        #[cfg(not(feature = "token_economics"))]
        MsgType::TokenTransfer => Err(ApplyError::TokenEconomicsDisabled),
        MsgType::KeyAdd => key_mgmt::apply_key_add(store, tx),
        MsgType::KeyRotate => key_mgmt::apply_key_rotate(store, tx),
        MsgType::KeyRevoke => key_mgmt::apply_key_revoke(store, tx),
        MsgType::GovernanceProposal => governance::apply_governance_proposal(store, tx),
        MsgType::GovernanceVote => governance::apply_governance_vote(store, tx),
        MsgType::ConsensusKeyRotate => consensus_rotate::apply_consensus_key_rotate(store, tx),
        MsgType::ValidatorRegister => validator::apply_validator_register(store, tx),
        MsgType::ValidatorExit => validator::apply_validator_exit(store, tx),
        MsgType::ValidatorUnjail => validator::apply_validator_unjail(store, tx),
        MsgType::ValidatorRotatePeerId => validator::apply_validator_rotate_peer_id(store, tx),
        #[cfg(feature = "token_economics")]
        MsgType::SubmitEquivocationEvidence => dispatch_equivocation_evidence(store, tx),
        #[cfg(not(feature = "token_economics"))]
        MsgType::SubmitEquivocationEvidence => Err(ApplyError::TokenEconomicsDisabled),
        MsgType::ValidatorRegisterArchivalKey => {
            archival::apply_validator_register_archival_key(store, tx)
        }
        MsgType::ArchivalRecordSubmit => dispatch_archival_record_submit(store, tx),
        MsgType::ArchivalRecordAddAnchor => {
            let h = store.block_height();
            archival::apply_archival_record_add_anchor(store, tx, h)
        }
        MsgType::ArchivalRecordRenew => {
            let h = store.block_height();
            archival::apply_archival_record_renew(store, tx, h)
        }
    }
}

/// Tally governance proposals whose voting window has closed and execute or
/// expire them.  Must be called once per block after all transactions are
/// applied, mirroring the engine / recovery call sites (TASK-100).
pub fn process_governance_tallies(store: &mut StateStore, current_height: u64) {
    governance::process_governance_tallies(store, current_height);
}

/// Check pending software upgrades at the start of block application (ADR-031).
///
/// Returns `Err(SoftwareUpgradeVersionMismatch)` if an upgrade scheduled for
/// `current_height` requires a different `STATE_FORMAT_VERSION` than the compiled
/// binary provides.  Callers must abort block production or replay on error.
pub fn check_pending_upgrades(
    store: &mut StateStore,
    current_height: u64,
    compiled_version: u16,
) -> Result<(), ApplyError> {
    governance::check_pending_upgrades(store, current_height, compiled_version)
}

/// Credit all fees collected during a block to the block proposer and validator pool.
///
/// MUST be called once per block, after all `apply_tx` calls and before
/// `StateStore::advance_height()`. Both `assemble_block` (production path) and
/// `replay_blocks_from_state` (recovery path) call this function to keep fee
/// accounting deterministic and included in the state root.
///
/// # Split rule
///
/// The proposer receives `dist.proposer_share_bps / 10_000` of the total
/// `fees_collected` as a priority share for block production. The remainder is
/// split equally among **all** addresses in `pool_validators` (which typically
/// includes every active validator, including the proposer themselves if they
/// are also a validator). Integer-division rounding goes to the proposer.
///
/// When `pool_validators` is empty the full amount goes to the proposer,
/// regardless of `dist.proposer_share_bps`. This maintains backward compat
/// for tests and for nodes that have not yet wired a validator set.
///
/// # Accounting invariant
///
/// Every token debited from senders during block execution appears exactly once
/// in `fees_collected`. Crediting recipients completes the double-entry: no
/// fee is created or destroyed.
///
/// # Implicit account creation
///
/// If any recipient does not yet have an account it is created implicitly with
/// `balance = credited_amount`, `nonce = 0`, and an empty `KeySet`.
pub fn distribute_block_fees(
    store: &mut StateStore,
    proposer: &Address,
    fees_collected: u128,
    pool_validators: &[Address],
    dist: &FeeDistributionParams,
) {
    if fees_collected == 0 {
        return;
    }

    // ── Burn (SPEC-FEE-002 §9.3) ─────────────────────────────────────────────
    // In Phase 8, burn_rate_bps = 0 so this is a no-op. Governance activates
    // burn later via a BurnRateUpdate proposal. Burned tokens credit the zero
    // address ([0x00; 32]), which has no private key and is provably unspendable.
    let burn_rate_bps = u128::from(store.fee_market.burn_rate_bps);
    let burn_amount = if burn_rate_bps > 0 {
        fees_collected.saturating_mul(burn_rate_bps) / 10_000
    } else {
        0
    };
    if burn_amount > 0 {
        let zero_addr = Address([0x00u8; 32]);
        credit_account(store, &zero_addr, burn_amount);
    }
    let validator_fees = fees_collected.saturating_sub(burn_amount);

    if validator_fees == 0 {
        return;
    }

    // Empty-pool fallback: all validator_fees to proposer (backward compat, tests).
    if pool_validators.is_empty() {
        credit_account(store, proposer, validator_fees);
        return;
    }

    let proposer_bps = u128::from(dist.proposer_share_bps).min(10_000);
    let proposer_priority = validator_fees.saturating_mul(proposer_bps) / 10_000;
    let pool_total = validator_fees.saturating_sub(proposer_priority);

    let pool_count = pool_validators.len() as u128;
    let per_validator = pool_total / pool_count;
    // Integer-division remainder goes to proposer.
    let pool_distributed = per_validator.saturating_mul(pool_count);
    let remainder = pool_total.saturating_sub(pool_distributed);

    credit_account(store, proposer, proposer_priority.saturating_add(remainder));

    if per_validator > 0 {
        for addr in pool_validators {
            credit_account(store, addr, per_validator);
        }
    }
}

fn credit_account(store: &mut StateStore, addr: &Address, amount: u128) {
    if amount == 0 {
        return;
    }
    if store.get_account(addr).is_some() {
        if let Some(acc) = store.get_account_mut(addr) {
            acc.balance = acc.balance.saturating_add(amount);
        }
        store.commit_account_mutation(addr);
    } else {
        store.insert_account(Account {
            address: addr.clone(),
            balance: amount,
            nonce: 0,
            keys: KeySet::default(),
            policy_version: 0,
            policy_hash: None,
            verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
            auth_data: Vec::new(),
        });
    }
}

/// Dispatch `ArchivalRecordSubmit` — selects verifier based on build feature.
///
/// Mirrors `dispatch_equivocation_evidence`. The archival path uses
/// SLH-DSA-SHAKE-256s (not ML-DSA-65) but the injection pattern is identical.
fn dispatch_archival_record_submit(
    store: &mut StateStore,
    tx: &Transaction,
) -> Result<(), ApplyError> {
    let current_height = store.block_height();

    #[cfg(feature = "pq-verifier")]
    {
        let verifier = pqc_crypto::PqVerifier;
        archival::apply_archival_record_submit(store, tx, current_height, &verifier)
    }

    #[cfg(not(feature = "pq-verifier"))]
    {
        let verifier = DevnetPassthroughVerifier;
        archival::apply_archival_record_submit(store, tx, current_height, &verifier)
    }
}

/// Dispatch `SubmitEquivocationEvidence` — selects the verifier based on build features.
///
/// With `pq-verifier` feature: uses `pqc_crypto::PqVerifier` (real ML-DSA-65 verification).
/// Without it (devnet default): uses `DevnetPassthroughVerifier` which accepts all signatures.
///
/// Gated behind `token_economics` because the tombstone-and-economic-penalty path
/// in `slashing::apply_submit_equivocation_evidence` writes to validator self_bond
/// and credits the treasury — both meaningless on the tokenless viper-research-1
/// substrate. In tokenless deployments, validator misbehavior is dealt with
/// off-chain (operator removes the validator from the genesis set, or via a
/// governance proposal that updates the active validator set). See
/// the private planning notes-off.
#[cfg(feature = "token_economics")]
fn dispatch_equivocation_evidence(
    store: &mut StateStore,
    tx: &Transaction,
) -> Result<(), ApplyError> {
    let current_height = store.block_height();

    #[cfg(feature = "pq-verifier")]
    {
        let verifier = pqc_crypto::PqVerifier;
        slashing::apply_submit_equivocation_evidence(
            store,
            &tx.sender,
            &tx.payload,
            current_height,
            &verifier,
        )
    }

    #[cfg(not(feature = "pq-verifier"))]
    {
        let verifier = DevnetPassthroughVerifier;
        slashing::apply_submit_equivocation_evidence(
            store,
            &tx.sender,
            &tx.payload,
            current_height,
            &verifier,
        )
    }
}

fn settle_sender(
    store: &mut StateStore,
    tx: &Transaction,
    fee_charged: u64,
) -> Result<(), ApplyError> {
    let total_debit = u128::from(fee_charged).saturating_add(u128::from(tx.fee_tip));
    {
        let sender = store
            .get_account_mut(&tx.sender)
            .ok_or(ApplyError::InsufficientFunds)?;

        if sender.balance < total_debit {
            return Err(ApplyError::InsufficientFunds);
        }

        sender.balance -= total_debit;
        sender.nonce += 1;
    }
    store.commit_account_mutation(&tx.sender);
    Ok(())
}
