// SPDX-License-Identifier: BUSL-1.1
//! Mempool admission pipeline — SPEC-FEE-001 §9.
//!
//! Ordering (SPEC-FEE-001 §9.5 — cheap checks before expensive ones):
//!   1. Decode CBOR (structural, cheap)
//!   2. Duplicate check (hash lookup, cheap)
//!   3. Registry lifecycle pre-check (one map lookup — before crypto)
//!   4. V-C cap check (counter read — before crypto)
//!   5. Full validation pipeline: version, chain_id, sender lookup, key lookup,
//!      signature verify, nonce, fee sufficiency, balance (SPEC-TX-001 §8)
//!   6. Replacement policy (SPEC-FEE-001 §11)
//!   7. Insert into pool
//!
//! The mempool does NOT mutate state. It reads state via the `StateView` trait.

use crate::{
    error::MempoolError,
    pool::{Mempool, PendingEntry},
};
use pqc_crypto::{SigClass, SignatureVerifier};
use pqc_tx::{
    codec::decode_tx,
    compute_tx_hash,
    validate::{validate_tx, FeeParams, ValidationContext},
    TxError,
};

pub use pqc_tx::state_view::StateView;

/// Minimum replacement fee bump: new_fee ≥ old_fee × 110 / 100 — SPEC-FEE-001 §11.
const REPLACEMENT_FEE_BUMP_NUM: u64 = 110;
const REPLACEMENT_FEE_BUMP_DEN: u64 = 100;

/// Result of a successful admission.
#[derive(Debug)]
pub struct AdmissionResult {
    pub tx_hash: [u8; 32],
    /// If a previous tx was replaced, its hash is returned so the caller can update
    /// its tx-status tracking.
    pub replaced: Option<[u8; 32]>,
}

/// Attempt to admit a raw transaction into the mempool.
///
/// Returns `Ok(AdmissionResult)` if the transaction was admitted (possibly replacing
/// an existing pending tx). Returns `Err(MempoolError)` for any rejection.
pub fn try_admit(
    pool: &mut Mempool,
    raw_bytes: Vec<u8>,
    state: &dyn StateView,
    verifier: &dyn SignatureVerifier,
    fee_params: &FeeParams,
) -> Result<AdmissionResult, MempoolError> {
    // ── Step 1: Decode CBOR (structural check) ───────────────────────────────
    let tx = decode_tx(&raw_bytes)?;

    // ── Step 2: Duplicate check (cheap hash lookup before crypto) ────────────
    let tx_hash = compute_tx_hash(&raw_bytes);
    if pool.get(&tx_hash).is_some() {
        return Err(MempoolError::Duplicate);
    }

    // ── Step 3: Registry lifecycle pre-check (before expensive crypto) ───────
    // Banned and Deprecated algorithms are rejected immediately.
    // SPEC-FEE-001 §9.1 — this check precedes signature verification.
    let lifecycle = state.alg_lifecycle(tx.sig_alg_id).ok_or_else(|| {
        MempoolError::ValidationFailed(TxError::AlgorithmNotFound(tx.sig_alg_id.as_u16()))
    })?;

    if !lifecycle.admits_transactions() {
        return Err(MempoolError::ValidationFailed(TxError::AlgorithmBanned(
            tx.sig_alg_id.as_u16(),
        )));
    }

    // ── Step 4: V-C per-block cap (before crypto) ─────────────────────────────
    // SLH-DSA verification is ~58× slower than ML-DSA-65; cap admissions to
    // prevent CPU exhaustion even at correct fee levels — SPEC-FEE-001 §10.2.
    if state.alg_sig_class(tx.sig_alg_id) == Some(SigClass::Premium)
        && pool.vc_admitted_count() >= pool.vc_per_block_cap
    {
        return Err(MempoolError::VcCapReached);
    }

    // ── Step 5: Full validation pipeline ────────────────────────────────────
    // This includes: version, chain_id, sender lookup, key lookup,
    // signature verification, nonce, fee sufficiency, balance.
    // SPEC-TX-001 §8 — all 15 steps.
    //
    // Populate `base_fee_dynamic` from state so the lane-adjusted effective
    // base fee (SPEC-FEE-002 §7) is used for fee sufficiency checks. When state
    // returns 0 (test stubs), `fee_params.base_fee` is used as the fallback.
    let sender_account = state.get_account(&tx.sender);
    let mut admission_fee_params = fee_params.clone();
    let dynamic = state.base_fee_dynamic();
    if dynamic > 0 {
        admission_fee_params.base_fee_dynamic = dynamic;
    }
    let fork_digest = state.fork_digest();
    let ctx = ValidationContext {
        chain_id: state.chain_id(),
        fork_digest: &fork_digest,
        current_height: state.current_height(),
        sender_account,
        fee_params: admission_fee_params,
        verifier,
        alg_lifecycle: &|alg_id| state.alg_lifecycle(alg_id),
        alg_min_fee: &|alg_id| state.alg_min_fee(alg_id),
    };
    validate_tx(&tx, &raw_bytes, &ctx)?;

    // ── Step 6: Replacement policy — SPEC-FEE-001 §11 ────────────────────────
    let mut replaced_hash: Option<[u8; 32]> = None;

    if let Some(&existing_hash) = pool.pending_for_slot(&tx.sender.0, tx.nonce) {
        let existing = match pool.get(&existing_hash) {
            Some(e) => e,
            None => {
                // Internal index inconsistency: by_sender_nonce references a hash not in by_hash.
                // Evict the stale index entry rather than crashing the node.
                tracing::error!(
                    hash = %hex::encode(existing_hash),
                    "mempool index inconsistency: by_sender_nonce references missing hash"
                );
                pool.evict(&existing_hash);
                // Treat as no existing entry; proceed to insert the new tx.
                let is_vc = state.alg_sig_class(tx.sig_alg_id) == Some(SigClass::Premium);
                let sender_hex = hex::encode(tx.sender.0);
                let entry = PendingEntry {
                    fee: tx.fee,
                    fee_tip: tx.fee_tip,
                    tx_hash,
                    tx,
                    raw_bytes,
                };
                pool.insert(entry);
                if is_vc {
                    pool.increment_vc_count();
                }
                tracing::debug!(
                    tx_hash = %hex::encode(tx_hash),
                    sender = %sender_hex,
                    replaced = false,
                    pool_depth = pool.len(),
                    "tx admitted (after index recovery)",
                );
                return Ok(AdmissionResult {
                    tx_hash,
                    replaced: None,
                });
            }
        };

        // new_fee ≥ old_fee × 1.10
        let min_replacement_fee =
            existing.fee.saturating_mul(REPLACEMENT_FEE_BUMP_NUM) / REPLACEMENT_FEE_BUMP_DEN;

        if tx.fee < min_replacement_fee || tx.fee_tip < existing.fee_tip {
            return Err(MempoolError::ReplacementUnderpriced {
                existing_fee: existing.fee,
                existing_tip: existing.fee_tip,
                min_required_fee: min_replacement_fee,
            });
        }

        // Replacement conditions met: evict old tx before inserting new one.
        replaced_hash = Some(existing_hash);
        pool.evict(&existing_hash);
    }

    // ── Step 7: Insert ────────────────────────────────────────────────────────
    let is_vc = state.alg_sig_class(tx.sig_alg_id) == Some(SigClass::Premium);
    let sender_hex = hex::encode(tx.sender.0);
    let entry = PendingEntry {
        fee: tx.fee,
        fee_tip: tx.fee_tip,
        tx_hash,
        tx,
        raw_bytes,
    };
    pool.insert(entry);

    if is_vc {
        pool.increment_vc_count();
    }

    tracing::debug!(
        tx_hash = %hex::encode(tx_hash),
        sender = %sender_hex,
        replaced = replaced_hash.is_some(),
        pool_depth = pool.len(),
        "tx admitted",
    );

    Ok(AdmissionResult {
        tx_hash,
        replaced: replaced_hash,
    })
}
