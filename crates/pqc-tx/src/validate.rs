// SPDX-License-Identifier: Apache-2.0
//! Transaction validation pipeline — SPEC-TX-001 §8.
//!
//! 15 steps, in order: structural → pre-crypto → cryptographic → economic → payload.
//! The verifier is injected so the pipeline is testable without a real crypto backend.

use crate::{compute_tx_hash, error::TxError, preimage};
use pqc_crypto::{AlgId, Lifecycle, Signature, SignatureVerifier};
use pqc_types::{account::Account, transaction::Transaction, ForkDigest};
use serde::{Deserialize, Serialize};

/// External context required to validate a transaction.
///
/// The pipeline does not own state — it is supplied at call time.
/// This keeps the validation logic pure and independently testable.
pub struct ValidationContext<'a> {
    /// Expected network identifier. SPEC-TX-001 §8, step 3.
    pub chain_id: &'a [u8],
    /// Fork digest used when rebuilding the signed preimage (ADR-053 §T1.2).
    pub fork_digest: &'a ForkDigest,
    /// Current finalized block height. Used for key lifecycle checks.
    pub current_height: u64,
    /// Sender account state. `None` means the account does not exist.
    pub sender_account: Option<&'a Account>,
    /// Fee parameters (all in base token units). Numbers are TBD (Phase 2);
    /// supply zeros for now to keep the pipeline structurally complete.
    pub fee_params: FeeParams,
    /// Signature verifier (injected — real or stub).
    pub verifier: &'a dyn SignatureVerifier,
    /// Algorithm Registry lookup. Returns `None` for unknown alg_ids.
    pub alg_lifecycle: &'a dyn Fn(AlgId) -> Option<Lifecycle>,
    /// Algorithm Registry min_fee lookup. Returns `None` for unknown alg_ids.
    pub alg_min_fee: &'a dyn Fn(AlgId) -> Option<u64>,
}

/// Fee computation parameters — SPEC-FEE-001 §3.
/// All values are in base token units.
///
/// `base_fee_dynamic` is the AIMD adaptive base fee (SPEC-FEE-002). When
/// non-zero it overrides `base_fee` for lane-adjusted fee calculations. It is
/// NOT persisted to node config; it is populated at runtime from `StateStore`
/// before each mempool admission or block execution call.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeParams {
    pub base_fee: u64,
    pub byte_fee: u64,          // per byte of tx_bytes
    pub sigverify_fee_v_a: u64, // V-A reduced class (FN-DSA)
    pub sigverify_fee_v_b: u64, // V-B standard class (ML-DSA) — reference
    pub sigverify_fee_v_c: u64, // V-C premium class (SLH-DSA)
    pub exec_fee_per_gas: u64,
    /// AIMD adaptive base fee — SPEC-FEE-002 §6. Set at runtime from
    /// `StateStore::base_fee_dynamic()`. When zero, `base_fee` is used as fallback.
    /// Serialized with `default` so existing configs are not broken.
    #[serde(default)]
    pub base_fee_dynamic: u64,
}

/// Return the fee lane multiplier in basis points for a given `msg_type` — SPEC-FEE-002 §7.
///
/// | Lane        | MsgTypes                                                      | Multiplier (bips) |
/// |-------------|---------------------------------------------------------------|-------------------|
/// | heavy       | validator_register, validator_exit, governance_propose        | 20 000 (2.0×)     |
/// | all others  | standard / attestation / system lanes                         | 10 000 (1.0×)     |
///
/// This mapping is NOT a governance parameter. Changes require a hard fork.
pub fn lane_multiplier_bps(msg_type: pqc_types::transaction::MsgType) -> u64 {
    use pqc_types::transaction::MsgType;
    match msg_type {
        // Heavy lane — 2.0× multiplier.
        MsgType::ValidatorRegister | MsgType::ValidatorExit | MsgType::GovernanceProposal => 20_000,
        // All other lanes — 1.0× multiplier.
        _ => 10_000,
    }
}

/// Compute the effective base fee for a transaction in its fee lane — SPEC-FEE-002 §7.2.
///
/// Uses `base_fee_dynamic` if set (non-zero); falls back to `base_fee` for
/// backward compatibility with call sites that have not yet wired AIMD state.
/// Intermediate u128 multiplication prevents overflow.
pub fn effective_base_fee(params: &FeeParams, msg_type: pqc_types::transaction::MsgType) -> u64 {
    let dynamic = if params.base_fee_dynamic > 0 {
        params.base_fee_dynamic
    } else {
        params.base_fee
    };
    let multiplier = lane_multiplier_bps(msg_type);
    // Intermediate u128 to avoid overflow for heavy lane at BASE_FEE_MAX.
    ((dynamic as u128).saturating_mul(multiplier as u128) / 10_000_u128) as u64
}

/// Deterministic fee component breakdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeBreakdown {
    pub base: u64,
    pub bytes: u64,
    pub sigverify: u64,
    pub exec: u64,
}

impl FeeBreakdown {
    pub fn total(self) -> u64 {
        self.base
            .saturating_add(self.bytes)
            .saturating_add(self.sigverify)
            .saturating_add(self.exec)
    }
}

/// Hard upper bound on raw transaction bytes — SPEC-TX-001 §5.9.
///
/// Enforced before signature verification so an attacker cannot craft a
/// \>1 MiB payload to exhaust CPU even at a valid fee level. The byte-fee
/// component prices storage/bandwidth costs; this cap closes the gap while
/// FeeParams coefficients remain at zero.
pub const MAX_TX_BYTES: usize = 1_048_576; // 1 MiB

/// Run the full 15-step validation pipeline against a decoded transaction.
///
/// Returns `Ok(())` if the transaction is valid for mempool admission.
/// Returns the first `TxError` encountered — pipeline aborts on first failure.
///
/// SPEC-TX-001 §8.
pub fn validate_tx(
    tx: &Transaction,
    raw_bytes: &[u8],
    ctx: &ValidationContext<'_>,
) -> Result<(), TxError> {
    // ── Step 1: canonical encoding + size cap ───────────────────────────────
    // EncodingInvalid is raised by codec::decode_tx before this function.
    // Size cap is checked here — cheapest structural guard before any crypto.
    if raw_bytes.len() > MAX_TX_BYTES {
        return Err(TxError::TxTooLarge(raw_bytes.len()));
    }

    // ── Step 2: tx_version ──────────────────────────────────────────────────
    if tx.tx_version != 1 {
        return Err(TxError::VersionUnsupported(tx.tx_version));
    }

    // ── Step 3: chain_id ────────────────────────────────────────────────────
    if tx.chain_id != ctx.chain_id {
        return Err(TxError::ChainIdMismatch);
    }

    // ── Step 4: msg_type is known ────────────────────────────────────────────
    // Already enforced by decode_tx (MsgTypeUnknown). No additional check needed.

    // ── Step 5: alg_id exists in Algorithm Registry ─────────────────────────
    let lifecycle = (ctx.alg_lifecycle)(tx.sig_alg_id)
        .ok_or(TxError::AlgorithmNotFound(tx.sig_alg_id.as_u16()))?;

    // ── Step 6: alg_id admits transactions (Active or Discouraged) ──────────
    // `admits_transactions()` returns false for both Deprecated and Banned.
    // Both are rejected with AlgorithmBanned to preserve a single error variant.
    if !lifecycle.admits_transactions() {
        return Err(TxError::AlgorithmBanned(tx.sig_alg_id.as_u16()));
    }

    // ── Step 7: sender account exists ───────────────────────────────────────
    let account = ctx.sender_account.ok_or(TxError::SenderNotFound)?;

    // ── Step 8: key lookup ───────────────────────────────────────────────────
    let permission_bit = tx.msg_type.required_permission_bit();
    let key_entry = account.keys.lookup(
        tx.sig_alg_id,
        tx.sig_key_version,
        permission_bit,
        ctx.current_height,
    )?;

    // ── Step 9: signature verification ──────────────────────────────────────
    let preimage =
        preimage::build_preimage(ctx.fork_digest, tx).map_err(|_| TxError::EncodingInvalid)?;

    let public_key = pqc_types::keyset::KeySet::resolve_public_key(key_entry);
    let sig = Signature {
        alg_id: tx.sig_alg_id,
        bytes: tx.signature.clone(),
    };

    ctx.verifier
        .verify(&public_key, &preimage, &sig)
        .map_err(|_| TxError::SignatureInvalid)?;

    // ── Step 10: nonce ───────────────────────────────────────────────────────
    let expected_nonce = account.nonce;
    if tx.nonce != expected_nonce {
        return Err(TxError::NonceInvalid {
            expected: expected_nonce,
            got: tx.nonce,
        });
    }

    // ── Steps 11-13: fee components + total sufficiency ─────────────────────
    let registry_min_fee = (ctx.alg_min_fee)(tx.sig_alg_id)
        .ok_or(TxError::AlgorithmNotFound(tx.sig_alg_id.as_u16()))?;
    let fee_breakdown =
        required_fee_breakdown(tx, raw_bytes.len(), &ctx.fee_params, registry_min_fee);
    let required = fee_breakdown.total();

    if tx.fee < required {
        return Err(TxError::FeeInsufficient {
            paid: tx.fee,
            required,
            base: fee_breakdown.base,
            bytes: fee_breakdown.bytes,
            sigverify: fee_breakdown.sigverify,
            exec: fee_breakdown.exec,
        });
    }

    // ── Step 14: balance check ───────────────────────────────────────────────
    let max_debit = u128::from(tx.fee).saturating_add(u128::from(tx.fee_tip));
    if account.balance < max_debit {
        return Err(TxError::BalanceInsufficient {
            balance: account.balance,
            fee: u128::from(tx.fee).saturating_add(u128::from(tx.fee_tip)),
        });
    }

    // ── Step 15: payload structure ───────────────────────────────────────────
    // Payload schema validation is operation-specific and lives in pqc-state.
    // The pipeline stub accepts all payloads at this layer; pqc-state validates
    // per-operation semantics after mempool admission.

    tracing::debug!(
        tx_hash = %hex::encode(compute_tx_hash(raw_bytes)),
        sender = %tx.sender,
        msg_type = ?tx.msg_type,
        fee = tx.fee,
        "transaction validated"
    );

    Ok(())
}

fn sigverify_fee_for_alg(alg_id: AlgId, params: &FeeParams, registry_min_fee: u64) -> u64 {
    use pqc_crypto::alg::AlgId::*;
    use pqc_crypto::SigClass;

    let class = match alg_id {
        FnDsaPadded512 => SigClass::Reduced,
        MlDsa44 | MlDsa65 | MlDsa87 => SigClass::Standard,
        SlhDsaSha2128s => SigClass::Premium,
        _ => SigClass::Standard,
    };

    let class_fee = match class {
        SigClass::Reduced => params.sigverify_fee_v_a,
        SigClass::Standard => params.sigverify_fee_v_b,
        SigClass::Premium => params.sigverify_fee_v_c,
    };

    class_fee.max(registry_min_fee)
}

/// Minimum required fee at mempool admission, using declared `gas_limit`.
///
/// The base component uses the lane-adjusted effective base fee (SPEC-FEE-002 §7).
/// When `params.base_fee_dynamic` is non-zero (live node path), the AIMD adaptive
/// value is used; otherwise `params.base_fee` provides the static fallback for tests.
pub fn required_fee_breakdown(
    tx: &Transaction,
    raw_bytes_len: usize,
    params: &FeeParams,
    registry_min_fee: u64,
) -> FeeBreakdown {
    FeeBreakdown {
        base: effective_base_fee(params, tx.msg_type),
        bytes: params.byte_fee.saturating_mul(raw_bytes_len as u64),
        sigverify: sigverify_fee_for_alg(tx.sig_alg_id, params, registry_min_fee),
        exec: params.exec_fee_per_gas.saturating_mul(tx.gas_limit),
    }
}

/// Actual charged fee after execution, using measured `gas_used`.
///
/// The base component uses the lane-adjusted effective base fee (SPEC-FEE-002 §7).
pub fn actual_fee_breakdown(
    tx: &Transaction,
    raw_bytes_len: usize,
    gas_used: u64,
    params: &FeeParams,
    registry_min_fee: u64,
) -> FeeBreakdown {
    FeeBreakdown {
        base: effective_base_fee(params, tx.msg_type),
        bytes: params.byte_fee.saturating_mul(raw_bytes_len as u64),
        sigverify: sigverify_fee_for_alg(tx.sig_alg_id, params, registry_min_fee),
        exec: params
            .exec_fee_per_gas
            .saturating_mul(gas_used.min(tx.gas_limit)),
    }
}
