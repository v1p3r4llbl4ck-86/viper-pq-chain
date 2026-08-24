// SPDX-License-Identifier: BUSL-1.1
//! Equivocation slashing state transition — SPEC-SLASH-001.
//!
//! Validates two conflicting signed votes by the same validator and, if
//! evidence is valid, slashes `self_bond` by 5%, jails, and tombstones the
//! validator permanently.
//!
//! All 12 validation rules from SPEC-SLASH-001 §8 are enforced in order,
//! with cheap structural and state checks before the two expensive ML-DSA
//! signature verifications (rules 11–12).
//!
//! This code is in the Phase 4 audit scope (pqc-state::apply). Follow the
//! audit-scope rules: small functions, explicit checks, inline invariant
//! reasoning as comments, no unwrap/expect.

use crate::{error::ApplyError, store::StateStore};
use pqc_crypto::{
    sign::{PublicKey, Signature, SignatureVerifier},
    tagged_hash,
};
use pqc_types::{
    account::{Account, Address},
    keyset::KeySet,
    slashing::{decode_equivocation_evidence, EquivocationVote, RecentSlashEntry},
    validator::ValidatorStatus,
};

/// Evidence validity window: 28 days at 1 block/second (SPEC-SLASH-001 §12, ADR-024).
///
/// The spec uses 6-second block times (403 200 blocks), but 1 s/block is the devnet
/// target (ADR-024 note). The constant is stored in blocks; governance can update it.
/// At 6 s/block: use 403_200. At 1 s/block: 2_419_200.
pub const EVIDENCE_VALIDITY_WINDOW_BLOCKS: u64 = 2_419_200;

/// Slash fraction for equivocation: 500 bps = 5% (ADR-024, SPEC-SLASH-001 §10).
const SLASH_FRACTION_BPS: u128 = 500;

/// Total basis points (denominator for slash fraction).
const BASIS_POINTS_TOTAL: u128 = 10_000;

/// Treasury account address: placeholder [0x01; 32] (SPEC-SLASH-001 §11).
const TREASURY_ADDRESS: [u8; 32] = [0x01u8; 32];

/// Correlation penalty sliding window: 36 days at 500 ms/block (ADR-048, SPEC-SLASH-001 §17).
///
/// 36 × 86_400 / 0.5 = 6_220_800 blocks. This mirrors Ethereum's ETH2 "slashing window"
/// where a proposer's effective balance is reduced over a 36-day epoch span.
/// At 1 s/block devnet cadence the same window is 3_110_400; the constant below
/// matches the 500 ms mainnet target (ADR-042, EpochConfig::mainnet()).
pub const CORRELATION_WINDOW_BLOCKS: u64 = 6_220_800;

/// Maximum multiplicative boost on the base slash fraction (ADR-048).
///
/// Formula: `effective = base * (1 + correlation_multiplier * MAX_MULT_BOOST)`.
/// With `MAX_MULT_BOOST = 19`, a fully-saturated correlation (`multiplier = 1.0`)
/// yields a 20× penalty, so a 5% base becomes 100% — capped at `self_bond` anyway.
/// See ADR-048 rationale for the 24-committee calibration.
const MAX_MULT_BOOST: u128 = 19;

/// Correlation base multiplier `(f / f_threshold)` where `f_threshold = 1/3`.
///
/// We store this as an integer scale factor: `multiplier_bps = min(10_000,
/// fraction_slashed_bps × CORRELATION_BASE_MULT)`. With `CORRELATION_BASE_MULT = 3`,
/// the multiplier saturates (`1.0`) when 1/3 of active stake is slashed in window.
const CORRELATION_BASE_MULT: u128 = 3;

/// Apply a `SubmitEquivocationEvidence` transaction (SPEC-SLASH-001 §8–§9).
///
/// `current_block_height` is the height of the block in which this transaction
/// is being applied. `verifier` is the signature verifier — inject `StubVerifier`
/// in tests; `MlDsaVerifier` or `PqVerifier` in production.
///
/// Validation rules are checked in the order mandated by §8. Signature
/// verification (rules 11–12) is last so invalid structure is rejected cheaply
/// without performing two ML-DSA-65 verifications.
///
/// On success, applies all §9 state mutations atomically (the caller holds a
/// working copy of the store; failure bubbles up before `*store = working` in
/// `apply_tx`).
pub fn apply_submit_equivocation_evidence<V: SignatureVerifier>(
    store: &mut StateStore,
    sender: &Address,
    payload_bytes: &[u8],
    current_block_height: u64,
    verifier: &V,
) -> Result<(), ApplyError> {
    // ── Rule 1 (FORMAT): decode EquivocationEvidence CBOR ─────────────────────
    let evidence = decode_equivocation_evidence(payload_bytes)
        .map_err(|e| ApplyError::PayloadDecode(format!("INVALID_EVIDENCE_FORMAT: {e}")))?;

    // Rules 2–3 (VOTE_FORMAT_A/B): step validity is enforced inside the decoder.
    // The decoder already rejects step ∉ {0x01, 0x02}. No extra check needed.

    // ── Rule 4 (SAME_HEIGHT): all three height values must agree ──────────────
    if evidence.vote_a.height != evidence.height || evidence.vote_b.height != evidence.height {
        return Err(ApplyError::EvidenceHeightMismatch);
    }

    // ── Rule 5 (SAME_ROUND) ───────────────────────────────────────────────────
    if evidence.vote_a.round != evidence.vote_b.round {
        return Err(ApplyError::EvidenceRoundMismatch);
    }

    // ── Rule 6 (SAME_STEP) ────────────────────────────────────────────────────
    if evidence.vote_a.step != evidence.vote_b.step {
        return Err(ApplyError::EvidenceStepMismatch);
    }

    // ── Rule 7 (CONFLICTING_HASHES): hashes must differ and at least one is non-nil ──
    // Two nil votes at the same (height, round, step) are not equivocation.
    let nil = [0x00u8; 32];
    if evidence.vote_a.block_hash == evidence.vote_b.block_hash {
        return Err(ApplyError::EquivocationNotProven);
    }
    if evidence.vote_a.block_hash == nil && evidence.vote_b.block_hash == nil {
        // Logically unreachable (they are already equal to each other above), but
        // listed explicitly per SPEC-SLASH-001 §8 rule 7 for clarity.
        return Err(ApplyError::EquivocationNotProven);
    }

    // ── Rule 8 (VALIDITY_WINDOW): saturating check to handle evidence_height > current ──
    //
    // Saturating subtraction returns 0 when evidence_height > current_block_height,
    // which is ≤ EVIDENCE_VALIDITY_WINDOW_BLOCKS (always true), so we must
    // explicitly check for future evidence first per SPEC-SLASH-001 §12.
    if evidence.height > current_block_height {
        return Err(ApplyError::EvidenceExpired);
    }
    let age = current_block_height - evidence.height;
    if age > EVIDENCE_VALIDITY_WINDOW_BLOCKS {
        return Err(ApplyError::EvidenceExpired);
    }

    // ── Rule 9 (VALIDATOR_EXISTS) ─────────────────────────────────────────────
    let validator_addr = Address(evidence.validator_address);
    let (consensus_alg_id, consensus_pk_bytes, was_active) = {
        let record = store
            .get_validator(&validator_addr)
            .ok_or(ApplyError::NotAValidator)?;

        // ── Rule 10 (NOT_TOMBSTONED) ───────────────────────────────────────────
        if record.tombstoned {
            return Err(ApplyError::AlreadyTombstoned);
        }

        let was_active = record.status == ValidatorStatus::Active;
        (
            record.consensus_alg_id,
            record.consensus_pk.clone(),
            was_active,
        )
    };

    // ── Rules 11–12 (SIG_A, SIG_B): signature verification ────────────────────
    //
    // Placed last (per §8 note) so all cheap checks are done before two expensive
    // ML-DSA-65 verifications. The preimage is computed per SPEC-SLASH-001 §6.1
    // (identical to SPEC-CONSENSUS-001 §7.4).
    let pk = PublicKey {
        alg_id: consensus_alg_id,
        bytes: consensus_pk_bytes,
    };

    verify_vote_signature(verifier, &pk, &evidence.vote_a)
        .map_err(|_| ApplyError::InvalidSignature)?;

    verify_vote_signature(verifier, &pk, &evidence.vote_b)
        .map_err(|_| ApplyError::InvalidSignature)?;

    // ── Execution: all validation passed — apply state mutations (§9) ──────────

    // Step 0: prune correlation ledger entries older than the 36-day window
    // BEFORE computing the multiplier. Lazy pruning — every validator runs
    // the same prune for the same `current_block_height`, so state_root stays
    // deterministic (ADR-048).
    let cutoff = current_block_height.saturating_sub(CORRELATION_WINDOW_BLOCKS);
    store.prune_recent_slashes_before(cutoff);

    // Step 1: compute the effective slash fraction (base × correlation multiplier)
    //         and apply it to the validator's current self_bond.
    //
    // Base fraction is 500 bps = 5% (SPEC-SLASH-001 §10, hardcoded per ADR-042).
    // The correlation multiplier (ADR-048, D-02) boosts it up to 20× when the
    // ratio of stake slashed in the recent window hits the 1/3 threshold.
    //
    // Correlation is computed AFTER prune but BEFORE recording the current
    // slash — a single isolated slash sees an empty window and gets the base
    // 5% unchanged. Two simultaneous slashes in the same block see each other
    // in the window the second time around; this is the desired "correlation
    // boosts both" behavior described in SPEC-SLASH-001 §17.1.
    let self_bond = store
        .get_validator(&validator_addr)
        .ok_or(ApplyError::NotAValidator)? // safety: existence checked above
        .self_bond;
    let active_stake = store.total_active_self_bond();
    let window_sum =
        store.recent_slashed_stake_in_window(current_block_height, CORRELATION_WINDOW_BLOCKS);
    let effective_fraction_bps =
        correlation_adjusted_slash_fraction_bps(SLASH_FRACTION_BPS, window_sum, active_stake);
    let slash_amount = compute_slash_amount(self_bond, effective_fraction_bps);

    // Step 2: deduct from self_bond; if self_bond < slash_amount, zero it (§13 edge case).
    {
        let record = store
            .get_validator_mut(&validator_addr)
            .ok_or(ApplyError::NotAValidator)?;
        // Phase 5: if bond was partially returned during unbonding and is smaller
        // than slash_amount, slash to zero (no debt recovery — deferred to Phase 8).
        if record.self_bond >= slash_amount {
            record.self_bond -= slash_amount;
        } else {
            record.self_bond = 0;
        }

        // Step 4: set status to Jailed (valid from any source status per §9 Step 4).
        record.status = ValidatorStatus::Jailed;

        // Step 5: set tombstone flag permanently.
        record.tombstoned = true;
    }
    store.commit_validator_mutation(&validator_addr);

    // Step 3: credit slash_amount to treasury (create account if absent).
    credit_treasury(store, slash_amount)?;

    // Step 3a: record this slash in the correlation ledger (ADR-048, D-02).
    // Recorded AFTER treasury credit but still inside the same apply_tx working
    // copy, so the ledger update is atomic with the slash: either both happen
    // or neither. The next slash in the same window will observe this entry.
    store.record_recent_slash(RecentSlashEntry {
        height: current_block_height,
        slashed_stake: slash_amount,
    });

    // Step 6: the validator's status is now Jailed (set above). If it was Active,
    // it is immediately removed from the active set. `active_validators()` and
    // `CommitQuorumPolicy::from_state_store()` filter on `status == Active`, so
    // setting status to Jailed is sufficient — no separate active-set data structure
    // needs updating in the current devnet implementation.
    //
    // Invariant: if was_active was true before and now status == Jailed, the active
    // count decreases by 1. The Phase 4 minimum active-set threshold is undefined
    // (TBD-SLASH-04); the chain continues with the remaining validators.
    let _ = was_active; // consumed for documentation; no additional action required

    // Step 7: persist tombstone index entry.
    // In the devnet prototype, the tombstone is embedded in ValidatorRecord.tombstoned.
    // The full tombstone index (validator_address, height, submitter, block_height_applied,
    // slash_amount) is not a separate store entity in Phase 4; it is covered by the
    // ValidatorRecord leaf hash already committed above. This satisfies the audit-trail
    // requirement at Phase 4 scope.
    //
    // A separate `TombstoneIndex` map can be introduced in Phase 5 without breaking
    // state-root determinism (it would add a new leaf-hash collection to `state_root()`).
    let _ = (
        sender,
        current_block_height,
        slash_amount,
        effective_fraction_bps,
    ); // available for future tombstone + correlation audit index

    Ok(())
}

/// Compute the canonical vote preimage and verify the ML-DSA signature
/// (SPEC-SLASH-001 §6.1 + ADR-053 §T1.2).
///
/// Preimage:
///   SHAKE-256(fork_digest[4] || "VIPER-VOTE-V1" || height_be64 ||
///             round_be32 || step_u8 || block_hash, 32)
fn verify_vote_signature<V: SignatureVerifier>(
    verifier: &V,
    pk: &PublicKey,
    vote: &EquivocationVote,
) -> Result<(), pqc_crypto::CryptoError> {
    let fork_digest = pqc_types::ForkDigest::viper_research_1();
    let preimage = compute_vote_preimage(&fork_digest, vote);

    let sig = Signature {
        alg_id: pk.alg_id,
        bytes: vote.signature.clone(),
    };

    verifier.verify(pk, &preimage, &sig)
}

/// Compute the 32-byte vote preimage for equivocation verification
/// (SPEC-SLASH-001 §6.1 + ADR-053 §T1.2 + §T2.4).
///
/// This MUST produce the exact same bytes as `pqc_consensus::round::
/// vote_preimage`; any drift means the slashing verifier would reject
/// legitimately-signed votes or accept forged ones. The preimage is the
/// BIP340 double-tagged hash:
///
/// ```text
/// tagged_hash(
///     "VIPER-VOTE-V1",
///     fork_digest[4] || height_be64 || round_be32 || step_u8 || block_hash,
/// )
/// ```
fn compute_vote_preimage(fork_digest: &pqc_types::ForkDigest, vote: &EquivocationVote) -> [u8; 32] {
    let mut body = Vec::with_capacity(4 + 8 + 4 + 1 + 32);
    body.extend_from_slice(fork_digest.as_bytes());
    body.extend_from_slice(&vote.height.to_be_bytes());
    body.extend_from_slice(&vote.round.to_be_bytes());
    body.push(vote.step);
    body.extend_from_slice(&vote.block_hash);
    tagged_hash(b"VIPER-VOTE-V1", &body)
}

/// Compute the correlation-adjusted slash fraction in basis points — ADR-048, D-02.
///
/// Inputs:
/// - `base_fraction_bps`: governance-fixed base fraction (500 bps = 5% for equivocation).
/// - `window_slashed_stake`: sum of stake slashed in the last `CORRELATION_WINDOW_BLOCKS`
///   blocks (venom units). Does NOT include the current slash — a single isolated slash
///   therefore passes a `window_slashed_stake = 0` and receives the base fraction unchanged.
/// - `active_stake`: total `self_bond` over currently-Active validators (venom units).
///
/// Formula (fixed-point, all-integer, no floats):
///
/// ```text
/// ratio_bps        = min(10_000, window_slashed_stake × 10_000 / active_stake)
/// multiplier_bps   = min(10_000, ratio_bps × CORRELATION_BASE_MULT)   // capped at 1.0
/// boost_bps        = 10_000 + multiplier_bps × MAX_MULT_BOOST          // 10_000 = 1.0
/// effective_bps    = min(10_000, base_fraction_bps × boost_bps / 10_000)
/// ```
///
/// Edge cases:
/// - `active_stake == 0`: division-by-zero; degenerate input (no active validators).
///   We treat this as "no correlation applies" and return the base fraction.
/// - All intermediate arithmetic is performed with `u128` `saturating_mul` /
///   `checked_add` to ensure no panic. For realistic values
///   (`window_slashed_stake ≤ total_supply ≤ 10^27`), every product stays well
///   below `u128::MAX ≈ 3.4 × 10^38`.
///
/// Return type is `u128` so callers can multiply by `self_bond` in `u128` without
/// narrowing conversions.
fn correlation_adjusted_slash_fraction_bps(
    base_fraction_bps: u128,
    window_slashed_stake: u128,
    active_stake: u128,
) -> u128 {
    if active_stake == 0 {
        // Degenerate: there is no active stake to correlate against. This can
        // only happen on an empty chain or an all-jailed chain — in both cases
        // the base fraction (§10) is the correct answer.
        return base_fraction_bps;
    }

    // ratio_bps = window_slashed_stake × 10_000 / active_stake, capped at 10_000.
    //
    // window_slashed_stake ≤ 10^27 and 10^27 × 10^4 = 10^31 < u128::MAX, so the
    // multiplication is safe. saturating_mul is belt-and-braces against future
    // changes to total_supply.
    let ratio_bps_unclamped =
        window_slashed_stake.saturating_mul(BASIS_POINTS_TOTAL) / active_stake;
    let ratio_bps = ratio_bps_unclamped.min(BASIS_POINTS_TOTAL);

    // multiplier_bps = min(10_000, ratio_bps × CORRELATION_BASE_MULT).
    let multiplier_bps = ratio_bps
        .saturating_mul(CORRELATION_BASE_MULT)
        .min(BASIS_POINTS_TOTAL);

    // boost_bps = 10_000 + multiplier_bps × MAX_MULT_BOOST.
    //   min = 10_000 (mult=0 → 1.0 → unchanged base)
    //   max = 10_000 + 10_000 × 19 = 200_000 (mult=1.0 → 20.0 → 20× base)
    let boost_bps =
        BASIS_POINTS_TOTAL.saturating_add(multiplier_bps.saturating_mul(MAX_MULT_BOOST));

    // effective_bps = base × boost / 10_000, capped at 10_000 (100%).
    let product = base_fraction_bps.saturating_mul(boost_bps);
    let effective_bps = product / BASIS_POINTS_TOTAL;
    effective_bps.min(BASIS_POINTS_TOTAL)
}

/// Compute the slash amount from `self_bond × fraction_bps / 10_000` with saturation.
///
/// Split out for readability and for the `two_simultaneous_equivocations_correlation_boosts_both`
/// test which exercises the integer floor-division edge at the boundary between
/// the two slashes.
fn compute_slash_amount(self_bond: u128, fraction_bps: u128) -> u128 {
    let product = self_bond.saturating_mul(fraction_bps);
    product / BASIS_POINTS_TOTAL
}

/// Credit `amount` venom to the treasury account (SPEC-SLASH-001 §11).
///
/// If the treasury account does not yet exist, create it with `balance = amount`.
/// The treasury address is `[0x01; 32]` — a protocol placeholder until Phase 8.
fn credit_treasury(store: &mut StateStore, amount: u128) -> Result<(), ApplyError> {
    if amount == 0 {
        return Ok(());
    }
    let treasury = Address(TREASURY_ADDRESS);
    if store.get_account(&treasury).is_some() {
        let acc = store
            .get_account_mut(&treasury)
            .ok_or(ApplyError::InsufficientFunds)?;
        acc.balance = acc.balance.saturating_add(amount);
        store.commit_account_mutation(&treasury);
    } else {
        store.insert_account(Account {
            address: treasury,
            balance: amount,
            nonce: 0,
            keys: KeySet::default(),
            policy_version: 0,
            policy_hash: None,
            verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
            auth_data: Vec::new(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
