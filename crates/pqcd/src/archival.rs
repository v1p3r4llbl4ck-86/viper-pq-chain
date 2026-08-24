// SPDX-License-Identifier: BUSL-1.1
//! Archival-overlay submission helpers — pqcd side of SPEC-ARCHIVAL-001 §4.6,
//! ADR-045, TASK-163 / M4.4.
//!
//! Called from the consensus loop after every block commit. When the committed
//! height is an epoch boundary, the loop:
//!
//! 1. Computes the closed epoch's `ArchivalEpochSummary` (`epoch_root` +
//!    `epoch_number` + first/last heights). See `pqc_consensus::archival`.
//! 2. For each Active validator this node holds both a consensus ML-DSA seed
//!    AND an SLH-DSA-SHAKE-256s archival secret key for, and for whom the
//!    on-chain `archival_signer_set` admits membership (`is_archival_signer`),
//!    this module builds a signed `ArchivalRecordSubmit` transaction carrying
//!    that one signer's single-sig over the §4.5 preimage.
//! 3. The consensus loop hands the raw bytes to `LiveNode::inject_tx` — the
//!    tx then flows through the normal mempool → block-apply path.
//!
//! # Single-signer vs. threshold quorum
//!
//! The current apply path requires `|verified_sigs| >= m` where `m =
//! ceil(2n/3)` by default (SPEC §4.3). Independent single-sig submissions
//! thus land only when `m == 1` — either because the signer set has a single
//! registered archival key (`n == 1` → `m == 1`), or because governance has
//! set an explicit `(1, n)` threshold. Multi-signer assembly needs an
//! off-chain signature aggregator (gossip via
//! `/viper/<chain>/archival-sigs/1.0.0` + aggregator picks up the fan-in).
//! That aggregator is deliberately out of M4.4 scope — the devnet-2 exit
//! criterion at SPEC §13 T7 is satisfied with a single registered archival
//! key.
//!
//! # Error handling
//!
//! Every failure here is non-fatal. The archival overlay is explicitly one
//! level above consensus finality (SPEC §4.7) — a failed submission delays
//! archival for the affected epoch but MUST NOT halt block production.
//! Failures are logged at `WARN`; metrics live in
//! `pqchain_archival_submit_attempted_total` / `_ok_total` / `_failed_total`.

use anyhow::{anyhow, Result};
use pqc_consensus::archival::ArchivalEpochSummary;
use pqc_crypto::{ml_dsa_sign_with_seed, slh_dsa_shake_256s_sign, AlgId};
use pqc_state::apply::archival::archival_sig_preimage;
use pqc_state::StateStore;
use pqc_tx::codec::encode_tx;
use pqc_types::account::Address;
use pqc_types::archival::SLH_DSA_SHAKE_256S_SIG_LEN;
use pqc_types::transaction::{MsgType, Transaction};

use crate::keystore::Keystore;

/// Gas limit for the `ArchivalRecordSubmit` transaction. The apply path's
/// base gas (`GAS_ARCHIVAL_RECORD_SUBMIT = 50`) plus small per-byte overhead
/// — a generous ceiling avoids under-gas rejections during the M4.4
/// bootstrap when payload sizes have not yet been soak-tuned.
const SUBMIT_GAS_LIMIT: u64 = 5_000;

/// Fee for the `ArchivalRecordSubmit` transaction (venom). Sized to clear the
/// devnet base fee with headroom; the validator self-funds from block rewards.
const SUBMIT_FEE: u64 = 30_000;

/// One candidate archival submission: a validator this node can sign for,
/// admitted by the on-chain signer set, together with the consensus ML-DSA
/// seed used to sign the outer tx envelope and the SLH secret key used to
/// sign the §4.5 preimage.
#[derive(Debug, Clone)]
pub struct SubmissionCandidate {
    pub operator: Address,
    pub consensus_alg_id: AlgId,
    pub consensus_seed: [u8; 32],
    pub archival_sk: Vec<u8>,
    pub sender_nonce: u64,
}

/// Enumerate candidates from the current state + keystore intersection.
///
/// Returns one entry per `(operator, sk_pair)` the node can both produce an
/// archival signature for AND the on-chain state admits as an archival
/// signer. Non-signers and missing keys are silently skipped.
///
/// The consensus loop holds the state lock while calling this; no I/O or
/// blocking work is done inside.
pub fn collect_submission_candidates(
    state: &StateStore,
    keystore: &Keystore,
) -> Vec<SubmissionCandidate> {
    let mut out = Vec::new();
    for v in state.active_validators() {
        let operator = &v.operator;
        if !state.is_archival_signer(operator) {
            continue;
        }
        let Some(entry) = keystore.get(&operator.0) else {
            continue;
        };
        let Some(archival_sk) = entry.archival_sk.as_ref() else {
            continue;
        };
        // The on-chain archival_pk must also be registered — otherwise the
        // apply path rejects with `ArchivalMissingKey`. Cheaper to skip here.
        if state.get_archival_key(operator).is_none() {
            continue;
        }
        let sender_nonce = state.get_account(operator).map(|a| a.nonce).unwrap_or(0);
        out.push(SubmissionCandidate {
            operator: operator.clone(),
            consensus_alg_id: entry.sig_alg_id,
            consensus_seed: entry.commit_seed,
            archival_sk: archival_sk.clone(),
            sender_nonce,
        });
    }
    out
}

/// Build a fully-signed `ArchivalRecordSubmit` tx (raw CBOR-encoded bytes)
/// for one candidate, containing that validator's single SLH-DSA-SHAKE-256s
/// signature over the §4.5 preimage.
///
/// Pure + CPU-bound — invoke off the tokio runtime via `spawn_blocking` so
/// the ~3 ms SLH sign does not stall block production on single-CPU nodes.
pub fn build_signed_submit_tx(
    chain_id: &[u8],
    candidate: &SubmissionCandidate,
    summary: &ArchivalEpochSummary,
) -> Result<Vec<u8>> {
    let fork_digest = pqc_types::ForkDigest::viper_research_1();
    let preimage = archival_sig_preimage(&fork_digest, summary.epoch_number, &summary.epoch_root);
    let sig = slh_dsa_shake_256s_sign(&candidate.archival_sk, &preimage)
        .map_err(|e| anyhow!("SLH-DSA-SHAKE-256s sign failed: {e}"))?;
    if sig.len() != SLH_DSA_SHAKE_256S_SIG_LEN {
        return Err(anyhow!(
            "unexpected SLH-256s sig length: got {}, want {}",
            sig.len(),
            SLH_DSA_SHAKE_256S_SIG_LEN
        ));
    }

    let payload = pqc_state::apply::archival::encode_archival_record_submit_payload(
        summary.epoch_number,
        summary.first_height,
        summary.last_height,
        &summary.epoch_root,
        &[(candidate.operator.clone(), sig)],
    );

    let unsigned_tx = Transaction {
        tx_version: 1,
        chain_id: chain_id.to_vec(),
        msg_type: MsgType::ArchivalRecordSubmit,
        sender: candidate.operator.clone(),
        nonce: candidate.sender_nonce,
        fee: SUBMIT_FEE,
        fee_tip: 0,
        gas_limit: SUBMIT_GAS_LIMIT,
        payload,
        sig_alg_id: candidate.consensus_alg_id,
        sig_key_version: 1,
        signature: Vec::new(),
    };

    // SPEC-TX-001 §9 signed preimage: `"PQC-TX-V1" || CBOR(tx fields 1..11)`.
    // The mempool admission pipeline rebuilds this preimage from the decoded
    // tx fields; signing the same structure via `build_preimage` matches
    // byte-for-byte.
    let tx_fork_digest = pqc_types::ForkDigest::viper_research_1();
    let preimage = pqc_tx::preimage::build_preimage(&tx_fork_digest, &unsigned_tx)
        .map_err(|e| anyhow!("build ArchivalRecordSubmit preimage: {e}"))?;
    let sig = ml_dsa_sign_with_seed(
        candidate.consensus_alg_id,
        &candidate.consensus_seed,
        &preimage,
    )
    .map_err(|e| anyhow!("ml_dsa_sign_with_seed: {e}"))?;

    let mut signed_tx = unsigned_tx;
    signed_tx.signature = sig;
    let signed_cbor =
        encode_tx(&signed_tx).map_err(|e| anyhow!("encode signed ArchivalRecordSubmit: {e}"))?;

    Ok(signed_cbor)
}

/// Build a fully-signed `ValidatorRegisterArchivalKey` tx (raw CBOR-encoded
/// bytes) for an operator registering a fresh SLH-DSA-SHAKE-256s archival
/// public key on-chain — SPEC-ARCHIVAL-001 §4.5.
///
/// The archival pk is a 64-byte SLH-DSA-SHAKE-256s public key; the outer
/// envelope is signed with the operator's ML-DSA consensus seed (so the
/// existing mempool admission pipeline verifies the sender's authority over
/// this tx without new verifier-dispatch code).
pub fn build_signed_register_archival_key_tx(
    chain_id: &[u8],
    operator: Address,
    consensus_alg_id: AlgId,
    consensus_seed: &[u8; 32],
    archival_pk: &[u8],
    nonce: u64,
) -> Result<Vec<u8>> {
    let payload = pqc_state::apply::archival::encode_register_archival_key_payload(
        AlgId::SlhDsaShake256s.as_u16(),
        archival_pk,
    );
    let unsigned_tx = Transaction {
        tx_version: 1,
        chain_id: chain_id.to_vec(),
        msg_type: MsgType::ValidatorRegisterArchivalKey,
        sender: operator,
        nonce,
        fee: SUBMIT_FEE,
        fee_tip: 0,
        gas_limit: SUBMIT_GAS_LIMIT,
        payload,
        sig_alg_id: consensus_alg_id,
        sig_key_version: 1,
        signature: Vec::new(),
    };
    let tx_fork_digest = pqc_types::ForkDigest::viper_research_1();
    let preimage = pqc_tx::preimage::build_preimage(&tx_fork_digest, &unsigned_tx)
        .map_err(|e| anyhow!("build ValidatorRegisterArchivalKey preimage: {e}"))?;
    let sig = ml_dsa_sign_with_seed(consensus_alg_id, consensus_seed, &preimage)
        .map_err(|e| anyhow!("ml_dsa_sign_with_seed: {e}"))?;
    let mut signed_tx = unsigned_tx;
    signed_tx.signature = sig;
    encode_tx(&signed_tx).map_err(|e| anyhow!("encode signed ValidatorRegisterArchivalKey: {e}"))
}

/// Produce signed `ArchivalRecordSubmit` raw bytes for every eligible
/// candidate. Runs sequentially — the SLH-256s sign is ~3 ms so even 24
/// candidates finish well inside a block-time budget.
pub fn build_submissions(
    chain_id: &[u8],
    candidates: &[SubmissionCandidate],
    summary: &ArchivalEpochSummary,
) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(candidates.len());
    for (i, cand) in candidates.iter().enumerate() {
        match build_signed_submit_tx(chain_id, cand, summary) {
            Ok(bytes) => out.push(bytes),
            Err(e) => tracing::warn!(
                operator = %hex::encode(cand.operator.0),
                error = %e,
                "archival submit build failed (non-fatal)"
            ),
        }
        // Each subsequent candidate from the same sender (rare but
        // possible in tests) needs a fresh nonce to not stack-admission;
        // the live state lookup outside this function already gave the
        // right value, so no adjustment needed. Variable `i` kept for
        // potential future fan-out instrumentation.
        let _ = i;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqc_consensus::archival::compute_archival_epoch_root;

    #[test]
    fn build_signed_submit_tx_produces_valid_cbor() {
        // Candidate with a randomly-generated ML-DSA seed; the real archival
        // sk is produced inline so the resulting tx is actually signable.
        let consensus_seed = [0x11u8; 32];
        let operator = Address([0xA1u8; 32]);

        // Generate a real SLH-256s sk (faster than faking — ~200 µs keygen).
        let (_, sk) = pqc_crypto::slh_dsa_shake_256s_generate()
            .expect("SLH-256s keygen must succeed in tests");

        let cand = SubmissionCandidate {
            operator: operator.clone(),
            consensus_alg_id: AlgId::MlDsa65,
            consensus_seed,
            archival_sk: sk,
            sender_nonce: 0,
        };
        let epoch_root = compute_archival_epoch_root(7, &[[0x42u8; 32], [0x43u8; 32]]);
        let summary = ArchivalEpochSummary {
            epoch_number: 7,
            first_height: 1,
            last_height: 2,
            epoch_root,
        };

        let bytes = build_signed_submit_tx(b"viper-test-1", &cand, &summary)
            .expect("build signed submit tx must succeed");

        // Round-trip via the production codec — decodes to our expected fields.
        let decoded = pqc_tx::codec::decode_tx(&bytes).expect("decode tx");
        assert_eq!(decoded.msg_type, MsgType::ArchivalRecordSubmit);
        assert_eq!(decoded.sender, operator);
        assert_eq!(decoded.sig_alg_id, AlgId::MlDsa65);
        assert!(!decoded.signature.is_empty(), "signature must be attached");
    }
}
