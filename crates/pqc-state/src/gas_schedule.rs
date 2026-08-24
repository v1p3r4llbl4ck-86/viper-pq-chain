// SPDX-License-Identifier: BUSL-1.1
//! Deterministic per-operation gas schedule — SPEC-OPS / TASK-007.
//!
//! # Gas unit definition
//!
//! 1 gas unit ≈ 1 µs of state-machine execution time on the reference Linux
//! node (Linux 6.8.0-107-generic, pure-Rust ml-dsa crate, release build).
//! Gas costs are derived from the block-production benchmarks in SPEC-FEE-001
//! §6.4: an empty block costs ~7 µs; adding one transfer costs ~11 µs
//! incremental — the difference is the combined CBOR decode, balance apply,
//! and leaf-hash recompute cost for that operation.
//!
//! # Conversion to fee units
//!
//! ```text
//! exec_fee = exec_fee_per_gas × gas_used
//! ```
//!
//! `exec_fee_per_gas = 43` (floor of the 43.3 units/µs calibration rate from
//! TASK-042, the same rate used to calibrate `sigverify_fee_v_b`).
//!
//! At this rate, execution fees are intentionally small relative to signature
//! verification:
//!
//! | Operation           | Gas | Exec fee (at 43) | sigverify_fee_v_b |
//! |---------------------|-----|-----------------|-------------------|
//! | token_transfer      |   5 |            215  |          14 000   |
//! | vault_create        |  10 |            430  |          14 000   |
//! | vault_policy_update |   6 |            258  |          14 000   |
//! | attestation_create  |   8 |            344  |          14 000   |
//! | attestation_revoke  |   6 |            258  |          14 000   |
//! | proof_anchor        |   7 |            301  |          14 000   |
//! | key_add             |  12 |            516  |          14 000   |
//! | key_rotate          |  15 |            645  |          14 000   |
//! | key_revoke          |  10 |            430  |          14 000   |
//! | governance_proposal |  18 |            774  |          14 000   |
//!
//! Signature verification dominates Phase 1 transaction cost; execution
//! contributes 1.5 – 5.5 % of total fee for a standard ML-DSA-65 sender.

use pqc_types::transaction::{MsgType, Transaction};

use crate::error::ApplyError;

/// Gas cost for a `token_transfer` (≈5 µs: 2 reads, 2 balance writes, 2 leaf hashes).
pub const GAS_TOKEN_TRANSFER: u64 = 5;

/// Gas cost for a `vault_create` (≈10 µs: key material write, account create, leaf hash).
pub const GAS_VAULT_CREATE: u64 = 10;

/// Gas cost for a `vault_policy_update` (≈6 µs: policy_version + policy_hash field update, leaf hash recompute).
pub const GAS_VAULT_POLICY_UPDATE: u64 = 6;

/// Gas cost for an `attestation_create` (≈8 µs: attestation record write, leaf hash).
pub const GAS_ATTESTATION_CREATE: u64 = 8;

/// Gas cost for a `proof_anchor` (≈7 µs: anchor record write, leaf hash; no secondary indexes).
pub const GAS_PROOF_ANCHOR: u64 = 7;

/// Gas cost for an `attestation_revoke` (≈6 µs: status field update + leaf hash recompute).
pub const GAS_ATTESTATION_REVOKE: u64 = 6;

/// Gas cost for a `key_add` (≈12 µs: key push, invariant check, account leaf hash).
pub const GAS_KEY_ADD: u64 = 12;

/// Gas cost for a `key_rotate` (≈15 µs: revoke old key + add new key + invariant + leaf hash).
pub const GAS_KEY_ROTATE: u64 = 15;

/// Gas cost for a `key_revoke` (≈10 µs: status change, invariant check, leaf hash).
pub const GAS_KEY_REVOKE: u64 = 10;

/// Gas cost for a `governance_proposal` (≈18 µs: registry update, receipt write, 2 leaf hashes).
pub const GAS_GOVERNANCE_PROPOSAL: u64 = 18;

/// Gas cost for a `consensus_key_rotate` (≈15 µs: payload decode, pk validation, rotation record write, leaf hash).
pub const GAS_CONSENSUS_KEY_ROTATE: u64 = 15;

/// Gas cost for a `validator_register` (≈20 µs: payload decode, pk validation, bond deduction, validator record write, leaf hash).
pub const GAS_VALIDATOR_REGISTER: u64 = 20;

/// Gas cost for a `validator_exit` (≈10 µs: status change to Unbonding, leaf hash update).
pub const GAS_VALIDATOR_EXIT: u64 = 10;

/// Gas cost for a `validator_unjail` (≈10 µs: status change to Candidate, leaf hash update).
pub const GAS_VALIDATOR_UNJAIL: u64 = 10;

/// Gas cost for a `validator_rotate_peer_id` (≈10 µs; ADR-047).
pub const GAS_VALIDATOR_ROTATE_PEER_ID: u64 = 10;

/// Gas cost for a `submit_equivocation_evidence` (≈30 µs: decode, 2× ML-DSA verify, slash, tombstone).
pub const GAS_SUBMIT_EQUIVOCATION_EVIDENCE: u64 = 30;

/// Gas cost for a `governance_vote` (≈5 µs: proposal lookup, vote record write, leaf hash recompute).
pub const GAS_GOVERNANCE_VOTE: u64 = 5;

// ── Archival overlay (SPEC-ARCHIVAL-001, ADR-045, TASK-161) ──────────────────
//
// Archival apply costs dominate anything else in the schedule: a single
// ArchivalRecordSubmit can fold in up to 24 SLH-DSA-SHAKE-256s verifies at
// ~200 µs each on release builds (~5 ms wall time = 5 000 gas units in the
// µs→gas mapping). The value below is a placeholder until the M4 soak yields
// a measured replacement — 50 is an order-of-magnitude stand-in that keeps
// archival txs affordable at the fee floor and lets the M4 tests run. The
// effective fee is still anchored by `sigverify_fee_v_c` for the SLH family,
// which is the dominant cost in the user-visible fee.

/// Gas cost for `ValidatorRegisterArchivalKey` (≈15 µs: pk validation, record write, leaf hash recompute).
pub const GAS_VALIDATOR_REGISTER_ARCHIVAL_KEY: u64 = 15;

/// Gas cost for `ArchivalRecordSubmit` — placeholder (see comment above; adjust in M4 soak).
pub const GAS_ARCHIVAL_RECORD_SUBMIT: u64 = 50;

/// Gas cost for `ArchivalRecordAddAnchor` (≈8 µs: record lookup, anchor append, leaf hash recompute).
pub const GAS_ARCHIVAL_RECORD_ADD_ANCHOR: u64 = 8;

/// Gas cost for `ArchivalRecordRenew` (≈12 µs: record lookup, version bump, leaf hash recompute).
pub const GAS_ARCHIVAL_RECORD_RENEW: u64 = 12;

/// Return the deterministic scheduled gas for a supported operation.
pub fn scheduled_gas_for_msg_type(msg_type: MsgType) -> Result<u64, ApplyError> {
    match msg_type {
        MsgType::TokenTransfer => Ok(GAS_TOKEN_TRANSFER),
        MsgType::VaultCreate => Ok(GAS_VAULT_CREATE),
        MsgType::VaultPolicyUpdate => Ok(GAS_VAULT_POLICY_UPDATE),
        MsgType::AttestationCreate => Ok(GAS_ATTESTATION_CREATE),
        MsgType::AttestationRevoke => Ok(GAS_ATTESTATION_REVOKE),
        MsgType::ProofAnchor => Ok(GAS_PROOF_ANCHOR),
        MsgType::KeyAdd => Ok(GAS_KEY_ADD),
        MsgType::KeyRotate => Ok(GAS_KEY_ROTATE),
        MsgType::KeyRevoke => Ok(GAS_KEY_REVOKE),
        MsgType::GovernanceProposal => Ok(GAS_GOVERNANCE_PROPOSAL),
        MsgType::ConsensusKeyRotate => Ok(GAS_CONSENSUS_KEY_ROTATE),
        MsgType::ValidatorRegister => Ok(GAS_VALIDATOR_REGISTER),
        MsgType::ValidatorExit => Ok(GAS_VALIDATOR_EXIT),
        MsgType::ValidatorUnjail => Ok(GAS_VALIDATOR_UNJAIL),
        MsgType::ValidatorRotatePeerId => Ok(GAS_VALIDATOR_ROTATE_PEER_ID),
        MsgType::SubmitEquivocationEvidence => Ok(GAS_SUBMIT_EQUIVOCATION_EVIDENCE),
        MsgType::GovernanceVote => Ok(GAS_GOVERNANCE_VOTE),
        MsgType::ValidatorRegisterArchivalKey => Ok(GAS_VALIDATOR_REGISTER_ARCHIVAL_KEY),
        MsgType::ArchivalRecordSubmit => Ok(GAS_ARCHIVAL_RECORD_SUBMIT),
        MsgType::ArchivalRecordAddAnchor => Ok(GAS_ARCHIVAL_RECORD_ADD_ANCHOR),
        MsgType::ArchivalRecordRenew => Ok(GAS_ARCHIVAL_RECORD_RENEW),
    }
}

/// Return the deterministic scheduled gas for a transaction.
pub fn scheduled_gas_for_tx(tx: &Transaction) -> Result<u64, ApplyError> {
    scheduled_gas_for_msg_type(tx.msg_type)
}

#[cfg(test)]
mod tests {
    use pqc_types::transaction::MsgType;

    use super::{
        scheduled_gas_for_msg_type, GAS_ATTESTATION_CREATE, GAS_ATTESTATION_REVOKE,
        GAS_GOVERNANCE_PROPOSAL, GAS_KEY_ADD, GAS_KEY_REVOKE, GAS_KEY_ROTATE, GAS_TOKEN_TRANSFER,
        GAS_VAULT_CREATE,
    };

    #[test]
    fn token_transfer_gas_cost() {
        assert_eq!(
            scheduled_gas_for_msg_type(MsgType::TokenTransfer).unwrap(),
            GAS_TOKEN_TRANSFER
        );
    }

    #[test]
    fn vault_create_gas_cost() {
        assert_eq!(
            scheduled_gas_for_msg_type(MsgType::VaultCreate).unwrap(),
            GAS_VAULT_CREATE
        );
    }

    #[test]
    fn attestation_create_gas_cost() {
        assert_eq!(
            scheduled_gas_for_msg_type(MsgType::AttestationCreate).unwrap(),
            GAS_ATTESTATION_CREATE
        );
    }

    #[test]
    fn key_management_gas_costs() {
        assert_eq!(
            scheduled_gas_for_msg_type(MsgType::KeyAdd).unwrap(),
            GAS_KEY_ADD
        );
        assert_eq!(
            scheduled_gas_for_msg_type(MsgType::KeyRotate).unwrap(),
            GAS_KEY_ROTATE
        );
        assert_eq!(
            scheduled_gas_for_msg_type(MsgType::KeyRevoke).unwrap(),
            GAS_KEY_REVOKE
        );
        assert_eq!(
            scheduled_gas_for_msg_type(MsgType::GovernanceProposal).unwrap(),
            GAS_GOVERNANCE_PROPOSAL
        );
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn key_rotate_costs_more_than_key_add_and_key_revoke() {
        assert!(
            GAS_KEY_ROTATE > GAS_KEY_ADD,
            "rotate = revoke + add — must cost more than add alone"
        );
        assert!(
            GAS_KEY_ROTATE > GAS_KEY_REVOKE,
            "rotate = revoke + add — must cost more than revoke alone"
        );
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn attestation_revoke_gas_cost() {
        assert_eq!(
            scheduled_gas_for_msg_type(MsgType::AttestationRevoke).unwrap(),
            GAS_ATTESTATION_REVOKE
        );
        // revoke costs less than create (simpler state mutation: no new record, just status update)
        assert!(GAS_ATTESTATION_REVOKE < GAS_ATTESTATION_CREATE);
    }

    #[test]
    fn vault_policy_update_gas_cost() {
        use super::GAS_VAULT_POLICY_UPDATE;
        assert_eq!(
            scheduled_gas_for_msg_type(MsgType::VaultPolicyUpdate).unwrap(),
            GAS_VAULT_POLICY_UPDATE
        );
    }

    #[test]
    fn consensus_key_rotate_gas_cost() {
        use super::GAS_CONSENSUS_KEY_ROTATE;
        assert_eq!(
            scheduled_gas_for_msg_type(MsgType::ConsensusKeyRotate).unwrap(),
            GAS_CONSENSUS_KEY_ROTATE
        );
    }

    #[test]
    fn governance_vote_gas_cost() {
        use super::GAS_GOVERNANCE_VOTE;
        assert_eq!(
            scheduled_gas_for_msg_type(MsgType::GovernanceVote).unwrap(),
            GAS_GOVERNANCE_VOTE
        );
    }
}
