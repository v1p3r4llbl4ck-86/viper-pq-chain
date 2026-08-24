// SPDX-License-Identifier: Apache-2.0
//! Consensus key rotation record — SPEC-OPS-001 §7.4.

use crate::account::Address;
use pqc_crypto::AlgId;

/// An on-chain record of a pending consensus key rotation for a validator.
///
/// Indexed by operator address in `StateStore`.  When the same operator
/// submits a second `consensus_key_rotate` the existing record is replaced,
/// so only the most recent (or in-progress) rotation is tracked per operator.
///
/// **Phase 4 status (2026-05-09):** runtime activation is **SHIPPED**.
/// `StateStore::activate_pending_consensus_key_rotations` is wired into
/// the live block-production path (`engine.rs:259`) and the cold-sync
/// replay path (`recovery.rs:272`); the verifier reads `consensus_pk`
/// fresh from state per block. The producer-side keystore lookup uses
/// `Keystore::get_for_pk(addr, expected_pk)` which matches the rotated
/// pk by `key_version` (`pqcd::devnet::snapshot_block_signers`). Operator
/// CLI: `pqcd wallet rotate-consensus-key --in-place` stages the new
/// seed in `keystore.json` and submits the `ConsensusKeyRotate` tx in
/// one call. See the private design notes
/// and the private design notes §"Phase 4 keystore
/// versioning landed".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusKeyRotation {
    /// Operator address that submitted the rotation request.
    pub operator: Address,
    /// Algorithm for the new consensus key.
    pub new_alg_id: AlgId,
    /// Raw public key bytes for the new consensus key.
    pub new_pk_bytes: Vec<u8>,
    /// Block height at which the new key becomes the sole valid consensus key.
    pub rotation_start_height: u64,
    /// Block height at which this record was written to state.
    pub recorded_at_height: u64,
}
