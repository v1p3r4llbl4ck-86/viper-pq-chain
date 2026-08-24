// SPDX-License-Identifier: Apache-2.0
//! Proof anchor state types — SPEC-OPS-001 §6.3.

use crate::account::Address;

/// 32-byte anchor identifier. Equal to the tx_hash of the `proof_anchor` transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AnchorId(pub [u8; 32]);

impl AnchorId {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// Proof anchor record stored on-chain — SPEC-OPS-001 §6.3.
///
/// The `anchor_id` equals the `tx_hash` of the submitting `proof_anchor`
/// transaction. Records are immutable once written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofAnchor {
    /// Unique identifier equal to the submitting transaction hash.
    pub anchor_id: AnchorId,
    /// Sender address that submitted the `proof_anchor` transaction.
    pub claimer: Address,
    /// Claim type value (see §6.3.1 for recognized values).
    pub claim_type: u16,
    /// SHAKE-256 digest of the asset identifier (32 bytes).
    pub asset_id_hash: [u8; 32],
    /// SHAKE-256 digest of the proof document or credential (32 bytes).
    pub proof_hash: [u8; 32],
    /// Optional schema governing `proof_hash` interpretation (32 bytes).
    pub schema_id: Option<[u8; 32]>,
    /// Block height at which this anchor was finalized.
    pub anchor_height: u64,
}

/// Return `true` if `claim_type` is a recognized Phase 1 value (§6.3.1).
///
/// Recognized values: `0x0001` (ownership), `0x0002` (custody),
/// `0x0003` (asset_metadata). Reserved ranges (`0x0000`, `0x8000–0xFFFF`)
/// are rejected.
pub fn is_supported_claim_type(claim_type: u16) -> bool {
    matches!(claim_type, 0x0001..=0x0003)
}

/// Return the human-readable name for a recognized claim type, or `None`.
pub fn claim_type_name(claim_type: u16) -> Option<&'static str> {
    match claim_type {
        0x0001 => Some("ownership"),
        0x0002 => Some("custody"),
        0x0003 => Some("asset_metadata"),
        _ => None,
    }
}
