// SPDX-License-Identifier: Apache-2.0
//! Validator lifecycle types — SPEC-VAL-001 + ADR-047.

use crate::account::Address;
use pqc_crypto::AlgId;

/// Maximum number of validators in the active set (ADR-013: 24 prototype).
pub const VALIDATOR_MAX_ACTIVE_SET_SIZE: usize = 24;

/// Unbonding period in blocks — devnet default.
pub const VALIDATOR_UNBONDING_PERIOD: u64 = 120;

/// Epoch duration for devnet in blocks — ADR-042 documentation reference.
pub const VALIDATOR_EPOCH_DURATION_DEVNET: u64 = 60;

/// Upper bound for an on-chain libp2p PeerId multihash — ADR-047, D-03, TASK-159.
///
/// libp2p PeerIds are multihash-encoded. We clamp at 64 bytes per ADR-047 to
/// exclude pathological very-large digests while admitting the identity hash
/// (~38 bytes), SHA-256 (34 bytes), and Keccak-256 (34 bytes) PeerIds.
/// Apply-time enforcement rejects oversized bindings with
/// `ApplyError::ValidatorPeerIdTooLarge`.
pub const VALIDATOR_PEER_ID_MAX_LEN: usize = 64;

/// Lifecycle state of a validator — SPEC-VAL-001 §5.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatorStatus {
    Candidate,
    Active,
    Jailed,
    Unbonding { start_height: u64 },
    Exited,
}

/// On-chain record for a registered validator — SPEC-VAL-001 §4–§5.
#[derive(Debug, Clone)]
pub struct ValidatorRecord {
    pub operator: Address,
    pub node_id: String,
    pub consensus_alg_id: AlgId,
    pub consensus_pk: Vec<u8>,
    pub self_bond: u128,
    pub status: ValidatorStatus,
    pub registered_height: u64,
    pub tombstoned: bool,
}

/// Decoded payload for a `ValidatorRegister` transaction — SPEC-VAL-001 §4 + ADR-047.
///
/// CBOR map fields (ADR-047):
/// - 1: node_id (bstr — UTF-8 encoded)
/// - 2: consensus_alg_id (u16)
/// - 3: consensus_pk (bstr)
/// - 4: self_bond (bstr, 16-byte big-endian u128)
/// - 5: peer_id (bstr — libp2p PeerId multihash, ≤ 64 bytes; optional for legacy txs)
pub struct ValidatorRegisterPayload {
    pub node_id: String,
    pub consensus_alg_id: u16,
    pub consensus_pk: Vec<u8>,
    pub self_bond: u128,
    pub peer_id: Vec<u8>,
}

/// Decoded payload for a `ValidatorRotatePeerId` transaction — ADR-047, TASK-159.
pub struct ValidatorRotatePeerIdPayload {
    pub new_peer_id: Vec<u8>,
}
