// SPDX-License-Identifier: BUSL-1.1
//! Peer identity types — ADR-041.

use pqc_crypto::AlgId;

/// A validator's P2P identity, binding their network PeerId to their on-chain validator pubkey.
///
/// ADR-041: node ID is bound to validator pubkey on-chain (anti-eclipse).
#[derive(Debug, Clone)]
pub struct ValidatorPeerId {
    /// libp2p PeerId (derived from node key).
    pub peer_id_bytes: Vec<u8>,
    /// On-chain validator public key (TLV envelope — ADR-044).
    pub validator_pk_envelope: Vec<u8>,
    /// Signing algorithm of the validator key.
    pub alg_id: AlgId,
    /// On-chain validator index (for stake-weighted peer scoring).
    pub validator_index: u64,
}

/// Peer metadata for scoring and anti-eclipse enforcement.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub peer_id_bytes: Vec<u8>,
    /// Autonomous System Number (for /24 diversity enforcement).
    pub asn: Option<u32>,
    /// Whether this is a bootstrap peer (persistent connection).
    pub is_bootstrap: bool,
}

/// Check whether an inbound P2P message claiming to come from `operator`
/// originates from that operator's on-chain-bound PeerId — ADR-047, D-03, TASK-159.
///
/// `registry` is an iterator over `(operator_address_bytes, peer_id_multihash)` —
/// typically produced by `pqc_state::StateStore::validator_peer_id_bindings`.
/// Returns `true` iff the registry contains a binding that matches exactly.
///
/// An operator with no on-chain binding (pre-ADR-047 devnet-2 genesis validator)
/// fails the match — callers apply the migration-window policy at a higher layer.
/// An empty `peer_id_bytes` is never valid and always returns `false`.
pub fn validator_peer_id_matches<'a, I>(
    operator_bytes: &[u8; 32],
    peer_id_bytes: &[u8],
    registry: I,
) -> bool
where
    I: IntoIterator<Item = (&'a [u8; 32], &'a [u8])>,
{
    if peer_id_bytes.is_empty() {
        return false;
    }
    registry
        .into_iter()
        .any(|(op, bound)| op == operator_bytes && bound == peer_id_bytes)
}
