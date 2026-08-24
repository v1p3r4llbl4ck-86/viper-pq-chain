// SPDX-License-Identifier: BUSL-1.1
//! Chain-scoped libp2p protocol IDs — TASK-135 step 12.
//!
//! Gossipsub topic strings live in `topics.rs`. Request-response
//! protocols (and any future stream-based protocols that are NOT
//! subscribable) live here: they are negotiated per-connection via
//! Identify rather than broadcast across a mesh, so keeping them in a
//! separate module makes the distinction visible to future maintainers.

/// Per-chain set of libp2p protocol IDs. All IDs are chain-scoped so a
/// validator accidentally dialling a peer on a different network cannot
/// negotiate a protocol and start exchanging block bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Protocols {
    /// `/viper/{chain_id}/block-fetch/1.0.0` — ranged block-body fetch
    /// (request-response, CBOR codec). Used by followers to close height
    /// gaps surfaced by the TASK-135 step 11 inbound classifier.
    pub block_fetch: String,
    /// `/viper/{chain_id}/snapshot/1.0.0` — full trusted-checkpoint
    /// snapshot fetch (request-response, CBOR codec). Used by a cold-
    /// starting follower before it begins tailing via `block_fetch`.
    /// Replaces the Phase 6 HTTP `/internal/p2p/snapshot` endpoint at
    /// TASK-141 cutover.
    pub snapshot_fetch: String,
    /// `/viper/{chain_id}/block-fetch-by-hash/1.0.0` — single-block
    /// fetch by hash (request-response, CBOR codec). ADR-054 §Stage 4.
    /// Used by orphan resolution to retrieve the *specific* canonical
    /// variant of a parent block when the receiver's local copy is a
    /// state-equivalent sibling.
    pub block_fetch_by_hash: String,
}

impl Protocols {
    pub fn for_chain(chain_id: &str) -> Self {
        Self {
            block_fetch: format!("/viper/{chain_id}/block-fetch/1.0.0"),
            snapshot_fetch: format!("/viper/{chain_id}/snapshot/1.0.0"),
            block_fetch_by_hash: format!("/viper/{chain_id}/block-fetch-by-hash/1.0.0"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // SPEC-P2P-002 §10 T1 counterpart for request-response: any change
    // to a protocol ID string is a wire-breaking bump and must be
    // caught by CI, not at runtime on a production follower whose peers
    // will silently fail to negotiate the new protocol.
    #[test]
    fn block_fetch_protocol_id_is_stable() {
        let p = Protocols::for_chain("viper-devnet-2");
        assert_eq!(p.block_fetch, "/viper/viper-devnet-2/block-fetch/1.0.0");
    }

    #[test]
    fn snapshot_fetch_protocol_id_is_stable() {
        let p = Protocols::for_chain("viper-devnet-2");
        assert_eq!(p.snapshot_fetch, "/viper/viper-devnet-2/snapshot/1.0.0");
    }

    #[test]
    fn protocol_ids_are_chain_scoped() {
        let a = Protocols::for_chain("chain-a");
        let b = Protocols::for_chain("chain-b");
        assert_ne!(
            a.block_fetch, b.block_fetch,
            "block-fetch protocol ID must be chain-scoped — cross-chain \
             negotiation would let a follower fetch blocks from a peer \
             on a different network"
        );
        assert_ne!(
            a.snapshot_fetch, b.snapshot_fetch,
            "snapshot-fetch protocol ID must be chain-scoped"
        );
    }

    #[test]
    fn block_fetch_and_snapshot_fetch_are_distinct() {
        // Belt-and-braces: the two request-response protocols must be
        // disambiguatable inside the same Identify round so libp2p can
        // route inbound frames to the right sub-behaviour.
        let p = Protocols::for_chain("any-chain");
        assert_ne!(p.block_fetch, p.snapshot_fetch);
    }

    #[test]
    fn block_fetch_by_hash_protocol_id_is_stable() {
        // ADR-054 §Stage 4. Wire ID is part of the on-the-wire contract;
        // any change is a protocol bump and must be caught at CI rather
        // than at runtime when a follower silently fails to negotiate.
        let p = Protocols::for_chain("viper-pq-1");
        assert_eq!(
            p.block_fetch_by_hash,
            "/viper/viper-pq-1/block-fetch-by-hash/1.0.0"
        );
    }

    #[test]
    fn three_request_response_protocols_are_pairwise_distinct() {
        let p = Protocols::for_chain("any-chain");
        assert_ne!(p.block_fetch, p.snapshot_fetch);
        assert_ne!(p.block_fetch, p.block_fetch_by_hash);
        assert_ne!(p.snapshot_fetch, p.block_fetch_by_hash);
    }
}
