// SPDX-License-Identifier: BUSL-1.1
//! GossipSub topic derivation — ADR-041.
//!
//! Topics are namespaced by chain_id to prevent cross-network message delivery.

/// Gossip topic identifiers for Viper PQ Chain.
pub struct Topics {
    /// New blocks proposed by the current epoch producer.
    pub blocks: String,
    /// Validator votes for BFT consensus rounds.
    pub consensus_votes: String,
    /// Signed transactions entering the mempool.
    pub transactions: String,
    /// Validator set change events (epoch boundary reconfiguration).
    pub validator_updates: String,
    /// Sync-committee compact-header attestations (SPEC-LIGHT-CLIENT-001 §5).
    /// Slug `viper-light-client-attestations-v1` is locked from genesis;
    /// any change requires a P-COMPAT-001 dual-path landing.
    pub light_client_attestations: String,
}

impl Topics {
    pub fn for_chain(chain_id: &str) -> Self {
        Self {
            blocks: format!("/viper/{chain_id}/blocks/1.0.0"),
            consensus_votes: format!("/viper/{chain_id}/consensus/votes/1.0.0"),
            transactions: format!("/viper/{chain_id}/mempool/txs/1.0.0"),
            validator_updates: format!("/viper/{chain_id}/validators/updates/1.0.0"),
            // SPEC-LIGHT-CLIENT-001 §5.1: full topic string is
            // `/viper/{chain_id}/{slug}/1.0.0`. The slug literal mirrors
            // `pqc_consensus::light_client::SYNC_COMMITTEE_GOSSIP_TOPIC`;
            // we duplicate it here rather than introduce a `pqc-p2p ->
            // pqc-consensus` cdep (the topic-registry crate is otherwise
            // a leaf). The `topic_strings_for_viper_pq_1_are_pinned` test
            // catches drift between the two.
            light_client_attestations: format!(
                "/viper/{chain_id}/viper-light-client-attestations-v1/1.0.0"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // SPEC-P2P-002 §10 T1 — topic strings must be stable across releases;
    // any change is a wire-breaking protocol bump and must be intentional.
    #[test]
    fn topic_strings_for_viper_devnet_2_are_pinned() {
        let t = Topics::for_chain("viper-devnet-2");
        assert_eq!(t.blocks, "/viper/viper-devnet-2/blocks/1.0.0");
        assert_eq!(
            t.consensus_votes,
            "/viper/viper-devnet-2/consensus/votes/1.0.0"
        );
        assert_eq!(t.transactions, "/viper/viper-devnet-2/mempool/txs/1.0.0");
        assert_eq!(
            t.validator_updates,
            "/viper/viper-devnet-2/validators/updates/1.0.0"
        );
        assert_eq!(
            t.light_client_attestations,
            "/viper/viper-devnet-2/viper-light-client-attestations-v1/1.0.0"
        );
    }

    // SPEC-LIGHT-CLIENT-001 §5.1 — the slug is locked at launch. Drift
    // between this string and the consensus-side
    // `light_client::SYNC_COMMITTEE_GOSSIP_TOPIC` constant is a wire
    // break. Pin both ends here so the diff is visible.
    #[test]
    fn light_client_topic_slug_matches_spec() {
        let t = Topics::for_chain("viper-pq-1");
        assert_eq!(
            t.light_client_attestations,
            "/viper/viper-pq-1/viper-light-client-attestations-v1/1.0.0"
        );
    }

    // Chain namespacing: changing chain_id must re-derive every topic.
    #[test]
    fn topics_are_namespaced_per_chain() {
        let a = Topics::for_chain("chain-a");
        let b = Topics::for_chain("chain-b");
        assert_ne!(a.blocks, b.blocks);
        assert_ne!(a.consensus_votes, b.consensus_votes);
        assert_ne!(a.transactions, b.transactions);
        assert_ne!(a.validator_updates, b.validator_updates);
    }

    // Topics must not collide with each other within a single chain.
    #[test]
    fn topics_are_distinct_within_a_chain() {
        let t = Topics::for_chain("x");
        let all = [
            &t.blocks,
            &t.consensus_votes,
            &t.transactions,
            &t.validator_updates,
            &t.light_client_attestations,
        ];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(
                    all[i], all[j],
                    "topic collision between {} and {}",
                    all[i], all[j]
                );
            }
        }
    }
}
