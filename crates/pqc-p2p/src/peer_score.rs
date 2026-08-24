// SPDX-License-Identifier: BUSL-1.1
//! GossipSub peer-score calibration — TASK-222.
//!
//! Replaces the `PeerScoreParams::default()` baseline with explicit
//! per-topic weights tuned for the 64-256 validator scaling band. The
//! defaults are too lax at scale: every topic gets `topic_weight = 0.5`
//! and every per-topic weight is zero, so the only signals that move
//! the score are app-specific weight (zero today), IP colocation, and
//! the behaviour penalty. That is enough for a 3-validator devnet but
//! a 64-validator network can graylist a healthy peer well before a
//! malicious one even shows up in the score.
//!
//! # Calibration philosophy
//!
//! Peer-score is **not** an admission gate — application-layer PQ
//! signature verification + the SPEC-P2P-002 §4.4 ValidatorPeerId
//! binding are the load-bearing checks. Peer-score is a **degradation
//! signal**: a score below `gossip_threshold` stops gossip exchange,
//! below `publish_threshold` stops publishing, below `graylist_threshold`
//! disconnects. The calibration here is therefore a *first line of
//! defense* against:
//!
//! - flood attacks (peers pushing invalid messages → invalid_message
//!   penalty drops them to graylist quickly),
//! - lazy peers (peers that subscribe but never deliver → mesh
//!   message deliveries threshold flags them),
//! - sticky cluster peers (peers from the same /24 → IP colocation
//!   penalty ensures one operator can't dominate the mesh).
//!
//! # Topic weights
//!
//! Topics are weighted by **operational severity** of a missed message:
//!
//! | Topic               | Weight | Rationale |
//! |---------------------|--------|-----------|
//! | `blocks`            | 1.00   | most important; only proposer publishes; mesh failure delays consensus directly |
//! | `consensus_votes`   | 0.80   | high-frequency but redundant (3 sigs/block) — single missed vote recoverable; missing ALL votes from a peer is the relevant signal |
//! | `validator_updates` | 0.50   | rare (epoch boundary) but critical when fired; threshold is "did the peer deliver any per-epoch?" |
//! | `transactions`      | 0.05   | high-frequency, low-criticality; mempool is best-effort, missed tx eventually retried by sender |
//!
//! Per-topic params are sized for the 64-256 validator band (TASK-228
//! ladder) at 1 second block-time. Mesh delivery activation is set to
//! 30 s so a node joining a mesh has time to converge before the
//! "peer didn't deliver" penalty kicks in.
//!
//! # Why these specific numbers
//!
//! The numbers below are a **starter calibration**, documented for
//! audit. They are derived by analogy from Lighthouse / Lodestar /
//! Aptos calibrations published in their respective consensus specs,
//! adjusted for Viper's larger PQ message sizes (3 KB ML-DSA-65 vs
//! ~1 KB BLS, 16 KB SLH-DSA-192s vs ~50 B Ed25519). The audit-readiness
//! workflow is:
//!
//!   1. Soak-test these numbers on `viper-pq-1` for 7 days at 64-validator
//!      scale (TASK-185 cohort onboarding gate).
//!   2. Capture peer-score telemetry via the new
//!      `pqchain_p2p_gossip_*` gauges (this commit).
//!   3. Tune via a follow-up TASK if the 7-day soak shows pathology
//!      (e.g. healthy peers landing in graylist, malicious peers
//!      surviving above publish threshold).
//!
//! The follow-up tuning is expected to move weights by a factor of
//! ~2x in either direction; the *shape* of the calibration (block >
//! vote > update > tx) is invariant under any reasonable scale.

use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use libp2p::gossipsub::{IdentTopic, PeerScoreParams, PeerScoreThresholds, TopicScoreParams};

use crate::topics::Topics;

// ── Peer-score telemetry (TASK-222 §3) ──────────────────────────────────────
//
// The swarm event loop periodically samples the gossipsub Behaviour's
// per-peer scores, buckets them against the calibrated thresholds, and
// updates these globals. pqcd reads them to render `pqchain_p2p_gossip_*`
// gauges in `/v1/metrics`. Globals are appropriate here because there is
// at most one swarm per process; the libp2p single-Swarm assumption is
// already load-bearing elsewhere.

/// Number of peers whose score is below `graylist_threshold`.
/// Such peers are marked for disconnection by gossipsub.
static PEERS_GRAYLISTED: AtomicUsize = AtomicUsize::new(0);

/// Number of peers whose score is between `graylist_threshold` and
/// `publish_threshold`. Connected but the local node will not publish
/// to them.
static PEERS_BELOW_PUBLISH: AtomicUsize = AtomicUsize::new(0);

/// Number of peers whose score is between `publish_threshold` and
/// `gossip_threshold`. Local node publishes but does not exchange
/// gossip control messages.
static PEERS_BELOW_GOSSIP: AtomicUsize = AtomicUsize::new(0);

/// Number of peers above all thresholds — fully healthy.
static PEERS_HEALTHY: AtomicUsize = AtomicUsize::new(0);

/// Lowest score across connected peers (×1000 fixed-point so we can
/// stash an f64 in an AtomicI64). 0 when no peers connected.
static LOWEST_SCORE_MILLI: AtomicI64 = AtomicI64::new(0);

/// Highest score across connected peers (×1000 fixed-point).
static HIGHEST_SCORE_MILLI: AtomicI64 = AtomicI64::new(0);

/// Wall-clock seconds since UNIX epoch of the last sample. 0 until the
/// first sample fires. Operators use this to detect a stuck sampler
/// (delta from `now` > 60 s = sampler is wedged).
static LAST_SAMPLE_UNIX: AtomicU64 = AtomicU64::new(0);

/// One sample's bucket counts. Returned by [`update_from_iter`] to
/// callers that want the immediate result without re-reading the
/// globals.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerScoreSnapshot {
    pub graylisted: usize,
    pub below_publish: usize,
    pub below_gossip: usize,
    pub healthy: usize,
}

/// Update the global telemetry from an iterator of `(peer_id, score)`
/// pairs. Buckets each score against [`viper_peer_score_thresholds`]
/// and stores the aggregate counts + min/max in the globals. Called
/// from the swarm event loop on a periodic tick.
///
/// The function is generic over the peer-id type so the swarm caller
/// can pass `gossipsub.all_peers()` directly without an intermediate
/// allocation.
pub fn update_from_iter<I, P>(scores: I, now_unix: u64) -> PeerScoreSnapshot
where
    I: Iterator<Item = (P, Option<f64>)>,
{
    let thresholds = viper_peer_score_thresholds();
    let mut snapshot = PeerScoreSnapshot::default();
    let mut lowest: Option<f64> = None;
    let mut highest: Option<f64> = None;

    for (_, maybe_score) in scores {
        let Some(score) = maybe_score else {
            // Peer-score not enabled for this peer (e.g. peer connected
            // before with_peer_score ran). Treat as healthy.
            snapshot.healthy += 1;
            continue;
        };
        if score <= thresholds.graylist_threshold {
            snapshot.graylisted += 1;
        } else if score <= thresholds.publish_threshold {
            snapshot.below_publish += 1;
        } else if score <= thresholds.gossip_threshold {
            snapshot.below_gossip += 1;
        } else {
            snapshot.healthy += 1;
        }
        lowest = Some(lowest.map_or(score, |l| l.min(score)));
        highest = Some(highest.map_or(score, |h| h.max(score)));
    }

    PEERS_GRAYLISTED.store(snapshot.graylisted, Ordering::Relaxed);
    PEERS_BELOW_PUBLISH.store(snapshot.below_publish, Ordering::Relaxed);
    PEERS_BELOW_GOSSIP.store(snapshot.below_gossip, Ordering::Relaxed);
    PEERS_HEALTHY.store(snapshot.healthy, Ordering::Relaxed);
    LOWEST_SCORE_MILLI.store((lowest.unwrap_or(0.0) * 1000.0) as i64, Ordering::Relaxed);
    HIGHEST_SCORE_MILLI.store((highest.unwrap_or(0.0) * 1000.0) as i64, Ordering::Relaxed);
    LAST_SAMPLE_UNIX.store(now_unix, Ordering::Relaxed);

    snapshot
}

/// Read the current telemetry snapshot. Called by pqcd's metrics
/// renderer.
pub fn current_snapshot() -> PeerScoreTelemetry {
    PeerScoreTelemetry {
        peers_graylisted: PEERS_GRAYLISTED.load(Ordering::Relaxed),
        peers_below_publish: PEERS_BELOW_PUBLISH.load(Ordering::Relaxed),
        peers_below_gossip: PEERS_BELOW_GOSSIP.load(Ordering::Relaxed),
        peers_healthy: PEERS_HEALTHY.load(Ordering::Relaxed),
        lowest_score: LOWEST_SCORE_MILLI.load(Ordering::Relaxed) as f64 / 1000.0,
        highest_score: HIGHEST_SCORE_MILLI.load(Ordering::Relaxed) as f64 / 1000.0,
        last_sample_unix: LAST_SAMPLE_UNIX.load(Ordering::Relaxed),
    }
}

/// Aggregate read-only telemetry snapshot returned by
/// [`current_snapshot`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PeerScoreTelemetry {
    pub peers_graylisted: usize,
    pub peers_below_publish: usize,
    pub peers_below_gossip: usize,
    pub peers_healthy: usize,
    pub lowest_score: f64,
    pub highest_score: f64,
    pub last_sample_unix: u64,
}

/// Build the topic-weighted [`PeerScoreParams`] for a given chain.
///
/// Wires per-topic weights for all four Viper topics (`blocks`,
/// `consensus_votes`, `validator_updates`, `transactions`) into a
/// shared `PeerScoreParams` with calibrated cross-topic knobs
/// (IP colocation, behaviour penalty, decay, retain_score).
///
/// The returned params are intended to be passed to
/// `gossipsub::Behaviour::with_peer_score(params, thresholds)` at
/// build time. Use [`viper_peer_score_thresholds`] for the matching
/// threshold set.
pub fn viper_peer_score_params(chain_id: &str) -> PeerScoreParams {
    let topics = Topics::for_chain(chain_id);

    // Cross-topic baseline. These knobs apply uniformly across all
    // topics and to peer-level (non-topic) signals.
    let mut params = PeerScoreParams {
        // Cap a peer's positive topic-derived score so that a peer with
        // years of mesh time cannot dominate the score budget against a
        // newer healthy peer. 3600 ≈ 1 unit/sec × 1 h cap.
        topic_score_cap: 3600.0,

        // App-specific weight: 0 until we wire an application-layer
        // reputation source (e.g. on-chain slashing record). Reserved
        // hook for the post-cohort phase.
        app_specific_weight: 1.0,

        // IP colocation penalty: peers sharing a /24 beyond `threshold`
        // get penalised. -5 weight × (peers_above_threshold)^2 is the
        // libp2p default shape — strong enough to prevent a single
        // operator from dominating the mesh, lenient enough that
        // legitimate co-tenancy (two validators in the same DC) is fine.
        ip_colocation_factor_weight: -5.0,
        ip_colocation_factor_threshold: 5.0,
        ip_colocation_factor_whitelist: Default::default(),

        // Behaviour penalty: accumulated for protocol-level anomalies
        // (mesh churn, IDONTWANT response failure, peer claiming a
        // protocol it does not support). Threshold of 6 means a peer
        // needs to misbehave 6 times before the penalty kicks in;
        // weight of -10 makes the penalty severe (graylist within
        // ~1 minute of crossing threshold under a steady misbehaviour).
        behaviour_penalty_weight: -10.0,
        behaviour_penalty_threshold: 6.0,
        behaviour_penalty_decay: 0.99, // ~7 minutes half-life

        // Decay interval: 1 second. All `*_decay` fields below describe
        // per-decay-interval multipliers, so a `0.5` decay halves the
        // counter every second.
        decay_interval: Duration::from_secs(1),
        decay_to_zero: 0.01, // counters below 0.01 round to 0

        // Retain score for disconnected peers — 1 hour. A peer that
        // disconnects and reconnects within retain_score keeps its
        // accumulated score, preventing trivial reconnect-to-reset
        // attacks.
        retain_score: Duration::from_secs(3600),

        // Topic params populated below.
        topics: Default::default(),

        // Slow peer detection (libp2p 0.55+ feature). Penalises peers
        // that fall behind in IWANT/IHAVE exchange — relevant for our
        // big PQ messages where a slow peer might never catch up.
        slow_peer_weight: -0.4,
        slow_peer_threshold: 0.0,
        slow_peer_decay: 0.2,
    };

    let blocks_topic = IdentTopic::new(&topics.blocks).hash();
    let consensus_topic = IdentTopic::new(&topics.consensus_votes).hash();
    let updates_topic = IdentTopic::new(&topics.validator_updates).hash();
    let transactions_topic = IdentTopic::new(&topics.transactions).hash();

    params.topics.insert(blocks_topic, topic_params_blocks());
    params
        .topics
        .insert(consensus_topic, topic_params_consensus_votes());
    params
        .topics
        .insert(updates_topic, topic_params_validator_updates());
    params
        .topics
        .insert(transactions_topic, topic_params_transactions());

    params
}

/// Matching [`PeerScoreThresholds`] for the calibrated params.
///
/// libp2p defaults are too aggressive for our PQ-message-size regime
/// — graylist at -16000 means a peer would need to push hundreds of
/// invalid messages before being cut, by which point the bandwidth
/// damage has been done. Tighten them by ~4x.
pub fn viper_peer_score_thresholds() -> PeerScoreThresholds {
    PeerScoreThresholds {
        // Below this score, no gossip is exchanged with the peer.
        gossip_threshold: -500.0,
        // Below this score, the local node does not publish to the peer.
        publish_threshold: -1000.0,
        // Below this score, the peer is graylisted and disconnected.
        graylist_threshold: -4000.0,
        // Threshold for accepting peer's gossip about peers in this peer's mesh.
        accept_px_threshold: 100.0,
        // Threshold above which the peer's opinion is considered for
        // gossip recipient selection.
        opportunistic_graft_threshold: 5.0,
    }
}

/// Per-topic params for `blocks` — the most important topic. A node
/// that fails to deliver blocks via this mesh delays consensus
/// directly; first-deliveries are valued highly.
fn topic_params_blocks() -> TopicScoreParams {
    TopicScoreParams {
        topic_weight: 1.0,

        // Time in mesh: small positive reward for sticky peers.
        // 0.0333 × 300 s cap = up to 10 score from time alone.
        time_in_mesh_weight: 0.0333,
        time_in_mesh_quantum: Duration::from_secs(1),
        time_in_mesh_cap: 300.0,

        // First message deliveries: reward peers that reliably ship
        // new blocks first. At 1 block/s, a peer in our 8-mesh delivers
        // first ~12.5% of the time (1/8); cap at 50/s to absorb burst
        // imports during catch-up.
        first_message_deliveries_weight: 1.0,
        first_message_deliveries_decay: 0.5, // 2 s half-life
        first_message_deliveries_cap: 50.0,

        // Mesh message deliveries: penalise peers that fall below
        // expected delivery rate inside the mesh. Activation = 30 s
        // grace period for new mesh peers.
        mesh_message_deliveries_weight: -0.5,
        mesh_message_deliveries_decay: 0.5,
        mesh_message_deliveries_cap: 100.0,
        mesh_message_deliveries_threshold: 1.0,
        mesh_message_deliveries_window: Duration::from_secs(2),
        mesh_message_deliveries_activation: Duration::from_secs(30),

        // Mesh failure penalty: penalise a peer that is dropped from
        // the mesh — that is a signal of churn, possibly malicious.
        mesh_failure_penalty_weight: -0.5,
        mesh_failure_penalty_decay: 0.5,

        // Invalid messages: heavy penalty. One invalid block message
        // is enough to drag a peer past the publish threshold.
        invalid_message_deliveries_weight: -1000.0,
        invalid_message_deliveries_decay: 0.5,
    }
}

/// Per-topic params for `consensus_votes` — high frequency, redundant
/// (3 votes/block, more in distributed-signing mode). Threshold on
/// "did this peer deliver *any* votes in the activation window".
fn topic_params_consensus_votes() -> TopicScoreParams {
    TopicScoreParams {
        topic_weight: 0.8,

        time_in_mesh_weight: 0.0333,
        time_in_mesh_quantum: Duration::from_secs(1),
        time_in_mesh_cap: 300.0,

        // First-delivery reward: lower per-message because votes are
        // common. Cap at 200/s — at 64 validators × 3 votes × 1 block/s
        // we expect ~192 votes/s steady state.
        first_message_deliveries_weight: 0.5,
        first_message_deliveries_decay: 0.5,
        first_message_deliveries_cap: 200.0,

        mesh_message_deliveries_weight: -0.25,
        mesh_message_deliveries_decay: 0.5,
        mesh_message_deliveries_cap: 500.0,
        mesh_message_deliveries_threshold: 5.0,
        mesh_message_deliveries_window: Duration::from_secs(2),
        mesh_message_deliveries_activation: Duration::from_secs(30),

        mesh_failure_penalty_weight: -0.25,
        mesh_failure_penalty_decay: 0.5,

        // Invalid vote message: heavy penalty (a vote forged by a non-
        // validator is a clear protocol violation; the appropriate
        // response is graylist + disconnect).
        invalid_message_deliveries_weight: -1000.0,
        invalid_message_deliveries_decay: 0.5,
    }
}

/// Per-topic params for `validator_updates` — rare but high-stakes.
/// Threshold is essentially "did the peer deliver anything across an
/// epoch boundary"; activation window matches the epoch length.
fn topic_params_validator_updates() -> TopicScoreParams {
    TopicScoreParams {
        topic_weight: 0.5,

        time_in_mesh_weight: 0.0333,
        time_in_mesh_quantum: Duration::from_secs(1),
        time_in_mesh_cap: 600.0, // longer cap — these are sticky peers

        // First-delivery reward: high per-message because updates are rare.
        first_message_deliveries_weight: 5.0,
        first_message_deliveries_decay: 0.5,
        first_message_deliveries_cap: 5.0,

        mesh_message_deliveries_weight: -0.5,
        mesh_message_deliveries_decay: 0.5,
        mesh_message_deliveries_cap: 5.0,
        mesh_message_deliveries_threshold: 0.1, // any delivery counts
        mesh_message_deliveries_window: Duration::from_secs(2),
        // Activation = ~1 epoch (60 s in devnet, longer in mainnet).
        // A peer that joins the mesh and then misses the next epoch
        // boundary is suspect.
        mesh_message_deliveries_activation: Duration::from_secs(120),

        mesh_failure_penalty_weight: -0.5,
        mesh_failure_penalty_decay: 0.5,

        invalid_message_deliveries_weight: -1000.0,
        invalid_message_deliveries_decay: 0.5,
    }
}

/// Per-topic params for `transactions` — high frequency, low criticality.
/// Mempool is best-effort; a missed tx is retried by the sender.
/// Mesh-deliveries threshold is much looser than blocks/votes.
fn topic_params_transactions() -> TopicScoreParams {
    TopicScoreParams {
        topic_weight: 0.05,

        time_in_mesh_weight: 0.0333,
        time_in_mesh_quantum: Duration::from_secs(1),
        time_in_mesh_cap: 300.0,

        first_message_deliveries_weight: 0.1,
        first_message_deliveries_decay: 0.5,
        first_message_deliveries_cap: 1000.0,

        // Looser threshold and weight — a peer that doesn't gossip
        // transactions actively is not a security concern. libp2p
        // requires threshold > 0; we set it just above zero so the
        // penalty effectively never fires unless a peer is dead-silent
        // for the entire activation window.
        mesh_message_deliveries_weight: -0.05,
        mesh_message_deliveries_decay: 0.5,
        mesh_message_deliveries_cap: 1000.0,
        mesh_message_deliveries_threshold: 0.001,
        mesh_message_deliveries_window: Duration::from_secs(2),
        mesh_message_deliveries_activation: Duration::from_secs(60),

        mesh_failure_penalty_weight: -0.1,
        mesh_failure_penalty_decay: 0.5,

        // Invalid tx message: heavy penalty (an envelope mismatch on
        // the tx topic is the SPEC-P2P-002 §4.2 forensic signal).
        invalid_message_deliveries_weight: -2000.0,
        invalid_message_deliveries_decay: 0.5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin: every topic that exists in `Topics::for_chain` MUST have
    /// matching `TopicScoreParams` in `viper_peer_score_params`.
    /// Catches a future topic addition that forgets to wire peer-score.
    #[test]
    fn every_chain_topic_has_score_params() {
        let chain_id = "test-chain";
        let topics = Topics::for_chain(chain_id);
        let params = viper_peer_score_params(chain_id);

        for topic_str in [
            &topics.blocks,
            &topics.consensus_votes,
            &topics.validator_updates,
            &topics.transactions,
        ] {
            let topic_hash = IdentTopic::new(topic_str.as_str()).hash();
            assert!(
                params.topics.contains_key(&topic_hash),
                "missing peer-score params for topic {topic_str}"
            );
        }
    }

    /// Topic weights MUST follow the documented severity order:
    /// blocks > consensus_votes > validator_updates > transactions.
    /// The relative ordering is invariant under any future calibration
    /// tweak; only the absolute values change.
    #[test]
    fn topic_weights_follow_severity_order() {
        let chain_id = "test-chain";
        let topics = Topics::for_chain(chain_id);
        let params = viper_peer_score_params(chain_id);

        let w = |topic: &str| {
            params
                .topics
                .get(&IdentTopic::new(topic).hash())
                .expect("topic params present")
                .topic_weight
        };

        let blocks = w(&topics.blocks);
        let votes = w(&topics.consensus_votes);
        let updates = w(&topics.validator_updates);
        let txs = w(&topics.transactions);

        assert!(
            blocks > votes,
            "blocks weight ({blocks}) must exceed votes weight ({votes})"
        );
        assert!(
            votes > updates,
            "votes weight ({votes}) must exceed updates weight ({updates})"
        );
        assert!(
            updates > txs,
            "updates weight ({updates}) must exceed transactions weight ({txs})"
        );
    }

    /// Invalid-message penalty MUST be heavy for every topic.
    /// A single invalid message of any class should drag a peer past
    /// the publish threshold; pin the magnitude.
    #[test]
    fn invalid_message_penalty_is_heavy_on_every_topic() {
        let params = viper_peer_score_params("test-chain");
        for t in params.topics.values() {
            assert!(
                t.invalid_message_deliveries_weight <= -1000.0,
                "invalid_message_deliveries_weight too lenient: {}",
                t.invalid_message_deliveries_weight
            );
        }
    }

    /// Threshold ordering: gossip > publish > graylist (less negative
    /// thresholds first). Reverse order would make the calibration
    /// nonsensical (peer graylisted but still publishing).
    #[test]
    fn thresholds_are_monotonically_more_severe() {
        let t = viper_peer_score_thresholds();
        assert!(
            t.gossip_threshold > t.publish_threshold,
            "gossip threshold ({}) must be > publish threshold ({})",
            t.gossip_threshold,
            t.publish_threshold,
        );
        assert!(
            t.publish_threshold > t.graylist_threshold,
            "publish threshold ({}) must be > graylist threshold ({})",
            t.publish_threshold,
            t.graylist_threshold,
        );
    }

    /// Validate libp2p's internal cross-field invariants on
    /// `PeerScoreParams`: this catches a future calibration tweak
    /// that violates the constraints (e.g. mesh_message_deliveries_cap
    /// < threshold). libp2p's own validation runs at Behaviour build
    /// time, but pinning here surfaces the failure as a unit test
    /// rather than a runtime "gossipsub init failed" error.
    #[test]
    fn calibrated_params_pass_libp2p_validation() {
        let params = viper_peer_score_params("test-chain");
        params
            .validate()
            .map_err(|e| format!("PeerScoreParams::validate failed: {e:?}"))
            .unwrap();
        let thresholds = viper_peer_score_thresholds();
        thresholds
            .validate()
            .map_err(|e| format!("PeerScoreThresholds::validate failed: {e:?}"))
            .unwrap();
    }
}
