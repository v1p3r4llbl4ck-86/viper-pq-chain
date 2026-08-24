// SPDX-License-Identifier: BUSL-1.1
//! Prometheus metrics rendering for /v1/metrics + /internal/metrics.
//!
//! Extracted from `devnet.rs` 2026-05-10 as the tenth slice of the
//! split. The handler renders the full Prometheus text exposition
//! format from a single locked snapshot of `LiveNodeState` plus the
//! workspace-wide `crate::p2p` and `crate::log_metrics` counters.
//!
//! Two helper functions ride along: a recursive byte-counter for
//! `pqchain_chain_data_bytes` and a rolling-window growth-rate
//! calculator for `pqchain_chain_growth_rate_bytes_per_hour`. Both
//! are private to this module — `handle_metrics` is the only entry
//! point.
//!
//! `use super::*;` keeps every sibling type in scope so the original
//! handler body — which reaches into LiveNodeState fields directly
//! to read counters and gauges — survives the move byte-for-byte.

use super::*;

/// TASK-187 — recursively walk `dir` and sum the byte size of every regular
/// file beneath it. Used by `handle_metrics` to expose
/// `pqchain_chain_data_bytes`. Errors (broken symlinks, files deleted mid-walk
/// concurrently with RocksDB compaction, permission denied) are swallowed —
/// the metric must never crash the scrape; partial undercounts are acceptable.
pub(super) fn chain_data_dir_bytes(dir: &Path) -> u64 {
    fn walk(p: &Path) -> u64 {
        let mut total: u64 = 0;
        let Ok(rd) = std::fs::read_dir(p) else {
            return 0;
        };
        for entry in rd.flatten() {
            let path = entry.path();
            match entry.file_type() {
                Ok(ft) if ft.is_dir() => total = total.saturating_add(walk(&path)),
                Ok(ft) if ft.is_file() => {
                    if let Ok(meta) = entry.metadata() {
                        total = total.saturating_add(meta.len());
                    }
                }
                _ => {}
            }
        }
        total
    }
    walk(dir)
}

/// TASK-187 — push the current `(now, bytes)` sample into `samples`, evict
/// samples older than 65 minutes, and return the implied growth rate in
/// bytes/hour from the oldest still-in-window sample to the newest. Returns
/// `0.0` when the window is too short (< 60 s span) or holds < 2 samples.
pub(super) fn update_chain_size_samples_and_compute_rate(
    samples: &mut VecDeque<(Instant, u64)>,
    now: Instant,
    bytes: u64,
) -> f64 {
    samples.push_back((now, bytes));
    let window = Duration::from_secs(65 * 60);
    while let Some(&(t, _)) = samples.front() {
        if now.saturating_duration_since(t) > window {
            samples.pop_front();
        } else {
            break;
        }
    }
    if samples.len() < 2 {
        return 0.0;
    }
    let (t_old, b_old) = *samples.front().expect("len >= 2");
    let (t_new, b_new) = *samples.back().expect("len >= 2");
    let dt_secs = t_new.saturating_duration_since(t_old).as_secs_f64();
    if dt_secs < 60.0 {
        return 0.0;
    }
    // Use i64 for the byte delta so a shrinking chain (after a prune /
    // compaction) reports a negative rate rather than wrapping under u64.
    let db = (b_new as i64).saturating_sub(b_old as i64);
    (db as f64) * 3600.0 / dt_secs
}

/// Render node metrics in Prometheus text exposition format.
///
/// Called by both the P2P router (`GET /internal/metrics`) and the public API
/// router (`GET /v1/metrics`). All counter and gauge names are stable — a change
/// to any name is a breaking change that must be noted in CHANGELOG.md.
pub(super) async fn handle_metrics(State(state): State<SharedLiveNodeState>) -> impl IntoResponse {
    let mut guard = state.lock().await;
    let height = guard.disk.height();
    let mempool_depth = guard.mempool.len();
    let recovery_source_val: u8 = match guard.recovery_source {
        RecoverySource::FullReplay => 0,
        RecoverySource::TrustedCheckpoint => 1,
    };
    let epoch_length_blocks = guard.config.devnet.epoch_duration;
    let current_epoch = pqc_consensus::epoch::epoch_for_height(height, epoch_length_blocks);

    // TASK-187 — chain disk-size + growth-rate sampling. Read the data dir
    // path before mutating the samples deque so the borrow checker is happy
    // about reborrowing `guard` mutably for the deque update.
    let data_dir = guard.config.data_dir.clone();
    let chain_data_bytes = chain_data_dir_bytes(&data_dir);
    let chain_growth_rate_bytes_per_hour = update_chain_size_samples_and_compute_rate(
        &mut guard.chain_size_samples,
        Instant::now(),
        chain_data_bytes,
    );

    // Render the per-reason rejection breakdown deterministically (sorted by
    // reason label) so scrapers see a stable line ordering. The block is
    // injected into the format string verbatim; it is empty at startup
    // (no rejections yet) which is valid Prometheus exposition.
    let txs_rejected_by_reason_block: String = {
        let mut entries: Vec<(&'static str, u64)> = guard
            .txs_rejected_by_reason
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        entries.sort_by_key(|(reason, _)| *reason);
        let mut s = String::new();
        for (reason, count) in entries {
            use std::fmt::Write as _;
            let _ = writeln!(
                s,
                "pqchain_txs_rejected_by_reason_total{{reason=\"{reason}\"}} {count}"
            );
        }
        // Drop the trailing newline; the surrounding format! adds one.
        if s.ends_with('\n') {
            s.pop();
        }
        s
    };

    let body = format!(
        "\
# HELP pqchain_blocks_produced_total Total blocks produced and committed by this proposer node since startup
# TYPE pqchain_blocks_produced_total counter
pqchain_blocks_produced_total {blocks_produced}
# HELP pqchain_blocks_imported_total Total blocks imported from peers since startup
# TYPE pqchain_blocks_imported_total counter
pqchain_blocks_imported_total {blocks_imported}
# HELP pqchain_txs_admitted_total Total transactions admitted to the mempool since startup
# TYPE pqchain_txs_admitted_total counter
pqchain_txs_admitted_total {txs_admitted}
# HELP pqchain_txs_rejected_total Total transactions rejected at mempool admission since startup
# TYPE pqchain_txs_rejected_total counter
pqchain_txs_rejected_total {txs_rejected}
# HELP pqchain_txs_rejected_by_reason_total Per-reason breakdown of mempool rejections. Reason labels are stable: DUPLICATE, REPLACEMENT_UNDERPRICED, ALREADY_INCLUDED, RATE_LIMITED, VC_CAP_REACHED, SENDER_RATE_LIMITED, plus all TxError-derived codes (ENCODING_ERROR, INVALID_SIGNATURE, INSUFFICIENT_FEE, NONCE_CONFLICT, ...). Sum equals pqchain_txs_rejected_total.
# TYPE pqchain_txs_rejected_by_reason_total counter
{txs_rejected_by_reason_block}
# HELP pqchain_peer_sync_errors_total Total peer sync failures (session errors included) since startup
# TYPE pqchain_peer_sync_errors_total counter
pqchain_peer_sync_errors_total {peer_sync_errors}
# HELP pqchain_chain_height Current chain tip height
# TYPE pqchain_chain_height gauge
pqchain_chain_height {height}
# HELP pqchain_mempool_depth Current number of transactions in the mempool
# TYPE pqchain_mempool_depth gauge
pqchain_mempool_depth {mempool_depth}
# HELP pqchain_node_start_unix_secs UNIX timestamp (seconds) when this node process started
# TYPE pqchain_node_start_unix_secs gauge
pqchain_node_start_unix_secs {node_start_unix_secs}
# HELP pqchain_recovery_source Bootstrap recovery source: 0=FullReplay 1=TrustedCheckpoint
# TYPE pqchain_recovery_source gauge
pqchain_recovery_source {recovery_source_val}
# HELP pqchain_current_epoch Current epoch number (height / epoch_length_blocks)
# TYPE pqchain_current_epoch gauge
pqchain_current_epoch {current_epoch}
# HELP pqchain_epoch_length_blocks Number of blocks per epoch (ADR-042)
# TYPE pqchain_epoch_length_blocks gauge
pqchain_epoch_length_blocks {epoch_length_blocks}
# HELP pqchain_p2p_peers_connected libp2p peers currently connected (Phase 8 M1). Zero until libp2p.enable=true.
# TYPE pqchain_p2p_peers_connected gauge
pqchain_p2p_peers_connected {p2p_peers_connected}
# HELP pqchain_p2p_tx_rejected_unbound_peer_total Transaction gossip messages dropped because the publisher PeerId was not in validator_peer_ids (SPEC-P2P-002 §4.4). Stays at 0 when the allow-list is empty.
# TYPE pqchain_p2p_tx_rejected_unbound_peer_total counter
pqchain_p2p_tx_rejected_unbound_peer_total {p2p_tx_rejected_unbound_peer_total}
# HELP pqchain_p2p_block_gap_total Inbound Block gossip envelopes whose height exceeded local tip by more than 1 (TASK-135 step 11 height-gap detection). Non-zero means the node missed blocks and will need block-fetch catch-up (step 12) to close the gap.
# TYPE pqchain_p2p_block_gap_total counter
pqchain_p2p_block_gap_total {p2p_block_gap_total}
# HELP pqchain_p2p_block_fetch_requests_received_total Inbound /viper/<chain>/block-fetch/1.0.0 requests served by this node (TASK-135 step 12b).
# TYPE pqchain_p2p_block_fetch_requests_received_total counter
pqchain_p2p_block_fetch_requests_received_total {p2p_bf_requests_received}
# HELP pqchain_p2p_block_fetch_requests_sent_total Outbound block-fetch requests dispatched by this node to close height gaps (TASK-135 step 12b).
# TYPE pqchain_p2p_block_fetch_requests_sent_total counter
pqchain_p2p_block_fetch_requests_sent_total {p2p_bf_requests_sent}
# HELP pqchain_p2p_block_fetch_responses_received_total Inbound block-fetch responses decoded by this node (TASK-135 step 12b; ingest to chain store deferred to step 13).
# TYPE pqchain_p2p_block_fetch_responses_received_total counter
pqchain_p2p_block_fetch_responses_received_total {p2p_bf_responses_received}
# HELP pqchain_p2p_block_fetch_failures_total Outbound block-fetch failures (timeout, peer disconnected mid-request, unsupported protocol). TASK-135 step 12b.
# TYPE pqchain_p2p_block_fetch_failures_total counter
pqchain_p2p_block_fetch_failures_total {p2p_bf_failures}
# HELP pqchain_p2p_blocks_imported_total Blocks imported into the chain store via a libp2p-sourced path (gossip Next + block-fetch response). TASK-135 step 13. Disjoint from pqchain_blocks_imported_total which aggregates across all ingest paths.
# TYPE pqchain_p2p_blocks_imported_total counter
pqchain_p2p_blocks_imported_total {p2p_blocks_imported}
# HELP pqchain_p2p_snapshot_requests_received_total Inbound /viper/<chain>/snapshot/1.0.0 requests served by this node. Phase 8 M1 cold-start.
# TYPE pqchain_p2p_snapshot_requests_received_total counter
pqchain_p2p_snapshot_requests_received_total {p2p_sn_requests_received}
# HELP pqchain_p2p_snapshot_requests_sent_total Outbound snapshot requests dispatched. Stays at 0 until the cold-start consumer wiring lands.
# TYPE pqchain_p2p_snapshot_requests_sent_total counter
pqchain_p2p_snapshot_requests_sent_total {p2p_sn_requests_sent}
# HELP pqchain_p2p_snapshot_responses_received_total Inbound snapshot responses observed.
# TYPE pqchain_p2p_snapshot_responses_received_total counter
pqchain_p2p_snapshot_responses_received_total {p2p_sn_responses_received}
# HELP pqchain_p2p_snapshot_failures_total Outbound snapshot-fetch failures (timeout, peer disconnect, unsupported protocol).
# TYPE pqchain_p2p_snapshot_failures_total counter
pqchain_p2p_snapshot_failures_total {p2p_sn_failures}
# HELP pqchain_p2p_envelope_mismatch_total GossipSub envelopes dropped because msg_type disagreed with the topic they arrived on (SPEC-P2P-002 §4.2 defense-in-depth; TASK-179).
# TYPE pqchain_p2p_envelope_mismatch_total counter
pqchain_p2p_envelope_mismatch_total {p2p_envelope_mismatch}
# HELP pqchain_p2p_light_client_attestations_total Inbound LightClientAttestation envelopes accepted on the gossip topic (SPEC-LIGHT-CLIENT-001 §5.2). Pre-aggregation (single-signer) and aggregated (>= 11) envelopes both increment this counter at observation-mode landing; the SDK milestone splits them per `sigs.len()`. Malformed envelopes are dropped under pqchain_p2p_envelope_mismatch_total.
# TYPE pqchain_p2p_light_client_attestations_total counter
pqchain_p2p_light_client_attestations_total {p2p_light_client_attestations}
# HELP pqchain_chain_data_bytes Total bytes consumed on disk by the chain data directory (recursive — RocksDB SSTs + WAL + checkpoint dumps + any legacy flat files). Sampled at scrape time. Use this to alert on disk pressure (TASK-187, KNOWN-ISSUES R-10) and to size the operator prune budget.
# TYPE pqchain_chain_data_bytes gauge
pqchain_chain_data_bytes {chain_data_bytes}
# HELP pqchain_chain_growth_rate_bytes_per_hour Rolling growth rate of pqchain_chain_data_bytes computed from the oldest still-in-window sample (≤ 65 min) to the newest. Equivalent to rate(pqchain_chain_data_bytes[1h]) but computed in-process so a fresh-start node has a value within ~1 min of the second scrape; returns 0 until the deque holds ≥ 2 samples ≥ 60 s apart. Negative values mean a prune / compaction shrunk the chain since the last sample.
# TYPE pqchain_chain_growth_rate_bytes_per_hour gauge
pqchain_chain_growth_rate_bytes_per_hour {chain_growth_rate_bytes_per_hour:.2}
# HELP pqchain_log_events_total Total log events emitted, partitioned by tracing level. Incremented by the LogMetricsLayer (crates/pqcd/src/log_metrics.rs); reflects events that survived the EnvFilter (i.e., what was actually written to journald). Use rate(pqchain_log_events_total{{level=\"error\"}}[5m]) to alert on error spikes.
# TYPE pqchain_log_events_total counter
pqchain_log_events_total{{level=\"error\"}} {log_events_error}
pqchain_log_events_total{{level=\"warn\"}} {log_events_warn}
pqchain_log_events_total{{level=\"info\"}} {log_events_info}
pqchain_log_events_total{{level=\"debug\"}} {log_events_debug}
pqchain_log_events_total{{level=\"trace\"}} {log_events_trace}
# HELP pqchain_p2p_gossip_peers_graylisted Connected peers whose gossipsub peer-score is below graylist_threshold (-4000). These peers are marked for disconnection. TASK-222.
# TYPE pqchain_p2p_gossip_peers_graylisted gauge
pqchain_p2p_gossip_peers_graylisted {gossip_peers_graylisted}
# HELP pqchain_p2p_gossip_peers_below_publish Connected peers whose score is between graylist (-4000) and publish (-1000) thresholds — connected but the local node will not publish to them. TASK-222.
# TYPE pqchain_p2p_gossip_peers_below_publish gauge
pqchain_p2p_gossip_peers_below_publish {gossip_peers_below_publish}
# HELP pqchain_p2p_gossip_peers_below_gossip Connected peers whose score is between publish (-1000) and gossip (-500) thresholds — local node publishes but does not exchange gossip control messages. TASK-222.
# TYPE pqchain_p2p_gossip_peers_below_gossip gauge
pqchain_p2p_gossip_peers_below_gossip {gossip_peers_below_gossip}
# HELP pqchain_p2p_gossip_peers_healthy Connected peers above all peer-score thresholds — fully healthy. TASK-222.
# TYPE pqchain_p2p_gossip_peers_healthy gauge
pqchain_p2p_gossip_peers_healthy {gossip_peers_healthy}
# HELP pqchain_p2p_gossip_peer_score_lowest Lowest gossipsub peer-score across connected peers (0 when no peers). Negative values indicate degraded peers. TASK-222.
# TYPE pqchain_p2p_gossip_peer_score_lowest gauge
pqchain_p2p_gossip_peer_score_lowest {gossip_peer_score_lowest:.3}
# HELP pqchain_p2p_gossip_peer_score_highest Highest gossipsub peer-score across connected peers. TASK-222.
# TYPE pqchain_p2p_gossip_peer_score_highest gauge
pqchain_p2p_gossip_peer_score_highest {gossip_peer_score_highest:.3}
# HELP pqchain_p2p_gossip_peer_score_last_sample_unix UNIX seconds of the last peer-score sample. Stays at 0 until the first sample fires (~30 s after libp2p starts). Operators alert when (now - last_sample) > 60 s = sampler is wedged. TASK-222.
# TYPE pqchain_p2p_gossip_peer_score_last_sample_unix gauge
pqchain_p2p_gossip_peer_score_last_sample_unix {gossip_peer_score_last_sample_unix}
",
        blocks_produced = guard.blocks_produced,
        blocks_imported = guard.blocks_imported,
        txs_admitted = guard.txs_admitted,
        txs_rejected = guard.txs_rejected,
        txs_rejected_by_reason_block = txs_rejected_by_reason_block,
        peer_sync_errors = guard.peer_sync_errors,
        height = height,
        mempool_depth = mempool_depth,
        node_start_unix_secs = guard.node_start_unix_secs,
        recovery_source_val = recovery_source_val,
        current_epoch = current_epoch,
        epoch_length_blocks = epoch_length_blocks,
        p2p_peers_connected = crate::p2p::peers_connected(),
        p2p_tx_rejected_unbound_peer_total = crate::p2p::tx_rejected_unbound_peer_total(),
        p2p_block_gap_total = crate::p2p::block_gap_total(),
        p2p_bf_requests_received = crate::p2p::block_fetch_requests_received_total(),
        p2p_bf_requests_sent = crate::p2p::block_fetch_requests_sent_total(),
        p2p_bf_responses_received = crate::p2p::block_fetch_responses_received_total(),
        p2p_bf_failures = crate::p2p::block_fetch_failures_total(),
        p2p_blocks_imported = crate::p2p::blocks_imported_total(),
        p2p_sn_requests_received = crate::p2p::snapshot_requests_received_total(),
        p2p_sn_requests_sent = crate::p2p::snapshot_requests_sent_total(),
        p2p_sn_responses_received = crate::p2p::snapshot_responses_received_total(),
        p2p_sn_failures = crate::p2p::snapshot_failures_total(),
        p2p_envelope_mismatch = crate::p2p::envelope_mismatch_total(),
        p2p_light_client_attestations = crate::p2p::light_client_attestations_total(),
        chain_data_bytes = chain_data_bytes,
        chain_growth_rate_bytes_per_hour = chain_growth_rate_bytes_per_hour,
        log_events_error = crate::log_metrics::events_total(tracing::Level::ERROR),
        log_events_warn = crate::log_metrics::events_total(tracing::Level::WARN),
        log_events_info = crate::log_metrics::events_total(tracing::Level::INFO),
        log_events_debug = crate::log_metrics::events_total(tracing::Level::DEBUG),
        log_events_trace = crate::log_metrics::events_total(tracing::Level::TRACE),
        gossip_peers_graylisted = crate::p2p::gossip_telemetry().peers_graylisted,
        gossip_peers_below_publish = crate::p2p::gossip_telemetry().peers_below_publish,
        gossip_peers_below_gossip = crate::p2p::gossip_telemetry().peers_below_gossip,
        gossip_peers_healthy = crate::p2p::gossip_telemetry().peers_healthy,
        gossip_peer_score_lowest = crate::p2p::gossip_telemetry().lowest_score,
        gossip_peer_score_highest = crate::p2p::gossip_telemetry().highest_score,
        gossip_peer_score_last_sample_unix = crate::p2p::gossip_telemetry().last_sample_unix,
    );

    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

#[cfg(test)]
mod chain_size_metric_tests;
