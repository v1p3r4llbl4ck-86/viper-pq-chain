// SPDX-License-Identifier: BUSL-1.1
//! Runtime event handlers — outbound gossip emission + inbound dispatch.
//!
//! Extracted from `devnet.rs` 2026-05-10 as the seventh slice of the
//! M-effort split (CONCERNS.md "[MEDIUM] crates/pqcd/src/devnet.rs is
//! 7,247 lines"). The 22 functions here are everything that fires off
//! the producer/consensus tick (`emit_*`) plus everything that consumes
//! libp2p inbound messages (`handle_inbound_*`, `block_inbound_loop`,
//! `stale_tip_recovery_loop`, `dispatch_orphan_parent_fetch`).
//!
//! `use super::*;` pulls every sibling helper, type, and constant from
//! the parent module into scope — same pattern that worked cleanly for
//! `consensus_loops.rs`. Rust's "private items are visible to descendant
//! modules" rule means no sibling fn or struct field has to widen its
//! visibility for this extraction.
//!
//! Entry points are `pub(super)`:
//!   - emit_block_gossip, rotate_kem_if_epoch_boundary,
//!     emit_archival_submissions_if_epoch_boundary,
//!     emit_light_client_attestation_if_committee_member,
//!     emit_block_proposal_gossip_if_distributed,
//!     emit_precommit_votes — called from producer_loop / consensus_loop
//!   - block_inbound_loop, stale_tip_recovery_loop — spawned from
//!     `start_from_config_path`
//!   - The handle_inbound_* family — dispatched from block_inbound_loop
//!     by libp2p message type
//!   - hex_decode_32, dispatch_orphan_parent_fetch — internal helpers
//!     reused across the inbound family
//!
//! See the parent module's "Panic strategy" doc for why `expect()` is
//! the correct failure mode in the keystore + state-store paths.

use super::*;

/// Emit a freshly-persisted block over libp2p gossip (TASK-135 step 1).
///
/// Observation-mode during M1: the block is published on the `Block`
/// topic as the canonical CBOR-encoded `StoredBlock` produced by
/// `DiskChainStore::export_block_bytes`. Remote nodes receive and decode
/// the envelope but do not yet feed it into their chain — block ingest
/// (height-gap detection + request-response fetch) lands in the next
/// TASK-135 steps.
///
/// The lock is held just long enough to clone the SwarmHandle, read
/// `chain_id_hex`, and export the block bytes from the in-memory chain.
/// Encoding runs under the lock because `export_block_bytes` borrows the
/// ChainStore — but at devnet-2 block sizes (<1 MB of CBOR even with
/// full ML-DSA-65 commit quorums) this is microseconds of CPU. The
/// publish itself runs after the lock is released so the next producer
/// iteration is never blocked by gossip backpressure.
///
/// When libp2p is disabled, `publish_if_enabled` is a no-op and the
/// encode is skipped entirely (we short-circuit on `handle.is_none()`).
pub(super) async fn emit_block_gossip(state: &SharedLiveNodeState, height: u64) {
    let emit_inputs: Option<(Option<pqc_p2p::SwarmHandle>, String, Vec<u8>)> = {
        let guard = state.lock().await;
        // Skip all work — including the CBOR encode — when libp2p is off.
        if guard.p2p_handle.is_none() {
            None
        } else {
            match guard.disk.export_block_bytes(height) {
                Ok(Some(bytes)) => Some((
                    guard.p2p_handle.clone(),
                    guard.config.chain_id_hex.clone(),
                    bytes,
                )),
                Ok(None) => {
                    tracing::warn!(
                        height,
                        "libp2p: block missing from chain store for gossip emit (race?)"
                    );
                    None
                }
                Err(e) => {
                    tracing::warn!(
                        height,
                        error = %e,
                        "libp2p: failed to encode block for gossip emit"
                    );
                    None
                }
            }
        }
    };
    if let Some((handle, chain_id, block_bytes)) = emit_inputs {
        let envelope = crate::p2p::block_envelope(&chain_id, block_bytes);
        crate::p2p::publish_if_enabled(handle.as_ref(), envelope).await;
    }
}

/// Emit archival-overlay submissions at the close of each epoch — TASK-163 /
/// M4.4, SPEC-ARCHIVAL-001 §4.6.
///
/// If `block_height` is an epoch boundary:
///   1. Compute the closed epoch's `ArchivalEpochSummary` (epoch_root +
///      block-height range) from the chain store.
///   2. Enumerate this node's eligible signers: Active validators for whom
///      the on-chain `archival_signer_set` admits membership AND for whom
///      the local keystore holds both a consensus seed and an SLH archival
///      secret key. Non-eligible validators are silently skipped.
///   3. Off-runtime (`spawn_blocking`): sign the §4.5 preimage for each
///      candidate and build a signed `ArchivalRecordSubmit` envelope.
///   4. Inject each encoded tx via the normal mempool path.
///
/// Every failure is non-fatal. The archival overlay runs one level above
/// consensus finality (SPEC §4.7) — a failed submission delays archival
/// for the epoch but MUST NOT halt block production. Errors are logged
/// at `warn` and do not propagate.
/// Rotate the long-term ML-KEM identity-keypair when `block_height` is an
/// epoch boundary — `PHASE-4-KEY-ROTATION-RESEARCH.md` §2.4 / Gap B fix.
///
/// At every boundary, a fresh keypair is derived for the new epoch using
/// the same `(node_id, salt, epoch_number)` formula as the startup path.
/// The rotation is atomic: the prior `current` slides to `previous` (with
/// a one-epoch retire window), the new derivation becomes `current`, and
/// any peer that fetches `kem_pk` after this returns sees the new key.
///
/// No-op off-boundary, plus an early-out at height 0 since the genesis
/// path is treated as bootstrap (no derived keypair to rotate; the
/// startup path already populated `current` for epoch 0).
///
/// Failure mode: there is none — derivation is deterministic and total
/// over `(node_id, salt, epoch_number)`. The lock window is the time of
/// one ML-KEM keygen (≈100 µs on x86_64) plus a `Vec` mutation; this
/// fits comfortably inside the per-block tick budget.
pub(super) async fn rotate_kem_if_epoch_boundary(state: &SharedLiveNodeState, block_height: u64) {
    let mut guard = state.lock().await;
    let epoch_duration = guard.config.devnet.epoch_duration;
    if !pqc_consensus::is_epoch_boundary(block_height, epoch_duration) {
        return;
    }
    let new_epoch_number = pqc_consensus::epoch::epoch_for_height(block_height, epoch_duration);
    if new_epoch_number == guard.kem_keyset.current.epoch_number {
        // Defence-in-depth — should not fire because is_epoch_boundary
        // guarantees a new epoch has started, but if the startup path
        // pre-derived the same epoch we are now closing into (e.g. a
        // recovery exactly at a boundary), skip the redundant rotate.
        return;
    }

    let node_id = guard.config.node_id.clone();
    let salt = guard.kem_secret_salt;
    let new_material = derive_kem_keypair(&node_id, salt.as_ref(), new_epoch_number);
    let prior_epoch = guard.kem_keyset.current.epoch_number;
    guard
        .kem_keyset
        .rotate_to(new_material, block_height, epoch_duration);
    tracing::info!(
        block_height,
        prior_epoch,
        new_epoch = new_epoch_number,
        salted = salt.is_some(),
        "ML-KEM identity keypair rotated at epoch boundary (Gap B)"
    );
}

pub(super) async fn emit_archival_submissions_if_epoch_boundary(
    state: &SharedLiveNodeState,
    block_height: u64,
) {
    // Phase 1: under the state lock, decide whether this height closes an
    // epoch and, if so, collect the submission candidates for this node.
    let (summary, chain_id, candidates) = {
        let guard = state.lock().await;
        let epoch_duration = guard.config.devnet.epoch_duration;
        if !pqc_consensus::is_epoch_boundary(block_height, epoch_duration) {
            return;
        }
        let Some(summary) =
            pqc_consensus::summarize_closed_epoch(guard.disk.chain(), block_height, epoch_duration)
        else {
            // Bootstrap: block 0 missing → first epoch has no record. This
            // is expected exactly once (at the close of epoch 0) and is a
            // no-op, not a failure.
            tracing::debug!(
                block_height,
                epoch_duration,
                "archival: epoch summary unavailable (bootstrap or missing block), skipping"
            );
            return;
        };
        let chain_id = guard.config.chain_id_hex.clone();
        let keystore_guard = guard.keystore.read().expect("keystore RwLock poisoned");
        let candidates =
            crate::archival::collect_submission_candidates(&guard.state, &keystore_guard);
        drop(keystore_guard);
        (summary, chain_id, candidates)
    };

    if candidates.is_empty() {
        tracing::debug!(
            epoch = summary.epoch_number,
            "archival: no eligible signers on this node for the closed epoch"
        );
        return;
    }

    let n_candidates = candidates.len();
    tracing::info!(
        epoch = summary.epoch_number,
        first_height = summary.first_height,
        last_height = summary.last_height,
        epoch_root = %hex::encode(summary.epoch_root),
        candidates = n_candidates,
        "archival: epoch boundary, building submissions"
    );

    // Phase 2: off-runtime signing + tx assembly.
    let chain_id_bytes = chain_id.clone().into_bytes();
    let candidates_owned = candidates.clone();
    let summary_owned = summary.clone();
    let submissions: Vec<Vec<u8>> = match tokio::task::spawn_blocking(move || {
        crate::archival::build_submissions(&chain_id_bytes, &candidates_owned, &summary_owned)
    })
    .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                error = %e,
                epoch = summary.epoch_number,
                "archival: signing task panicked (non-fatal, epoch left to retry on next signer)"
            );
            return;
        }
    };

    // Phase 3: inject each raw tx. Failures are expected when the quorum
    // races (first-writer-wins) or a sibling signer's tx has already landed.
    for bytes in submissions {
        let mut guard = state.lock().await;

        // Reuse the same admission pipeline as `DevnetNodeHandle::inject_tx`
        // without the per-sender budget check — archival submissions are
        // operator-initiated and should always get pool room.
        let verifier = guard.verifier.clone();
        let result = {
            let LiveNodeState {
                state: ref mut state_store,
                ref mut mempool,
                ref fee_params,
                ..
            } = *guard;
            pqc_mempool::admission::try_admit(
                mempool,
                bytes,
                state_store,
                verifier.as_ref(),
                fee_params,
            )
        };
        match result {
            Ok(_) => {
                tracing::info!(
                    epoch = summary.epoch_number,
                    "archival: submission admitted to mempool"
                );
            }
            Err(e) => {
                tracing::debug!(
                    epoch = summary.epoch_number,
                    error = %e,
                    "archival: submission rejected by mempool (likely dup-sig or first-writer-wins race)"
                );
            }
        }
    }
}

/// SPEC-LIGHT-CLIENT-001 §4 — emit a per-member compact-header
/// attestation for the just-finalized block at `height`, gated on this
/// node holding signing material for at least one of the current
/// epoch's sync-committee members.
///
/// Symmetrical with [`emit_block_gossip`] / [`emit_precommit_votes`]:
/// libp2p-off path is a no-op; the helper logs at warn on any error
/// path and never propagates an error that could halt block
/// production.
///
/// The committee for the epoch containing `height` is computed from
/// the same active-validator set + state_root the apply path produces
/// after persisting the block. For the launch state (3 validators),
/// the §7.2 total-set fallback returns all three indices in
/// stake-sorted order, so a node holding any of the three commit seeds
/// emits one attestation per held seed. Once the active set crosses
/// `SYNC_COMMITTEE_SIZE`, the §2.2 weighted shuffle gates the emit to
/// nodes whose held seed maps to a sampled committee index.
///
/// Pre-aggregation single-signature form per §4.3: each `sigs` vec
/// carries exactly one `(committee_index, signature)` pair. Aggregation
/// of ≥ 11 of these into a quorum envelope is performed by the
/// aggregator role (§4.2) — landing with the verifier SDK milestone.
pub(super) async fn emit_light_client_attestation_if_committee_member(
    state: &SharedLiveNodeState,
    height: u64,
) {
    use pqc_consensus::light_client::{select_committee, CompactHeader, LightClientAttestation};

    // Phase 1 (under the state lock): collect inputs + filter to the
    // local node's committee-member seeds. Heavy work (signing) runs
    // off-runtime in Phase 2.
    struct LocalSigner {
        committee_index: u8,
        sig_alg_id: pqc_crypto::AlgId,
        seed: [u8; 32],
    }
    let inputs: Option<(
        Option<pqc_p2p::SwarmHandle>,
        String,
        CompactHeader,
        Vec<LocalSigner>,
    )> = {
        let guard = state.lock().await;
        if guard.p2p_handle.is_none() {
            None
        } else {
            let chain_id = guard.config.chain_id_hex.clone();
            let epoch_duration = guard.config.devnet.epoch_duration;
            let epoch = pqc_consensus::epoch::epoch_for_height(height, epoch_duration);

            // Build the compact header from the just-persisted block.
            let stored = match guard.disk.chain().get_stored_block_by_height(height) {
                Some(b) => b.clone(),
                None => {
                    tracing::warn!(
                        height,
                        "light-client emit: block missing from chain store (race?)"
                    );
                    return;
                }
            };
            let header = stored.block.header;
            let compact = CompactHeader {
                header_version: header.header_version,
                height: header.height,
                prev_hash: header.prev_hash.0,
                state_root: header.state_root.0,
                tx_root: header.tx_root.0,
                extension_root: header.extension_root,
                epoch,
            };

            // Active set sorted by address (the `select_committee`
            // input contract). `state.active_validators()` already
            // sorts by operator address.
            let active = guard.state.active_validators();
            let validators_vec: Vec<([u8; 32], u128)> =
                active.iter().map(|v| (v.operator.0, v.self_bond)).collect();
            let committee = select_committee(&header.state_root.0, epoch, &validators_vec);

            // Filter to indices for which the local keystore holds a
            // signing seed.
            let keystore = guard.keystore.read().expect("keystore RwLock poisoned");
            let signers: Vec<LocalSigner> = committee
                .iter()
                .enumerate()
                .filter_map(|(committee_idx, &orig_idx)| {
                    let addr = validators_vec.get(orig_idx)?.0;
                    keystore.get(&addr).map(|entry| LocalSigner {
                        committee_index: committee_idx as u8,
                        sig_alg_id: entry.sig_alg_id,
                        seed: entry.commit_seed,
                    })
                })
                .collect();
            drop(keystore);

            if signers.is_empty() {
                None
            } else {
                Some((guard.p2p_handle.clone(), chain_id, compact, signers))
            }
        }
    };
    let Some((handle, chain_id, compact, signers)) = inputs else {
        return;
    };

    // Phase 2: ML-DSA signing on a blocking thread.
    let attestations: Vec<LightClientAttestation> =
        match tokio::task::spawn_blocking(move || -> Result<Vec<LightClientAttestation>> {
            let fork_digest = *pqc_types::ForkDigest::viper_research_1().as_bytes();
            let preimage = compact.preimage(fork_digest);
            let header_root = compact.header_root(fork_digest);
            let mut atts = Vec::with_capacity(signers.len());
            for signer in signers {
                let sig =
                    pqc_crypto::ml_dsa_sign_with_seed(signer.sig_alg_id, &signer.seed, &preimage)
                        .context("light-client ML-DSA signing failed")?;
                atts.push(LightClientAttestation {
                    epoch: compact.epoch,
                    header_root,
                    sigs: vec![(signer.committee_index, sig)],
                    agg_proof: None,
                });
            }
            Ok(atts)
        })
        .await
        {
            Ok(Ok(atts)) => atts,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "light-client attestation signing failed");
                return;
            }
            Err(e) => {
                tracing::warn!(error = %e, "light-client signing task panicked");
                return;
            }
        };

    // Phase 3: publish each attestation. Single-signer envelopes are
    // intentional: aggregator role (§4.2) collects ≥ 11 over the topic
    // and re-publishes the aggregated form (verifier SDK milestone).
    for att in attestations {
        let bytes = att.encode();
        let envelope = crate::p2p::light_client_attestation_envelope(&chain_id, bytes);
        crate::p2p::publish_if_enabled(handle.as_ref(), envelope).await;
    }
}

/// SPEC-LIGHT-CLIENT-001 §5.2 receive-side handler — log + count for
/// now (the verifier SDK milestone adds quorum aggregation, slashing-
/// rule wiring for slots `0x0005` / `0x0006`, and persistence).
pub(super) async fn handle_inbound_light_client_attestation(
    _state: &SharedLiveNodeState,
    source: Option<pqc_p2p::PeerId>,
    attestation: pqc_consensus::light_client::LightClientAttestation,
) {
    tracing::info!(
        epoch = attestation.epoch,
        sig_count = attestation.sigs.len(),
        header_root = %hex::encode(attestation.header_root),
        source = ?source,
        "light-client attestation received (observation mode — \
         aggregation + slashing land with verifier SDK)"
    );
}

/// TASK-135 steps 11+12b — Single consumer loop for every inbound libp2p
/// event that needs chain-store access.
///
/// Drains `inbound_rx` (fed by `route_event` in `crate::p2p`) and
/// dispatches on the [`crate::p2p::InboundP2pEvent`] variant:
///  * `Block` → [`handle_inbound_block`] (step 11 height-gap classifier)
///  * `BlockFetchRequest` → [`handle_inbound_block_fetch_request`]
///    (step 12b — read requested heights, reply via SwarmHandle)
///  * `BlockFetchResponse` → [`handle_inbound_block_fetch_response`]
///    (step 12b — observation-mode decode; ingest lands in step 13)
///
/// Result is `Ok(())` by design — handler failures must never crash
/// the node. Log-only during observation mode.
pub(super) async fn block_inbound_loop(
    state: SharedLiveNodeState,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    mut inbound_rx: tokio::sync::mpsc::UnboundedReceiver<crate::p2p::InboundP2pEvent>,
) -> Result<()> {
    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    return Ok(());
                }
            }
            maybe_inbound = inbound_rx.recv() => {
                match maybe_inbound {
                    Some(crate::p2p::InboundP2pEvent::Block(inbound)) => {
                        handle_inbound_block(&state, *inbound).await;
                    }
                    Some(crate::p2p::InboundP2pEvent::BlockFetchRequest {
                        peer,
                        request_id,
                        request,
                    }) => {
                        handle_inbound_block_fetch_request(&state, peer, request_id, request).await;
                    }
                    Some(crate::p2p::InboundP2pEvent::BlockFetchResponse { peer, response }) => {
                        handle_inbound_block_fetch_response(&state, peer, response).await;
                    }
                    Some(crate::p2p::InboundP2pEvent::SnapshotFetchRequest {
                        peer,
                        request_id,
                        request,
                    }) => {
                        handle_inbound_snapshot_request(&state, peer, request_id, request).await;
                    }
                    Some(crate::p2p::InboundP2pEvent::SnapshotFetchResponse { peer, response }) => {
                        handle_inbound_snapshot_response(&state, peer, response).await;
                    }
                    Some(crate::p2p::InboundP2pEvent::Precommit { source, vote }) => {
                        handle_inbound_precommit(&state, source, vote).await;
                    }
                    Some(crate::p2p::InboundP2pEvent::Transaction { source, raw_tx }) => {
                        handle_inbound_transaction(&state, source, raw_tx).await;
                    }
                    Some(crate::p2p::InboundP2pEvent::BlockFetchByHashRequest {
                        peer,
                        request_id,
                        request,
                    }) => {
                        handle_inbound_block_fetch_by_hash_request(
                            &state,
                            peer,
                            request_id,
                            request,
                        )
                        .await;
                    }
                    Some(crate::p2p::InboundP2pEvent::BlockFetchByHashResponse {
                        peer,
                        response,
                    }) => {
                        handle_inbound_block_fetch_by_hash_response(&state, peer, response)
                            .await;
                    }
                    Some(crate::p2p::InboundP2pEvent::LightClientAttestation {
                        source,
                        attestation,
                    }) => {
                        handle_inbound_light_client_attestation(&state, source, attestation).await;
                    }
                    None => return Ok(()),
                }
            }
        }
    }
}

/// Stale-tip self-heal — closes the gossip-driven catch-up gap that
/// SPEC-P2P-002 §block-fetch leaves open under N=3 quorum=3 (no BFT).
///
/// ## The deadlock this fixes
///
/// The standard catch-up path is gossip-driven: a node N blocks behind
/// imports the next block as soon as it sees an inbound `Block` envelope
/// at height > local_tip + 1, which triggers `BlockFetchRequest` for the
/// missing range. That works *while the chain keeps producing*, because
/// every newly-finalized block re-sets the gossip ticker.
///
/// With N=3 quorum=3 (zero Byzantine fault tolerance), a *single* lagging
/// node halts production: if the elected proposer for `tip+1` is the
/// lagging node itself, no one can sign the next block, no gossip flows,
/// no gap is detected, and the lagging node never asks for the missing
/// blocks — classic deadlock. Observed live 2026-04-27 after a rolling
/// restart left follower-a one block behind producer-1 / follower-b.
///
/// ## What this loop does
///
/// Every `STALE_TIP_PROBE_INTERVAL` it samples the local chain height.
/// When the height has not advanced for `STALE_TIP_THRESHOLD` AND there
/// is at least one connected peer, it dispatches a single
/// `BlockFetchRequest{from=local_tip+1,to=local_tip+1}` to one of the
/// connected peers — exactly what the gossip path would have done if a
/// gap had been observed. The response flows through the existing
/// inbound handler and ingests the missing block; the chain then makes
/// progress on its own.
///
/// ## Why this is safe
///
/// * Single-block requests only — never larger than `MAX_BLOCKS_PER_REQUEST`.
/// * Triggered ONLY when `local_tip` is stale; under normal operation
///   the height ticks every block_time_ms and this loop's `last_seen`
///   is constantly refreshed → no fetch is ever sent.
/// * Re-uses the same `block-fetch/1.0.0` protocol used by gap-detection;
///   no new wire surface, no new validation path.
/// * No effect when libp2p is disabled (`p2p_handle = None`) — caller
///   spawns this loop only when libp2p is on.
///
/// ## Interaction with N≥4 BFT (future)
///
/// Once the validator set grows past N=3 with proper f=floor((N-1)/3)
/// quorum, a single lagging node can no longer halt production: the
/// remaining 2f+1 quorum keeps producing blocks, gossip flows, the
/// gap-detection path catches up automatically. This loop becomes a
/// belt-and-braces safety net rather than a primary recovery mechanism.
pub(super) async fn stale_tip_recovery_loop(
    state: SharedLiveNodeState,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    use std::time::{Duration, Instant};

    /// How often to sample the tip and check for stalls.
    const STALE_TIP_PROBE_INTERVAL: Duration = Duration::from_secs(10);
    /// Tip must be stuck this long before we issue a recovery fetch.
    /// Comfortably above block_time_ms × max_round_timeout.
    const STALE_TIP_THRESHOLD: Duration = Duration::from_secs(30);
    /// Cool-down between successive recovery fetches against the same
    /// peer for the same height. Avoids bombarding a peer if the
    /// response is in flight or got lost.
    const STALE_TIP_FETCH_COOLDOWN: Duration = Duration::from_secs(15);

    // Snapshot we compare against on each tick.
    let (mut last_height, mut last_seen) = {
        let guard = state.lock().await;
        (guard.disk.height(), Instant::now())
    };
    let mut last_fetch_at: Option<Instant> = None;
    let mut last_fetch_height: Option<u64> = None;
    // Rotation cursor over the connected-peer set. Different peers may
    // hold different tail-tips (the live-debug case: producer-1 at H,
    // follower-b at H+1; if we keep asking follower-a for H+1 we never
    // get it, but rotating to follower-b on the next tick succeeds).
    let mut peer_rotation_cursor: usize = 0;

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    return Ok(());
                }
            }
            _ = tokio::time::sleep(STALE_TIP_PROBE_INTERVAL) => {
                // Read the current tip + p2p handle under the lock and
                // release before any await — we never want this loop
                // to sit on the SharedLiveNodeState mutex.
                let (current_tip, handle) = {
                    let guard = state.lock().await;
                    (guard.disk.height(), guard.p2p_handle.clone())
                };

                if current_tip > last_height {
                    last_height = current_tip;
                    last_seen = Instant::now();
                    last_fetch_height = None; // tip moved, reset
                    continue;
                }

                let stuck_for = last_seen.elapsed();
                if stuck_for < STALE_TIP_THRESHOLD {
                    continue;
                }

                let Some(handle) = handle else {
                    // libp2p disabled — nothing we can do. The HTTP
                    // sync_loop is the recovery mechanism on that path.
                    continue;
                };

                let peers = crate::p2p::connected_peer_ids();
                if peers.is_empty() {
                    continue;
                }

                // Cooldown is per (height, peer): we may have just asked
                // peer A for H+1 and gotten an empty response (peer didn't
                // have it); we want to ask peer B next tick without a
                // cooldown wall. The cooldown applies only when we are
                // about to re-ask the SAME peer for the SAME height in
                // less than STALE_TIP_FETCH_COOLDOWN.
                let now = Instant::now();

                // Round-robin cursor over connected peers — see comment
                // at `peer_rotation_cursor` declaration. Wrap modulo
                // `peers.len()` so the cursor stays valid even when
                // peers churn.
                let peer = peers[peer_rotation_cursor % peers.len()];
                peer_rotation_cursor = peer_rotation_cursor.wrapping_add(1);

                if last_fetch_height == Some(current_tip)
                    && last_fetch_at.is_some_and(|t| now.duration_since(t) < STALE_TIP_FETCH_COOLDOWN)
                    && peers.len() == 1
                {
                    // Single peer + same height + still in cooldown:
                    // nothing useful to do. Skip this tick.
                    continue;
                }
                let target_height = current_tip + 1;
                let request = pqc_p2p::BlockFetchRequest {
                    from_height: target_height,
                    to_height: target_height,
                };
                if request.validate().is_err() {
                    // BlockFetchRequest validation only fails on empty/
                    // inverted ranges; a single height is always valid.
                    // Nothing useful to do if it ever happens.
                    continue;
                }

                tracing::warn!(
                    local_tip = current_tip,
                    target_height,
                    stuck_for_secs = stuck_for.as_secs(),
                    %peer,
                    peers_connected = peers.len(),
                    "stale-tip recovery: tip has not advanced; issuing out-of-band block-fetch"
                );

                crate::p2p::incr_block_fetch_requests_sent();
                if let Err(e) = handle.request_blocks(peer, request).await {
                    tracing::warn!(
                        error = %e,
                        %peer,
                        target_height,
                        "stale-tip recovery: block-fetch dispatch failed"
                    );
                } else {
                    last_fetch_at = Some(now);
                    last_fetch_height = Some(current_tip);
                }
            }
        }
    }
}

/// Handle an inbound libp2p Precommit vote — TASK-113 Step 6 closure,
/// distributed_signing mode.
///
/// Validates the vote signature against the voter's on-chain consensus
/// public key, drops votes for already-finalized heights, and inserts
/// the vote into `pending_precommits[(height, block_hash)][voter]`. The
/// producer/consensus loop drains this map when finalizing a block it
/// proposed.
///
/// Silently dropped categories (log at debug/info, no error surface):
///   * vote.height <= current tip              → already committed
///   * voter address not in active validators  → no stake weight
///   * signature fails ML-DSA verify           → malformed or forged
///
/// Gossipsub's best-effort delivery means duplicate votes for the same
/// (height, block_hash, voter) are common; the inner HashMap keyed on
/// voter address naturally dedups.
pub(super) async fn handle_inbound_precommit(
    state: &SharedLiveNodeState,
    source: Option<pqc_p2p::PeerId>,
    vote: pqc_types::SignedVote,
) {
    let mut guard = state.lock().await;

    // Drop votes at or below the tip — the block either already landed or
    // has been superseded.
    let tip = guard.disk.height();
    if vote.height <= tip {
        tracing::debug!(
            height = vote.height,
            tip,
            source = ?source,
            block_hash = %hex::encode(vote.block_hash),
            "distributed-signing: drop stale precommit (at/below tip)"
        );
        return;
    }

    // Voter must be an Active validator so the producer knows their weight.
    let voter_addr_bytes = match <[u8; 32]>::try_from(vote.validator_address.as_slice()) {
        Ok(a) => a,
        Err(_) => {
            tracing::warn!("distributed-signing: drop precommit with non-32B voter address");
            return;
        }
    };
    let voter_addr = pqc_types::account::Address(voter_addr_bytes);
    let voter_record = guard.state.active_validators().iter().find_map(|v| {
        if v.operator == voter_addr {
            Some((*v).clone())
        } else {
            None
        }
    });
    let Some(record) = voter_record else {
        tracing::debug!(
            voter = %hex::encode(voter_addr_bytes),
            height = vote.height,
            block_hash = %hex::encode(vote.block_hash),
            "distributed-signing: drop precommit from non-active validator"
        );
        return;
    };

    // Verify ML-DSA signature on the §8.4 vote preimage. The preimage is
    // rebuilt from the vote's own fields via the canonical helper in
    // pqc-consensus (same function the signing side uses in
    // p2p::build_signed_precommit); a tampered vote mis-matches its own
    // sig and fails here.
    let step = match vote.msg_type {
        pqc_types::MSG_TYPE_PREVOTE => pqc_consensus::VoteStep::Prevote,
        pqc_types::MSG_TYPE_PRECOMMIT => pqc_consensus::VoteStep::Precommit,
        other => {
            tracing::warn!(
                voter = %hex::encode(voter_addr_bytes),
                msg_type = format!("{:#04x}", other),
                "distributed-signing: drop vote with unknown msg_type"
            );
            return;
        }
    };
    let fork_digest = pqc_types::ForkDigest::viper_research_1();
    let preimage = pqc_consensus::vote_preimage(
        &fork_digest,
        vote.height,
        vote.round,
        step,
        &vote.block_hash,
    );
    let pk = pqc_crypto::PublicKey {
        alg_id: record.consensus_alg_id,
        bytes: record.consensus_pk.clone(),
    };
    let sig = pqc_crypto::Signature {
        alg_id: record.consensus_alg_id,
        bytes: vote.signature.clone(),
    };
    use pqc_crypto::sign::SignatureVerifier;
    if let Err(e) = pqc_crypto::PqVerifier.verify(&pk, &preimage, &sig) {
        tracing::warn!(
            voter = %hex::encode(voter_addr_bytes),
            height = vote.height,
            block_hash = %hex::encode(vote.block_hash),
            error = ?e,
            "distributed-signing: drop precommit with invalid signature"
        );
        return;
    }

    let block_hash = BlockHash(vote.block_hash);
    let key = (vote.height, block_hash);
    // G-02 / TASK-241: both vote maps are height-scoped resources. Evict
    // everything at or below the local tip on every insert so they stay
    // bounded at O(validators × in-flight rounds) instead of growing by
    // one entry per block for the life of the process.
    let tip_now = guard.disk.height();
    guard.pending_precommits.retain(|(h, _), _| *h > tip_now);
    guard
        .own_precommits_emitted
        .retain(|(h, _, _)| *h > tip_now);
    let bucket = guard.pending_precommits.entry(key).or_default();
    let had_existing = bucket.insert(voter_addr_bytes, vote.clone()).is_some();
    let bucket_size = bucket.len();
    tracing::info!(
        height = vote.height,
        voter = %hex::encode(voter_addr_bytes),
        block_hash = %hex::encode(vote.block_hash),
        bucket_size,
        replaced = had_existing,
        "distributed-signing: buffered precommit"
    );
}

/// ADR-051 / TASK-167 Step 4 — emit the block as a PROPOSAL before
/// finalization, so peer validators can see it and return their own
/// Precommit votes.
///
/// The proposer's `proposal.execution.block` at this point carries
/// only its own CommitSig (Phase 2 signed; Phase 2.5 drain has not yet
/// run). Peers receiving the block see `commit_signatures.len() <
/// quorum_threshold`, route through the non-proposer branch
/// (`handle_non_proposer_proposal_if_applicable`), and gossip their
/// Precommit votes back.
///
/// No-op in legacy mode — the proposer's block already carries all
/// sigs before Phase 4 `emit_block_gossip`.
pub(super) async fn emit_block_proposal_gossip_if_distributed(
    state: &SharedLiveNodeState,
    proposal: &pqc_consensus::ProposedBlock,
    mode: pqc_consensus::CommitPreimageMode,
) {
    if !matches!(mode, pqc_consensus::CommitPreimageMode::Distributed { .. }) {
        return;
    }
    // Build a StoredBlock carrying the proposer's partial-sig block and
    // the accompanying metadata. We DO NOT persist here — this is a
    // gossip-only envelope.
    let (chain_id, handle, proposal_bytes) = {
        let guard = state.lock().await;
        if guard.p2p_handle.is_none() {
            return;
        }
        let stored = pqc_consensus::StoredBlock {
            block: proposal.execution.block.clone(),
            metadata: pqc_consensus::BlockMetadata {
                block_hash: proposal.block_hash.clone(),
                height: proposal.execution.block.header.height,
                prev_hash: proposal.execution.block.header.prev_hash.clone(),
                state_root: proposal.execution.state_root.clone(),
                tx_root: proposal.execution.tx_root.clone(),
                timestamp: proposal.execution.block.header.timestamp,
                bytes_used: proposal.execution.bytes_used,
                included_count: proposal.execution.included.len(),
                deferred_count: proposal.execution.deferred.len(),
                skipped_count: proposal.execution.skipped.len(),
                vc_budget_consumed: proposal.execution.vc_budget_consumed,
            },
            included_transactions: proposal.execution.included_transactions.clone(),
        };
        match pqc_consensus::RocksDbChainStore::encode_block_bytes(&stored) {
            Ok(bytes) => (
                guard.config.chain_id_hex.clone(),
                guard.p2p_handle.clone(),
                bytes,
            ),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    height = proposal.execution.block.header.height,
                    "distributed-signing: failed to encode proposal for gossip (non-fatal)"
                );
                return;
            }
        }
    };
    let envelope = crate::p2p::block_envelope(&chain_id, proposal_bytes);
    crate::p2p::publish_if_enabled(handle.as_ref(), envelope).await;
    tracing::info!(
        height = proposal.execution.block.header.height,
        block_hash = %hex::encode(proposal.block_hash.0),
        "distributed-signing: proposer emitted PROPOSAL block (partial sigs)"
    );
    tracing::info!(
        target: "viper.audit",
        event = "block_proposed",
        height = proposal.execution.block.header.height,
        block_hash = %hex::encode(proposal.block_hash.0),
        proposer = %hex::encode(&proposal.execution.block.header.proposer),
    );
}

/// ADR-051 / TASK-167 Step 3 — non-proposer branch on inbound Block gossip.
///
/// Returns `true` when this node has acted as a non-proposer for the
/// inbound block (signed its own Precommit, gossiped it, buffered the
/// height+block_hash in `own_precommits_emitted`), and the caller
/// SHOULD NOT attempt to import the block as-is. Returns `false` when
/// the block should flow through the normal import path: i.e.
///
/// - `distributed_signing = false` (legacy devnet-2 single-producer
///   path — every gossiped block is already a final block), OR
/// - `commit_signatures.len() >= quorum_threshold` (threshold met, the
///   block is a FINAL emit, import it), OR
/// - this node holds no keystore seed for any validator in the on-chain
///   active set (we're not a validator for this epoch; observers
///   import normally), OR
/// - we already signed and gossiped a Precommit for this
///   `(height, block_hash, validator)` tuple and don't want to re-emit
///   on duplicate-inbound-gossip.
///
/// The function holds the state lock for the full span so the decision
/// is atomic against in-flight block commits (if the proposer finalizes
/// the block mid-call and advances tip, the `height <= tip` check at
/// the top prevents double-signing).
pub(super) async fn handle_non_proposer_proposal_if_applicable(
    state: &SharedLiveNodeState,
    inbound: &crate::p2p::InboundBlock,
) -> bool {
    let mut guard = state.lock().await;

    // Legacy mode — every gossiped block is final; let the normal path
    // import it. This preserves devnet-2 byte-stability.
    if !guard.config.devnet.distributed_signing {
        return false;
    }

    let block = &inbound.block;
    let height = block.metadata.height;
    let block_hash = block.metadata.block_hash.clone();

    // Guard against signing for already-finalized heights.
    if height <= guard.disk.height() {
        return false;
    }

    // Threshold check: if the gossiped block already carries threshold
    // sigs, it's a final block — fall through to import.
    let policy = match pqc_consensus::CommitQuorumPolicy::from_state_store(&guard.state, None)
        .expect("StateStore yields a valid CommitQuorumPolicy")
    {
        Some(p) => p,
        None => {
            // Pre-genesis-seed boot or empty active set — no validators
            // to sign with; let the normal import path handle it
            // (typically it will skip quorum validation on `None`).
            return false;
        }
    };
    let threshold = policy.quorum_threshold();
    let sig_count = block.block.commit_signatures.len();
    if sig_count >= threshold {
        // Final block — import.
        return false;
    }

    // Who am I? Read my active-validator addresses (address × keystore
    // intersection). If none of my validators are Active on-chain, I
    // have no business signing anything; pass through (observer node).
    //
    // Scope the keystore RwLockReadGuard tightly — it is not `Send`, so
    // it MUST be dropped before the function hits any `.await` further
    // down. The explicit block scope guarantees the RAII drop runs
    // before the gossip `publish_if_enabled` await at the end.
    let active = guard.state.active_validators();
    let active_records: Vec<pqc_types::validator::ValidatorRecord> =
        active.iter().map(|v| (*v).clone()).collect();
    let signers = {
        let keystore_guard = guard.keystore.read().expect("keystore RwLock poisoned");
        let active_refs: Vec<&pqc_types::validator::ValidatorRecord> =
            active_records.iter().collect();
        snapshot_block_signers(&keystore_guard, &active_refs)
    };

    if signers.is_empty() {
        return false;
    }

    // TASK-219 / L3 — `attack_mode = "WithholdPrecommit"` injection point.
    // ONLY honoured when the binary is built with `--features attack-modes`
    // (off in every release build). The check is at the signer entrypoint
    // for symmetry with the legacy producer_loop signing path; both ignore
    // the field unless the feature is on. Test fixture lives at
    // `crates/pqcd/tests/malicious_node.rs` (TASK-219 integration test).
    #[cfg(feature = "attack-modes")]
    if guard.config.devnet.attack_mode.as_deref() == Some("WithholdPrecommit") {
        tracing::warn!(
            height,
            block_hash = %hex::encode(block_hash.0),
            "[ATTACK MODE: WithholdPrecommit] silently dropping {} local precommit(s)",
            signers.len()
        );
        return false;
    }

    // Sign + gossip one Precommit per validator this node signs for,
    // skipping duplicates we've already emitted for this exact
    // (height, block_hash, validator) tuple.
    let chain_id_hex = guard.config.chain_id_hex.clone();
    let p2p_handle = guard.p2p_handle.clone();
    let mut emitted: Vec<pqc_types::SignedVote> = Vec::with_capacity(signers.len());
    for signer in &signers {
        let Ok(addr_arr) = <[u8; 32]>::try_from(signer.validator_address.as_slice()) else {
            continue;
        };
        let key = (height, block_hash.clone(), addr_arr);
        if guard.own_precommits_emitted.contains(&key) {
            continue;
        }
        match crate::p2p::build_signed_precommit(
            signer.sig_alg_id,
            &signer.commit_seed,
            addr_arr,
            height,
            block_hash.0,
        ) {
            Ok(vote) => {
                guard.own_precommits_emitted.insert(key);
                // Insert into our own pending_precommits buffer too,
                // so when this node later wins proposer for the next
                // height it has the full picture. Also naturally
                // deduplicated by handle_inbound_precommit on
                // gossipsub-self-delivery.
                let bucket = guard
                    .pending_precommits
                    .entry((height, block_hash.clone()))
                    .or_default();
                bucket.insert(addr_arr, vote.clone());
                emitted.push(vote);
            }
            Err(e) => tracing::warn!(
                error = %e,
                height,
                validator = %hex::encode(addr_arr),
                "distributed-signing: non-proposer precommit signing failed"
            ),
        }
    }

    let any_emitted = !emitted.is_empty();
    drop(guard);

    // Gossip each precommit outside the state lock — publish_if_enabled
    // is a tokio::sync::Mutex await; no state access required.
    for vote in emitted {
        let envelope = crate::p2p::consensus_vote_envelope(&chain_id_hex, &vote);
        crate::p2p::publish_if_enabled(p2p_handle.as_ref(), envelope).await;
    }

    if any_emitted {
        tracing::info!(
            height,
            block_hash = %hex::encode(block_hash.0),
            sig_count,
            threshold,
            "distributed-signing: non-proposer signed + gossiped Precommit for proposal"
        );
    }
    any_emitted
}

/// ADR-051 / TASK-167 Step 2 — per-role proposer dispatch.
///
/// Returns `true` when the validator running this loop iteration SHOULD
/// build + emit a block for `(next_height, round)`:
///
/// - In legacy mode (`distributed_signing = false`), every tick of
///   `consensus_loop` builds — this is the current devnet-2 single-
///   producer pattern. The gate is a pass-through so zero behaviour
///   changes on the live chain.
/// - In distributed-signing mode, only the validator whose address is
///   the `select_proposer`-elected proposer for this `(height, round)`
///   pair builds. Every other validator stays quiescent — it will
///   react to the elected proposer's block via `handle_inbound_block`
///   (Step 3: auto-sign a Precommit, gossip, buffer the proposal). If
///   no validator addresses in the set are proposer-eligible this
///   tick, or if this node's keystore holds none of the elected
///   address's signing seed, we skip.
///
/// Pure function — no I/O, no state lock; exposed so a tight unit
/// test can exercise the two-address scenario without any loop
/// plumbing.
pub(crate) fn should_build_as_proposer(
    distributed_signing: bool,
    validator_addresses: &[[u8; 32]],
    next_height: u64,
    round: u32,
    keystore: &Keystore,
) -> bool {
    if !distributed_signing {
        return true;
    }
    let Some(proposer_addr) =
        pqc_consensus::select_proposer(validator_addresses, next_height, round, None)
    else {
        return false;
    };
    keystore.contains(&proposer_addr)
}

/// Drain `pending_precommits[(height, block_hash)]` into the block's
/// `commit_signatures` vector — ADR-051 §Decision item 4, the M2b
/// multi-node BFT path.
///
/// Peer Precommit votes buffered by `handle_inbound_precommit` are
/// already pre-verified (ML-DSA sig, voter-is-active-validator), so this
/// function only has to:
///   1. Check the producer is in distributed-signing mode — if legacy,
///      no-op and let the producer's self-signed commit sigs ride as-is.
///   2. Drain votes for this exact (height, block_hash) pair.
///   3. Convert each SignedVote to a CommitSig (same signature bytes;
///      §8.4 preimage is identical on both sides per the signing-side
///      branch in producer/consensus loops).
///   4. Skip duplicates (proposer's own precommit may already be in
///      block.commit_signatures if the keystore held its own seed).
pub(super) async fn merge_distributed_precommits_into_block(
    state: &SharedLiveNodeState,
    commit_sigs: &mut Vec<pqc_types::block::CommitSig>,
    block_height: u64,
    block_hash: &pqc_types::block::BlockHash,
    mode: pqc_consensus::CommitPreimageMode,
) {
    // No-op in legacy mode (default devnet-2 today).
    if !matches!(mode, pqc_consensus::CommitPreimageMode::Distributed { .. }) {
        return;
    }

    let mut guard = state.lock().await;
    let key = (block_height, block_hash.clone());
    let Some(bucket) = guard.pending_precommits.remove(&key) else {
        tracing::debug!(
            height = block_height,
            block_hash = %hex::encode(block_hash.0),
            "distributed-signing: no peer precommits in buffer for this block"
        );
        return;
    };

    // Track already-attached signers so the proposer's own sig (which we
    // just inserted in phase 2) does not get double-counted.
    let already: std::collections::HashSet<[u8; 32]> = commit_sigs
        .iter()
        .filter_map(|cs| <[u8; 32]>::try_from(cs.validator_address.as_slice()).ok())
        .collect();

    // Need each voter's on-chain alg_id to populate CommitSig.sig_alg_id.
    // The precommit buffer keys on validator address; the state carries
    // the algorithm registered with that validator.
    let active = guard.state.active_validators();
    let alg_by_addr: std::collections::HashMap<[u8; 32], pqc_crypto::AlgId> = active
        .iter()
        .map(|v| (v.operator.0, v.consensus_alg_id))
        .collect();

    let mut added = 0usize;
    for (voter, vote) in bucket {
        if already.contains(&voter) {
            continue;
        }
        let Some(alg_id) = alg_by_addr.get(&voter).copied() else {
            // Voter is not (no longer?) active; their precommit is stale.
            tracing::debug!(
                height = block_height,
                voter = %hex::encode(voter),
                "distributed-signing: drop peer precommit from inactive voter"
            );
            continue;
        };
        commit_sigs.push(pqc_types::block::CommitSig {
            validator_address: voter.to_vec(),
            sig_alg_id: alg_id,
            // ADR-051 / TASK-171: carry the peer's round through from
            // their SignedVote into the block's CommitSig so the
            // verifier rebuilds the §8.4 preimage with the correct
            // round per §10.1. Before this, merging collapsed every
            // peer sig to round=0 regardless of what they'd signed —
            // fine at round 0 but catastrophic once any round > 0
            // occurs.
            round: vote.round,
            signature: vote.signature,
        });
        added += 1;
    }

    if added > 0 {
        tracing::info!(
            height = block_height,
            block_hash = %hex::encode(block_hash.0),
            sigs_added = added,
            total_sigs = commit_sigs.len(),
            "distributed-signing: merged peer precommits into block.commit_signatures"
        );
    }
}

/// Handle an inbound gossip-sourced transaction envelope — TASK-172,
/// the receive-side mirror of `DevnetNodeHandle::inject_tx`.
///
/// `route_event` has already enforced the SPEC-P2P-002 §4.4 ValidatorPeerId
/// binding check before emitting `InboundP2pEvent::Transaction`, so the
/// payload comes from a peer we are willing to accept txs from (or the
/// allow-list is disabled — devnet-2 default per ADR-041 addendum).
/// Despite that upstream trust, this handler still runs the full
/// admission pipeline: structural decode → per-sender budget check
/// (SPEC-FEE-001 §10.1) → `try_admit`. Gossip is NOT exempt from spam
/// controls — a compromised peer's PeerId could still flood one
/// sender's budget, and `check_sender_budget` is the layer that caps
/// that.
///
/// **No re-publish**: gossipsub's native mesh forwarding propagates the
/// payload to other peers transparently. Calling `publish_if_enabled`
/// here would duplicate-amplify every gossiped tx into an O(N²)
/// re-broadcast storm.
///
/// **No error surface**: decode failures, duplicates, budget-exhaustion
/// and validation failures are logged at debug/info and dropped.
/// Handler failures must never crash the inbound loop.
pub(super) async fn handle_inbound_transaction(
    state: &SharedLiveNodeState,
    source: Option<pqc_p2p::PeerId>,
    raw_tx: Vec<u8>,
) {
    let mut guard = state.lock().await;

    // Structural decode (no crypto) to extract sender for the budget check.
    // A decode failure here is not a signal to propagate an error — we
    // just count the rejection and move on.
    let maybe_sender = decode_tx(&raw_tx).ok().map(|tx| tx.sender);

    // Per-sender admission budget — mirrors inject_tx (SPEC-FEE-001 §10.1).
    // Gossipsub rate-limits at the transport level; this caps per-sender
    // admission to the window's budget regardless of how many peers
    // re-broadcast the same sender's tx.
    if let Some(ref sender) = maybe_sender {
        if guard.check_sender_budget(sender) {
            guard.record_rejection("SENDER_RATE_LIMITED");
            tracing::debug!(
                source = ?source,
                payload_len = raw_tx.len(),
                "gossip-tx: drop — per-sender admission budget exhausted"
            );
            return;
        }
    }

    let verifier = guard.verifier.clone();
    let result = {
        let LiveNodeState {
            state,
            mempool,
            fee_params,
            ..
        } = &mut *guard;
        try_admit(mempool, raw_tx, state, verifier.as_ref(), fee_params)
    };

    match &result {
        Ok(admission) => {
            guard.txs_admitted += 1;
            if let Some(sender) = maybe_sender {
                guard.record_sender_admission(&sender);
            }
            tracing::debug!(
                source = ?source,
                tx_hash = %hex::encode(admission.tx_hash),
                replaced = ?admission.replaced.map(hex::encode),
                "gossip-tx: admitted to local mempool"
            );
        }
        Err(e) => {
            let (reason, _) = mempool_error_code(e);
            guard.record_rejection(reason);
            // Most rejections here are benign (duplicate already in
            // mempool, sender unknown, fee below floor). Log at debug so
            // operators can still filter noisy peers but the healthy
            // case of "peer re-broadcasts a tx we already have" doesn't
            // flood the log.
            let level_is_debug = matches!(
                e,
                MempoolError::Duplicate
                    | MempoolError::AlreadyIncluded
                    | MempoolError::ReplacementUnderpriced { .. }
            );
            if level_is_debug {
                tracing::debug!(
                    source = ?source,
                    error = %e,
                    "gossip-tx: rejected (benign)"
                );
            } else {
                tracing::info!(
                    source = ?source,
                    error = %e,
                    "gossip-tx: rejected by admission pipeline"
                );
            }
        }
    }
    // Guard drops at end of scope — there is no downstream I/O, so we
    // do not need the explicit `drop(guard)` dance that inject_tx uses
    // before its re-publish step.
}

/// TASK-135 step 11 — Classify an inbound block envelope against the
/// local chain tip and, when a gap is detected, issue a block-fetch
/// request against the envelope's publisher (TASK-135 step 12b).
///
/// The chain-store mutex is held only long enough to read
/// `disk.height()` + clone the `SwarmHandle` and chain_id; zero writes,
/// no CBOR work. Classification uses the pure helper
/// `crate::p2p::classify_inbound_height` so branch decisions remain
/// unit-testable. Ingest of the `Next` branch still lands in step 13.
pub(super) async fn handle_inbound_block(
    state: &SharedLiveNodeState,
    inbound: crate::p2p::InboundBlock,
) {
    // Pull the tip + a SwarmHandle clone inside a single short guard so
    // the potential request_blocks dispatch below never holds the state
    // lock across an await point.
    let (local_tip, p2p_handle) = {
        let guard = state.lock().await;
        (guard.disk.height(), guard.p2p_handle.clone())
    };
    let received = inbound.block.metadata.height;
    let block_hash_hex = hex::encode(inbound.block.metadata.block_hash.0);
    match crate::p2p::classify_inbound_height(local_tip, received) {
        crate::p2p::BlockInboundClass::Behind => {
            tracing::info!(
                local_tip,
                received,
                source = ?inbound.source,
                block_hash = %block_hash_hex,
                "libp2p: inbound block at or below tip (dedup, observation)"
            );
        }
        crate::p2p::BlockInboundClass::Next => {
            // ADR-051 / TASK-167 Step 3 — Non-proposer branch.
            //
            // In distributed-signing mode, a block can arrive in two
            // shapes on the `Next` path:
            //
            //   1. PROPOSAL — `commit_signatures.len() < quorum_threshold`.
            //      The proposer emitted the block after signing just its
            //      own CommitSig; peers are expected to inspect, sign
            //      their own Precommit vote, gossip it back, and WAIT
            //      for a final block. Do NOT import.
            //   2. FINAL    — `commit_signatures.len() >= quorum_threshold`.
            //      Threshold reached; import normally via the TASK-135
            //      step 13 path below.
            //
            // The flag-off legacy path (devnet-2 current) always takes
            // the FINAL branch — `producer_loop` is the single signer
            // and attaches all sigs before emit, so the first block
            // ever seen carries full sigs.
            let should_non_proposer_sign =
                handle_non_proposer_proposal_if_applicable(state, &inbound).await;
            if should_non_proposer_sign {
                // We've signed + gossiped our own Precommit; now wait
                // for the final (threshold-met) block to arrive and be
                // imported below.
                return;
            }

            // TASK-135 step 13 — ingest directly from gossip.
            // ADR-054 §Stage 4 routes the import through the staged
            // pipeline; the outcome decides whether we additionally
            // dispatch a by-hash fetch for an unknown parent.
            let mut guard = state.lock().await;
            let outcome = guard.import_remote_block(inbound.block);
            // Capture the SwarmHandle for the post-await dispatch
            // before dropping the guard.
            let handle_for_fetch = guard.p2p_handle.clone();
            drop(guard);
            match outcome {
                Ok(ImportOutcome::Imported) => {
                    crate::p2p::incr_blocks_imported();
                    tracing::info!(
                        local_tip,
                        received,
                        source = ?inbound.source,
                        block_hash = %block_hash_hex,
                        "libp2p: gossip block ingested (Next)"
                    );
                    tracing::info!(
                        target: "viper.audit",
                        event = "block_finalized_via_gossip",
                        height = received,
                        block_hash = %block_hash_hex,
                        source = ?inbound.source,
                    );
                }
                Ok(ImportOutcome::Duplicate) => {
                    tracing::debug!(
                        local_tip,
                        received,
                        block_hash = %block_hash_hex,
                        "libp2p: gossip block already on canonical chain (Duplicate)"
                    );
                }
                Ok(ImportOutcome::OrphanedNeedsParent { parent_hash }) => {
                    dispatch_orphan_parent_fetch(inbound.source, handle_for_fetch, parent_hash)
                        .await;
                }
                Err(e) => tracing::warn!(
                    error = %e,
                    local_tip,
                    received,
                    source = ?inbound.source,
                    block_hash = %block_hash_hex,
                    "libp2p: gossip block ingest failed"
                ),
            }
        }
        crate::p2p::BlockInboundClass::Gap { ahead_by } => {
            crate::p2p::incr_block_gap_total();
            tracing::warn!(
                local_tip,
                received,
                ahead_by,
                source = ?inbound.source,
                block_hash = %block_hash_hex,
                "libp2p: inbound block ahead of local tip — issuing block-fetch"
            );
            // TASK-135 step 12b — close the gap by requesting the
            // intermediate heights from the envelope publisher. Skip
            // when:
            //   * the publisher PeerId is unknown (anonymous gossip —
            //     we have nothing to dial),
            //   * the swarm is disabled (`p2p_handle = None`),
            //   * the range would exceed MAX_BLOCKS_PER_REQUEST (we
            //     issue a single first-pass request; the next inbound
            //     block triggers a follow-up once we've ingested).
            if let (Some(peer), Some(handle)) = (inbound.source, p2p_handle) {
                let from = local_tip + 1;
                let cap = pqc_p2p::MAX_BLOCKS_PER_REQUEST;
                let to = received.saturating_sub(1).min(from + cap - 1);
                let request = pqc_p2p::BlockFetchRequest {
                    from_height: from,
                    to_height: to,
                };
                if request.validate().is_ok() {
                    crate::p2p::incr_block_fetch_requests_sent();
                    if let Err(e) = handle.request_blocks(peer, request).await {
                        tracing::warn!(
                            error = %e,
                            %peer,
                            "libp2p: block-fetch request dispatch failed"
                        );
                    }
                }
            }
        }
    }
}

/// TASK-135 step 12b — Serve an inbound block-fetch request by reading
/// the requested heights from the local chain store and replying via
/// the SwarmHandle.
///
/// Tail-truncates the response: iteration stops at the first height we
/// don't hold (SPEC-P2P-002 — responders MAY return fewer blocks, but
/// never gaps). An I/O failure mid-range is logged and also truncates
/// — the peer gets whatever prefix we could export cleanly.
///
/// State lock is held for the entire range read so we see a consistent
/// tip snapshot; the SwarmHandle dispatch runs after the lock is
/// released.
pub(super) async fn handle_inbound_block_fetch_request(
    state: &SharedLiveNodeState,
    peer: pqc_p2p::PeerId,
    request_id: pqc_p2p::BlockFetchRequestId,
    request: pqc_p2p::BlockFetchRequest,
) {
    crate::p2p::incr_block_fetch_requests_received();
    // Belt-and-braces: the swarm driver already validates on receipt,
    // but the wire-level re-check costs nothing and guards against a
    // future driver refactor that drops the guard there.
    if let Err(e) = request.validate() {
        tracing::warn!(
            %peer, request_id, error = %e,
            "libp2p: dropping malformed inbound block-fetch request"
        );
        return;
    }

    let (p2p_handle, blocks) = {
        let guard = state.lock().await;
        let handle = guard.p2p_handle.clone();
        let mut blocks: Vec<Vec<u8>> = Vec::new();
        for h in request.from_height..=request.to_height {
            match guard.disk.export_block_bytes(h) {
                Ok(Some(bytes)) => blocks.push(bytes),
                Ok(None) => break,
                Err(e) => {
                    tracing::warn!(
                        height = h, error = %e,
                        "libp2p: block-fetch export_block_bytes failed — truncating response"
                    );
                    break;
                }
            }
        }
        (handle, blocks)
    };

    tracing::info!(
        %peer,
        request_id,
        from_height = request.from_height,
        to_height = request.to_height,
        returned = blocks.len(),
        "libp2p: serving block-fetch request"
    );

    let response = pqc_p2p::BlockFetchResponse { blocks };
    if let Some(h) = p2p_handle {
        if let Err(e) = h.reply_block_fetch(request_id, response).await {
            tracing::warn!(
                %peer,
                request_id,
                error = %e,
                "libp2p: block-fetch reply dispatch failed"
            );
        }
    }
}

/// TASK-135 step 13 — Consume an inbound block-fetch response by
/// importing each returned block into the local chain store.
///
/// Blocks are expected in strictly ascending order per SPEC-P2P-002
/// (`block_fetch` module — responders MAY truncate from the tail but
/// never skip). We decode each body, then hand it to
/// `import_remote_block` which re-validates signatures, parent
/// linkage and state root before appending. On the FIRST import error
/// we stop: subsequent blocks in the range parent-link through the
/// failed one and would fail the same check.
///
/// State lock is held for the duration of the import sweep so the
/// response arrives as an atomic batch — mid-batch tip changes from
/// a concurrent gossip Next ingest would invalidate subsequent
/// parent-hash checks.
pub(super) async fn handle_inbound_block_fetch_response(
    state: &SharedLiveNodeState,
    peer: pqc_p2p::PeerId,
    response: pqc_p2p::BlockFetchResponse,
) {
    crate::p2p::incr_block_fetch_responses_received();
    let n = response.blocks.len();
    tracing::info!(%peer, blocks_len = n, "libp2p: block-fetch response received");
    if n == 0 {
        return;
    }

    let mut guard = state.lock().await;
    // Collect parent-hashes whose orphans need fetching after the
    // batch completes — the await-dispatch happens after we drop the
    // guard so we never hold the lock across an await point.
    let mut parents_to_fetch: Vec<pqc_types::block::BlockHash> = Vec::new();
    for (idx, block_bytes) in response.blocks.iter().enumerate() {
        let block = match pqc_consensus::RocksDbChainStore::decode_block_bytes(block_bytes) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(
                    idx, error = %e,
                    "libp2p: block-fetch response entry decode failed — aborting batch"
                );
                break;
            }
        };
        let height = block.metadata.height;
        let hash_hex = hex::encode(block.metadata.block_hash.0);
        match guard.import_remote_block(block) {
            Ok(ImportOutcome::Imported) => {
                crate::p2p::incr_blocks_imported();
                tracing::info!(
                    idx, height, block_hash = %hash_hex,
                    "libp2p: block-fetch entry ingested"
                );
                // ADR-054 §Stage 4 — try to drain orphan children whose
                // parent we just imported. Bounded recursion inside
                // drain_orphan_children; the returned hashes are
                // grandparents we still need to fetch.
                let imported_hash = pqc_types::block::BlockHash(hex_decode_32(&hash_hex));
                let mut more_needed = guard.drain_orphan_children(&imported_hash);
                parents_to_fetch.append(&mut more_needed);
            }
            Ok(ImportOutcome::Duplicate) => {
                tracing::debug!(
                    idx, height, block_hash = %hash_hex,
                    "libp2p: block-fetch entry already on chain (Duplicate)"
                );
            }
            Ok(ImportOutcome::OrphanedNeedsParent { parent_hash }) => {
                tracing::info!(
                    idx,
                    height,
                    block_hash = %hash_hex,
                    parent_hash = %hex::encode(parent_hash.0),
                    "libp2p: block-fetch entry buffered as orphan"
                );
                parents_to_fetch.push(parent_hash);
            }
            Err(e) => {
                tracing::warn!(
                    idx, height, error = %e,
                    "libp2p: block-fetch entry ingest failed — aborting batch"
                );
                break;
            }
        }
    }
    let p2p_handle = guard.p2p_handle.clone();
    drop(guard);

    for parent_hash in parents_to_fetch {
        dispatch_orphan_parent_fetch(Some(peer), p2p_handle.clone(), parent_hash).await;
    }
}

/// Decode a 32-byte hex string back into raw bytes. Tiny helper used
/// only by the local re-derivation in
/// `handle_inbound_block_fetch_response`. The hex string was produced
/// by `hex::encode` on the same metadata field one line earlier so
/// `expect` is safe.
pub(super) fn hex_decode_32(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).expect("hex::encode output is always valid hex");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// ADR-054 §Stage 4 — dispatch a `BlockFetchByHashRequest` for a
/// missing parent. Best-effort: if the source peer is unknown, the
/// swarm is disabled, or the fetch fails on the wire, the orphan
/// stays in the cache and is retried by the next gossip / fetch event
/// that brings the parent back into our view (or expires via the TTL).
pub(super) async fn dispatch_orphan_parent_fetch(
    source: Option<pqc_p2p::PeerId>,
    p2p_handle: Option<pqc_p2p::SwarmHandle>,
    parent_hash: pqc_types::block::BlockHash,
) {
    let (Some(peer), Some(handle)) = (source, p2p_handle) else {
        tracing::debug!(
            parent_hash = %hex::encode(parent_hash.0),
            "ADR-054 §Stage 4: orphan parent fetch skipped (no peer or no swarm)"
        );
        return;
    };
    let request = pqc_p2p::BlockFetchByHashRequest {
        hash: parent_hash.0,
    };
    crate::p2p::incr_block_fetch_by_hash_requests_sent();
    if let Err(e) = handle.request_block_by_hash(peer, request).await {
        tracing::warn!(
            error = %e,
            %peer,
            parent_hash = %hex::encode(parent_hash.0),
            "ADR-054 §Stage 4: by-hash parent fetch dispatch failed"
        );
    } else {
        tracing::info!(
            %peer,
            parent_hash = %hex::encode(parent_hash.0),
            "ADR-054 §Stage 4: requested missing parent by hash"
        );
    }
}

/// ADR-054 §Stage 4 — serve an inbound `block-fetch-by-hash` request.
///
/// Looks the requested hash up in:
///   1. The canonical chain via `RocksDbChainStore::read_stored_block_by_hash`
///      (covers any block the receiver currently has on its canonical
///      head).
///   2. The siblings CF via `RocksDbChainStore::read_sibling_by_hash`
///      (covers blocks displaced by a previous swap — useful when this
///      node was once on the variant the requester is now asking for).
///
/// Replies with the raw CBOR bytes when found, `None` otherwise.
/// Mirror of [`handle_inbound_block_fetch_request`] — the same
/// park-lock-and-reply discipline applies; the bytes returned are the
/// same `StoredBlockRecord` shape `decode_block_bytes` accepts.
pub(super) async fn handle_inbound_block_fetch_by_hash_request(
    state: &SharedLiveNodeState,
    peer: pqc_p2p::PeerId,
    request_id: pqc_p2p::BlockFetchByHashRequestId,
    request: pqc_p2p::BlockFetchByHashRequest,
) {
    let target = pqc_types::block::BlockHash(request.hash);
    let (p2p_handle, payload) = {
        let guard = state.lock().await;
        let handle = guard.p2p_handle.clone();
        // Canonical lookup first. We don't have a direct hash→bytes API
        // on RocksDbChainStore today, so resolve hash→height via the
        // chain's by_hash map (hot path, in-memory) and read bytes by
        // height. If the hash is below the in-memory tail (long-history
        // node) the lookup falls back to the siblings CF below.
        let canonical = guard
            .disk
            .chain()
            .get_metadata_by_hash(&target)
            .map(|m| m.height)
            .and_then(|h| guard.disk.export_block_bytes(h).ok().flatten());
        let bytes = match canonical {
            Some(b) => Some(b),
            None => {
                // Siblings CF fallback (ADR-054 §Stage 4 — recently
                // displaced state-equivalent variants).
                match guard.disk.read_sibling_by_hash(&target) {
                    Ok(Some(stored)) => {
                        match pqc_consensus::RocksDbChainStore::encode_block_bytes(&stored) {
                            Ok(b) => Some(b),
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    target = %hex::encode(target.0),
                                    "block-fetch-by-hash: sibling encode failed",
                                );
                                None
                            }
                        }
                    }
                    Ok(None) => None,
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            target = %hex::encode(target.0),
                            "block-fetch-by-hash: siblings CF read failed",
                        );
                        None
                    }
                }
            }
        };
        (handle, bytes)
    };

    tracing::info!(
        %peer,
        request_id,
        target_hash = %hex::encode(target.0),
        present = payload.is_some(),
        "libp2p: serving block-fetch-by-hash request",
    );

    let response = pqc_p2p::BlockFetchByHashResponse { block: payload };
    if let Some(h) = p2p_handle {
        if let Err(e) = h.reply_block_fetch_by_hash(request_id, response).await {
            tracing::warn!(
                %peer,
                request_id,
                error = %e,
                "libp2p: block-fetch-by-hash reply dispatch failed",
            );
        }
    }
}

/// ADR-054 §Stage 4 — orphan resolution loop.
///
/// On `Some(bytes)`: import the parent through `import_remote_block`.
/// If it resolves cleanly (`Imported` or `Duplicate`), walk the
/// `BlockTreeCache` for children whose `prev_hash` matches the just-
/// imported block; re-import each. Each grandparent that re-surfaces
/// as `OrphanedNeedsParent` triggers another by-hash fetch, bounded
/// by the cache size + TTL.
///
/// On `None`: the peer holds neither a canonical nor a sibling for
/// the requested hash. Log and move on — the orphan stays in the
/// cache and either ages out or gets resolved by a different peer's
/// future response.
pub(super) async fn handle_inbound_block_fetch_by_hash_response(
    state: &SharedLiveNodeState,
    peer: pqc_p2p::PeerId,
    response: pqc_p2p::BlockFetchByHashResponse,
) {
    let Some(bytes) = response.block else {
        tracing::warn!(
            %peer,
            "libp2p: block-fetch-by-hash response: peer has no canonical or sibling match"
        );
        return;
    };

    let parent = match pqc_consensus::RocksDbChainStore::decode_block_bytes(&bytes) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(
                %peer, error = %e,
                "libp2p: block-fetch-by-hash response decode failed"
            );
            return;
        }
    };

    let parent_height = parent.metadata.height;
    let parent_hash_hex = hex::encode(parent.metadata.block_hash.0);
    let parent_hash = parent.metadata.block_hash.clone();

    let mut guard = state.lock().await;
    let parent_outcome = guard.import_remote_block(parent);
    let mut grandparent_fetches: Vec<pqc_types::block::BlockHash> = Vec::new();

    match parent_outcome {
        Ok(ImportOutcome::Imported) => {
            crate::p2p::incr_blocks_imported();
            tracing::info!(
                %peer,
                height = parent_height,
                block_hash = %parent_hash_hex,
                "libp2p: block-fetch-by-hash parent imported — draining orphans"
            );
            let mut more = guard.drain_orphan_children(&parent_hash);
            grandparent_fetches.append(&mut more);
        }
        Ok(ImportOutcome::Duplicate) => {
            // The parent was already on our chain — nothing new to
            // import, but children might still be in the cache from
            // a previous race. Drain them anyway.
            let mut more = guard.drain_orphan_children(&parent_hash);
            grandparent_fetches.append(&mut more);
        }
        Ok(ImportOutcome::OrphanedNeedsParent { parent_hash: gp }) => {
            // The parent we fetched is itself orphaned — its parent
            // (grandparent of the original orphan) is also missing.
            // Cascade the by-hash fetch.
            grandparent_fetches.push(gp);
        }
        Err(e) => {
            tracing::warn!(
                %peer, error = %e,
                height = parent_height,
                block_hash = %parent_hash_hex,
                "libp2p: block-fetch-by-hash parent import failed"
            );
        }
    }

    let p2p_handle = guard.p2p_handle.clone();
    drop(guard);

    for gp in grandparent_fetches {
        dispatch_orphan_parent_fetch(Some(peer), p2p_handle.clone(), gp).await;
    }
}

/// Phase 8 M1 cold-start — Serve an inbound snapshot-fetch request
/// from the latest trusted checkpoint.
///
/// Reads `disk.export_checkpoint_bytes()` under a short lock guard.
/// Three outcomes:
///   * `Ok(Some(bytes))` — decode the embedded height for the response
///     envelope, reply with the full checkpoint body.
///   * `Ok(None)` — no checkpoint yet (genesis-bootstrapped and no
///     checkpoint interval hit). Reply with the default (empty) body
///     so the peer knows "this node has no snapshot"; requester falls
///     back to a different peer or genesis replay.
///   * `Err(..)` — chain-store error. Log and reply with empty body
///     (reasonable "I have nothing for you" semantics).
///
/// `request.at_height` is intentionally ignored during M1 — the
/// archival snapshot model lands with ADR-043 / M2. Documented in
/// `snapshot_fetch.rs`.
pub(super) async fn handle_inbound_snapshot_request(
    state: &SharedLiveNodeState,
    peer: pqc_p2p::PeerId,
    request_id: pqc_p2p::SnapshotFetchRequestId,
    request: pqc_p2p::SnapshotFetchRequest,
) {
    crate::p2p::incr_snapshot_requests_received();

    let (p2p_handle, response) = {
        let guard = state.lock().await;
        let handle = guard.p2p_handle.clone();
        let response = match guard.disk.export_checkpoint_bytes() {
            Ok(Some(bytes)) => {
                // Decode only the height (cheap — no full state replay)
                // so the response envelope carries both the raw body
                // and the duplicate `snapshot_height` field used by the
                // requester for pre-decode validation. If metadata
                // decode fails here, the checkpoint body itself is
                // corrupt — we still ship the bytes so the peer can
                // fail loudly, but zero out the height to make the
                // mismatch obvious on the wire.
                let snapshot_height =
                    match pqc_consensus::RocksDbChainStore::decode_snapshot_metadata(&bytes) {
                        Ok((h, _hash)) => h,
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "libp2p: snapshot metadata decode failed locally — wire height zeroed"
                            );
                            0
                        }
                    };
                pqc_p2p::SnapshotFetchResponse {
                    snapshot_bytes: bytes,
                    snapshot_height,
                }
            }
            Ok(None) => {
                tracing::info!(
                    %peer,
                    "libp2p: snapshot request — no checkpoint yet, replying empty"
                );
                pqc_p2p::SnapshotFetchResponse::default()
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "libp2p: export_checkpoint_bytes failed — replying empty"
                );
                pqc_p2p::SnapshotFetchResponse::default()
            }
        };
        (handle, response)
    };

    tracing::info!(
        %peer,
        request_id,
        at_height = ?request.at_height,
        snapshot_height = response.snapshot_height,
        snapshot_bytes_len = response.snapshot_bytes.len(),
        "libp2p: serving snapshot request"
    );

    if let Some(h) = p2p_handle {
        if let Err(e) = h.reply_snapshot_fetch(request_id, response).await {
            tracing::warn!(
                %peer, request_id, error = %e,
                "libp2p: snapshot reply dispatch failed"
            );
        }
    }
}

/// Phase 8 M1 cold-start — Consume an inbound snapshot-fetch response.
///
/// Decodes the embedded height + tip_hash for logging and cross-checks
/// them against the envelope's `snapshot_height` field (a mismatched
/// pair signals a buggy or malicious responder — logged at warn, no
/// bootstrap attempted). The actual
/// `bootstrap_from_external_snapshot` wiring needs cold-start timing
/// changes in `build_devnet_node` (libp2p must be running before the
/// follower asks for a snapshot) and is deferred.
pub(super) async fn handle_inbound_snapshot_response(
    _state: &SharedLiveNodeState,
    peer: pqc_p2p::PeerId,
    response: pqc_p2p::SnapshotFetchResponse,
) {
    crate::p2p::incr_snapshot_responses_received();
    if response.is_empty() {
        tracing::info!(
            %peer,
            "libp2p: snapshot response empty (peer has no checkpoint)"
        );
        return;
    }
    match pqc_consensus::RocksDbChainStore::decode_snapshot_metadata(&response.snapshot_bytes) {
        Ok((height, hash)) => {
            if height != response.snapshot_height {
                tracing::warn!(
                    %peer,
                    envelope_height = response.snapshot_height,
                    embedded_height = height,
                    "libp2p: snapshot response height mismatch between envelope and body (buggy peer?)"
                );
            }
            tracing::info!(
                %peer,
                height,
                tip_hash = %hex::encode(hash.0),
                bytes_len = response.snapshot_bytes.len(),
                "libp2p: snapshot response decoded (observation; bootstrap wiring deferred)"
            );
        }
        Err(e) => tracing::warn!(
            %peer, error = %e,
            "libp2p: snapshot response metadata decode failed"
        ),
    }
}

/// Emit a batch of signed Precommit votes over libp2p gossip.
///
/// Observation-mode during M1 (TASK-136): votes are produced alongside
/// commit signatures and published on the ConsensusVote topic. Remote
/// nodes only log them — no feeder wires them into a BFT engine yet.
///
/// `state.lock()` is acquired only long enough to clone the SwarmHandle
/// and read `chain_id_hex`, so per-block lock hold time stays bounded.
/// When libp2p is disabled, `publish_if_enabled` is a no-op and this
/// function degrades to one mutex-clone-drop per block — measurably free.
pub(super) async fn emit_precommit_votes(
    state: &SharedLiveNodeState,
    votes: &[pqc_types::SignedVote],
) {
    if votes.is_empty() {
        return;
    }
    let (handle, chain_id, _attack_mode) = {
        let guard = state.lock().await;
        (
            guard.p2p_handle.clone(),
            guard.config.chain_id_hex.clone(),
            guard.config.devnet.attack_mode.clone(),
        )
    };
    // TASK-219 / L3 — second WithholdPrecommit injection point. Mirrors the
    // gate in `handle_non_proposer_proposal_if_applicable`; covers the
    // legacy producer_loop / consensus_loop emission path so a node in
    // attack mode is silent across all three signer entrypoints. Feature-
    // gated; in release builds the attack_mode field is read into
    // _attack_mode but immediately ignored below.
    #[cfg(feature = "attack-modes")]
    if _attack_mode.as_deref() == Some("WithholdPrecommit") {
        tracing::warn!(
            count = votes.len(),
            "[ATTACK MODE: WithholdPrecommit] dropping {} precommit gossip envelope(s)",
            votes.len()
        );
        return;
    }
    for vote in votes {
        let envelope = crate::p2p::consensus_vote_envelope(&chain_id, vote);
        crate::p2p::publish_if_enabled(handle.as_ref(), envelope).await;
    }
}

#[cfg(test)]
mod proposer_dispatch_tests;
