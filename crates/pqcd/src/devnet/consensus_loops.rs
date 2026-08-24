// SPDX-License-Identifier: BUSL-1.1
//! BFT producer + consensus loops — the chain's hot path.
//!
//! Extracted from `devnet.rs` 2026-05-10. The two loops were the
//! single largest pair of fns in the original file (913 LOC combined).
//! They wire SPEC-CONSENSUS-001 §5 proposer rotation +
//! ADR-051 distributed-signing + Phase 7 light-client emission +
//! ADR-054 strict-finality audit at every block tick.
//!
//! `use super::*;` pulls every helper, type, and constant from the
//! parent module into scope so the loops keep their original call
//! shape (`emit_block_gossip(...)`, `next_block_timestamp()`, etc).
//! Rust's visibility rule "private items are visible to descendant
//! modules" makes this work without widening visibility on any
//! sibling helper. Both loops are `pub(super)` — only `start_from_
//! config_path` (in the parent) constructs them.
//!
//! See the parent module's "Panic strategy" doc comment for why
//! `expect()` is the correct failure mode in these paths.

use super::*;

pub(super) async fn producer_loop(
    state: SharedLiveNodeState,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let block_time_ms = {
        let guard = state.lock().await;
        guard.config.devnet.block_time_ms.max(1)
    };
    let mut ticker = time::interval(Duration::from_millis(block_time_ms));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => break,
            _ = ticker.tick() => {
                let timestamp = next_block_timestamp();

                // Phase 0: D-06 keystore reload — mtime-gated, so in the
                // steady state this is a single stat() call per block.
                // When the operator stages a keystore file with new
                // per-validator seeds (e.g. for a freshly-registered
                // validator), the next block tick merges them into the
                // in-memory keystore without a process restart.
                refresh_keystore_from_file(&state).await;

                // Phase 1: build proposal — holds lock only for state reads.
                let (mut proposal, signers, preimage_mode) = {
                    let mut guard = state.lock().await;
                    let proposer = guard
                        .proposer
                        .take()
                        .ok_or_else(|| anyhow!("producer loop started without proposer"))?;
                    let proposal = {
                        let LiveNodeState { state: state_store, mempool, .. } = &mut *guard;
                        proposer
                            .build_next_block(state_store, mempool, timestamp)
                            .context("local proposer build_next_block failed")?
                    };
                    // D-06: derive the block's signer set per-block from
                    // the keystore × the live Active validator set. A
                    // newly-registered validator whose seed has been
                    // loaded into the keystore contributes a commit sig
                    // on the very next block. An Active validator with
                    // no seed is silently skipped.
                    let active = guard.state.active_validators();
                    let keystore = guard
                        .keystore
                        .read()
                        .expect("keystore RwLock poisoned");
                    let signers = snapshot_block_signers(&keystore, &active);
                    drop(keystore);
                    guard.proposer = Some(proposer);
                    // ADR-051: pick the commit-sig preimage mode once per
                    // block from the live config. Captured into the
                    // spawn_blocking closure below.
                    let preimage_mode = if guard.config.devnet.distributed_signing {
                        pqc_consensus::CommitPreimageMode::Distributed { round: 0 }
                    } else {
                        pqc_consensus::CommitPreimageMode::Legacy
                    };
                    (proposal, signers, preimage_mode)
                }; // lock released before ML-DSA signing

                // Phase 2: compute commit signatures AND observation-mode
                // precommit votes on the blocking thread pool so the tokio
                // runtime can continue processing P2P and sync tasks while
                // ML-DSA signing is in progress. The precommit votes are
                // SPEC-CONSENSUS-001 §8.3 SignedVote objects intended for
                // gossip emit (observation mode only during M1 — no
                // consumer feeds them into a BFT engine yet).
                let block_height = proposal.execution.block.header.height;
                let block_hash_for_sign = proposal.block_hash.clone();
                let block_hash_for_merge = block_hash_for_sign.clone();
                let (sigs, precommit_votes) = tokio::task::spawn_blocking(
                    move || -> Result<(Vec<CommitSig>, Vec<pqc_types::SignedVote>)> {
                        // ADR-051: pick preimage from policy mode.
                        // Distributed mode uses the §8.4 Precommit preimage
                        // — identical bytes to what `build_signed_precommit`
                        // signs, so peer-gossip precommits are zero-copy
                        // usable as commit sigs.
                        let fork_digest = pqc_types::ForkDigest::viper_research_1();
                        let preimage = pqc_consensus::commit_preimage_for_mode(
                            &fork_digest, preimage_mode, block_height, &block_hash_for_sign,
                        );
                        let mut sigs = Vec::with_capacity(signers.len());
                        let mut votes = Vec::with_capacity(signers.len());
                        for signer in &signers {
                            let signature = ml_dsa_sign_with_seed(
                                signer.sig_alg_id,
                                &signer.commit_seed,
                                &preimage,
                            )
                            .context("ML-DSA commit signing failed")?;
                            sigs.push(CommitSig {
                                validator_address: signer.validator_address.clone(),
                                sig_alg_id: signer.sig_alg_id,
                                // ADR-051 / TASK-171: CommitSig carries
                                // the BFT round its signature was
                                // produced at — §10.1 compatibility. In
                                // Legacy mode this field is wire-present
                                // but not preimage-bearing; in
                                // Distributed mode it must match the
                                // `round` used in vote_preimage.
                                round: match preimage_mode {
                                    pqc_consensus::CommitPreimageMode::Legacy => 0,
                                    pqc_consensus::CommitPreimageMode::Distributed { round } => round,
                                },
                                signature,
                            });
                            // Observation-mode precommit vote.
                            // Non-fatal: a sign failure here must NOT block
                            // the block from being finalized, because the
                            // precommit is telemetry-only during M1.
                            match <[u8; 32]>::try_from(signer.validator_address.as_slice()) {
                                Ok(addr) => {
                                    match crate::p2p::build_signed_precommit(
                                        signer.sig_alg_id,
                                        &signer.commit_seed,
                                        addr,
                                        block_height,
                                        block_hash_for_sign.0,
                                    ) {
                                        Ok(v) => votes.push(v),
                                        Err(e) => tracing::warn!(
                                            error = %e,
                                            "precommit vote signing failed (observation)"
                                        ),
                                    }
                                }
                                Err(_) => tracing::warn!(
                                    "validator_address is not 32 bytes; skip precommit emit"
                                ),
                            }
                        }
                        Ok((sigs, votes))
                    },
                )
                .await
                .context("commit signing task panicked")??;
                proposal.execution.block.commit_signatures = sigs;

                // Phase 2.5: ADR-051 distributed-signing — drain
                // pending_precommits from the libp2p buffer into the
                // block's commit_signatures. The peer-gossiped precommits
                // ARE valid CommitSigs (same §8.4 preimage, same bytes).
                merge_distributed_precommits_into_block(
                    &state,
                    &mut proposal.execution.block.commit_signatures,
                    block_height,
                    &block_hash_for_merge,
                    preimage_mode,
                ).await;

                // Phase 3: commit state and persist block — lock held only for
                // state mutation and disk write; validation is skipped because
                // the producer just signed these bytes.
                //
                // `commit_block_preserve_pool` is used instead of `commit_block`
                // so that any transactions injected via `inject_tx` during phase 2
                // (ML-DSA signing) are not silently discarded by the pool
                // replacement that `commit_block` would perform. Pool diff is
                // applied explicitly: included + skipped txs are evicted, and
                // stale nonces are flushed for included senders.
                {
                    let mut guard = state.lock().await;
                    let mut proposer = guard
                        .proposer
                        .take()
                        .ok_or_else(|| anyhow!("producer proposer missing after phase 2"))?;
                    let result = {
                        let LiveNodeState { state: state_store, mempool, .. } = &mut *guard;
                        let result = proposer
                            .commit_block_preserve_pool(state_store, proposal)
                            .context("local proposer commit_block_preserve_pool failed")?;
                        // Apply pool diff: evict processed txs, preserve injected.
                        for tx_hash in &result.included {
                            mempool.evict(&tx_hash.0);
                        }
                        for skipped in &result.skipped {
                            mempool.evict(&skipped.tx_hash.0);
                        }
                        for tx in &result.included_transactions {
                            mempool.evict_stale(&tx.sender.0, tx.nonce.saturating_add(1));
                        }
                        result
                    };
                    guard.proposer = Some(proposer);
                    guard
                        .disk
                        .append_block_trusted(&result)
                        .context("persisting produced block failed")?;
                    guard.last_sync_error = None;
                    guard.blocks_produced += 1;
                    // Write a trusted checkpoint every CHECKPOINT_INTERVAL blocks.
                    // The checkpoint bounds in-memory ChainStore growth on the next startup:
                    // only blocks after the checkpoint height are loaded into RAM.
                    if block_height.is_multiple_of(CHECKPOINT_INTERVAL) {
                        match guard.disk.write_trusted_checkpoint(&guard.state) {
                            Ok(meta) => {
                                guard.disk.compact_chain_to_checkpoint(meta.height, meta.tip_hash);
                                tracing::info!(
                                    checkpoint_height = meta.height,
                                    "trusted checkpoint written"
                                );
                            }
                            Err(e) => tracing::warn!(
                                error = %e,
                                "failed to write trusted checkpoint (non-fatal)"
                            ),
                        }
                    }
                    tracing::info!(
                        height = block_height,
                        included = result.included.len(),
                        skipped = result.skipped.len(),
                        "block produced and committed"
                    );
                    tracing::info!(
                        target: "viper.audit",
                        event = "block_finalized",
                        height = block_height,
                        block_hash = %hex::encode(pqc_consensus::engine::compute_block_hash(&result.block).0),
                        included_tx_count = result.included.len(),
                    );
                } // lock released

                // Phase 4: emit block gossip (TASK-135 step 1, observation mode).
                // Runs AFTER block persistence so we never emit a body for a
                // block that failed to commit. Mirrors the precommit path —
                // zero production impact when libp2p is disabled because
                // publish_if_enabled is a no-op.
                emit_block_gossip(&state, block_height).await;

                // Phase 6: archival submissions at epoch boundary (TASK-163 /
                // M4.4). No-op off-boundary; at a boundary, each eligible
                // signer on this node submits an ArchivalRecordSubmit for
                // the just-closed epoch. Runs AFTER block persistence so the
                // chain store already has the closing block's metadata.
                emit_archival_submissions_if_epoch_boundary(&state, block_height).await;

                // Phase 6b: rotate the long-term ML-KEM identity-keypair
                // (Gap B / `PHASE-4-KEY-ROTATION-RESEARCH.md` §2.4). No-op
                // off-boundary. At a boundary, the keypair is re-derived
                // from `(node_id, salt, new_epoch_number)` and the prior
                // keypair slides into the one-epoch grace window. Already-
                // established sessions (in `p2p_sessions`) are unaffected.
                rotate_kem_if_epoch_boundary(&state, block_height).await;

                // Phase 5: emit precommit gossip (observation mode).
                // Runs AFTER block persistence so we never emit a vote for a
                // block that failed to commit. Zero production impact when
                // libp2p is disabled — publish_if_enabled is a no-op.
                emit_precommit_votes(&state, &precommit_votes).await;

                // Phase 7: emit sync-committee compact-header attestations
                // (SPEC-LIGHT-CLIENT-001 §4). No-op when libp2p is off OR
                // when the local node holds no committee-member seed for
                // the current epoch. Runs AFTER block persistence so the
                // compact header reflects the just-finalized block.
                emit_light_client_attestation_if_committee_member(&state, block_height).await;
            }
        }
    }

    Ok(())
}

/// BFT consensus loop with proposer rotation (SPEC-CONSENSUS-001 §5, TASK-084).
///
/// Functionally identical to `producer_loop` except that the block `proposer`
/// field in each block header is set to the validator selected by
/// `select_proposer(validators, height, round)` rather than a fixed address.
///
/// This implements SPEC-CONSENSUS-001 §13 Phase B/C: the consensus engine uses
/// the round-robin proposer selection formula while still collecting all commit
/// signatures locally (single-node BFT simulation until full P2P vote exchange
/// is implemented in TASK-085).
///
/// For multi-validator single-node test setups, this allows the block headers
/// to carry rotating proposer addresses that match the spec formula, making the
/// proposer rotation property testable without a real P2P layer.
// Phase 8 M2 Step 3 (TASK-113): `validator_addresses` is NOT captured
// at spawn time. Each iteration queries `state.active_validators()`
// under the same lock guard it already holds for block production,
// so a validator that activates at an epoch boundary appears in the
// proposer rotation on the very next block.
pub(super) async fn consensus_loop(
    state: SharedLiveNodeState,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let block_time_ms = {
        let guard = state.lock().await;
        guard.config.devnet.block_time_ms.max(1)
    };
    let mut ticker = time::interval(Duration::from_millis(block_time_ms));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => break,
            _ = ticker.tick() => {
                let timestamp = next_block_timestamp();

                // TASK-219d / L3 — `attack_mode = "ReplayFinalizedBlock"` injection.
                // Once per tick, if this node is malicious AND has at least
                // 6 finalized blocks on disk, re-emit a sealed block from
                // height `current_height - 5` as if it were new. Honest
                // peers reject the replay via the
                // `BlockInboundClass::BelowFinalized` path in
                // `handle_inbound_block`. The replay is gossip-only (no
                // local state mutation) so it never disturbs this node's
                // own consensus progress. Feature-gated; release builds
                // skip the entire branch.
                #[cfg(feature = "attack-modes")]
                {
                    let replay_payload = {
                        let guard = state.lock().await;
                        if guard.config.devnet.attack_mode.as_deref()
                            == Some("ReplayFinalizedBlock")
                        {
                            let h = guard.disk.height();
                            if h > 5 {
                                let target_height = h - 5;
                                match guard
                                    .disk
                                    .read_stored_block_at_height(target_height)
                                {
                                    Ok(Some(stored)) => match
                                        pqc_consensus::RocksDbChainStore::encode_block_bytes(&stored)
                                    {
                                        Ok(bytes) => Some((
                                            guard.config.chain_id_hex.clone(),
                                            guard.p2p_handle.clone(),
                                            bytes,
                                            target_height,
                                            stored.metadata.block_hash.clone(),
                                        )),
                                        Err(e) => {
                                            tracing::warn!(
                                                error = %e,
                                                target_height,
                                                "[ATTACK MODE: ReplayFinalizedBlock] encode failed (non-fatal)"
                                            );
                                            None
                                        }
                                    },
                                    Ok(None) => None,
                                    Err(e) => {
                                        tracing::warn!(
                                            error = %e,
                                            target_height,
                                            "[ATTACK MODE: ReplayFinalizedBlock] disk read failed (non-fatal)"
                                        );
                                        None
                                    }
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    };
                    if let Some((chain_id, handle, bytes, target_height, target_hash)) =
                        replay_payload
                    {
                        tracing::warn!(
                            target_height,
                            block_hash = %hex::encode(target_hash.0),
                            "[ATTACK MODE: ReplayFinalizedBlock] re-emitting sealed block from H-5"
                        );
                        let envelope = crate::p2p::block_envelope(&chain_id, bytes);
                        crate::p2p::publish_if_enabled(handle.as_ref(), envelope).await;
                    }
                }

                // Phase 0: D-06 keystore reload (see `producer_loop` for
                // rationale). Runs BEFORE the per-block signer snapshot
                // so a freshly-staged keystore file is visible to the
                // same block it gates on.
                refresh_keystore_from_file(&state).await;

                // Phase 1: compute proposer rotation and build block candidate.
                let (mut proposal, signers, preimage_mode) = {
                    let mut guard = state.lock().await;

                    // Snapshot the active validator set for THIS iteration
                    // (see M2 plan §3.2). `active_validators()` already
                    // sorts by operator address deterministically; we
                    // clone into an owned Vec so the subsequent
                    // proposer `take()` / `build_next_block` calls can
                    // re-borrow `guard` mutably — the signer snapshot at
                    // the end of this block reads from the clone.
                    let active_records: Vec<pqc_types::validator::ValidatorRecord> = guard
                        .state
                        .active_validators()
                        .iter()
                        .map(|v| (*v).clone())
                        .collect();
                    let validator_addresses: Vec<[u8; 32]> = active_records
                        .iter()
                        .map(|v| v.operator.0)
                        .collect();

                    if validator_addresses.is_empty() {
                        // Pre-genesis-seed boot window or a state that
                        // has lost every Active validator — nothing to
                        // rotate over. Skip this tick; the next
                        // apply_block that seeds a validator will
                        // unblock us.
                        continue;
                    }

                    // Determine the next height and select the proposer for it.
                    let next_height = guard.state.block_height().saturating_add(1);
                    let proposer_addr = if validator_addresses.len() > 1 {
                        select_proposer(&validator_addresses, next_height, 0, None)
                            .unwrap_or(validator_addresses[0])
                    } else {
                        // Single-validator: use the only address.
                        validator_addresses[0]
                    };

                    let proposer = guard
                        .proposer
                        .take()
                        .ok_or_else(|| anyhow!("consensus loop started without proposer"))?;

                    // ADR-051 / TASK-167 Step 2 — per-role proposer dispatch.
                    // In distributed_signing mode, non-proposer validators
                    // stay quiescent this tick — no block build, no emit.
                    // They'll respond to the elected proposer's block via
                    // handle_inbound_block (Step 3). Legacy mode is a
                    // pass-through so devnet-2 current behaviour is
                    // unchanged.
                    let keystore_guard = guard
                        .keystore
                        .read()
                        .expect("keystore RwLock poisoned");
                    if !should_build_as_proposer(
                        guard.config.devnet.distributed_signing,
                        &validator_addresses,
                        next_height,
                        0,
                        &keystore_guard,
                    ) {
                        drop(keystore_guard);
                        tracing::debug!(
                            next_height,
                            proposer = %hex::encode(proposer_addr),
                            "distributed-signing: not proposer this tick, skipping block build"
                        );
                        guard.proposer = Some(proposer);
                        continue;
                    }

                    // Apply proposer rotation before building.
                    let mut proposer = proposer;
                    proposer.set_proposer(proposer_addr);

                    // TASK-219b / L3 — `attack_mode = "InvalidParentHash"` injection.
                    // We are the elected proposer for this height (the
                    // `should_build_as_proposer` gate above returned true).
                    // Corrupt the proposer's tip_hash with all-0xFF bytes so
                    // the upcoming `build_next_block` produces a header whose
                    // `prev_hash` does NOT match any known block. Honest
                    // peers reject the resulting block via the
                    // `PARENT_HASH_MISMATCH` path in `handle_inbound_block`
                    // / `engine.rs`. Feature-gated; release builds skip the
                    // corruption entirely. Test fixture:
                    // `crates/pqcd/tests/malicious_node.rs`.
                    #[cfg(feature = "attack-modes")]
                    if guard.config.devnet.attack_mode.as_deref()
                        == Some("InvalidParentHash")
                    {
                        tracing::warn!(
                            next_height,
                            proposer = %hex::encode(proposer_addr),
                            "[ATTACK MODE: InvalidParentHash] corrupting tip_hash to [0xFF; 32] before build_next_block"
                        );
                        proposer.advance_tip(BlockHash([0xFF; 32]));
                    }

                    let proposal = {
                        // Drop the keystore guard before reborrowing `guard` mutably
                        // for build_next_block. The guard was only needed for the
                        // `should_build_as_proposer` gate above.
                        drop(keystore_guard);
                        let LiveNodeState { state: state_store, mempool, .. } = &mut *guard;
                        proposer
                            .build_next_block(state_store, mempool, timestamp)
                            .context("consensus proposer build_next_block failed")?
                    };
                    // D-06: derive signers from keystore × active set.
                    let keystore = guard
                        .keystore
                        .read()
                        .expect("keystore RwLock poisoned");
                    let active_refs: Vec<&pqc_types::validator::ValidatorRecord> =
                        active_records.iter().collect();
                    let signers = snapshot_block_signers(&keystore, &active_refs);
                    drop(keystore);
                    guard.proposer = Some(proposer);
                    // ADR-051 preimage mode (mirror of producer_loop phase 1).
                    let preimage_mode = if guard.config.devnet.distributed_signing {
                        pqc_consensus::CommitPreimageMode::Distributed { round: 0 }
                    } else {
                        pqc_consensus::CommitPreimageMode::Legacy
                    };
                    (proposal, signers, preimage_mode)
                };

                // Phase 2: sign commit material AND observation-mode precommit
                // votes off the tokio runtime. Symmetrical with producer_loop —
                // see that loop's phase 2 for why the precommit emit is
                // non-fatal on per-signer failure.
                let block_height = proposal.execution.block.header.height;
                let block_hash_for_sign = proposal.block_hash.clone();
                let block_hash_for_merge = block_hash_for_sign.clone();
                let (sigs, precommit_votes) = tokio::task::spawn_blocking(
                    move || -> Result<(Vec<pqc_types::block::CommitSig>, Vec<pqc_types::SignedVote>)> {
                        let fork_digest = pqc_types::ForkDigest::viper_research_1();
                        let preimage = pqc_consensus::commit_preimage_for_mode(
                            &fork_digest, preimage_mode, block_height, &block_hash_for_sign,
                        );
                        let mut sigs = Vec::with_capacity(signers.len());
                        let mut votes = Vec::with_capacity(signers.len());
                        for signer in &signers {
                            let signature = ml_dsa_sign_with_seed(
                                signer.sig_alg_id,
                                &signer.commit_seed,
                                &preimage,
                            )
                            .context("ML-DSA commit signing failed")?;
                            sigs.push(pqc_types::block::CommitSig {
                                validator_address: signer.validator_address.clone(),
                                sig_alg_id: signer.sig_alg_id,
                                // ADR-051 / TASK-171 — see producer_loop
                                // phase 2 equivalent for rationale.
                                round: match preimage_mode {
                                    pqc_consensus::CommitPreimageMode::Legacy => 0,
                                    pqc_consensus::CommitPreimageMode::Distributed { round } => round,
                                },
                                signature,
                            });
                            match <[u8; 32]>::try_from(signer.validator_address.as_slice()) {
                                Ok(addr) => {
                                    match crate::p2p::build_signed_precommit(
                                        signer.sig_alg_id,
                                        &signer.commit_seed,
                                        addr,
                                        block_height,
                                        block_hash_for_sign.0,
                                    ) {
                                        Ok(v) => votes.push(v),
                                        Err(e) => tracing::warn!(
                                            error = %e,
                                            "precommit vote signing failed (observation)"
                                        ),
                                    }
                                }
                                Err(_) => tracing::warn!(
                                    "validator_address is not 32 bytes; skip precommit emit"
                                ),
                            }
                        }
                        Ok((sigs, votes))
                    },
                )
                .await
                .context("consensus commit signing task panicked")??;
                proposal.execution.block.commit_signatures = sigs;

                // Phase 2a: ADR-051 / TASK-167 Step 4 — emit PROPOSAL
                // gossip with just the proposer's own sig so peers can
                // see the block, sign their own Precommit, and gossip
                // back. No-op in legacy mode.
                emit_block_proposal_gossip_if_distributed(
                    &state,
                    &proposal,
                    preimage_mode,
                ).await;

                // TASK-219c / L3 — `attack_mode = "DoubleProposeAtHeight"` injection.
                // After the honest proposal has been gossiped, build a SECOND
                // distinct block at the same height with `state_root` mutated
                // to `[0xCC; 32]`, recompute the block_hash, re-sign the new
                // commit material with this proposer's keystore seed(s), and
                // emit again. This drives the equivocation-evidence path
                // (TASK-213): honest peers detect the double-sign, surface
                // an `EquivocationEvidence` tx, and slash 5 % of the
                // malicious validator's bonded stake per ADR-024. Feature-
                // gated; no-op in release builds.
                #[cfg(feature = "attack-modes")]
                {
                    let is_double_propose = {
                        let guard = state.lock().await;
                        guard.config.devnet.attack_mode.as_deref()
                            == Some("DoubleProposeAtHeight")
                    };
                    if is_double_propose
                        && matches!(
                            preimage_mode,
                            pqc_consensus::CommitPreimageMode::Distributed { .. }
                        )
                    {
                        // Build a twin block by cloning the inner pieces of
                        // the original `proposal` (ProposedBlock itself is
                        // not Clone — its private next_state / next_pool
                        // fields are not exposed). For the gossip-only
                        // equivocation emit we only need the Block,
                        // execution metadata, and a re-signed
                        // commit_signatures vec — no state-store update.
                        let mut twin_block = proposal.execution.block.clone();
                        twin_block.header.state_root = BlockHash([0xCC; 32]);
                        let twin_hash = pqc_consensus::compute_block_hash(&twin_block);
                        let twin_height = twin_block.header.height;
                        let twin_included_transactions =
                            proposal.execution.included_transactions.clone();
                        let twin_state_root_meta = BlockHash([0xCC; 32]);
                        let twin_tx_root = proposal.execution.tx_root.clone();
                        let twin_prev_hash = twin_block.header.prev_hash.clone();
                        let twin_timestamp = twin_block.header.timestamp;
                        let twin_bytes_used = proposal.execution.bytes_used;
                        let twin_included_count = proposal.execution.included.len();
                        let twin_deferred_count = proposal.execution.deferred.len();
                        let twin_skipped_count = proposal.execution.skipped.len();
                        let twin_vc_budget = proposal.execution.vc_budget_consumed;
                        // Snapshot signers fresh from the keystore × active
                        // set; the original `signers` Vec was moved into
                        // the spawn_blocking task above and is no longer in
                        // scope here.
                        let twin_signers: Vec<LocalCommitSigner> = {
                            let guard = state.lock().await;
                            let active = guard.state.active_validators();
                            let active_records: Vec<
                                pqc_types::validator::ValidatorRecord,
                            > = active.iter().map(|v| (*v).clone()).collect();
                            let keystore_guard = guard
                                .keystore
                                .read()
                                .expect("keystore RwLock poisoned");
                            let active_refs: Vec<
                                &pqc_types::validator::ValidatorRecord,
                            > = active_records.iter().collect();
                            snapshot_block_signers(&keystore_guard, &active_refs)
                        };
                        let twin_hash_for_sign = twin_hash.clone();
                        let twin_sigs = match tokio::task::spawn_blocking(
                            move || -> Result<Vec<pqc_types::block::CommitSig>> {
                                let fork_digest =
                                    pqc_types::ForkDigest::viper_research_1();
                                let preimage = pqc_consensus::commit_preimage_for_mode(
                                    &fork_digest,
                                    preimage_mode,
                                    twin_height,
                                    &twin_hash_for_sign,
                                );
                                let mut sigs = Vec::with_capacity(twin_signers.len());
                                for signer in &twin_signers {
                                    let signature = ml_dsa_sign_with_seed(
                                        signer.sig_alg_id,
                                        &signer.commit_seed,
                                        &preimage,
                                    )
                                    .context("ML-DSA twin commit signing failed")?;
                                    sigs.push(pqc_types::block::CommitSig {
                                        validator_address: signer
                                            .validator_address
                                            .clone(),
                                        sig_alg_id: signer.sig_alg_id,
                                        round: match preimage_mode {
                                            pqc_consensus::CommitPreimageMode::Legacy => 0,
                                            pqc_consensus::CommitPreimageMode::Distributed {
                                                round,
                                            } => round,
                                        },
                                        signature,
                                    });
                                }
                                Ok(sigs)
                            },
                        )
                        .await
                        {
                            Ok(Ok(sigs)) => sigs,
                            Ok(Err(e)) => {
                                tracing::warn!(
                                    error = %e,
                                    "[ATTACK MODE: DoubleProposeAtHeight] twin re-sign failed; \
                                     skipping equivocation emit (non-fatal)"
                                );
                                Vec::new()
                            }
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    "[ATTACK MODE: DoubleProposeAtHeight] twin re-sign task panicked; \
                                     skipping equivocation emit (non-fatal)"
                                );
                                Vec::new()
                            }
                        };
                        if !twin_sigs.is_empty() {
                            twin_block.commit_signatures = twin_sigs;
                            tracing::warn!(
                                height = twin_height,
                                original_block_hash = %hex::encode(proposal.block_hash.0),
                                twin_block_hash = %hex::encode(twin_hash.0),
                                "[ATTACK MODE: DoubleProposeAtHeight] emitting twin block to drive equivocation evidence"
                            );
                            // Inline the gossip-emit body of
                            // `emit_block_proposal_gossip_if_distributed`,
                            // since we cannot construct a `ProposedBlock`
                            // from the outside (private fields).
                            let (chain_id, handle, encoded) = {
                                let guard = state.lock().await;
                                if guard.p2p_handle.is_none() {
                                    (String::new(), None, None)
                                } else {
                                    let stored = pqc_consensus::StoredBlock {
                                        block: twin_block.clone(),
                                        metadata: pqc_consensus::BlockMetadata {
                                            block_hash: twin_hash.clone(),
                                            height: twin_height,
                                            prev_hash: twin_prev_hash,
                                            state_root: twin_state_root_meta,
                                            tx_root: twin_tx_root,
                                            timestamp: twin_timestamp,
                                            bytes_used: twin_bytes_used,
                                            included_count: twin_included_count,
                                            deferred_count: twin_deferred_count,
                                            skipped_count: twin_skipped_count,
                                            vc_budget_consumed: twin_vc_budget,
                                        },
                                        included_transactions: twin_included_transactions,
                                    };
                                    match pqc_consensus::RocksDbChainStore::encode_block_bytes(
                                        &stored,
                                    ) {
                                        Ok(bytes) => (
                                            guard.config.chain_id_hex.clone(),
                                            guard.p2p_handle.clone(),
                                            Some(bytes),
                                        ),
                                        Err(e) => {
                                            tracing::warn!(
                                                error = %e,
                                                "[ATTACK MODE: DoubleProposeAtHeight] failed to encode twin (non-fatal)"
                                            );
                                            (String::new(), None, None)
                                        }
                                    }
                                }
                            };
                            if let (Some(handle), Some(bytes)) = (handle, encoded) {
                                let envelope = crate::p2p::block_envelope(&chain_id, bytes);
                                crate::p2p::publish_if_enabled(Some(&handle), envelope).await;
                            }
                        }
                    }
                }

                // Phase 2b: sleep for distributed_signing_quorum_wait_ms.
                // During this window, peer precommits flow through the
                // libp2p inbound path into `pending_precommits`, ready
                // to be drained in phase 2.5. In legacy mode the wait
                // is zero — we do not need peer sigs.
                let quorum_wait_ms =
                    if matches!(preimage_mode, pqc_consensus::CommitPreimageMode::Distributed { .. }) {
                        let guard = state.lock().await;
                        guard.config.devnet.distributed_signing_quorum_wait_ms
                    } else {
                        0
                    };
                if quorum_wait_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(quorum_wait_ms)).await;
                }

                // Phase 2.5: ADR-051 distributed-signing — drain peer
                // precommits into block.commit_signatures (mirror of
                // producer_loop phase 2.5).
                merge_distributed_precommits_into_block(
                    &state,
                    &mut proposal.execution.block.commit_signatures,
                    block_height,
                    &block_hash_for_merge,
                    preimage_mode,
                ).await;

                // Phase 2c: threshold check. In distributed-signing
                // mode, if the collected sigs do not reach the quorum
                // threshold, DROP this proposal and let the next tick
                // retry — do not persist a partial block. In legacy
                // mode the block inherently carries all needed sigs,
                // so this check is skipped.
                if matches!(preimage_mode, pqc_consensus::CommitPreimageMode::Distributed { .. }) {
                    let threshold_met = {
                        let guard = state.lock().await;
                        let policy =
                            pqc_consensus::CommitQuorumPolicy::from_state_store(&guard.state, None)
                                .expect("StateStore yields a valid CommitQuorumPolicy");
                        match policy {
                            None => false,
                            Some(p) => {
                                proposal.execution.block.commit_signatures.len()
                                    >= p.quorum_threshold()
                            }
                        }
                    };
                    if !threshold_met {
                        tracing::warn!(
                            block_height,
                            block_hash = %hex::encode(block_hash_for_merge.0),
                            sig_count = proposal.execution.block.commit_signatures.len(),
                            "distributed-signing: quorum not reached within wait window, dropping proposal; next tick retries"
                        );
                        // Drop the proposal; the next tick will select
                        // the proposer for the same height again and
                        // rebuild. Multi-round retry with incrementing
                        // round is the SPEC-CONSENSUS-001 §12 follow-up.
                        continue;
                    }
                }

                // Phase 3: commit and persist.
                {
                    let mut guard = state.lock().await;
                    let mut proposer = guard
                        .proposer
                        .take()
                        .ok_or_else(|| anyhow!("consensus proposer missing after phase 2"))?;
                    let result = {
                        let LiveNodeState { state: state_store, mempool, .. } = &mut *guard;
                        let result = proposer
                            .commit_block_preserve_pool(state_store, proposal)
                            .context("consensus commit_block_preserve_pool failed")?;
                        for tx_hash in &result.included {
                            mempool.evict(&tx_hash.0);
                        }
                        for skipped in &result.skipped {
                            mempool.evict(&skipped.tx_hash.0);
                        }
                        for tx in &result.included_transactions {
                            mempool.evict_stale(&tx.sender.0, tx.nonce.saturating_add(1));
                        }
                        result
                    };
                    guard.proposer = Some(proposer);
                    guard
                        .disk
                        .append_block_trusted(&result)
                        .context("consensus: persisting produced block failed")?;
                    guard.last_sync_error = None;
                    guard.blocks_produced += 1;
                    if block_height.is_multiple_of(CHECKPOINT_INTERVAL) {
                        match guard.disk.write_trusted_checkpoint(&guard.state) {
                            Ok(meta) => {
                                guard.disk.compact_chain_to_checkpoint(meta.height, meta.tip_hash);
                                tracing::info!(
                                    checkpoint_height = meta.height,
                                    "trusted checkpoint written"
                                );
                            }
                            Err(e) => tracing::warn!(
                                error = %e,
                                "failed to write trusted checkpoint (non-fatal)"
                            ),
                        }
                    }
                    tracing::info!(
                        height = block_height,
                        included = result.included.len(),
                        skipped = result.skipped.len(),
                        "block committed (consensus loop, proposer rotated)",
                    );
                    tracing::info!(
                        target: "viper.audit",
                        event = "block_finalized",
                        height = block_height,
                        block_hash = %hex::encode(pqc_consensus::engine::compute_block_hash(&result.block).0),
                        included_tx_count = result.included.len(),
                    );
                }

                // Phase 4: emit block gossip (TASK-135 step 1, observation mode).
                // Symmetrical with producer_loop — see that loop for rationale.
                emit_block_gossip(&state, block_height).await;

                // Phase 6: archival submissions at epoch boundary (TASK-163 /
                // M4.4). Mirror of producer_loop's phase 6.
                emit_archival_submissions_if_epoch_boundary(&state, block_height).await;

                // Phase 6b: rotate the long-term ML-KEM identity-keypair —
                // mirror of producer_loop's phase 6b. See that loop's
                // comment for the full rationale (Gap B,
                // `PHASE-4-KEY-ROTATION-RESEARCH.md` §2.4).
                rotate_kem_if_epoch_boundary(&state, block_height).await;

                // Phase 5: emit precommit gossip (observation mode).
                // Symmetrical with producer_loop — see that loop for rationale.
                emit_precommit_votes(&state, &precommit_votes).await;

                // Phase 7: emit sync-committee compact-header attestations
                // (SPEC-LIGHT-CLIENT-001 §4). Mirror of producer_loop's
                // phase 7 — see that loop for rationale.
                emit_light_client_attestation_if_committee_member(&state, block_height).await;
            }
        }
    }

    Ok(())
}
