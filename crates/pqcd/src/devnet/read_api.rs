// SPDX-License-Identifier: BUSL-1.1
//! Public Read API endpoints (`GET /v1/...`) for the devnet HTTP server.
//!
//! Extracted from `devnet.rs` 2026-05-10 as the largest single slice of
//! the M-effort split (CONCERNS.md "[MEDIUM] devnet.rs is 7,247 lines").
//! All handlers are read-only against `LiveNodeState` (lock + render),
//! plus the helper formatters (lifecycle_str, validator_status_str,
//! proposal_status_str, parse_address_hex, parse_tx_hash_hex,
//! proposal_to_json, alg_entry_to_json) that only the Read endpoints
//! depend on.
//!
//! `handle_tx_submit` (the one POST endpoint at /v1/txs) lives in
//! sibling `tx_submit.rs` because it has its own request/response
//! shapes + per-IP rate-limit + admission pipeline plumbing.

use axum::{
    extract::{Path as AxumPath, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use pqc_tx::{codec::encode_tx, compute_tx_hash};

use super::SharedLiveNodeState;

/// GET /v1/status — returns chain tip height, chain ID, state root, and node health.
/// Used by the block explorer to determine ONLINE/OFFLINE status.
pub(super) async fn handle_status(State(state): State<SharedLiveNodeState>) -> Response {
    let guard = state.lock().await;
    let height = guard.state.block_height();
    let chain_id = String::from_utf8_lossy(guard.state.chain_id()).to_string();
    let state_root = hex::encode(guard.state.state_root());
    let tip_hash = guard
        .disk
        .tip_hash()
        .map(|h| hex::encode(h.0))
        .unwrap_or_default();
    let base_fee = guard.state.fee_market.compute.base_fee;
    let epoch_length_blocks = guard.config.devnet.epoch_duration;
    let epoch_number = pqc_consensus::epoch::epoch_for_height(height, epoch_length_blocks);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "height": height,
            "chain_id": chain_id,
            "state_root": state_root,
            "tip_hash": tip_hash,
            "node_id": guard.config.node_id,
            "syncing": false,
            "base_fee": base_fee,
            "epoch_number": epoch_number,
            "epoch_length_blocks": epoch_length_blocks,
        })),
    )
        .into_response()
}

/// GET /v1/fee-market — returns the current EIP-4844 multi-dim fee
/// market state (ADR-053 §T2.1 / SPEC-FEE-002 revised §11).
///
/// Response fields:
/// - `base_fee`: compute-dim base fee (backward-compat alias)
/// - `block_gas_limit`: compute-dim hard cap per block
/// - `burn_rate_bps`: burn rate in basis points
/// - `compute`, `storage`, `witness`, `contention`: per-dimension
///   `{base_fee, limit, target, excess, reserve_floor, update_fraction}`
///   (reserved dims carry `target = 0` until a future P-COMPAT-001
///   upgrade activates them).
pub(super) async fn handle_fee_market(State(state): State<SharedLiveNodeState>) -> Response {
    let guard = state.lock().await;
    let fm = &guard.state.fee_market;
    fn dim_json(d: &pqc_state::FeeMarketDimension) -> serde_json::Value {
        serde_json::json!({
            "base_fee": d.base_fee,
            "limit": d.limit,
            "target": d.target,
            "excess": d.excess,
            "reserve_floor": d.reserve_floor,
            "update_fraction": d.update_fraction,
        })
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "base_fee": fm.compute.base_fee,
            "block_gas_limit": fm.compute.limit,
            "burn_rate_bps": fm.burn_rate_bps,
            "compute": dim_json(&fm.compute),
            "storage": dim_json(&fm.storage),
            "witness": dim_json(&fm.witness),
            "contention": dim_json(&fm.contention),
        })),
    )
        .into_response()
}

/// GET /v1/archival/records — list all archival records (SPEC-ARCHIVAL-001 §4.4).
///
/// Query params:
///   - `since`: return only records with `epoch_number >= since` (default 0)
///   - `limit`: cap the number of returned records (default 256, max 4096)
///
/// Used by the M4.5 TSA sidecar (TASK-164) to find freshly-admitted records
/// that still need external anchoring.
pub(super) async fn handle_archival_records_list(
    State(state): State<SharedLiveNodeState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let since: u64 = params
        .get("since")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let limit: usize = params
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(256)
        .min(4096);
    let guard = state.lock().await;
    let records: Vec<serde_json::Value> = guard
        .state
        .archival_records_in_order()
        .into_iter()
        .filter(|r| r.epoch_number >= since)
        .take(limit)
        .map(|r| {
            serde_json::json!({
                "epoch_number":              r.epoch_number,
                "epoch_root":                hex::encode(r.epoch_root),
                "signer_addresses":          r.signer_addresses.iter().map(hex::encode).collect::<Vec<_>>(),
                "slh_signatures_count":      r.slh_signatures.len(),
                "timestamp_anchors_count":   r.timestamp_anchors.len(),
                "evidence_record_version":   r.evidence_record_version,
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({ "records": records })),
    )
        .into_response()
}

/// GET /v1/archival/records/:epoch — return a single archival record by epoch.
pub(super) async fn handle_archival_record_by_epoch(
    AxumPath(epoch): AxumPath<u64>,
    State(state): State<SharedLiveNodeState>,
) -> Response {
    let guard = state.lock().await;
    match guard.state.get_archival_record(epoch) {
        Some(r) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "epoch_number":              r.epoch_number,
                "epoch_root":                hex::encode(r.epoch_root),
                "signer_addresses":          r.signer_addresses.iter().map(hex::encode).collect::<Vec<_>>(),
                "slh_signatures":            r.slh_signatures.iter().map(hex::encode).collect::<Vec<_>>(),
                "timestamp_anchors":         r.timestamp_anchors.iter().map(|a| serde_json::json!({
                    "kind":             a.kind.as_u8(),
                    "external_hash":    hex::encode(&a.external_hash),
                    "posted_at_height": a.posted_at_height,
                })).collect::<Vec<_>>(),
                "evidence_record_version":   r.evidence_record_version,
            })),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "archival record not found",
                "epoch_number": epoch,
            })),
        )
            .into_response(),
    }
}

/// GET /v1/validators — returns all registered validators.
/// Used by the block explorer Validators tab.
pub(super) async fn handle_validators(State(state): State<SharedLiveNodeState>) -> Response {
    let guard = state.lock().await;
    let validators: Vec<serde_json::Value> = guard
        .state
        .validators_in_order()
        .into_iter()
        .map(|v| {
            let status_str = match &v.status {
                pqc_types::ValidatorStatus::Candidate => "candidate",
                pqc_types::ValidatorStatus::Active => "active",
                pqc_types::ValidatorStatus::Jailed => "jailed",
                pqc_types::ValidatorStatus::Unbonding { .. } => "unbonding",
                pqc_types::ValidatorStatus::Exited => "exited",
            };
            // ADR-047 on-chain libp2p PeerId binding. `null` for validators
            // that have not yet bound a PeerId (D-03 deferred-to-M2; today
            // every viper-pq-1 validator returns null until the rotation
            // cron fires). Hex-encoded multihash when set, suitable for
            // `pqcd peer-id`-style comparison.
            let peer_id = guard
                .state
                .get_validator_peer_id(&v.operator)
                .map(hex::encode);
            serde_json::json!({
                "address": hex::encode(v.operator.0),
                "node_id": v.node_id,
                "consensus_alg_id": v.consensus_alg_id.as_u16(),
                "status": status_str,
                "self_bond": v.self_bond.to_string(),
                "registered_height": v.registered_height,
                "peer_id_hex": peer_id,
            })
        })
        .collect();
    (StatusCode::OK, Json(serde_json::json!(validators))).into_response()
}

// ── Helpers for the API.md "Public Read API" endpoints ─────────────────────

pub(super) fn lifecycle_str(lc: pqc_crypto::Lifecycle) -> &'static str {
    match lc {
        pqc_crypto::Lifecycle::Active => "active",
        pqc_crypto::Lifecycle::Discouraged => "discouraged",
        pqc_crypto::Lifecycle::Deprecated => "deprecated",
        pqc_crypto::Lifecycle::Banned => "banned",
    }
}

pub(super) fn alg_entry_to_json(e: &pqc_crypto::registry::AlgEntry) -> serde_json::Value {
    // Public algorithm-registry response — DELIBERATELY redacted:
    // - `benchmark_verify_per_sec`: hardware-calibration constant; an external
    //   client gains nothing from it but a competitor profiling our reference
    //   bench machine learns our cost model.
    // - `min_fee`: economic-calibration scalar; same logic — public clients
    //   read the live `/v1/fee-market` for the per-dimension base fees they
    //   actually need to pay, and `min_fee` per algorithm is an internal
    //   floor that operators can re-tune via governance without the public
    //   needing to know.
    //
    // Public clients (notary, explorer, SDK 0.3.0+ typed methods) get
    // exactly the fields they need to encode a tx against the right algorithm
    // and to display lifecycle status; nothing more. Auditor / operator
    // surfaces with the full record live behind /internal/* (not exposed
    // by the devnet-serve nginx vhost).
    serde_json::json!({
        "alg_id": e.alg_id.as_u16(),
        "spec_ref": e.spec_ref.as_ref(),
        "pk_size": e.pk_size,
        "sig_size": e.sig_size,
        "sig_class": e.sig_class.map(|c| match c {
            pqc_crypto::SigClass::Reduced => "reduced",
            pqc_crypto::SigClass::Standard => "standard",
            pqc_crypto::SigClass::Premium => "premium",
        }),
        "lifecycle": lifecycle_str(e.lifecycle),
    })
}

pub(super) fn validator_status_str(s: &pqc_types::ValidatorStatus) -> &'static str {
    match s {
        pqc_types::ValidatorStatus::Candidate => "candidate",
        pqc_types::ValidatorStatus::Active => "active",
        pqc_types::ValidatorStatus::Jailed => "jailed",
        pqc_types::ValidatorStatus::Unbonding { .. } => "unbonding",
        pqc_types::ValidatorStatus::Exited => "exited",
    }
}

pub(super) fn proposal_status_str(s: pqc_types::governance::ProposalStatus) -> &'static str {
    match s {
        pqc_types::governance::ProposalStatus::Voting => "voting",
        pqc_types::governance::ProposalStatus::Executed => "executed",
        pqc_types::governance::ProposalStatus::Expired => "expired",
        pqc_types::governance::ProposalStatus::Rejected => "rejected",
        pqc_types::governance::ProposalStatus::ExecutionFailed => "execution_failed",
    }
}

pub(super) fn parse_address_hex(hex_str: &str) -> Option<pqc_types::account::Address> {
    let b = hex::decode(hex_str).ok()?;
    if b.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&b);
    Some(pqc_types::account::Address(arr))
}

pub(super) fn parse_tx_hash_hex(hex_str: &str) -> Option<pqc_types::transaction::TxHash> {
    let b = hex::decode(hex_str).ok()?;
    if b.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&b);
    Some(pqc_types::transaction::TxHash(arr))
}

/// GET /v1/algorithms — list all Algorithm Registry entries
/// (API.md §"Public Read API" + ADR-049 + ADR-053 §T1.4 dispatch family).
pub(super) async fn handle_algorithms_list(State(state): State<SharedLiveNodeState>) -> Response {
    let guard = state.lock().await;
    let entries: Vec<serde_json::Value> = guard
        .state
        .alg_entries_in_order()
        .into_iter()
        .map(alg_entry_to_json)
        .collect();
    (StatusCode::OK, Json(serde_json::json!({ "data": entries }))).into_response()
}

/// GET /v1/algorithms/:alg_id — single Algorithm Registry entry.
pub(super) async fn handle_algorithm_get(
    AxumPath(alg_id_raw): AxumPath<u16>,
    State(state): State<SharedLiveNodeState>,
) -> Response {
    let alg_id = match pqc_crypto::AlgId::from_u16(alg_id_raw) {
        Some(a) => a,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": { "code": "ALGORITHM_NOT_FOUND",
                               "message": format!("alg_id {alg_id_raw} not registered") }
                })),
            )
                .into_response();
        }
    };
    let guard = state.lock().await;
    match guard.state.alg_entry(alg_id) {
        Some(e) => (
            StatusCode::OK,
            Json(serde_json::json!({ "data": alg_entry_to_json(e) })),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": { "code": "ALGORITHM_NOT_FOUND",
                           "message": format!("alg_id {alg_id_raw} not registered") }
            })),
        )
            .into_response(),
    }
}

/// GET /v1/validators/:address — single validator by operator address.
pub(super) async fn handle_validator_get(
    AxumPath(addr_hex): AxumPath<String>,
    State(state): State<SharedLiveNodeState>,
) -> Response {
    let addr = match parse_address_hex(&addr_hex) {
        Some(a) => a,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": { "code": "INVALID_ADDRESS",
                               "message": format!("address must be 64-char hex; got {addr_hex:?}") }
                })),
            )
                .into_response();
        }
    };
    let guard = state.lock().await;
    match guard.state.get_validator(&addr) {
        Some(v) => {
            // ADR-047 on-chain libp2p PeerId binding. `null` when unset
            // (D-03 deferred-to-M2 default); hex-encoded multihash when
            // bound. The `pqcd wallet rotate-peer-id` CLI polls this
            // field after submitting a `ValidatorRotatePeerId` tx to
            // confirm the on-chain binding flipped before atomically
            // writing the new salt into the host's node.json.
            let peer_id = guard
                .state
                .get_validator_peer_id(&v.operator)
                .map(hex::encode);
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "data": {
                        "address": hex::encode(v.operator.0),
                        "node_id": v.node_id,
                        "consensus_alg_id": v.consensus_alg_id.as_u16(),
                        "consensus_pk_hex": hex::encode(&v.consensus_pk),
                        "self_bond": v.self_bond.to_string(),
                        "status": validator_status_str(&v.status),
                        "registered_height": v.registered_height,
                        "tombstoned": v.tombstoned,
                        "peer_id_hex": peer_id,
                    }
                })),
            )
                .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": { "code": "VALIDATOR_NOT_FOUND",
                           "message": format!("no validator at address {addr_hex}") }
            })),
        )
            .into_response(),
    }
}

/// GET /v1/accounts/:address/attestations — attestations issued by an account.
pub(super) async fn handle_account_attestations(
    AxumPath(addr_hex): AxumPath<String>,
    State(state): State<SharedLiveNodeState>,
) -> Response {
    let addr = match parse_address_hex(&addr_hex) {
        Some(a) => a,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": { "code": "INVALID_ADDRESS",
                               "message": format!("address must be 64-char hex; got {addr_hex:?}") }
                })),
            )
                .into_response();
        }
    };
    let guard = state.lock().await;
    let items: Vec<serde_json::Value> = guard
        .state
        .attestations_in_order()
        .into_iter()
        .filter(|a| a.attester == addr)
        .map(|a| {
            serde_json::json!({
                "attestation_id": a.attestation_id.to_hex(),
                "attester": a.attester.to_hex(),
                "subject": hex::encode(a.subject),
                "attestation_type": a.attestation_type,
                "content_hash": hex::encode(a.content_hash),
                "schema_id": hex::encode(a.schema_id),
                "metadata_hash": a.metadata_hash.map(hex::encode),
                "anchor_height": a.anchor_height,
                "status": match a.status {
                    pqc_types::attestation::AttestationStatus::Active => "active",
                    pqc_types::attestation::AttestationStatus::Revoked => "revoked",
                },
            })
        })
        .collect();
    (StatusCode::OK, Json(serde_json::json!({ "data": items }))).into_response()
}

pub(super) fn proposal_to_json(p: &pqc_types::governance::PendingProposal) -> serde_json::Value {
    let yes_count = p.votes.values().filter(|v| **v).count();
    let no_count = p.votes.values().filter(|v| !**v).count();
    serde_json::json!({
        "proposal_id": p.proposal_id.to_hex(),
        "proposal_type": p.proposal_type.as_str(),
        "proposer": p.proposer.to_hex(),
        "voting_deadline": p.voting_deadline,
        "execute_after": p.execute_after,
        "status": proposal_status_str(p.status),
        "rationale_hash": hex::encode(p.rationale_hash),
        "vote_summary": { "yes": yes_count, "no": no_count, "total": p.votes.len() },
    })
}

/// GET /v1/governance/proposals — list all pending governance proposals.
pub(super) async fn handle_proposals_list(State(state): State<SharedLiveNodeState>) -> Response {
    let guard = state.lock().await;
    let items: Vec<serde_json::Value> = guard
        .state
        .pending_proposals_in_order()
        .into_iter()
        .map(proposal_to_json)
        .collect();
    (StatusCode::OK, Json(serde_json::json!({ "data": items }))).into_response()
}

/// GET /v1/governance/proposals/:proposal_id — single proposal.
pub(super) async fn handle_proposal_get(
    AxumPath(id_hex): AxumPath<String>,
    State(state): State<SharedLiveNodeState>,
) -> Response {
    let id = match parse_tx_hash_hex(&id_hex) {
        Some(h) => h,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": { "code": "INVALID_PROPOSAL_ID",
                               "message": format!("proposal_id must be 64-char hex; got {id_hex:?}") }
                })),
            )
                .into_response();
        }
    };
    let guard = state.lock().await;
    match guard.state.get_pending_proposal(&id) {
        Some(p) => (
            StatusCode::OK,
            Json(serde_json::json!({ "data": proposal_to_json(p) })),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": { "code": "PROPOSAL_NOT_FOUND",
                           "message": format!("no pending proposal with id {id_hex}") }
            })),
        )
            .into_response(),
    }
}

/// GET /v1/governance/proposals/:proposal_id/votes — per-voter ballot for a proposal.
pub(super) async fn handle_proposal_votes(
    AxumPath(id_hex): AxumPath<String>,
    State(state): State<SharedLiveNodeState>,
) -> Response {
    let id = match parse_tx_hash_hex(&id_hex) {
        Some(h) => h,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": { "code": "INVALID_PROPOSAL_ID",
                               "message": format!("proposal_id must be 64-char hex; got {id_hex:?}") }
                })),
            )
                .into_response();
        }
    };
    let guard = state.lock().await;
    let proposal = match guard.state.get_pending_proposal(&id) {
        Some(p) => p,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": { "code": "PROPOSAL_NOT_FOUND",
                               "message": format!("no pending proposal with id {id_hex}") }
                })),
            )
                .into_response();
        }
    };
    let mut votes: Vec<(&pqc_types::account::Address, &bool)> = proposal.votes.iter().collect();
    votes.sort_by_key(|(addr, _)| addr.0);
    let items: Vec<serde_json::Value> = votes
        .into_iter()
        .map(|(addr, yes)| {
            serde_json::json!({
                "voter": hex::encode(addr.0),
                "vote": if *yes { "yes" } else { "no" },
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "data": {
                "proposal_id": id_hex,
                "voting_deadline": proposal.voting_deadline,
                "status": proposal_status_str(proposal.status),
                "votes": items,
            }
        })),
    )
        .into_response()
}

/// GET /v1/blocks/:height — returns a block by height for the explorer.
pub(super) async fn handle_block(
    AxumPath(height): AxumPath<u64>,
    State(state): State<SharedLiveNodeState>,
) -> Response {
    let guard = state.lock().await;
    // Try in-memory chain first, then fall back to disk.
    let block_opt = guard.disk.read_stored_block_at_height(height);
    drop(guard);
    match block_opt {
        Ok(Some(stored)) => {
            let b = &stored.block;
            let m = &stored.metadata;
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "height": b.header.height,
                    "block_hash": hex::encode(m.block_hash.0),
                    "prev_hash": hex::encode(b.header.prev_hash.0),
                    "state_root": hex::encode(b.header.state_root.0),
                    "tx_root": hex::encode(b.header.tx_root.0),
                    "proposer": hex::encode(&b.header.proposer),
                    "timestamp": b.header.timestamp,
                    "tx_count": b.tx_hashes.len(),
                    "tx_hashes": b.tx_hashes.iter().map(|h| hex::encode(h.0)).collect::<Vec<_>>(),
                    "bytes_used": m.bytes_used,
                })),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "block not found"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// GET /v1/attestations/:id — returns an attestation record by ID.
/// Used by both the block explorer and the notary verify endpoint.
pub(super) async fn handle_attestation(
    AxumPath(id_hex): AxumPath<String>,
    State(state): State<SharedLiveNodeState>,
) -> Response {
    use pqc_types::attestation::AttestationId;

    let id_bytes = match hex::decode(&id_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "attestation_id must be 64 hex chars"})),
            )
                .into_response();
        }
    };
    let att_id = AttestationId(id_bytes);
    let guard = state.lock().await;
    match guard.state.get_attestation(&att_id) {
        Some(att) => {
            let revoked_at = att.revocation.as_ref().map(|r| r.revoked_at_height);
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "attestation_id": id_hex,
                    "issuer": hex::encode(att.attester.0),
                    "subject": hex::encode(att.subject),
                    "schema_id": hex::encode(att.schema_id),
                    "payload_hash": hex::encode(att.content_hash),
                    "issued_at_height": att.anchor_height,
                    "revoked_at_height": revoked_at,
                    "attestation_type": att.attestation_type,
                })),
            )
                .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "NOT_FOUND", "attestation_id": id_hex})),
        )
            .into_response(),
    }
}

/// GET /v1/accounts/:address — returns nonce and balance for the notary (and other callers).
pub(super) async fn handle_account_nonce(
    axum::extract::Path(address_hex): axum::extract::Path<String>,
    State(state): State<SharedLiveNodeState>,
) -> Response {
    let bytes = match hex::decode(&address_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid address hex"})),
            )
                .into_response();
        }
    };
    let mut addr_bytes = [0u8; 32];
    addr_bytes.copy_from_slice(&bytes);
    let address = pqc_types::Address(addr_bytes);

    let guard = state.lock().await;
    match guard.state.get_account(&address) {
        Some(account) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "address": address_hex,
                "nonce": account.nonce,
                "balance": account.balance.to_string(),
            })),
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "").into_response(),
    }
}

/// GET /v1/txs/:hash — finalized transaction lookup by SHAKE-256 hash.
///
/// Uses the RocksDB `tx_index` CF (ADR-032 / TASK-103) for O(1) lookup across
/// the full chain — including pre-checkpoint blocks that were previously
/// unreachable without scanning (TASK-104 closure).
///
/// Response field names match the explorer's `TxView` expectations:
///   tx_hash, block_height, sender, op_type, nonce, fee_venom, fee_tip,
///   alg_id, signature, op_payload, status.
pub(super) async fn handle_tx_lookup(
    AxumPath(hash_hex): AxumPath<String>,
    State(state): State<SharedLiveNodeState>,
) -> Response {
    use pqc_types::transaction::TxHash as PqTxHash;

    let hash_bytes: [u8; 32] = match hex::decode(&hash_hex).ok().and_then(|b| b.try_into().ok()) {
        Some(b) => b,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid tx hash: expected 64 hex chars"})),
            )
                .into_response();
        }
    };

    let target = PqTxHash(hash_bytes);

    // Phase 1: O(1) tx_index lookup — find the block height for this tx hash.
    let block_height_opt = {
        let guard = state.lock().await;
        match guard.disk.get_tx_block_height(&target) {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(error = %e, "tx_index lookup error");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "tx index lookup failed"})),
                )
                    .into_response();
            }
        }
    };

    let block_height = match block_height_opt {
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "tx not found"})),
            )
                .into_response();
        }
        Some(h) => h,
    };

    // Phase 2: read the block at the indexed height, find and return the tx.
    let stored_opt = {
        let guard = state.lock().await;
        guard.disk.read_stored_block_at_height(block_height)
    };

    if let Ok(Some(stored)) = stored_opt {
        for tx in &stored.included_transactions {
            let raw = match encode_tx(tx) {
                Ok(r) => r,
                Err(_) => continue,
            };
            if compute_tx_hash(&raw) == hash_bytes {
                return (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "tx_hash":      hash_hex,
                        "block_height": stored.metadata.height,
                        "sender":       hex::encode(tx.sender.0),
                        "op_type":      format!("{:?}", tx.msg_type),
                        "nonce":        tx.nonce,
                        "fee_venom":    tx.fee.to_string(),
                        "fee_tip":      tx.fee_tip,
                        "alg_id":       format!("{:?}", tx.sig_alg_id),
                        "signature":    hex::encode(&tx.signature),
                        "op_payload":   hex::encode(&tx.payload),
                        "status":       "finalized",
                    })),
                )
                    .into_response();
            }
        }
    }

    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "tx not found"})),
    )
        .into_response()
}
