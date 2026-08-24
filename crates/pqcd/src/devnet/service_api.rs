// SPDX-License-Identifier: BUSL-1.1
//! Service API: business-friendly HTTP wrappers around chain primitives.
//!
//! Extracted from `devnet.rs` 2026-05-10. Three groups of leaf endpoints
//! aimed at customer integrations rather than direct chain interaction:
//!
//! - **Credentials** (`POST /api/credentials/issue`, `GET /api/credentials/{id}`)
//!   — wraps the attestation_create primitive in credential-oriented field
//!   names + a deterministic id derivation.
//! - **Proofs** (`POST /api/proofs/anchor`, `GET /api/proofs/{id}`) — wraps
//!   proof_anchor with the same shape.
//! - **Health** (`GET /api/health`) — node status + chain height + uptime.
//!
//! All handlers are read-only against `LiveNodeState` (or stateless for the
//! issue/anchor convenience endpoints, which only validate input + derive
//! an id without contacting the chain).

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Path as AxumPath, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use pqc_crypto::shake256_32;
use serde::Deserialize;

use super::SharedLiveNodeState;

// ── Service API: Credentials ────────────────────────────────────────────────

#[derive(Deserialize)]
pub(super) struct CredentialIssueRequest {
    issuer_address: String,
    subject: String,
    credential_type: String,
    content_hash: String,
    schema_id: String,
}

/// POST /api/credentials/issue — convenience wrapper that validates input and
/// returns a structured response describing the attestation_create tx that
/// would be built.
pub(super) async fn handle_credential_issue(Json(req): Json<CredentialIssueRequest>) -> Response {
    // Validate issuer_address (64 hex chars = 32 bytes)
    if hex::decode(&req.issuer_address)
        .ok()
        .filter(|b| b.len() == 32)
        .is_none()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": {"code": "INVALID_INPUT", "message": "issuer_address must be a 64-character hex string"}})),
        )
            .into_response();
    }
    // Validate subject (64 hex chars)
    if hex::decode(&req.subject)
        .ok()
        .filter(|b| b.len() == 32)
        .is_none()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": {"code": "INVALID_INPUT", "message": "subject must be a 64-character hex string"}})),
        )
            .into_response();
    }
    // Validate content_hash (64 hex chars)
    if hex::decode(&req.content_hash)
        .ok()
        .filter(|b| b.len() == 32)
        .is_none()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": {"code": "INVALID_INPUT", "message": "content_hash must be a 64-character hex string"}})),
        )
            .into_response();
    }
    if req.credential_type.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": {"code": "INVALID_INPUT", "message": "credential_type must not be empty"}})),
        )
            .into_response();
    }

    // Compute a deterministic credential_id from the inputs.
    let preimage = format!(
        "{}:{}:{}:{}",
        req.issuer_address, req.subject, req.content_hash, req.schema_id
    );
    let credential_id = hex::encode(shake256_32(preimage.as_bytes()));

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "accepted",
            "credential_id": credential_id,
            "msg_type": "attestation_create",
            "verify_url": format!("/api/credentials/{}", credential_id),
        })),
    )
        .into_response()
}

/// GET /api/credentials/{id} — business-friendly wrapper around the attestation
/// lookup. Returns credential-oriented field names.
pub(super) async fn handle_credential_get(
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
                Json(serde_json::json!({"error": {"code": "INVALID_INPUT", "message": "credential id must be 64 hex chars"}})),
            )
                .into_response();
        }
    };
    let att_id = AttestationId(id_bytes);
    let guard = state.lock().await;
    match guard.state.get_attestation(&att_id) {
        Some(att) => {
            let status = if att.revocation.is_some() {
                "revoked"
            } else {
                "active"
            };
            // Map attestation_type integer to a human-readable credential_type name.
            let credential_type = match att.attestation_type {
                1 => "identity_verification",
                2 => "document_notarization",
                3 => "credential_issuance",
                _ => "unknown",
            };
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "credential_id": id_hex,
                    "issuer": hex::encode(att.attester.0),
                    "subject": hex::encode(att.subject),
                    "credential_type": credential_type,
                    "issued_at_block": att.anchor_height,
                    "status": status,
                    "content_hash": hex::encode(att.content_hash),
                    "verify_url": format!("/api/credentials/{}", id_hex),
                })),
            )
                .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": {"code": "NOT_FOUND", "message": format!("credential {} not found", id_hex)}})),
        )
            .into_response(),
    }
}

// ── Service API: Proofs ─────────────────────────────────────────────────────

#[derive(Deserialize)]
pub(super) struct ProofAnchorApiRequest {
    owner_address: String,
    claim_type: String,
    document_hash: String,
    proof_hash: String,
}

/// POST /api/proofs/anchor — convenience wrapper that validates input and
/// returns a structured response describing the proof_anchor tx that would
/// be built.
pub(super) async fn handle_proof_anchor_api(Json(req): Json<ProofAnchorApiRequest>) -> Response {
    // Validate owner_address (64 hex chars = 32 bytes)
    if hex::decode(&req.owner_address)
        .ok()
        .filter(|b| b.len() == 32)
        .is_none()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": {"code": "INVALID_INPUT", "message": "owner_address must be a 64-character hex string"}})),
        )
            .into_response();
    }
    // Validate document_hash (64 hex chars)
    if hex::decode(&req.document_hash)
        .ok()
        .filter(|b| b.len() == 32)
        .is_none()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": {"code": "INVALID_INPUT", "message": "document_hash must be a 64-character hex string"}})),
        )
            .into_response();
    }
    // Validate proof_hash (64 hex chars)
    if hex::decode(&req.proof_hash)
        .ok()
        .filter(|b| b.len() == 32)
        .is_none()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": {"code": "INVALID_INPUT", "message": "proof_hash must be a 64-character hex string"}})),
        )
            .into_response();
    }
    if req.claim_type.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": {"code": "INVALID_INPUT", "message": "claim_type must not be empty"}})),
        )
            .into_response();
    }

    // Compute a deterministic proof_id from the inputs.
    let preimage = format!(
        "{}:{}:{}:{}",
        req.owner_address, req.claim_type, req.document_hash, req.proof_hash
    );
    let proof_id = hex::encode(shake256_32(preimage.as_bytes()));

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "accepted",
            "proof_id": proof_id,
            "msg_type": "proof_anchor",
            "verify_url": format!("/api/proofs/{}", proof_id),
        })),
    )
        .into_response()
}

/// GET /api/proofs/{id} — business-friendly wrapper around the proof anchor
/// lookup. Returns proof-oriented field names.
pub(super) async fn handle_proof_get(
    AxumPath(id_hex): AxumPath<String>,
    State(state): State<SharedLiveNodeState>,
) -> Response {
    use pqc_types::proof_anchor::{claim_type_name, AnchorId};

    let id_bytes = match hex::decode(&id_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": {"code": "INVALID_INPUT", "message": "proof id must be 64 hex chars"}})),
            )
                .into_response();
        }
    };

    let anchor_id = AnchorId(id_bytes);
    let guard = state.lock().await;

    match guard.state.get_proof_anchor(&anchor_id) {
        Some(anchor) => {
            let ct_name = claim_type_name(anchor.claim_type).unwrap_or("unknown");
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "proof_id": id_hex,
                    "owner": hex::encode(anchor.claimer.0),
                    "claim_type": ct_name,
                    "document_hash": hex::encode(anchor.asset_id_hash),
                    "proof_hash": hex::encode(anchor.proof_hash),
                    "anchored_at_block": anchor.anchor_height,
                    "status": "anchored",
                    "verify_url": format!("/api/proofs/{}", id_hex),
                })),
            )
                .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": {"code": "NOT_FOUND", "message": format!("proof {} not found", id_hex)}})),
        )
            .into_response(),
    }
}

// ── Service API: Health ─────────────────────────────────────────────────────

/// GET /api/health — returns node health status, chain height, and uptime.
pub(super) async fn handle_health(State(state): State<SharedLiveNodeState>) -> Response {
    let guard = state.lock().await;
    let height = guard.state.block_height();
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let uptime = now_secs.saturating_sub(guard.node_start_unix_secs);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "chain_height": height,
            "node_id": guard.config.node_id,
            "uptime_seconds": uptime,
        })),
    )
        .into_response()
}
