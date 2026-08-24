// SPDX-License-Identifier: BUSL-1.1
//! Minimal read/status API — finalized read endpoints exposing node state to external clients.
//!
//! Endpoints:
//! - `GET /v1/network`          — chain id, height, tip hash, recovery source
//! - `GET /v1/blocks/latest`    — latest committed block header
//! - `GET /v1/txs/{hash}`       — finalized transaction lookup by hash
//! - `GET /v1/accounts/{addr}`  — account balance, nonce, keyset
//! - `GET /v1/attestations/{id}` — finalized attestation lookup by id
//! - `GET /v1/proofs/{anchor_id}` — finalized proof anchor lookup by anchor id
//! - `GET /v1/governance/receipts/{proposal_id}` — governance execution receipt
//!
//! State is a snapshot taken at bootstrap and wrapped in `Arc`. For the Phase 2
//! single-node prototype this is accurate because block production and the API
//! server run sequentially. When the proposer loop is added (TASK-031), the
//! `Arc<RwLock<ApiNodeState>>` upgrade path is straightforward.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::get,
    Router,
};
use pqc_consensus::{RecoverySource, RocksDbChainStore};
use pqc_crypto::Lifecycle;
use pqc_state::StateStore;
use pqc_tx::{codec::encode_tx, compute_tx_hash};
use pqc_types::{
    account::Address,
    attestation::{attestation_type_name, AttestationId, AttestationStatus},
    governance::GovernanceProposalType,
    keyset::KeyStatus,
    proof_anchor::{claim_type_name, AnchorId},
    transaction::TxHash,
};
use serde::Serialize;

// ── Shared state ──────────────────────────────────────────────────────────────

pub struct ApiNodeState {
    pub chain_id: Vec<u8>,
    pub recovery_source: RecoverySource,
    pub state: StateStore,
    pub disk: RocksDbChainStore,
}

pub type SharedState = Arc<ApiNodeState>;

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct NetworkResponse {
    pub chain_id: String,
    pub height: u64,
    pub tip_hash: String,
    pub state_root: String,
    pub recovery_source: &'static str,
}

#[derive(Serialize)]
pub struct BlockResponse {
    pub height: u64,
    pub hash: String,
    pub prev_hash: String,
    pub state_root: String,
    pub tx_root: String,
    pub timestamp: u64,
    pub tx_count: usize,
}

#[derive(Serialize)]
pub struct TxResponse {
    pub hash: String,
    pub block_height: u64,
    pub sender: String,
    pub msg_type: String,
    pub nonce: u64,
    pub fee: u64,
    pub fee_tip: u64,
    pub status: &'static str,
}

#[derive(Serialize)]
pub struct KeyEntryResponse {
    pub alg_id: u16,
    pub key_version: u32,
    pub valid_from_height: u64,
    pub status: &'static str,
    pub allowed_tx_types: u32,
}

#[derive(Serialize)]
pub struct AccountResponse {
    pub address: String,
    pub balance: u128,
    pub nonce: u64,
    pub keys: Vec<KeyEntryResponse>,
}

#[derive(Serialize)]
pub struct AttestationRevocationResponse {
    pub revoked_at_height: u64,
    pub revoker: String,
    pub revocation_reason_hash: Option<String>,
}

#[derive(Serialize)]
pub struct AttestationResponse {
    pub attestation_id: String,
    pub attester: String,
    pub status: &'static str,
    pub attestation_type: u16,
    pub attestation_type_name: &'static str,
    pub subject: String,
    pub content_hash: String,
    pub schema_id: String,
    pub metadata_hash: Option<String>,
    pub anchor_height: u64,
    pub expires_at_height: Option<u64>,
    pub revocation: Option<AttestationRevocationResponse>,
}

#[derive(Serialize)]
pub struct ProofAnchorData {
    pub anchor_id: String,
    pub claimer: String,
    pub claim_type: u16,
    pub claim_type_name: Option<&'static str>,
    pub asset_id_hash: String,
    pub proof_hash: String,
    pub schema_id: Option<String>,
    pub anchor_height: u64,
}

#[derive(Serialize)]
pub struct ProofAnchorResponse {
    pub data: ProofAnchorData,
}

#[derive(Serialize)]
pub struct GovernanceReceiptResponse {
    pub proposal_id: String,
    pub proposal_type: u8,
    pub proposal_type_name: &'static str,
    pub proposer: String,
    pub target_alg_id: u16,
    pub lifecycle_before: &'static str,
    pub lifecycle_after: &'static str,
    pub min_fee_before: u64,
    pub min_fee_after: u64,
    pub rationale_hash: String,
    pub executed_at_height: u64,
}

// ── Error helper ──────────────────────────────────────────────────────────────

struct ApiError(StatusCode, &'static str);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, self.1).into_response()
    }
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/v1/network", get(handle_network))
        .route("/v1/blocks/latest", get(handle_latest_block))
        .route("/v1/txs/{hash}", get(handle_tx))
        .route("/v1/accounts/{address}", get(handle_account))
        .route("/v1/attestations/{id}", get(handle_attestation))
        .route("/v1/proofs/{anchor_id}", get(handle_proof_anchor))
        .route(
            "/v1/governance/receipts/{proposal_id}",
            get(handle_governance_receipt),
        )
        .with_state(state)
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn handle_network(State(s): State<SharedState>) -> Json<NetworkResponse> {
    let height = s.disk.height();
    let tip_hash = s
        .disk
        .tip_hash()
        .map(|h| hex::encode(h.0))
        .unwrap_or_default();
    let state_root = s
        .disk
        .chain()
        .tip()
        .map(|b| hex::encode(b.metadata.state_root.0))
        .unwrap_or_default();
    let recovery_source = match s.recovery_source {
        RecoverySource::FullReplay => "full_replay",
        RecoverySource::TrustedCheckpoint => "trusted_checkpoint",
    };
    Json(NetworkResponse {
        chain_id: hex::encode(&s.chain_id),
        height,
        tip_hash,
        state_root,
        recovery_source,
    })
}

async fn handle_latest_block(
    State(s): State<SharedState>,
) -> Result<Json<BlockResponse>, ApiError> {
    let tip = s
        .disk
        .chain()
        .tip()
        .ok_or(ApiError(StatusCode::NOT_FOUND, "no blocks committed yet"))?;
    let m = &tip.metadata;
    Ok(Json(BlockResponse {
        height: m.height,
        hash: hex::encode(m.block_hash.0),
        prev_hash: hex::encode(m.prev_hash.0),
        state_root: hex::encode(m.state_root.0),
        tx_root: hex::encode(m.tx_root.0),
        timestamp: m.timestamp,
        tx_count: m.included_count,
    }))
}

async fn handle_tx(
    State(s): State<SharedState>,
    Path(hash_hex): Path<String>,
) -> Result<Json<TxResponse>, ApiError> {
    let hash_bytes: [u8; 32] = hex::decode(&hash_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(ApiError(
            StatusCode::BAD_REQUEST,
            "invalid tx hash: expected 64 hex chars",
        ))?;

    for stored in s.disk.chain().blocks_in_order() {
        for tx in &stored.included_transactions {
            let raw = encode_tx(tx)
                .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "tx encode failed"))?;
            if compute_tx_hash(&raw) == hash_bytes {
                return Ok(Json(TxResponse {
                    hash: hash_hex,
                    block_height: stored.metadata.height,
                    sender: hex::encode(tx.sender.0),
                    msg_type: format!("{:?}", tx.msg_type),
                    nonce: tx.nonce,
                    fee: tx.fee,
                    fee_tip: tx.fee_tip,
                    status: "finalized",
                }));
            }
        }
    }

    Err(ApiError(StatusCode::NOT_FOUND, "tx not found"))
}

async fn handle_account(
    State(s): State<SharedState>,
    Path(addr_hex): Path<String>,
) -> Result<Json<AccountResponse>, ApiError> {
    let addr_bytes: [u8; 32] = hex::decode(&addr_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(ApiError(
            StatusCode::BAD_REQUEST,
            "invalid address: expected 64 hex chars",
        ))?;

    let addr = Address(addr_bytes);
    let account = s
        .state
        .get_account(&addr)
        .ok_or(ApiError(StatusCode::NOT_FOUND, "account not found"))?;

    let keys = account
        .keys
        .0
        .iter()
        .map(|k| KeyEntryResponse {
            alg_id: k.alg_id.as_u16(),
            key_version: k.key_version,
            valid_from_height: k.valid_from_height,
            status: match k.status {
                KeyStatus::Pending => "pending",
                KeyStatus::Active => "active",
                KeyStatus::Revoked => "revoked",
            },
            allowed_tx_types: k.allowed_tx_types,
        })
        .collect();

    Ok(Json(AccountResponse {
        address: addr_hex,
        balance: account.balance,
        nonce: account.nonce,
        keys,
    }))
}

async fn handle_attestation(
    State(s): State<SharedState>,
    Path(id_hex): Path<String>,
) -> Result<Json<AttestationResponse>, ApiError> {
    let id_bytes: [u8; 32] = hex::decode(&id_hex)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(ApiError(
            StatusCode::BAD_REQUEST,
            "invalid attestation id: expected 64 hex chars",
        ))?;

    let attestation = s
        .state
        .get_attestation(&AttestationId(id_bytes))
        .ok_or(ApiError(StatusCode::NOT_FOUND, "attestation not found"))?;

    Ok(Json(AttestationResponse {
        attestation_id: id_hex,
        attester: hex::encode(attestation.attester.0),
        status: match attestation.status {
            AttestationStatus::Active => "active",
            AttestationStatus::Revoked => "revoked",
        },
        attestation_type: attestation.attestation_type,
        attestation_type_name: attestation_type_name(attestation.attestation_type)
            .unwrap_or("unknown"),
        subject: hex::encode(attestation.subject),
        content_hash: hex::encode(attestation.content_hash),
        schema_id: hex::encode(attestation.schema_id),
        metadata_hash: attestation.metadata_hash.map(hex::encode),
        anchor_height: attestation.anchor_height,
        expires_at_height: attestation.expires_at_height,
        revocation: attestation.revocation.as_ref().map(|revocation| {
            AttestationRevocationResponse {
                revoked_at_height: revocation.revoked_at_height,
                revoker: hex::encode(revocation.revoker.0),
                revocation_reason_hash: revocation.revocation_reason_hash.map(hex::encode),
            }
        }),
    }))
}

async fn handle_proof_anchor(
    State(s): State<SharedState>,
    Path(anchor_id_hex): Path<String>,
) -> Result<Json<ProofAnchorResponse>, ApiError> {
    let id_bytes: [u8; 32] = hex::decode(&anchor_id_hex)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(ApiError(
            StatusCode::BAD_REQUEST,
            "invalid anchor id: expected 64 hex chars",
        ))?;

    let anchor = s
        .state
        .get_proof_anchor(&AnchorId(id_bytes))
        .ok_or(ApiError(StatusCode::NOT_FOUND, "proof anchor not found"))?;

    Ok(Json(ProofAnchorResponse {
        data: ProofAnchorData {
            anchor_id: anchor.anchor_id.to_hex(),
            claimer: hex::encode(anchor.claimer.0),
            claim_type: anchor.claim_type,
            claim_type_name: claim_type_name(anchor.claim_type),
            asset_id_hash: hex::encode(anchor.asset_id_hash),
            proof_hash: hex::encode(anchor.proof_hash),
            schema_id: anchor.schema_id.map(hex::encode),
            anchor_height: anchor.anchor_height,
        },
    }))
}

async fn handle_governance_receipt(
    State(s): State<SharedState>,
    Path(proposal_id_hex): Path<String>,
) -> Result<Json<GovernanceReceiptResponse>, ApiError> {
    let proposal_id_bytes: [u8; 32] = hex::decode(&proposal_id_hex)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(ApiError(
            StatusCode::BAD_REQUEST,
            "invalid proposal id: expected 64 hex chars",
        ))?;

    let receipt = s
        .state
        .get_governance_receipt(&TxHash(proposal_id_bytes))
        .ok_or(ApiError(
            StatusCode::NOT_FOUND,
            "governance receipt not found",
        ))?;

    Ok(Json(GovernanceReceiptResponse {
        proposal_id: proposal_id_hex,
        proposal_type: receipt.proposal_type.as_u8(),
        proposal_type_name: render_governance_proposal_type(receipt.proposal_type),
        proposer: hex::encode(receipt.proposer.0),
        target_alg_id: receipt.target_alg_id.as_u16(),
        lifecycle_before: render_lifecycle(receipt.lifecycle_before),
        lifecycle_after: render_lifecycle(receipt.lifecycle_after),
        min_fee_before: receipt.min_fee_before,
        min_fee_after: receipt.min_fee_after,
        rationale_hash: hex::encode(receipt.rationale_hash),
        executed_at_height: receipt.executed_at_height,
    }))
}

fn render_lifecycle(lifecycle: Lifecycle) -> &'static str {
    match lifecycle {
        Lifecycle::Active => "active",
        Lifecycle::Discouraged => "discouraged",
        Lifecycle::Deprecated => "deprecated",
        Lifecycle::Banned => "banned",
    }
}

fn render_governance_proposal_type(proposal_type: GovernanceProposalType) -> &'static str {
    proposal_type.as_str()
}
