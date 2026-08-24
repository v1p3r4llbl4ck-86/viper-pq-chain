// SPDX-License-Identifier: BUSL-1.1
//! Public-API handler for `GET /v1/proofs/{anchor_id}`.
//!
//! Self-contained leaf endpoint extracted from `devnet.rs` 2026-05-10 as
//! part of the M-effort split (CONCERNS.md "[MEDIUM] crates/pqcd/src/
//! devnet.rs is 7,247 lines"). Reads a single proof anchor from
//! StateStore by 32-byte AnchorId; renders 200 + JSON, 400 on bad
//! anchor_id_hex, 404 when the anchor is not on-chain.

use axum::{
    extract::{Path as AxumPath, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use serde::Serialize;

use super::SharedLiveNodeState;

#[derive(Serialize)]
struct ProofAnchorData {
    anchor_id: String,
    claimer: String,
    claim_type: u16,
    claim_type_name: Option<&'static str>,
    asset_id_hash: String,
    proof_hash: String,
    schema_id: Option<String>,
    anchor_height: u64,
}

#[derive(Serialize)]
struct ProofAnchorResponse {
    data: ProofAnchorData,
}

#[derive(Serialize)]
struct ProofAnchorNotFound {
    error: ProofAnchorNotFoundDetail,
}

#[derive(Serialize)]
struct ProofAnchorNotFoundDetail {
    code: &'static str,
    message: String,
}

pub(super) async fn handle_get_proof_anchor(
    State(state): State<SharedLiveNodeState>,
    AxumPath(anchor_id_hex): AxumPath<String>,
) -> Response {
    use pqc_types::proof_anchor::{claim_type_name, AnchorId};

    let id_bytes = match hex::decode(&anchor_id_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ProofAnchorNotFound {
                    error: ProofAnchorNotFoundDetail {
                        code: "INVALID_ANCHOR_ID",
                        message: format!(
                            "anchor_id must be a 64-character hex string; got {anchor_id_hex:?}"
                        ),
                    },
                }),
            )
                .into_response();
        }
    };

    let anchor_id = AnchorId(id_bytes);
    let guard = state.lock().await;

    match guard.state.get_proof_anchor(&anchor_id) {
        Some(anchor) => {
            let data = ProofAnchorData {
                anchor_id: anchor.anchor_id.to_hex(),
                claimer: anchor.claimer.to_hex(),
                claim_type: anchor.claim_type,
                claim_type_name: claim_type_name(anchor.claim_type),
                asset_id_hash: hex::encode(anchor.asset_id_hash),
                proof_hash: hex::encode(anchor.proof_hash),
                schema_id: anchor.schema_id.map(hex::encode),
                anchor_height: anchor.anchor_height,
            };
            (StatusCode::OK, Json(ProofAnchorResponse { data })).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(ProofAnchorNotFound {
                error: ProofAnchorNotFoundDetail {
                    code: "PROOF_ANCHOR_NOT_FOUND",
                    message: format!("no proof anchor with anchor_id {anchor_id_hex}"),
                },
            }),
        )
            .into_response(),
    }
}
