// SPDX-License-Identifier: BUSL-1.1
//! POST /v1/txs — transaction submission with per-IP rate limit + admission.
//!
//! Extracted from `devnet.rs` 2026-05-10 as the ninth slice of the
//! split. The handler is the only POST endpoint in the public API
//! and lives separately from the GET endpoints in `read_api.rs`
//! because it crosses three boundaries the read path doesn't:
//!
//!   - per-IP rate limit (LiveNodeState::check_and_record_ip_request)
//!   - mempool admission (try_admit + replacement policy)
//!   - error-code mapping for both MempoolError and TxError
//!
//! `use super::*;` keeps every sibling helper in scope.
//!
//! Request/response shapes (TxSubmitRequest, TxSubmitErrorDetail,
//! TxSubmitErrorBody) come along — they're submission-specific.

use super::*;

// ── Request / response shapes ─────────────────────────────────────────────────

#[derive(Deserialize)]
pub(super) struct TxSubmitRequest {
    encoding: String,
    tx_bytes: String,
}

#[derive(Serialize)]
pub(super) struct TxSubmitErrorDetail {
    code: &'static str,
    message: String,
}

#[derive(Serialize)]
pub(super) struct TxSubmitErrorBody {
    error: TxSubmitErrorDetail,
}

// ── Tx submission handler ─────────────────────────────────────────────────────

pub(super) async fn handle_tx_submit(
    State(state): State<SharedLiveNodeState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    Json(req): Json<TxSubmitRequest>,
) -> Response {
    // Per-IP rate limit check — only POST /v1/txs is limited.
    {
        let mut guard = state.lock().await;
        if guard.check_and_record_ip_request(peer_addr.ip()) {
            let window_secs = guard.rate_limit.window_secs;
            let max = guard.rate_limit.max_requests_per_window;
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(TxSubmitErrorBody {
                    error: TxSubmitErrorDetail {
                        code: "RATE_LIMITED",
                        message: format!(
                            "rate limit exceeded: max {max} requests per {window_secs}s per IP"
                        ),
                    },
                }),
            )
                .into_response();
        }
    }

    if req.encoding != "cbor-base64" {
        return (
            StatusCode::BAD_REQUEST,
            Json(TxSubmitErrorBody {
                error: TxSubmitErrorDetail {
                    code: "ENCODING_ERROR",
                    message: format!(
                        "unsupported encoding {:?}; only \"cbor-base64\" is accepted",
                        req.encoding
                    ),
                },
            }),
        )
            .into_response();
    }

    let raw = match BASE64_STANDARD.decode(&req.tx_bytes) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(TxSubmitErrorBody {
                    error: TxSubmitErrorDetail {
                        code: "ENCODING_ERROR",
                        message: format!("base64 decode failed: {e}"),
                    },
                }),
            )
                .into_response();
        }
    };

    // Structural decode (no crypto) to extract sender for per-sender budget check.
    let maybe_sender = decode_tx(&raw).ok().map(|tx| tx.sender);

    // Keep the exact wire bytes for gossip; `raw` gets consumed by try_admit.
    // Cheap: tx envelopes are typically < 2 KB. Any re-encoding would
    // invalidate the tx hash the sender's signature covers.
    let raw_for_gossip = raw.clone();
    let mut emit_inputs: Option<(Option<pqc_p2p::SwarmHandle>, String)> = None;
    let result = {
        let mut guard = state.lock().await;

        // Per-sender admission budget — checked before expensive sig verify.
        if let Some(ref sender) = maybe_sender {
            if guard.check_sender_budget(sender) {
                let window_secs = guard.sender_budget.window_secs;
                let max = guard.sender_budget.max_txs_per_window;
                guard.record_rejection("SENDER_RATE_LIMITED");
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(TxSubmitErrorBody {
                        error: TxSubmitErrorDetail {
                            code: "SENDER_RATE_LIMITED",
                            message: format!(
                                "per-sender admission budget exceeded: max {max} txs per \
                                 {window_secs}s — SPEC-FEE-001 §10.1"
                            ),
                        },
                    }),
                )
                    .into_response();
            }
        }

        let verifier = guard.verifier.clone();
        let res = {
            let LiveNodeState {
                state,
                mempool,
                fee_params,
                ..
            } = &mut *guard;
            try_admit(mempool, raw, state, verifier.as_ref(), fee_params)
        };
        match &res {
            Ok(_) => {
                guard.txs_admitted += 1;
                // Only admitted txs consume sender budget.
                if let Some(ref sender) = maybe_sender {
                    guard.record_sender_admission(sender);
                }
                emit_inputs = Some((guard.p2p_handle.clone(), guard.config.chain_id_hex.clone()));
            }
            Err(err) => {
                let (reason, _) = mempool_error_code(err);
                guard.record_rejection(reason);
            }
        }
        res
    };

    // Lock released; publish AFTER admission so we never gossip a tx the
    // local mempool rejected. `publish_if_enabled` is a no-op when the
    // libp2p swarm is disabled — zero production impact pre-cutover.
    if let Some((handle, chain_id)) = emit_inputs {
        let envelope = crate::p2p::tx_envelope(&chain_id, raw_for_gossip);
        crate::p2p::publish_if_enabled(handle.as_ref(), envelope).await;
    }

    match result {
        Ok(admission) => {
            let tx_hash = hex::encode(admission.tx_hash);
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "data": {
                        "tx_hash": tx_hash,
                        "status": "pending",
                        "min_fee_used": "0"
                    }
                })),
            )
                .into_response()
        }
        Err(err) => {
            let (code, http_status) = mempool_error_code(&err);
            (
                http_status,
                Json(TxSubmitErrorBody {
                    error: TxSubmitErrorDetail {
                        code,
                        message: err.to_string(),
                    },
                }),
            )
                .into_response()
        }
    }
}

pub(super) fn mempool_error_code(err: &MempoolError) -> (&'static str, StatusCode) {
    match err {
        MempoolError::ValidationFailed(tx_err) => tx_error_code(tx_err),
        MempoolError::Duplicate => ("DUPLICATE", StatusCode::CONFLICT),
        MempoolError::ReplacementUnderpriced { .. } => {
            ("REPLACEMENT_UNDERPRICED", StatusCode::BAD_REQUEST)
        }
        MempoolError::AlreadyIncluded => ("ALREADY_INCLUDED", StatusCode::CONFLICT),
        MempoolError::RateLimited => ("RATE_LIMITED", StatusCode::TOO_MANY_REQUESTS),
        MempoolError::VcCapReached => ("VC_CAP_REACHED", StatusCode::TOO_MANY_REQUESTS),
    }
}

pub(super) fn tx_error_code(err: &TxError) -> (&'static str, StatusCode) {
    match err {
        TxError::EncodingInvalid => ("ENCODING_ERROR", StatusCode::BAD_REQUEST),
        TxError::VersionUnsupported(_) => ("UNSUPPORTED_VERSION", StatusCode::BAD_REQUEST),
        TxError::ChainIdMismatch => ("CHAIN_ID_MISMATCH", StatusCode::BAD_REQUEST),
        TxError::MsgTypeUnknown(_) => ("UNSUPPORTED_MSG_TYPE", StatusCode::BAD_REQUEST),
        TxError::AlgorithmNotFound(_) | TxError::AlgorithmBanned(_) => {
            ("UNSUPPORTED_ALGORITHM", StatusCode::BAD_REQUEST)
        }
        TxError::SenderNotFound => ("INVALID_SENDER", StatusCode::BAD_REQUEST),
        TxError::KeyLookupFailed(_) => ("KEY_NOT_FOUND", StatusCode::BAD_REQUEST),
        TxError::SignatureInvalid => ("INVALID_SIGNATURE", StatusCode::BAD_REQUEST),
        TxError::NonceInvalid { .. } => ("NONCE_CONFLICT", StatusCode::CONFLICT),
        TxError::FeeInsufficient { .. } => ("INSUFFICIENT_FEE", StatusCode::BAD_REQUEST),
        TxError::GasLimitTooLow(_) => ("GAS_LIMIT_TOO_LOW", StatusCode::BAD_REQUEST),
        TxError::BalanceInsufficient { .. } => ("BALANCE_INSUFFICIENT", StatusCode::BAD_REQUEST),
        TxError::VerifyBudgetExceeded => ("RATE_LIMITED", StatusCode::TOO_MANY_REQUESTS),
        TxError::TxTooLarge(_) => ("INVALID_PAYLOAD", StatusCode::BAD_REQUEST),
        TxError::PayloadInvalid(_) => ("INVALID_PAYLOAD", StatusCode::BAD_REQUEST),
        TxError::FeeBelowMarket { .. } => ("FEE_BELOW_MARKET", StatusCode::BAD_REQUEST),
    }
}
