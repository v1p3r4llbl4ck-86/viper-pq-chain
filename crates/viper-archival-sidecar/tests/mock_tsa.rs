// SPDX-License-Identifier: BUSL-1.1
//! Mock-TSA integration test — TASK-164 / M4.5.
//!
//! Spins up an in-process axum server that accepts RFC 3161
//! `TimeStampReq` POSTs and returns a canned `TimeStampResp` DER blob.
//! Exercises `post_timestamp_request` end-to-end against it.
//!
//! This is the T8 acceptance test from SPEC-ARCHIVAL-001 §13 at
//! component-level — the full-sidecar integration (polling pqcd,
//! re-submitting AddAnchor) layers on top but depends on a live pqcd,
//! which is covered by the M4.7 product-workflow tests.

use std::{net::TcpListener, sync::Arc};

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    routing::post,
    Router,
};
use reqwest::Client;
use tokio::sync::Mutex;
use viper_archival_sidecar::{build_timestamp_request, post_timestamp_request, TsaEndpoint};

/// A canned TimeStampResp DER blob. Not a real TST — the apply path
/// doesn't validate the DER (SPEC §6.1), and our client doesn't parse
/// it either. Any bytes that look vaguely DER suffice for this test.
const CANNED_TST: &[u8] = &[
    0x30, 0x82, 0x03, 0x00, // SEQUENCE (big-length prefix — fake but valid-shape)
    // pad to ~768 bytes so we exercise the body reader
    0x04, 0x20, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99,
];

#[derive(Clone, Default)]
struct MockState {
    requests_received: Arc<Mutex<Vec<Vec<u8>>>>,
    content_types_seen: Arc<Mutex<Vec<String>>>,
}

async fn handle_tsa_post(
    State(state): State<MockState>,
    req: Request<Body>,
) -> (StatusCode, Vec<u8>) {
    let ct = req
        .headers()
        .get("Content-Type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let bytes = axum::body::to_bytes(req.into_body(), 1024 * 1024)
        .await
        .expect("read body")
        .to_vec();
    state.requests_received.lock().await.push(bytes);
    state.content_types_seen.lock().await.push(ct);
    (StatusCode::OK, CANNED_TST.to_vec())
}

#[tokio::test]
async fn sidecar_posts_to_mock_tsa_and_receives_canned_response() {
    // Reserve a local port by binding then dropping.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let mock_state = MockState::default();
    let app = Router::new()
        .route("/tsa", post(handle_tsa_post))
        .with_state(mock_state.clone());

    let server = tokio::spawn(async move {
        let l = tokio::net::TcpListener::bind(addr).await.unwrap();
        axum::serve(l, app).await.unwrap();
    });

    // Give the server a beat to come up.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let endpoint = TsaEndpoint {
        name: "mock".to_string(),
        url: format!("http://{addr}/tsa"),
        basic_auth_env: None,
    };

    let digest = [0x42u8; 32];
    let request_der = build_timestamp_request(&digest);
    assert!(!request_der.is_empty(), "request DER must be non-empty");
    assert_eq!(request_der[0], 0x30, "request must start with SEQUENCE tag");

    let client = Client::new();
    let response = post_timestamp_request(&client, &endpoint, None, &request_der)
        .await
        .expect("POST to mock TSA must succeed");

    assert_eq!(
        response, CANNED_TST,
        "response bytes must match the canned TST verbatim"
    );

    let received = mock_state.requests_received.lock().await;
    assert_eq!(
        received.len(),
        1,
        "mock TSA must have seen exactly 1 request"
    );
    assert_eq!(
        received[0], request_der,
        "request body bytes must round-trip"
    );

    let content_types = mock_state.content_types_seen.lock().await;
    assert_eq!(content_types.len(), 1);
    assert_eq!(
        content_types[0], "application/timestamp-query",
        "Content-Type must be RFC 3161 canonical"
    );

    server.abort();
}

#[tokio::test]
async fn sidecar_reports_error_on_non_2xx_tsa() {
    // Dedicated mock that returns 503.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    async fn handle_503() -> StatusCode {
        StatusCode::SERVICE_UNAVAILABLE
    }

    let app: Router<()> = Router::new().route("/tsa", post(handle_503));
    let server = tokio::spawn(async move {
        let l = tokio::net::TcpListener::bind(addr).await.unwrap();
        axum::serve(l, app).await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let endpoint = TsaEndpoint {
        name: "mock-503".to_string(),
        url: format!("http://{addr}/tsa"),
        basic_auth_env: None,
    };
    let request_der = build_timestamp_request(&[0; 32]);
    let client = Client::new();
    let err = post_timestamp_request(&client, &endpoint, None, &request_der)
        .await
        .expect_err("HTTP 503 must surface as TsaError::HttpStatus");
    let msg = format!("{err}");
    assert!(
        msg.contains("503"),
        "expected error to mention HTTP 503, got: {msg}"
    );

    server.abort();
}
