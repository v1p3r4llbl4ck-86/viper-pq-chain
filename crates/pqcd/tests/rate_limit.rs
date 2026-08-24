// SPDX-License-Identifier: BUSL-1.1
//! Integration tests for TASK-052: per-IP rate limiting on `POST /v1/txs`.
//!
//! The rate limiter is applied only to `POST /v1/txs`. Read endpoints
//! (`GET /v1/metrics`, etc.) and internal P2P endpoints are not affected.
//!
//! Tests configure nodes with a small `max_requests_per_window` so the limit
//! is reached quickly without long sleeps.

use std::{
    env, fs,
    net::TcpListener as StdTcpListener,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::Engine as _;
use pqc_tx::validate::FeeParams;
use pqcd::{
    devnet::start_from_config_path,
    node::{DevnetConfig, NodeConfig, NodeRole, RateLimitConfig},
};

// ── Helpers ───────────────────────────────────────────────────────────────────

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!("pqcd-rl-{label}-{}-{unique}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn reserve_local_addr() -> String {
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    format!("127.0.0.1:{}", addr.port())
}

fn write_config(path: &Path, config: &NodeConfig) {
    fs::write(path, serde_json::to_vec_pretty(config).unwrap()).unwrap();
}

/// Node config with a tight rate limit so tests reach the threshold quickly.
fn rate_limited_node_config(
    data_dir: &Path,
    api_addr: &str,
    max_requests: u32,
    window_secs: u64,
) -> NodeConfig {
    NodeConfig {
        node_id: "rl-node".to_owned(),
        data_dir: data_dir.to_path_buf(),
        chain_id_hex: String::new(),
        anchor_prev_hash_hex: hex::encode([0x11u8; 32]),
        fee_params: FeeParams::default(),
        p2p_listen_addr: None,
        api_listen_addr: Some(api_addr.to_owned()),
        peers: Vec::new(),
        devnet: DevnetConfig {
            role: NodeRole::SingleNode,
            sync_interval_ms: 100,
            block_time_ms: 500,
            proposer_address_hex: None,
            quorum_threshold: None,
            validators: Vec::new(),
            snapshot_source: None,
            ..Default::default()
        },
        genesis_accounts: Vec::new(),
        rate_limit: RateLimitConfig {
            max_requests_per_window: max_requests,
            window_secs,
        },
        libp2p: None,
        sender_budget: Default::default(),
        api: Default::default(),
    }
}

fn bad_tx_body() -> serde_json::Value {
    let bad_bytes = base64::engine::general_purpose::STANDARD.encode(b"not-a-valid-cbor-tx");
    serde_json::json!({ "encoding": "cbor-base64", "tx_bytes": bad_bytes })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// The (max+1)-th request from the same IP within the window receives 429.
#[tokio::test]
async fn rate_limit_blocks_excess_requests() {
    let data_dir = TempDir::new("rl-excess");
    let api_addr = reserve_local_addr();

    // Allow 2 requests per window; the 3rd must be rejected with 429.
    let config = rate_limited_node_config(data_dir.path(), &api_addr, 2, 60);
    let config_path = data_dir.path().join("config.json");
    write_config(&config_path, &config);

    let handle = start_from_config_path(&config_path)
        .await
        .expect("node start failed");
    let api_bound = handle.api_addr.expect("api_addr must be set");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let url = format!("http://{api_bound}/v1/txs");

    // Requests 1 and 2 are within the limit (they will be rejected for tx
    // semantics — ENCODING_ERROR or similar — but NOT for rate limiting).
    let r1 = client.post(&url).json(&bad_tx_body()).send().await.unwrap();
    assert_ne!(
        r1.status().as_u16(),
        429,
        "request 1 must not be rate-limited"
    );

    let r2 = client.post(&url).json(&bad_tx_body()).send().await.unwrap();
    assert_ne!(
        r2.status().as_u16(),
        429,
        "request 2 must not be rate-limited"
    );

    // Request 3 exceeds the limit.
    let r3 = client.post(&url).json(&bad_tx_body()).send().await.unwrap();
    assert_eq!(
        r3.status().as_u16(),
        429,
        "request 3 must be rate-limited (429)"
    );

    let body: serde_json::Value = r3.json().await.unwrap();
    assert_eq!(
        body["error"]["code"].as_str().unwrap(),
        "RATE_LIMITED",
        "429 response must carry RATE_LIMITED error code"
    );

    handle.shutdown().await.expect("shutdown failed");
}

/// After the window expires, the IP counter resets and requests are allowed again.
#[tokio::test]
async fn rate_limit_window_reset_allows_requests() {
    let data_dir = TempDir::new("rl-reset");
    let api_addr = reserve_local_addr();

    // Window of 1 second, max 1 request — the 2nd request in the same second is blocked.
    let config = rate_limited_node_config(data_dir.path(), &api_addr, 1, 1);
    let config_path = data_dir.path().join("config.json");
    write_config(&config_path, &config);

    let handle = start_from_config_path(&config_path)
        .await
        .expect("node start failed");
    let api_bound = handle.api_addr.expect("api_addr must be set");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let url = format!("http://{api_bound}/v1/txs");

    // First request is within limit.
    let r1 = client.post(&url).json(&bad_tx_body()).send().await.unwrap();
    assert_ne!(
        r1.status().as_u16(),
        429,
        "first request must not be rate-limited"
    );

    // Second request in the same window is rate-limited.
    let r2 = client.post(&url).json(&bad_tx_body()).send().await.unwrap();
    assert_eq!(
        r2.status().as_u16(),
        429,
        "second request in same window must be rate-limited"
    );

    // Wait for the window to expire, then verify the next request is allowed.
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let r3 = client.post(&url).json(&bad_tx_body()).send().await.unwrap();
    assert_ne!(
        r3.status().as_u16(),
        429,
        "request after window reset must not be rate-limited"
    );

    handle.shutdown().await.expect("shutdown failed");
}

/// `GET /v1/metrics` is never subject to rate limiting.
#[tokio::test]
async fn rate_limit_does_not_apply_to_read_endpoints() {
    let data_dir = TempDir::new("rl-reads");
    let api_addr = reserve_local_addr();

    // Very tight rate limit: max 1 request per long window.
    let config = rate_limited_node_config(data_dir.path(), &api_addr, 1, 3600);
    let config_path = data_dir.path().join("config.json");
    write_config(&config_path, &config);

    let handle = start_from_config_path(&config_path)
        .await
        .expect("node start failed");
    let api_bound = handle.api_addr.expect("api_addr must be set");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let metrics_url = format!("http://{api_bound}/v1/metrics");

    // Send more requests than the POST limit allows — all GET requests must succeed.
    for i in 0..5u32 {
        let r = client.get(&metrics_url).send().await.unwrap();
        assert_eq!(
            r.status().as_u16(),
            200,
            "GET /v1/metrics request {i} must not be rate-limited"
        );
    }

    handle.shutdown().await.expect("shutdown failed");
}

/// When rate limiting is disabled (`max_requests_per_window = 0`), unlimited requests succeed.
#[tokio::test]
async fn rate_limit_disabled_allows_unlimited_requests() {
    let data_dir = TempDir::new("rl-disabled");
    let api_addr = reserve_local_addr();

    // Disabled: max = 0.
    let config = rate_limited_node_config(data_dir.path(), &api_addr, 0, 60);
    let config_path = data_dir.path().join("config.json");
    write_config(&config_path, &config);

    let handle = start_from_config_path(&config_path)
        .await
        .expect("node start failed");
    let api_bound = handle.api_addr.expect("api_addr must be set");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let url = format!("http://{api_bound}/v1/txs");

    // Send 10 requests — none should be 429 with rate limiting disabled.
    for i in 0..10u32 {
        let r = client.post(&url).json(&bad_tx_body()).send().await.unwrap();
        assert_ne!(
            r.status().as_u16(),
            429,
            "request {i} must not be rate-limited when max=0 (disabled)"
        );
    }

    handle.shutdown().await.expect("shutdown failed");
}
