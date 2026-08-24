// SPDX-License-Identifier: BUSL-1.1
//! Integration tests for TASK-051 observability (metrics scrape endpoint).
//!
//! These tests verify that:
//! 1. `GET /v1/metrics` and `GET /internal/metrics` return 200 with
//!    Prometheus text exposition format.
//! 2. All required metric names are present in the response.
//! 3. The `txs_rejected_total` counter increments after a rejected transaction.
//! 4. The `txs_admitted_total` counter is 0 at startup.
//! 5. `pqchain_chain_height 0` is reported for a freshly bootstrapped node.

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
    node::{DevnetConfig, NodeConfig, NodeRole},
};

// ── Helpers ───────────────────────────────────────────────────────────────────

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            env::temp_dir().join(format!("pqcd-obs-{label}-{}-{unique}", std::process::id()));
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

/// Minimal `SingleNode` config with both P2P and API listeners active.
///
/// `SingleNode` requires no validators and starts no producer or sync loops,
/// making it the lightest possible live node for endpoint-availability tests.
fn metrics_node_config(data_dir: &Path, p2p_addr: &str, api_addr: &str) -> NodeConfig {
    NodeConfig {
        node_id: "obs-node".to_owned(),
        data_dir: data_dir.to_path_buf(),
        chain_id_hex: String::new(),
        anchor_prev_hash_hex: hex::encode([0x11u8; 32]),
        fee_params: FeeParams::default(),
        p2p_listen_addr: Some(p2p_addr.to_owned()),
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
        rate_limit: Default::default(),
        libp2p: None,
        sender_budget: Default::default(),
        api: Default::default(),
    }
}

/// Required metric names that must appear in every metrics response.
/// A change to any of these names is a breaking change (update CHANGELOG.md).
const REQUIRED_METRIC_NAMES: &[&str] = &[
    "pqchain_blocks_produced_total",
    "pqchain_blocks_imported_total",
    "pqchain_txs_admitted_total",
    "pqchain_txs_rejected_total",
    "pqchain_peer_sync_errors_total",
    "pqchain_chain_height",
    "pqchain_mempool_depth",
    "pqchain_node_start_unix_secs",
    "pqchain_recovery_source",
];

// ── Tests ─────────────────────────────────────────────────────────────────────

/// `GET /v1/metrics` returns 200 with text/plain and all required metric names.
#[tokio::test]
async fn metrics_endpoint_public_api_returns_required_names() {
    let data_dir = TempDir::new("metrics-api");
    let p2p_addr = reserve_local_addr();
    let api_addr = reserve_local_addr();

    let config = metrics_node_config(data_dir.path(), &p2p_addr, &api_addr);
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

    let resp = client
        .get(format!("http://{api_bound}/v1/metrics"))
        .send()
        .await
        .expect("metrics request failed");

    assert_eq!(
        resp.status().as_u16(),
        200,
        "metrics endpoint must return 200"
    );

    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("text/plain"),
        "content-type must be text/plain, got: {ct}"
    );

    let body = resp.text().await.expect("failed to read metrics body");
    for name in REQUIRED_METRIC_NAMES {
        assert!(
            body.contains(name),
            "expected metric '{name}' in response body:\n{body}"
        );
    }

    handle.shutdown().await.expect("shutdown failed");
}

/// `GET /internal/metrics` on the P2P listener returns the same metric set.
#[tokio::test]
async fn metrics_endpoint_p2p_internal_returns_required_names() {
    let data_dir = TempDir::new("metrics-p2p");
    let p2p_addr = reserve_local_addr();
    let api_addr = reserve_local_addr();

    let config = metrics_node_config(data_dir.path(), &p2p_addr, &api_addr);
    let config_path = data_dir.path().join("config.json");
    write_config(&config_path, &config);

    let handle = start_from_config_path(&config_path)
        .await
        .expect("node start failed");

    // Use the configured p2p_addr — the P2P server binds to it directly.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let resp = client
        .get(format!("http://{p2p_addr}/internal/metrics"))
        .send()
        .await
        .expect("internal metrics request failed");

    assert_eq!(
        resp.status().as_u16(),
        200,
        "internal metrics endpoint must return 200"
    );

    let body = resp.text().await.expect("failed to read metrics body");
    for name in REQUIRED_METRIC_NAMES {
        assert!(
            body.contains(name),
            "expected metric '{name}' in internal metrics:\n{body}"
        );
    }

    handle.shutdown().await.expect("shutdown failed");
}

/// A freshly started node reports height 0 and zero counters.
#[tokio::test]
async fn metrics_fresh_node_initial_values() {
    let data_dir = TempDir::new("metrics-init");
    let p2p_addr = reserve_local_addr();
    let api_addr = reserve_local_addr();

    let config = metrics_node_config(data_dir.path(), &p2p_addr, &api_addr);
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
    let body = client
        .get(format!("http://{api_bound}/v1/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert!(
        body.contains("pqchain_chain_height 0"),
        "height must be 0 at startup:\n{body}"
    );
    assert!(
        body.contains("pqchain_blocks_produced_total 0"),
        "blocks_produced must be 0 at startup:\n{body}"
    );
    assert!(
        body.contains("pqchain_txs_admitted_total 0"),
        "txs_admitted must be 0 at startup:\n{body}"
    );
    assert!(
        body.contains("pqchain_txs_rejected_total 0"),
        "txs_rejected must be 0 at startup:\n{body}"
    );
    assert!(
        body.contains("pqchain_recovery_source 0"),
        "fresh node must report FullReplay (0):\n{body}"
    );

    handle.shutdown().await.expect("shutdown failed");
}

/// Injecting a malformed transaction increments `txs_rejected_total` by 1.
#[tokio::test]
async fn metrics_rejected_tx_increments_counter() {
    let data_dir = TempDir::new("metrics-reject");
    let p2p_addr = reserve_local_addr();
    let api_addr = reserve_local_addr();

    let config = metrics_node_config(data_dir.path(), &p2p_addr, &api_addr);
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

    // Submit a clearly invalid transaction (random bytes encoded as cbor-base64).
    let bad_tx_b64 = base64::engine::general_purpose::STANDARD.encode(b"not-a-tx");
    let submit_resp = client
        .post(format!("http://{api_bound}/v1/txs"))
        .json(&serde_json::json!({
            "encoding": "cbor-base64",
            "tx_bytes": bad_tx_b64
        }))
        .send()
        .await
        .expect("tx submit request failed");
    assert_ne!(
        submit_resp.status().as_u16(),
        200,
        "bad tx must be rejected"
    );

    // Metrics must reflect the rejection.
    let body = client
        .get(format!("http://{api_bound}/v1/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert!(
        body.contains("pqchain_txs_rejected_total 1"),
        "txs_rejected must be 1 after one rejection:\n{body}"
    );
    assert!(
        body.contains("pqchain_txs_admitted_total 0"),
        "txs_admitted must still be 0:\n{body}"
    );
    // Per-reason breakdown: a malformed CBOR payload surfaces as
    // TxError::EncodingInvalid, which mempool_error_code maps to the
    // "ENCODING_ERROR" label. The aggregate above and the per-reason
    // line must move in lockstep — sum of all labels equals txs_rejected.
    assert!(
        body.contains("pqchain_txs_rejected_by_reason_total{reason=\"ENCODING_ERROR\"} 1"),
        "per-reason breakdown must show ENCODING_ERROR=1:\n{body}"
    );

    handle.shutdown().await.expect("shutdown failed");
}
