// SPDX-License-Identifier: BUSL-1.1
//! Stage A.3 integration test — `ValidatorRotatePeerId` apply contract +
//! `/v1/validators` API exposure of the rotated binding.
//!
//! Scope: the contract that the `pqcd wallet rotate-peer-id` CLI's
//! post-apply verification step depends on. Specifically:
//!
//!   1. A `ValidatorRotatePeerId` tx, signed by an Active validator's
//!      operator key and posted to the live mempool, lands and flips the
//!      on-chain `validator_peer_ids` binding (ADR-047 / TASK-159).
//!   2. The read-API endpoints `/v1/validators` (list) and
//!      `/v1/validators/<addr>` (single) both surface the rotated binding
//!      as a `peer_id_hex` field — `null` before any rotation, hex string
//!      after. The CLI's verification step at
//!      `cli/wallet.rs::cmd_wallet_rotate_peer_id` polls the single-endpoint
//!      variant and fail-closes when this field disagrees with the salt
//!      it staged on disk.
//!
//! Out of scope (covered elsewhere or not yet exercised in this test):
//! - The CLI's argv parsing → reqwest → poll loop. Mirror of the
//!   in-prod `cmd_wallet_rotate_consensus_key` precedent.
//! - The atomic node.json salt-write path. Covered by 11 helper unit
//!   tests at `crates/pqcd/src/cli/wallet/in_place_node_config_tests.rs`.
//! - The libp2p Keypair re-derivation on pqcd restart. Covered by
//!   Stage A.1's pin tests at `crates/pqcd/src/p2p/tests.rs`.

use std::{
    env, fs,
    net::TcpListener as StdTcpListener,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use pqc_crypto::{derive_address, ml_dsa_public_key_from_seed, ml_dsa_sign_with_seed, AlgId};
use pqc_state::encode_rotate_peer_id_payload;
use pqc_tx::{codec::encode_tx, preimage::build_preimage, validate::FeeParams};
use pqc_types::{
    account::Address,
    keyset::allowed_tx,
    transaction::{MsgType, Transaction},
};
use pqcd::{
    devnet::start_from_config_path,
    node::{
        DevnetConfig, GenesisAccountConfig, GenesisKeyConfig, GenesisKeyStatus, NodeConfig,
        NodeRole, RateLimitConfig, SenderBudgetConfig, ValidatorConfig,
    },
};

// ── Operator identity (genesis-seeded as both account + validator) ───────────

const OPERATOR_SEED: [u8; 32] = [0xDDu8; 32];
const ANCHOR_PREV_HASH: [u8; 32] = [0x11u8; 32];

fn operator_pk() -> Vec<u8> {
    ml_dsa_public_key_from_seed(AlgId::MlDsa65, &OPERATOR_SEED)
        .expect("operator pk derivation must succeed")
}

fn operator_address() -> Address {
    let pk = operator_pk();
    Address(derive_address(&[], AlgId::MlDsa65, &pk))
}

fn sign_tx(tx: &Transaction) -> Vec<u8> {
    let preimage = build_preimage(&pqc_types::ForkDigest::viper_research_1(), tx)
        .expect("preimage must build");
    ml_dsa_sign_with_seed(AlgId::MlDsa65, &OPERATOR_SEED, &preimage).expect("signing must succeed")
}

// ── Filesystem + port helpers (same shape as rate_limit.rs / key_rotation_drill.rs) ──

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "pqcd-rotate-peer-id-it-{label}-{}-{unique}",
            std::process::id()
        ));
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

fn single_node_config(data_dir: &Path, api_addr: &str, p2p_addr: &str) -> NodeConfig {
    // Operator is BOTH a genesis account (so its key can sign txs) AND a
    // genesis validator (so it's Active and rotatable via
    // ValidatorRotatePeerId). Same pk in both places — the apply path
    // looks the account up by sender to verify the tx signature, and the
    // validator-record up by operator address to apply the rotation.
    let op_addr_hex = hex::encode(operator_address().0);
    NodeConfig {
        node_id: "rotate-peer-id-it".to_owned(),
        data_dir: data_dir.to_path_buf(),
        chain_id_hex: String::new(),
        anchor_prev_hash_hex: hex::encode(ANCHOR_PREV_HASH),
        fee_params: FeeParams::default(),
        p2p_listen_addr: Some(p2p_addr.to_owned()),
        api_listen_addr: Some(api_addr.to_owned()),
        peers: Vec::new(),
        devnet: DevnetConfig {
            // Producer (not SingleNode) so the consensus_loop runs and
            // produces blocks. With one local validator (operator) acting
            // as proposer, the loop signs its own commit sig and quorum
            // 1/1 closes — same multi-validator-single-node simulation
            // pattern as crates/pqcd/tests/key_rotation_drill.rs.
            role: NodeRole::Validator,
            sync_interval_ms: 50,
            block_time_ms: 500,
            proposer_address_hex: Some(hex::encode(operator_address().0)),
            quorum_threshold: None,
            validators: vec![ValidatorConfig {
                node_id: "rotate-peer-id-it".to_owned(),
                address_hex: op_addr_hex.clone(),
                sig_alg_id: AlgId::MlDsa65.as_u16(),
                public_key_hex: hex::encode(operator_pk()),
                commit_seed_hex: Some(hex::encode(OPERATOR_SEED)),
                archival_sk_hex: None,
            }],
            snapshot_source: None,
            ..Default::default()
        },
        genesis_accounts: vec![GenesisAccountConfig {
            address_hex: op_addr_hex,
            balance: 10_000_000,
            nonce: 0,
            keys: vec![GenesisKeyConfig {
                alg_id: AlgId::MlDsa65.as_u16(),
                pk_hex: hex::encode(operator_pk()),
                key_version: 1,
                valid_from_height: 0,
                status: GenesisKeyStatus::Active,
                allowed_tx_types: allowed_tx::ALL,
            }],
        }],
        rate_limit: RateLimitConfig {
            max_requests_per_window: 0,
            window_secs: 60,
        },
        libp2p: None,
        sender_budget: SenderBudgetConfig {
            max_txs_per_window: 0,
            window_secs: 60,
        },
        api: Default::default(),
    }
}

/// Build a signed ValidatorRotatePeerId tx carrying `new_peer_id`.
fn rotate_peer_id_tx(sender: &Address, nonce: u64, new_peer_id: &[u8]) -> Vec<u8> {
    let mut tx = Transaction {
        tx_version: 1,
        chain_id: Vec::new(),
        msg_type: MsgType::ValidatorRotatePeerId,
        sender: sender.clone(),
        nonce,
        fee: 500,
        fee_tip: 0,
        gas_limit: 100_000,
        payload: encode_rotate_peer_id_payload(new_peer_id),
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: Vec::new(),
    };
    tx.signature = sign_tx(&tx);
    encode_tx(&tx).expect("encode_tx must succeed")
}

/// Poll /v1/validators/<addr> until peer_id_hex matches `expected_hex`.
async fn wait_for_peer_id_binding(
    client: &reqwest::Client,
    base_url: &str,
    addr_hex: &str,
    expected_hex: &str,
    timeout: Duration,
) -> Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    let url = format!(
        "{}/v1/validators/{}",
        base_url.trim_end_matches('/'),
        addr_hex
    );
    loop {
        let resp = client
            .get(&url)
            .send()
            .await
            .context("GET /v1/validators failed")?;
        if resp.status().is_success() {
            let body: serde_json::Value = resp.json().await.context("parse /v1/validators body")?;
            let got = body
                .pointer("/data/peer_id_hex")
                .and_then(|v| v.as_str())
                .map(str::to_owned);
            if got
                .as_deref()
                .is_some_and(|s| s.eq_ignore_ascii_case(expected_hex))
            {
                return Ok(());
            }
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "timeout waiting for /v1/validators/{addr_hex}::data.peer_id_hex == {expected_hex}"
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// End-to-end happy-path proof of the Stage A.3 contract:
///   - submit a ValidatorRotatePeerId tx via the live mempool;
///   - confirm /v1/validators/<addr> reflects the new binding;
///   - confirm /v1/validators (list) reflects the new binding too.
///
/// The CLI's HTTP polling + verification logic is structurally identical
/// to the post-rotation poll done by this test, so a green here is
/// strong evidence the CLI's verification step works against a live node.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn validator_rotate_peer_id_flips_on_chain_binding_and_api_exposes_it() {
    let dir = TempDir::new("happy");
    let api_addr = reserve_local_addr();
    let p2p_addr = reserve_local_addr();
    let config_path = dir.path().join("config.json");
    write_config(
        &config_path,
        &single_node_config(&dir.path().join("node"), &api_addr, &p2p_addr),
    );

    let node = start_from_config_path(&config_path)
        .await
        .expect("node start must succeed");
    let api_bound = node.api_addr.expect("api_listen_addr was set");
    let base_url = format!("http://{api_bound}");

    // Wait for height ≥ 1 so the genesis state is committed and queriable.
    node.wait_for_height(1, Duration::from_secs(15))
        .await
        .expect("node must reach height 1");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let operator = operator_address();
    let op_hex = hex::encode(operator.0);

    // ── 1. Initial state: peer_id_hex is null (D-03 deferred default). ──
    let pre_resp: serde_json::Value = client
        .get(format!("{base_url}/v1/validators/{op_hex}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        pre_resp
            .pointer("/data/peer_id_hex")
            .map(|v| v.is_null())
            .unwrap_or(false),
        "before any rotation the binding must be null, got: {pre_resp}"
    );

    // ── 2. Submit a ValidatorRotatePeerId tx with a known peer_id. ──
    // The bytes are arbitrary (≤ VALIDATOR_PEER_ID_MAX_LEN = 64); apply
    // accepts any non-empty non-conflicting blob. In production the CLI
    // computes these from `deterministic_peer_id(node_id, Some(&salt))`
    // — Stage A.1's pin tests cover that derivation; this test only
    // proves the on-chain binding flips to whatever bytes the tx carries.
    let new_peer_id: Vec<u8> = vec![0xC0, 0xDE, 0xCA, 0xFE, 0xBE, 0xEF, 0xBA, 0xAD];
    let expected_hex = hex::encode(&new_peer_id);
    let raw_tx = rotate_peer_id_tx(&operator, 0, &new_peer_id);
    node.inject_tx(raw_tx)
        .await
        .expect("ValidatorRotatePeerId tx must be admitted");

    // ── 3. Poll /v1/validators/<addr> until the binding flips. ──
    wait_for_peer_id_binding(
        &client,
        &base_url,
        &op_hex,
        &expected_hex,
        Duration::from_secs(15),
    )
    .await
    .expect("single-validator endpoint must expose the rotated peer_id");

    // ── 4. List endpoint /v1/validators surfaces the same binding. ──
    let list: serde_json::Value = client
        .get(format!("{base_url}/v1/validators"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let entry = list
        .as_array()
        .expect("/v1/validators returns a JSON array")
        .iter()
        .find(|v| v.get("address").and_then(|a| a.as_str()) == Some(op_hex.as_str()))
        .expect("operator's validator entry must be present in the list");
    assert_eq!(
        entry.get("peer_id_hex").and_then(|v| v.as_str()),
        Some(expected_hex.as_str()),
        "/v1/validators list endpoint must surface the rotated binding identically to \
         /v1/validators/<addr> — the CLI's verification step relies on either being authoritative"
    );

    node.shutdown().await.expect("shutdown must succeed");
}
