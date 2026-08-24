// SPDX-License-Identifier: BUSL-1.1
//! Integration tests for the local multi-node devnet runtime.
//!
//! These scenarios exercise the real `pqcd::devnet` process model with commit
//! signatures enabled: static peer configuration, local block production,
//! follower catch-up, restart recovery, and explicit rejection of invalid
//! commit material on import.

use std::{
    collections::HashMap,
    env, fs,
    net::TcpListener as StdTcpListener,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use axum::{
    extract::{Path as AxumPath, State},
    http::{header, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use pqc_consensus::{
    commit_preimage, AssemblyConfig, ChainStore, LocalProposer, LocalProposerConfig,
    RocksDbChainStore, StoredBlock,
};
use pqc_crypto::{
    kem_decapsulate, kem_generate, ml_dsa_public_key_from_seed, ml_dsa_sign_with_seed, shake256_32,
    AlgId, KEM_CT_LEN, KEM_PK_LEN, KEM_SK_LEN,
};
use pqc_mempool::Mempool;
use pqc_state::StateStore;
use pqc_tx::validate::FeeParams;
use pqc_types::account::Address;
use pqc_types::block::{Block, BlockHash, CommitSig};
use pqc_types::validator::{ValidatorRecord, ValidatorStatus};
use pqcd::{
    devnet::{start_from_config_path, DevnetNodeHandle, DevnetNodeSnapshot},
    node::{DevnetConfig, NodeConfig, NodeRole, PeerConfig, ValidatorConfig},
};
use serde_json::json;
use tokio::{
    net::TcpListener,
    sync::watch,
    task::JoinHandle,
    time::{self, Duration, Instant},
};

const ANCHOR_PREV_HASH: [u8; 32] = [0x11; 32];
const PRODUCER_ADDRESS: [u8; 32] = [0x99; 32];

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "pqcd-devnet-{label}-{}-{unique}",
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

#[derive(Clone)]
struct TestValidator {
    node_id: String,
    address: [u8; 32],
    sig_alg_id: AlgId,
    commit_seed: [u8; 32],
    public_key: Vec<u8>,
}

struct MaliciousPeerHandle {
    shutdown_tx: watch::Sender<bool>,
    task: JoinHandle<Result<()>>,
    p2p_addr: String,
}

impl MaliciousPeerHandle {
    fn peer_config(&self) -> PeerConfig {
        PeerConfig {
            node_id: "malicious-peer".to_owned(),
            p2p_addr: self.p2p_addr.clone(),
        }
    }

    async fn shutdown(self) -> Result<()> {
        let _ = self.shutdown_tx.send(true);
        self.task.await.context("malicious peer join failed")??;
        Ok(())
    }
}

struct MaliciousPeerState {
    height: u64,
    block_bytes: Vec<u8>,
    tip_hash_hex: String,
    state_root_hex: String,
    /// ML-KEM-768 public key (hex). Served at /internal/p2p/kem-pubkey.
    kem_pk_hex: String,
    /// ML-KEM-768 decapsulation key. Used in /internal/p2p/session.
    kem_sk: [u8; KEM_SK_LEN],
    /// Active sessions: session_id → shared_secret (accepted but not verified on fetch).
    sessions: tokio::sync::Mutex<HashMap<String, [u8; 32]>>,
}

const MALICIOUS_KEM_D: [u8; 32] = [0xCC; 32];
const MALICIOUS_KEM_Z: [u8; 32] = [0xDD; 32];

fn reserve_local_addr() -> String {
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    format!("127.0.0.1:{}", addr.port())
}

fn write_config(path: &Path, config: &NodeConfig) {
    fs::write(path, serde_json::to_vec_pretty(config).unwrap()).unwrap();
}

fn test_validators() -> Vec<TestValidator> {
    [
        ("validator-1", [0xA1; 32], [0x11; 32]),
        ("validator-2", [0xA2; 32], [0x22; 32]),
        ("validator-3", [0xA3; 32], [0x33; 32]),
    ]
    .into_iter()
    .map(|(node_id, address, commit_seed)| TestValidator {
        node_id: node_id.to_owned(),
        address,
        sig_alg_id: AlgId::MlDsa65,
        commit_seed,
        public_key: ml_dsa_public_key_from_seed(AlgId::MlDsa65, &commit_seed)
            .expect("public key derivation must succeed"),
    })
    .collect()
}

fn validator_configs(validators: &[TestValidator], include_seeds: bool) -> Vec<ValidatorConfig> {
    validators
        .iter()
        .map(|validator| ValidatorConfig {
            node_id: validator.node_id.clone(),
            address_hex: hex::encode(validator.address),
            sig_alg_id: validator.sig_alg_id.as_u16(),
            public_key_hex: hex::encode(&validator.public_key),
            commit_seed_hex: include_seeds.then(|| hex::encode(validator.commit_seed)),
            archival_sk_hex: None,
        })
        .collect()
}

fn producer_config(
    node_id: &str,
    data_dir: &Path,
    p2p_listen_addr: &str,
    peers: Vec<PeerConfig>,
    validators: &[TestValidator],
) -> NodeConfig {
    NodeConfig {
        node_id: node_id.to_owned(),
        data_dir: data_dir.to_path_buf(),
        chain_id_hex: String::new(),
        anchor_prev_hash_hex: hex::encode(ANCHOR_PREV_HASH),
        fee_params: FeeParams::default(),
        p2p_listen_addr: Some(p2p_listen_addr.to_owned()),
        api_listen_addr: None,
        peers,
        devnet: DevnetConfig {
            role: NodeRole::Validator,
            sync_interval_ms: 50,
            block_time_ms: 250,
            proposer_address_hex: Some(hex::encode(PRODUCER_ADDRESS)),
            quorum_threshold: None,
            validators: validator_configs(validators, true),
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

fn follower_config(
    node_id: &str,
    data_dir: &Path,
    p2p_listen_addr: &str,
    peers: Vec<PeerConfig>,
    validators: &[TestValidator],
) -> NodeConfig {
    NodeConfig {
        node_id: node_id.to_owned(),
        data_dir: data_dir.to_path_buf(),
        chain_id_hex: String::new(),
        anchor_prev_hash_hex: hex::encode(ANCHOR_PREV_HASH),
        fee_params: FeeParams::default(),
        p2p_listen_addr: Some(p2p_listen_addr.to_owned()),
        api_listen_addr: None,
        peers,
        devnet: DevnetConfig {
            role: NodeRole::Full,
            sync_interval_ms: 50,
            block_time_ms: 250,
            proposer_address_hex: None,
            quorum_threshold: None,
            validators: validator_configs(validators, false),
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

async fn wait_for_cluster_convergence(
    handles: &[&DevnetNodeHandle],
    min_height: u64,
    timeout: Duration,
) -> Result<Vec<DevnetNodeSnapshot>> {
    let deadline = Instant::now() + timeout;
    let mut last = Vec::new();

    loop {
        last.clear();
        for handle in handles {
            last.push(handle.snapshot().await);
        }

        let first = &last[0];
        if first.height >= min_height
            && last.iter().all(|snapshot| {
                snapshot.height == first.height
                    && snapshot.tip_hash == first.tip_hash
                    && snapshot.state_root == first.state_root
            })
        {
            return Ok(last.clone());
        }

        if Instant::now() >= deadline {
            bail!(
                "timed out waiting for cluster convergence at height >= {min_height}: {}",
                format_snapshots(&last)
            );
        }

        time::sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_for_sync_error(
    handle: &DevnetNodeHandle,
    timeout: Duration,
) -> Result<DevnetNodeSnapshot> {
    let deadline = Instant::now() + timeout;

    loop {
        let snapshot = handle.snapshot().await;
        if snapshot.last_sync_error.is_some() {
            return Ok(snapshot);
        }

        if Instant::now() >= deadline {
            bail!(
                "timed out waiting for sync error on node {}",
                snapshot.node_id
            );
        }

        time::sleep(Duration::from_millis(25)).await;
    }
}

fn format_snapshots(snapshots: &[DevnetNodeSnapshot]) -> String {
    snapshots
        .iter()
        .map(|snapshot| {
            format!(
                "{}@{} tip={} root={} err={:?}",
                snapshot.node_id,
                snapshot.height,
                hex::encode(snapshot.tip_hash.0),
                hex::encode(snapshot.state_root.0),
                snapshot.last_sync_error
            )
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

fn build_signed_commit_block(validators: &[TestValidator]) -> Result<StoredBlock> {
    let anchor = BlockHash(ANCHOR_PREV_HASH);
    // Seed genesis state with the same validators as the follower will have (TASK-064).
    let mut state = StateStore::new();
    for v in validators {
        state.insert_validator(ValidatorRecord {
            operator: Address(v.address),
            node_id: v.node_id.clone(),
            consensus_alg_id: v.sig_alg_id,
            consensus_pk: v.public_key.clone(),
            self_bond: 0,
            status: ValidatorStatus::Active,
            registered_height: 0,
            tombstoned: false,
        });
    }
    let mempool = Mempool::new();
    let proposer = LocalProposer::new(
        PRODUCER_ADDRESS,
        LocalProposerConfig {
            assembly: AssemblyConfig::default(),
            initial_prev_hash: anchor.clone(),
        },
    );

    let mut proposal = proposer
        .build_next_block(&state, &mempool, 1_710_000_000)
        .context("failed to build signed commit block")?;
    attach_test_commit_quorum(
        &mut proposal.execution.block,
        &proposal.block_hash,
        validators,
    )?;

    let mut chain = ChainStore::new(anchor);
    chain
        .append_block(&proposal.execution)
        .context("failed to append signed commit block")?;

    Ok(chain
        .get_stored_block_by_height(1)
        .expect("height 1 block must exist")
        .clone())
}

fn attach_test_commit_quorum(
    block: &mut Block,
    block_hash: &BlockHash,
    validators: &[TestValidator],
) -> Result<()> {
    let fd = pqc_types::ForkDigest::viper_research_1();
    let preimage = commit_preimage(&fd, block.header.height, block_hash);
    block.commit_signatures = validators
        .iter()
        .map(|validator| {
            let signature =
                ml_dsa_sign_with_seed(validator.sig_alg_id, &validator.commit_seed, &preimage)
                    .context("failed to sign test commit preimage")?;
            Ok(CommitSig {
                validator_address: validator.address.to_vec(),
                sig_alg_id: validator.sig_alg_id,
                round: 0,
                signature,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(())
}

async fn start_malicious_peer(stored: StoredBlock) -> Result<MaliciousPeerHandle> {
    // Generate a KEM keypair for the malicious peer so followers can establish sessions
    // and receive the bad block. The block validation (commit quorum check) will
    // still fail after the authenticated fetch.
    let (kem_pk, kem_sk) = kem_generate(&MALICIOUS_KEM_D, &MALICIOUS_KEM_Z);
    // Test-only: extract raw bytes from the ZeroizeOnDrop wrapper. The test
    // struct does not need its own zeroize discipline — seeds here are
    // fixed test constants (MALICIOUS_KEM_D/Z), not secrets.
    let kem_sk = kem_sk.into_bytes();
    let state = Arc::new(MaliciousPeerState {
        height: stored.metadata.height,
        tip_hash_hex: hex::encode(stored.metadata.block_hash.0),
        state_root_hex: hex::encode(stored.metadata.state_root.0),
        block_bytes: RocksDbChainStore::encode_block_bytes(&stored)
            .context("failed to encode malicious block")?,
        kem_pk_hex: hex::encode(kem_pk),
        kem_sk,
        sessions: tokio::sync::Mutex::new(HashMap::new()),
    });
    let listen_addr = reserve_local_addr();
    let listener = TcpListener::bind(&listen_addr)
        .await
        .with_context(|| format!("failed to bind malicious peer listener to {listen_addr}"))?;
    let p2p_addr = listener
        .local_addr()
        .context("failed to inspect malicious peer listener")?
        .to_string();
    let app = Router::new()
        .route("/internal/p2p/status", get(handle_malicious_status))
        .route("/internal/p2p/kem-pubkey", get(handle_malicious_kem_pubkey))
        .route("/internal/p2p/session", post(handle_malicious_session))
        .route("/internal/p2p/blocks/{height}", get(handle_malicious_block))
        .with_state(state);
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.changed().await;
            })
            .await
            .context("malicious peer server error")
    });

    Ok(MaliciousPeerHandle {
        shutdown_tx,
        task,
        p2p_addr,
    })
}

async fn handle_malicious_status(
    State(state): State<Arc<MaliciousPeerState>>,
) -> Json<serde_json::Value> {
    Json(json!({
        "node_id": "malicious-peer",
        "height": state.height,
        "tip_hash": state.tip_hash_hex,
        "state_root": state.state_root_hex,
    }))
}

async fn handle_malicious_kem_pubkey(
    State(state): State<Arc<MaliciousPeerState>>,
) -> Json<serde_json::Value> {
    Json(json!({ "kem_pk": &state.kem_pk_hex }))
}

async fn handle_malicious_session(
    State(state): State<Arc<MaliciousPeerState>>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let ct_hex = match body["ciphertext"].as_str() {
        Some(s) => s.to_owned(),
        None => return (StatusCode::BAD_REQUEST, "missing ciphertext").into_response(),
    };
    let ct_bytes = match hex::decode(&ct_hex) {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid ciphertext hex").into_response(),
    };
    let ct: [u8; KEM_CT_LEN] = match ct_bytes.try_into() {
        Ok(ct) => ct,
        Err(_) => return (StatusCode::BAD_REQUEST, "wrong ciphertext length").into_response(),
    };
    let ss = kem_decapsulate(&state.kem_sk, &ct);
    // Mirror the production KDF derivation: SHAKE-256(ss || "session-id")[..16].
    let session_id_bytes = shake256_32(&[ss.as_slice(), b"session-id"].concat());
    let session_id = hex::encode(&session_id_bytes[..16]);
    state.sessions.lock().await.insert(session_id.clone(), ss);
    Json(json!({ "session_id": session_id })).into_response()
}

async fn handle_malicious_block(
    State(state): State<Arc<MaliciousPeerState>>,
    AxumPath(height): AxumPath<u64>,
) -> Response {
    // Auth headers are intentionally ignored; the bad block itself causes rejection.
    if height != state.height {
        return (StatusCode::NOT_FOUND, "block not found").into_response();
    }

    (
        [(header::CONTENT_TYPE, "application/cbor")],
        state.block_bytes.clone(),
    )
        .into_response()
}

async fn assert_rejected_commit_block(
    label: &str,
    expected_error_fragment: &str,
    stored: StoredBlock,
) -> Result<()> {
    let dir = TempDir::new(label);
    let validators = test_validators();
    let follower_addr = reserve_local_addr();
    let follower_config_path = dir.path().join("follower.json");
    let malicious_peer = start_malicious_peer(stored).await?;

    write_config(
        &follower_config_path,
        &follower_config(
            "node-follower",
            &dir.path().join("node-follower"),
            &follower_addr,
            vec![malicious_peer.peer_config()],
            &validators,
        ),
    );

    let follower = start_from_config_path(&follower_config_path).await?;
    let snapshot = wait_for_sync_error(&follower, Duration::from_secs(5)).await?;

    assert_eq!(
        snapshot.height, 0,
        "follower must not accept invalid commit block"
    );
    let error = snapshot
        .last_sync_error
        .as_deref()
        .unwrap_or("<missing-sync-error>");
    assert!(
        error.contains(expected_error_fragment),
        "expected sync error to contain {expected_error_fragment}, got {error}"
    );

    // TASK-181 Part B: this is a NEGATIVE persistence check, not a poll
    // loop. We deliberately wait a fixed window to give the follower's
    // background sync ticks a chance to retry the (still-invalid) block
    // delivery from the malicious peer. If height advances during this
    // window, the rejection was not persistent. 200 ms covers ≥4 sync
    // ticks at the 50 ms `sync_interval_ms` configured in
    // `follower_config` — enough to surface a regression while staying
    // well under the test's overall budget. Increasing this would slow
    // the test for no detection benefit; decreasing it could miss a
    // single-tick acceptance regression.
    time::sleep(Duration::from_millis(200)).await;
    let after_retry = follower.snapshot().await;
    assert_eq!(
        after_retry.height, 0,
        "follower height must remain unchanged after repeated invalid commit attempts"
    );

    follower.shutdown().await?;
    malicious_peer.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn block_with_valid_quorum_is_accepted() -> Result<()> {
    let dir = TempDir::new("valid-quorum");
    let validators = test_validators();

    let producer_addr = reserve_local_addr();
    let follower_a_addr = reserve_local_addr();
    let follower_b_addr = reserve_local_addr();

    let producer_config_path = dir.path().join("producer.json");
    let follower_a_config_path = dir.path().join("follower-a.json");
    let follower_b_config_path = dir.path().join("follower-b.json");

    write_config(
        &producer_config_path,
        &producer_config(
            "node-1",
            &dir.path().join("node-1"),
            &producer_addr,
            Vec::new(),
            &validators,
        ),
    );
    write_config(
        &follower_a_config_path,
        &follower_config(
            "node-2",
            &dir.path().join("node-2"),
            &follower_a_addr,
            vec![PeerConfig {
                node_id: "node-1".to_owned(),
                p2p_addr: producer_addr.clone(),
            }],
            &validators,
        ),
    );
    write_config(
        &follower_b_config_path,
        &follower_config(
            "node-3",
            &dir.path().join("node-3"),
            &follower_b_addr,
            vec![PeerConfig {
                node_id: "node-1".to_owned(),
                p2p_addr: producer_addr.clone(),
            }],
            &validators,
        ),
    );

    let producer = start_from_config_path(&producer_config_path).await?;
    let follower_a = start_from_config_path(&follower_a_config_path).await?;
    let follower_b = start_from_config_path(&follower_b_config_path).await?;

    let snapshots = wait_for_cluster_convergence(
        &[&producer, &follower_a, &follower_b],
        3,
        Duration::from_secs(10),
    )
    .await?;

    assert!(snapshots
        .iter()
        .all(|snapshot| snapshot.last_sync_error.is_none()));
    assert_eq!(snapshots[0].tip_hash, snapshots[1].tip_hash);
    assert_eq!(snapshots[0].tip_hash, snapshots[2].tip_hash);
    assert_eq!(snapshots[0].state_root, snapshots[1].state_root);
    assert_eq!(snapshots[0].state_root, snapshots[2].state_root);

    // Inspect commit signatures via the live handle to avoid opening the data
    // directory while the producer is still writing to it.
    let sig_count = producer
        .tip_commit_sig_count()
        .await
        .expect("producer tip must exist after convergence");
    assert!(
        sig_count > 0,
        "committed block must carry non-empty commit signatures"
    );
    assert_eq!(
        sig_count,
        validators.len(),
        "producer signs with the full static validator set in the prototype path"
    );

    follower_b.shutdown().await?;
    follower_a.shutdown().await?;
    producer.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn follower_restart_catches_up_to_same_tip() -> Result<()> {
    let dir = TempDir::new("restart-catch-up");
    let validators = test_validators();

    let producer_addr = reserve_local_addr();
    let follower_a_addr = reserve_local_addr();
    let follower_b_addr = reserve_local_addr();

    let producer_config_path = dir.path().join("producer.json");
    let follower_a_config_path = dir.path().join("follower-a.json");
    let follower_b_config_path = dir.path().join("follower-b.json");

    write_config(
        &producer_config_path,
        &producer_config(
            "node-1",
            &dir.path().join("node-1"),
            &producer_addr,
            Vec::new(),
            &validators,
        ),
    );
    write_config(
        &follower_a_config_path,
        &follower_config(
            "node-2",
            &dir.path().join("node-2"),
            &follower_a_addr,
            vec![PeerConfig {
                node_id: "node-1".to_owned(),
                p2p_addr: producer_addr.clone(),
            }],
            &validators,
        ),
    );
    write_config(
        &follower_b_config_path,
        &follower_config(
            "node-3",
            &dir.path().join("node-3"),
            &follower_b_addr,
            vec![PeerConfig {
                node_id: "node-1".to_owned(),
                p2p_addr: producer_addr.clone(),
            }],
            &validators,
        ),
    );

    let producer = start_from_config_path(&producer_config_path).await?;
    let follower_a = start_from_config_path(&follower_a_config_path).await?;
    let follower_b = start_from_config_path(&follower_b_config_path).await?;

    let initial = wait_for_cluster_convergence(
        &[&producer, &follower_a, &follower_b],
        2,
        Duration::from_secs(10),
    )
    .await?;
    assert!(initial[2].height >= 2);

    follower_b.shutdown().await?;

    let source_pair =
        wait_for_cluster_convergence(&[&producer, &follower_a], 4, Duration::from_secs(10)).await?;
    assert_eq!(source_pair[0].tip_hash, source_pair[1].tip_hash);

    let follower_b = start_from_config_path(&follower_b_config_path).await?;
    let final_cluster = wait_for_cluster_convergence(
        &[&producer, &follower_a, &follower_b],
        5,
        Duration::from_secs(10),
    )
    .await?;

    assert!(final_cluster
        .iter()
        .all(|snapshot| snapshot.last_sync_error.is_none()));
    assert_eq!(final_cluster[0].tip_hash, final_cluster[1].tip_hash);
    assert_eq!(final_cluster[0].tip_hash, final_cluster[2].tip_hash);
    assert_eq!(final_cluster[0].state_root, final_cluster[1].state_root);
    assert_eq!(final_cluster[0].state_root, final_cluster[2].state_root);

    follower_b.shutdown().await?;
    follower_a.shutdown().await?;
    producer.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn block_with_insufficient_quorum_is_rejected() -> Result<()> {
    let validators = test_validators();
    let mut stored = build_signed_commit_block(&validators)?;
    stored
        .block
        .commit_signatures
        .truncate(validators.len() - 1);

    assert_rejected_commit_block("insufficient-quorum", "INSUFFICIENT_COMMIT_QUORUM", stored).await
}

#[tokio::test]
async fn block_with_corrupted_commit_signature_is_rejected() -> Result<()> {
    let validators = test_validators();
    let mut stored = build_signed_commit_block(&validators)?;
    stored.block.commit_signatures[0].signature[0] ^= 0x01;

    assert_rejected_commit_block("corrupted-commit-sig", "INVALID_COMMIT_SIGNATURE", stored).await
}

#[tokio::test]
async fn block_with_unknown_or_unauthorized_signer_is_rejected() -> Result<()> {
    let validators = test_validators();
    let mut stored = build_signed_commit_block(&validators)?;
    stored.block.commit_signatures[0].validator_address = vec![0xEE; 32];

    assert_rejected_commit_block("unauthorized-signer", "UNAUTHORIZED_COMMIT_SIGNER", stored).await
}

#[tokio::test]
async fn duplicate_signer_does_not_count_twice() -> Result<()> {
    let validators = test_validators();
    let mut stored = build_signed_commit_block(&validators)?;
    stored.block.commit_signatures[1] = stored.block.commit_signatures[0].clone();

    assert_rejected_commit_block("duplicate-signer", "DUPLICATE_COMMIT_SIGNER", stored).await
}

/// Verify that the ML-KEM-768 P2P session authentication gate works end-to-end:
/// - Unauthenticated block fetch → 401
/// - Authenticated fetch after KEM handshake → 200
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p2p_session_required_for_block_fetch() -> Result<()> {
    let dir = TempDir::new("kem-auth");
    let validators = test_validators();
    let producer_addr = reserve_local_addr();
    let producer_config_path = dir.path().join("producer.json");

    write_config(
        &producer_config_path,
        &producer_config(
            "node-kem-auth",
            &dir.path().join("node-kem-auth"),
            &producer_addr,
            Vec::new(),
            &validators,
        ),
    );

    let producer = start_from_config_path(&producer_config_path).await?;
    producer
        .wait_for_height(1, time::Duration::from_secs(5))
        .await
        .context("producer did not reach height 1")?;

    let client = reqwest::Client::builder()
        .timeout(time::Duration::from_secs(5))
        .build()
        .context("reqwest client build failed")?;

    // ── Unauthenticated fetch must be rejected with 401 ───────────────────────
    let status = client
        .get(format!("http://{producer_addr}/internal/p2p/blocks/1"))
        .send()
        .await
        .context("unauthenticated block fetch request failed")?
        .status();
    assert_eq!(
        status.as_u16(),
        401,
        "block fetch without session headers must return 401"
    );

    // ── KEM handshake: fetch peer's encapsulation key ─────────────────────────
    let pk_resp: serde_json::Value = client
        .get(format!("http://{producer_addr}/internal/p2p/kem-pubkey"))
        .send()
        .await?
        .json()
        .await
        .context("failed to decode kem-pubkey response")?;
    let pk_hex = pk_resp["kem_pk"].as_str().context("kem_pk missing")?;
    let pk_bytes = hex::decode(pk_hex).context("invalid kem_pk hex")?;
    let kem_pk: [u8; KEM_PK_LEN] = pk_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("pk length wrong"))?;

    // ── Encapsulate (deterministic rand for test reproducibility) ─────────────
    let rand = [0xE7u8; 32];
    let (ct, shared_secret) = pqc_crypto::kem_encapsulate(&kem_pk, &rand)
        .context("KEM encapsulation failed — peer key invalid")?;

    // ── POST ciphertext; receive session_id ───────────────────────────────────
    let sess_resp: serde_json::Value = client
        .post(format!("http://{producer_addr}/internal/p2p/session"))
        .json(&json!({ "ciphertext": hex::encode(ct) }))
        .send()
        .await?
        .json()
        .await
        .context("failed to decode session response")?;
    let session_id = sess_resp["session_id"]
        .as_str()
        .context("session_id missing")?
        .to_owned();

    // ── Compute the per-request token and fetch the block ─────────────────────
    let token = {
        let mut input = Vec::with_capacity(51);
        input.extend_from_slice(&shared_secret);
        input.extend_from_slice(b"block-fetch");
        input.extend_from_slice(&1u64.to_be_bytes());
        shake256_32(&input)
    };

    let authenticated_status = client
        .get(format!("http://{producer_addr}/internal/p2p/blocks/1"))
        .header("X-P2P-Session", &session_id)
        .header("X-P2P-Token", hex::encode(token))
        .send()
        .await
        .context("authenticated block fetch request failed")?
        .status();
    assert_eq!(
        authenticated_status.as_u16(),
        200,
        "authenticated block fetch must succeed"
    );

    producer.shutdown().await?;
    Ok(())
}
