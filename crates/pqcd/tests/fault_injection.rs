// SPDX-License-Identifier: BUSL-1.1
//! TASK-056 / TASK-065 — Fault injection and Byzantine validator simulation.
//!
//! Demonstrates that the validation layer handles fault conditions correctly.
//! The goal is NOT to implement full BFT consensus, but to show that the
//! existing commit validation layer correctly rejects Byzantine behaviour.
//!
//! ## Scenarios covered
//!
//! | # | Scenario | Expected outcome |
//! |---|----------|-----------------|
//! | 1 | Late-joining follower (simulated partition) | Catches up to identical tip and state root |
//! | 2 | Byzantine equivocation (valid sig for wrong block hash) | INVALID_COMMIT_SIGNATURE |
//! | 3 | Byzantine majority liveness halt (>f withhold commit sigs) | INSUFFICIENT_COMMIT_QUORUM |
//! | 4 | Fork-choice split-brain (competing chain at same height) | PARENT_HASH_MISMATCH |
//!
//! SPEC-TEST-001 §4.4 requires scenarios 1–2 before Phase 3-alpha exit.
//! Scenarios 3–4 close the Phase 3 gaps documented in `specs/fault-injection-report.md`
//! (TASK-065).
//!
//! ## What is NOT tested here (remaining gaps)
//!
//! - Dynamic validator set churn during active consensus (Phase 5)
//! - Network-level message dropping or reordering (static peer list)
//! - Active fork-choice protocol (none implemented; first-come-first-served documented)
//!
//! These are documented in `specs/fault-injection-report.md`.

use std::{
    collections::HashMap,
    env, fs,
    net::TcpListener as StdTcpListener,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
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
    kem_decapsulate, kem_generate, ml_dsa_public_key_from_seed, ml_dsa_sign_with_seed, AlgId,
    KEM_CT_LEN, KEM_SK_LEN,
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

// ── Shared constants ──────────────────────────────────────────────────────────

const ANCHOR_PREV_HASH: [u8; 32] = [0x11; 32];
/// Proposer address for the legitimate block.
const PRODUCER_ADDRESS: [u8; 32] = [0x99; 32];
/// Distinct proposer address used to build the phantom block in the equivocation
/// test. Different proposer → different block hash → sigs over H2 ≠ sigs over H1.
const PHANTOM_PRODUCER_ADDRESS: [u8; 32] = [0x88; 32];

const MALICIOUS_KEM_D: [u8; 32] = [0xCC; 32];
const MALICIOUS_KEM_Z: [u8; 32] = [0xDD; 32];

// ── Infrastructure ────────────────────────────────────────────────────────────

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "pqcd-fault-{label}-{}-{unique}",
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
    kem_pk_hex: String,
    kem_sk: [u8; KEM_SK_LEN],
    sessions: tokio::sync::Mutex<HashMap<String, [u8; 32]>>,
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
        .map(|v| ValidatorConfig {
            node_id: v.node_id.clone(),
            address_hex: hex::encode(v.address),
            sig_alg_id: v.sig_alg_id.as_u16(),
            public_key_hex: hex::encode(&v.public_key),
            commit_seed_hex: include_seeds.then(|| hex::encode(v.commit_seed)),
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
            epoch_duration: 60,
            unbonding_period: 120,
            keystore_path: None,
            distributed_signing: false,
            distributed_signing_quorum_wait_ms: 1500,
            attack_mode: None,
            kem_seed_salt_hex: None,
            libp2p_seed_salt_hex: None,
            signer_kind: pqc_hsm::SignerKind::default(),
            signer_config: pqc_hsm::SignerConfig::default(),
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
            epoch_duration: 60,
            unbonding_period: 120,
            keystore_path: None,
            distributed_signing: false,
            distributed_signing_quorum_wait_ms: 1500,
            attack_mode: None,
            kem_seed_salt_hex: None,
            libp2p_seed_salt_hex: None,
            signer_kind: pqc_hsm::SignerKind::default(),
            signer_config: pqc_hsm::SignerConfig::default(),
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
            && last.iter().all(|s| {
                s.height == first.height
                    && s.tip_hash == first.tip_hash
                    && s.state_root == first.state_root
            })
        {
            return Ok(last.clone());
        }

        if Instant::now() >= deadline {
            anyhow::bail!(
                "timed out waiting for cluster convergence at height >= {min_height}: {}",
                last.iter()
                    .map(|s| format!(
                        "{}@{} tip={}",
                        s.node_id,
                        s.height,
                        hex::encode(s.tip_hash.0)
                    ))
                    .collect::<Vec<_>>()
                    .join(" | ")
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
            anyhow::bail!(
                "timed out waiting for sync error on node {}",
                snapshot.node_id
            );
        }

        time::sleep(Duration::from_millis(25)).await;
    }
}

// ── Block construction helpers ────────────────────────────────────────────────

/// Attaches a commit quorum where `validators[0]` signs `equivocating_hash`
/// (simulating a Byzantine validator who signed a competing block at the same
/// height) while all other validators sign `legitimate_hash`.
///
/// The resulting commit_signatures vector is placed on the block whose content
/// hashes to `legitimate_hash`. When a follower verifies, `validators[0]`'s
/// signature will fail against `legitimate_hash` → INVALID_COMMIT_SIGNATURE.
fn attach_equivocating_quorum(
    block: &mut Block,
    legitimate_hash: &BlockHash,
    equivocating_hash: &BlockHash,
    validators: &[TestValidator],
) -> Result<()> {
    let fd = pqc_types::ForkDigest::viper_research_1();
    let legitimate_preimage = commit_preimage(&fd, block.header.height, legitimate_hash);
    let equivocating_preimage = commit_preimage(&fd, block.header.height, equivocating_hash);

    block.commit_signatures = validators
        .iter()
        .enumerate()
        .map(|(i, v)| {
            // validators[0] commits equivocation: valid sig, wrong block hash.
            let preimage = if i == 0 {
                &equivocating_preimage
            } else {
                &legitimate_preimage
            };
            let signature = ml_dsa_sign_with_seed(v.sig_alg_id, &v.commit_seed, preimage)
                .context("failed to sign commit preimage")?;
            Ok(CommitSig {
                validator_address: v.address.to_vec(),
                sig_alg_id: v.sig_alg_id,
                round: 0,
                signature,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(())
}

/// Builds a `StoredBlock` at height 1 whose commit quorum contains one
/// equivocating signature (validators[0] signed a phantom block's hash).
///
/// The phantom block is produced with a different proposer address, ensuring
/// a different block hash without requiring a stateful chain.
fn build_byzantine_equivocation_block(validators: &[TestValidator]) -> Result<StoredBlock> {
    let anchor = BlockHash(ANCHOR_PREV_HASH);
    // Seed genesis state with the same validators as the follower will have,
    // so the state_root of the legitimate block matches what the follower computes
    // after applying it. (TASK-064: validators are now included in the state root.)
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

    // ── Legitimate block (H1) ─────────────────────────────────────────────────
    let legitimate_proposer = LocalProposer::new(
        PRODUCER_ADDRESS,
        LocalProposerConfig {
            assembly: AssemblyConfig::default(),
            initial_prev_hash: anchor.clone(),
        },
    );
    let mut proposal = legitimate_proposer
        .build_next_block(&state, &mempool, 1_710_000_000)
        .context("failed to build legitimate block")?;
    let legitimate_hash = proposal.block_hash.clone();

    // ── Phantom block (H2) — different proposer → different block hash ────────
    let phantom_proposer = LocalProposer::new(
        PHANTOM_PRODUCER_ADDRESS,
        LocalProposerConfig {
            assembly: AssemblyConfig::default(),
            initial_prev_hash: anchor.clone(),
        },
    );
    let phantom_proposal = phantom_proposer
        .build_next_block(&state, &mempool, 1_710_000_000)
        .context("failed to build phantom block")?;
    let phantom_hash = phantom_proposal.block_hash.clone();

    assert_ne!(
        legitimate_hash.0, phantom_hash.0,
        "legitimate and phantom block hashes must differ for equivocation test to be meaningful"
    );

    // ── Attach mixed quorum: validators[0] equivocates, others sign H1 ────────
    attach_equivocating_quorum(
        &mut proposal.execution.block,
        &legitimate_hash,
        &phantom_hash,
        validators,
    )?;

    let mut chain = ChainStore::new(anchor);
    chain
        .append_block(&proposal.execution)
        .context("failed to append equivocating block to chain store")?;

    Ok(chain
        .get_stored_block_by_height(1)
        .expect("height 1 block must exist after append")
        .clone())
}

// ── Malicious peer server (serves bad blocks over KEM-authenticated P2P) ──────

async fn start_malicious_peer(stored: StoredBlock) -> Result<MaliciousPeerHandle> {
    let (kem_pk, kem_sk) = kem_generate(&MALICIOUS_KEM_D, &MALICIOUS_KEM_Z);
    // Test-only: unwrap the ZeroizeOnDrop wrapper into raw bytes for the test
    // struct (fixed test seeds, not secrets).
    let kem_sk = kem_sk.into_bytes();
    let state = Arc::new(MaliciousPeerState {
        height: stored.metadata.height,
        tip_hash_hex: hex::encode(stored.metadata.block_hash.0),
        state_root_hex: hex::encode(stored.metadata.state_root.0),
        block_bytes: RocksDbChainStore::encode_block_bytes(&stored)
            .context("failed to encode malicious block bytes")?,
        kem_pk_hex: hex::encode(kem_pk),
        kem_sk,
        sessions: tokio::sync::Mutex::new(HashMap::new()),
    });

    let listen_addr = reserve_local_addr();
    let listener = TcpListener::bind(&listen_addr)
        .await
        .with_context(|| format!("failed to bind malicious peer to {listen_addr}"))?;
    let p2p_addr = listener
        .local_addr()
        .context("failed to inspect malicious peer listener addr")?
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
    let session_id = hex::encode(&ss[..16]);
    state.sessions.lock().await.insert(session_id.clone(), ss);
    Json(json!({ "session_id": session_id })).into_response()
}

async fn handle_malicious_block(
    State(state): State<Arc<MaliciousPeerState>>,
    AxumPath(height): AxumPath<u64>,
) -> Response {
    // Auth headers are intentionally not verified here — the bad block itself
    // causes rejection at the follower's commit quorum validation step.
    if height != state.height {
        return (StatusCode::NOT_FOUND, "block not found").into_response();
    }
    (
        [(header::CONTENT_TYPE, "application/cbor")],
        state.block_bytes.clone(),
    )
        .into_response()
}

// ── Additional block construction helpers (TASK-065) ─────────────────────────

/// Attaches a full honest commit quorum: all validators sign the correct preimage
/// for `block_hash` at the block's height.
fn attach_honest_quorum(
    block: &mut Block,
    block_hash: &BlockHash,
    validators: &[TestValidator],
) -> Result<()> {
    let fd = pqc_types::ForkDigest::viper_research_1();
    let preimage = commit_preimage(&fd, block.header.height, block_hash);
    block.commit_signatures = validators
        .iter()
        .map(|v| {
            let signature = ml_dsa_sign_with_seed(v.sig_alg_id, &v.commit_seed, &preimage)
                .context("failed to sign commit preimage")?;
            Ok(CommitSig {
                validator_address: v.address.to_vec(),
                sig_alg_id: v.sig_alg_id,
                round: 0,
                signature,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(())
}

/// Builds a height-1 block signed by only `num_signers` of the `validators`.
///
/// With 3 validators and a default quorum threshold of ⌈2/3 × 3⌉ = 2:
/// - `num_signers = 1` → INSUFFICIENT_COMMIT_QUORUM: required 2, got 1
///
/// Models the liveness-halt scenario where >f Byzantine validators withhold
/// their commit signatures, preventing the required quorum from being reached.
fn build_undersigned_block(
    validators: &[TestValidator],
    num_signers: usize,
) -> Result<StoredBlock> {
    let anchor = BlockHash(ANCHOR_PREV_HASH);
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
        .context("failed to build undersigned block")?;
    let block_hash = proposal.block_hash.clone();

    // Only the first `num_signers` validators sign — the others withhold their signature.
    let fd = pqc_types::ForkDigest::viper_research_1();
    let preimage = commit_preimage(&fd, 1, &block_hash);
    proposal.execution.block.commit_signatures = validators[..num_signers]
        .iter()
        .map(|v| {
            let signature = ml_dsa_sign_with_seed(v.sig_alg_id, &v.commit_seed, &preimage)
                .context("failed to sign preimage for undersigned block")?;
            Ok(CommitSig {
                validator_address: v.address.to_vec(),
                sig_alg_id: v.sig_alg_id,
                round: 0,
                signature,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let mut chain = ChainStore::new(anchor);
    chain
        .append_block(&proposal.execution)
        .context("failed to append undersigned block to chain store")?;

    Ok(chain
        .get_stored_block_by_height(1)
        .expect("height 1 block must exist after append")
        .clone())
}

/// Builds a two-block split-brain chain:
///
/// - **A1** (height 1, prev=ANCHOR, proposer=PRODUCER_ADDRESS): the legitimate block
///   the follower will accept first. Full honest quorum from all validators.
/// - **B2** (height 2, prev=H(B1_phantom), proposer=PHANTOM_PRODUCER_ADDRESS): a valid
///   block from a competing fork. Full honest quorum, but its parent is a phantom
///   height-1 block that the follower never accepted. Appending B2 to a chain whose
///   tip is H(A1) causes PARENT_HASH_MISMATCH.
///
/// B1_phantom is built internally to establish the fork's tip; it is NOT returned
/// and is NOT served to the follower.
fn build_split_brain_chain(validators: &[TestValidator]) -> Result<(StoredBlock, StoredBlock)> {
    let anchor = BlockHash(ANCHOR_PREV_HASH);
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

    // ── A1: the legitimate block the follower will accept ─────────────────────
    let legitimate_proposer = LocalProposer::new(
        PRODUCER_ADDRESS,
        LocalProposerConfig {
            assembly: AssemblyConfig::default(),
            initial_prev_hash: anchor.clone(),
        },
    );
    let mut a1_proposal = legitimate_proposer
        .build_next_block(&state, &mempool, 1_710_000_000)
        .context("failed to build A1")?;
    let a1_hash = a1_proposal.block_hash.clone();
    attach_honest_quorum(&mut a1_proposal.execution.block, &a1_hash, validators)?;

    let mut a1_chain = ChainStore::new(anchor.clone());
    a1_chain
        .append_block(&a1_proposal.execution)
        .context("failed to append A1")?;
    let a1_stored = a1_chain
        .get_stored_block_by_height(1)
        .expect("A1 must exist")
        .clone();

    // ── B1_phantom: competing height-1 block (not served to follower) ─────────
    // We build and commit B1_phantom to advance the fork proposer's internal tip
    // to H(B1_phantom). B2 will have prev_hash = H(B1_phantom) ≠ H(A1).
    let mut fork_proposer = LocalProposer::new(
        PHANTOM_PRODUCER_ADDRESS,
        LocalProposerConfig {
            assembly: AssemblyConfig::default(),
            initial_prev_hash: anchor.clone(),
        },
    );
    let mut fork_state = state.clone();
    let mut fork_pool = mempool.clone();

    let b1_phantom_proposal = fork_proposer
        .build_next_block(&fork_state, &fork_pool, 1_710_000_001)
        .context("failed to build B1_phantom")?;
    let b1_phantom_execution = fork_proposer
        .commit_block(&mut fork_state, &mut fork_pool, b1_phantom_proposal)
        .context("failed to commit B1_phantom into fork proposer")?;
    // After commit_block: fork_proposer.tip_hash = H(B1_phantom); fork_state.block_height() == 1.

    // ── B2: extends the competing fork — prev_hash = H(B1_phantom) ───────────
    let mut b2_proposal = fork_proposer
        .build_next_block(&fork_state, &fork_pool, 1_710_000_002)
        .context("failed to build B2")?;
    let b2_hash = b2_proposal.block_hash.clone();
    attach_honest_quorum(&mut b2_proposal.execution.block, &b2_hash, validators)?;

    // Build the fork chain (B1_phantom then B2) so we can extract the StoredBlock for B2.
    let mut fork_chain = ChainStore::new(anchor.clone());
    fork_chain
        .append_block(&b1_phantom_execution)
        .context("failed to append B1_phantom to fork chain")?;
    fork_chain
        .append_block(&b2_proposal.execution)
        .context("failed to append B2 to fork chain")?;
    let b2_stored = fork_chain
        .get_stored_block_by_height(2)
        .expect("B2 must exist")
        .clone();

    Ok((a1_stored, b2_stored))
}

// ── Multi-block malicious peer (for split-brain fork-choice test) ─────────────

/// A malicious peer that can serve multiple blocks at different heights.
///
/// Used for the split-brain fork-choice test: block A1 at height 1 is valid and
/// accepted by the follower; block B2 at height 2 is cryptographically valid but
/// has a parent hash that does not match the follower's tip (H(A1)).
struct SplitBrainPeerState {
    /// Encoded block bytes keyed by height.
    blocks: HashMap<u64, Vec<u8>>,
    tip_height: u64,
    tip_hash_hex: String,
    state_root_hex: String,
    kem_pk_hex: String,
    kem_sk: [u8; KEM_SK_LEN],
    sessions: tokio::sync::Mutex<HashMap<String, [u8; 32]>>,
}

/// Starts a malicious peer that serves multiple blocks at different heights.
///
/// The status endpoint reports the tallest block as the peer's tip, causing a
/// follower to try syncing each height in sequence until the fork diverges.
async fn start_split_brain_peer(blocks: Vec<StoredBlock>) -> Result<MaliciousPeerHandle> {
    assert!(
        !blocks.is_empty(),
        "split-brain peer must serve at least one block"
    );

    let (kem_pk, kem_sk) = kem_generate(&MALICIOUS_KEM_D, &MALICIOUS_KEM_Z);
    // Test-only: unwrap the ZeroizeOnDrop wrapper into raw bytes for the test
    // struct (fixed test seeds, not secrets).
    let kem_sk = kem_sk.into_bytes();
    let tip = blocks.iter().max_by_key(|b| b.metadata.height).unwrap();

    let mut encoded_blocks = HashMap::new();
    for stored in &blocks {
        let bytes = RocksDbChainStore::encode_block_bytes(stored)
            .context("failed to encode split-brain block")?;
        encoded_blocks.insert(stored.metadata.height, bytes);
    }

    let state = Arc::new(SplitBrainPeerState {
        blocks: encoded_blocks,
        tip_height: tip.metadata.height,
        tip_hash_hex: hex::encode(tip.metadata.block_hash.0),
        state_root_hex: hex::encode(tip.metadata.state_root.0),
        kem_pk_hex: hex::encode(kem_pk),
        kem_sk,
        sessions: tokio::sync::Mutex::new(HashMap::new()),
    });

    let listen_addr = reserve_local_addr();
    let listener = TcpListener::bind(&listen_addr)
        .await
        .with_context(|| format!("failed to bind split-brain peer to {listen_addr}"))?;
    let p2p_addr = listener
        .local_addr()
        .context("failed to inspect split-brain peer addr")?
        .to_string();

    let app = Router::new()
        .route("/internal/p2p/status", get(handle_split_brain_status))
        .route(
            "/internal/p2p/kem-pubkey",
            get(handle_split_brain_kem_pubkey),
        )
        .route("/internal/p2p/session", post(handle_split_brain_session))
        .route(
            "/internal/p2p/blocks/{height}",
            get(handle_split_brain_block),
        )
        .with_state(state);

    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.changed().await;
            })
            .await
            .context("split-brain peer server error")
    });

    Ok(MaliciousPeerHandle {
        shutdown_tx,
        task,
        p2p_addr,
    })
}

async fn handle_split_brain_status(
    State(state): State<Arc<SplitBrainPeerState>>,
) -> Json<serde_json::Value> {
    Json(json!({
        "node_id": "split-brain-peer",
        "height": state.tip_height,
        "tip_hash": state.tip_hash_hex,
        "state_root": state.state_root_hex,
    }))
}

async fn handle_split_brain_kem_pubkey(
    State(state): State<Arc<SplitBrainPeerState>>,
) -> Json<serde_json::Value> {
    Json(json!({ "kem_pk": &state.kem_pk_hex }))
}

async fn handle_split_brain_session(
    State(state): State<Arc<SplitBrainPeerState>>,
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
    let session_id = hex::encode(&ss[..16]);
    state.sessions.lock().await.insert(session_id.clone(), ss);
    Json(json!({ "session_id": session_id })).into_response()
}

async fn handle_split_brain_block(
    State(state): State<Arc<SplitBrainPeerState>>,
    AxumPath(height): AxumPath<u64>,
) -> Response {
    // Auth headers are intentionally not verified here: the split-brain test
    // checks that the chain-level invariant (parent hash) rejects fork blocks,
    // not the session authentication layer.
    match state.blocks.get(&height) {
        Some(bytes) => {
            ([(header::CONTENT_TYPE, "application/cbor")], bytes.clone()).into_response()
        }
        None => (StatusCode::NOT_FOUND, "block not found").into_response(),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Simulated partition recovery: follower-b starts cold after the producer and
/// follower-a have already advanced several blocks. Verifies that a late-joining
/// node syncs all missed blocks from genesis and reaches the same tip hash and
/// state root as the rest of the cluster.
///
/// This is distinct from `follower_restart_catches_up_to_same_tip` in
/// `multi_node_devnet.rs`: there the follower has prior state on disk.
/// Here follower-b was never online — it joins cold, simulating a network
/// partition where the node was completely cut off during the initial run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_joining_follower_syncs_from_genesis() -> Result<()> {
    let dir = TempDir::new("partition-recovery");
    let validators = test_validators();

    let producer_addr = reserve_local_addr();
    let follower_a_addr = reserve_local_addr();
    let follower_b_addr = reserve_local_addr();

    let producer_config_path = dir.path().join("producer.json");
    let follower_a_config_path = dir.path().join("follower-a.json");
    let follower_b_config_path = dir.path().join("follower-b.json");

    let producer_peer = PeerConfig {
        node_id: "node-1".to_owned(),
        p2p_addr: producer_addr.clone(),
    };

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
            vec![producer_peer.clone()],
            &validators,
        ),
    );
    // follower-b config is written now but the node is NOT started yet.
    write_config(
        &follower_b_config_path,
        &follower_config(
            "node-3",
            &dir.path().join("node-3"),
            &follower_b_addr,
            vec![producer_peer.clone()],
            &validators,
        ),
    );

    // ── Phase 1: two-node cluster runs while follower-b is "partitioned" ──────
    let producer = start_from_config_path(&producer_config_path).await?;
    let follower_a = start_from_config_path(&follower_a_config_path).await?;

    let pre_join =
        wait_for_cluster_convergence(&[&producer, &follower_a], 4, Duration::from_secs(10)).await?;
    let partition_height = pre_join[0].height;

    // ── Phase 2: follower-b joins cold — partition recovery ───────────────────
    let follower_b = start_from_config_path(&follower_b_config_path).await?;

    // Wait for all three to converge at a height the late joiner could not have
    // produced itself (it must have caught up from genesis via P2P sync).
    let post_join = wait_for_cluster_convergence(
        &[&producer, &follower_a, &follower_b],
        partition_height + 1,
        Duration::from_secs(15),
    )
    .await?;

    assert!(
        post_join.iter().all(|s| s.last_sync_error.is_none()),
        "no node should carry a sync error after partition recovery"
    );
    assert_eq!(
        post_join[0].tip_hash, post_join[2].tip_hash,
        "late-joining follower must reach the same tip hash as the producer"
    );
    assert_eq!(
        post_join[0].state_root, post_join[2].state_root,
        "late-joining follower must have the same state root as the producer"
    );
    assert!(
        post_join[2].height >= partition_height,
        "late-joining follower must have advanced past the pre-partition height"
    );

    follower_b.shutdown().await?;
    follower_a.shutdown().await?;
    producer.shutdown().await?;
    Ok(())
}

/// Byzantine equivocation: `validators[0]` produces a cryptographically valid
/// ML-DSA-65 signature, but over the commit preimage of a PHANTOM block at the
/// same height (different proposer address → different block hash). This signed
/// equivocation is embedded in an otherwise-complete commit quorum on the
/// legitimate block and served to a follower via the KEM-authenticated P2P path.
///
/// Expected outcome: the follower rejects the block with INVALID_COMMIT_SIGNATURE
/// because `validators[0]`'s signature does not verify against the legitimate
/// block's hash, even though the signature bytes are valid ML-DSA-65 output.
///
/// The detection point is `validate_block_commit_quorum` in `pqc-consensus`,
/// which verifies each signature against `commit_preimage(height, block_hash)`.
/// A validator who signed a competing block at the same height is detected here.
#[tokio::test]
async fn byzantine_equivocating_commit_signature_rejected() -> Result<()> {
    let validators = test_validators();
    let stored = build_byzantine_equivocation_block(&validators)?;

    let dir = TempDir::new("byzantine-equivocation");
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
        "follower must not advance its chain when a commit quorum contains an equivocating signature"
    );
    let error = snapshot
        .last_sync_error
        .as_deref()
        .unwrap_or("<missing-sync-error>");
    assert!(
        error.contains("INVALID_COMMIT_SIGNATURE"),
        "expected INVALID_COMMIT_SIGNATURE in sync error; got: {error}"
    );

    // Confirm the rejection is persistent: follower must not eventually accept
    // the block after retrying.
    //
    // TASK-181 Part B: NEGATIVE persistence check, not a poll. The fixed
    // 200 ms window covers ≥4 sync ticks at the test's 50 ms
    // `sync_interval_ms`, enough to catch a regression that would
    // accept-on-retry. Documented (rather than swapped to event-driven)
    // because there is no "rejection persisted" event — the absence of
    // height advance IS the signal, and that absence has to be observed
    // over a wall-clock window.
    time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        follower.snapshot().await.height,
        0,
        "follower height must remain 0 after repeated equivocation delivery"
    );

    follower.shutdown().await?;
    malicious_peer.shutdown().await?;
    Ok(())
}

/// Byzantine majority liveness halt: >f validators withhold their commit signatures.
///
/// With 3 validators and quorum threshold = 2 (⌈2/3 × 3⌉), serving a block with
/// only 1 valid commit signature must cause INSUFFICIENT_COMMIT_QUORUM. This
/// simulates the liveness-halt condition where a Byzantine majority (2 of 3) refuses
/// to sign the proposed block — no node can advance the chain.
///
/// Phase 3 gap closed by TASK-065. Corresponds to Gap A in
/// `specs/fault-injection-report.md`.
///
/// Detection point: `validate_block_commit_quorum` in `pqc-consensus/src/commit.rs`,
/// which counts valid signatures against `policy.quorum_threshold()`.
#[tokio::test]
async fn byzantine_majority_liveness_halt() -> Result<()> {
    let validators = test_validators();
    // Only validators[0] signs — the other two withhold. 1 < 2 required → liveness halt.
    let stored = build_undersigned_block(&validators, 1)?;

    let dir = TempDir::new("byzantine-liveness-halt");
    let follower_addr = reserve_local_addr();
    let follower_config_path = dir.path().join("follower.json");
    let malicious_peer = start_malicious_peer(stored).await?;

    write_config(
        &follower_config_path,
        &follower_config(
            "node-follower-liveness",
            &dir.path().join("node-follower-liveness"),
            &follower_addr,
            vec![malicious_peer.peer_config()],
            &validators,
        ),
    );

    let follower = start_from_config_path(&follower_config_path).await?;
    let snapshot = wait_for_sync_error(&follower, Duration::from_secs(5)).await?;

    assert_eq!(
        snapshot.height, 0,
        "follower must not advance when the commit quorum is below threshold"
    );
    let error = snapshot
        .last_sync_error
        .as_deref()
        .unwrap_or("<missing-sync-error>");
    assert!(
        error.contains("INSUFFICIENT_COMMIT_QUORUM"),
        "expected INSUFFICIENT_COMMIT_QUORUM in sync error; got: {error}"
    );

    // Verify persistence: the follower must not eventually accept the block.
    //
    // TASK-181 Part B: NEGATIVE persistence check (see equivocating-quorum
    // test above for full rationale). The 200 ms window is fixed and
    // intentional — there is no "rejection persisted" event to wait on.
    time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        follower.snapshot().await.height,
        0,
        "follower height must remain 0 after repeated delivery of undersigned block"
    );

    follower.shutdown().await?;
    malicious_peer.shutdown().await?;
    Ok(())
}

/// Fork-choice split-brain: a competing fork is rejected at the chain layer.
///
/// The split-brain peer serves two blocks:
///
/// - **A1** (height 1, prev=ANCHOR): a fully valid block with honest quorum. The
///   follower accepts this, advancing to height 1 with tip = H(A1).
/// - **B2** (height 2, prev=H(B1_phantom)): a cryptographically valid block from a
///   competing fork whose height-1 ancestor (B1_phantom) the follower never accepted.
///   When the follower appends B2, its prev_hash ≠ follower's tip H(A1) → PARENT_HASH_MISMATCH.
///
/// This documents the Phase 3 behaviour: no active fork-choice protocol is implemented.
/// Chain selection is first-come-first-served at height 1; competing chains at later
/// heights are rejected because their parent hash does not match the local tip. This
/// closes Gap B in `specs/fault-injection-report.md` (TASK-065).
///
/// Detection point: `ChainStore::validate_stored_block` in `pqc-consensus/src/chain.rs`.
#[tokio::test]
async fn split_brain_fork_chain_rejected() -> Result<()> {
    let validators = test_validators();
    let (a1, b2) = build_split_brain_chain(&validators)?;

    let dir = TempDir::new("split-brain-fork");
    let follower_addr = reserve_local_addr();
    let follower_config_path = dir.path().join("follower.json");

    // Single peer serves both A1 (height 1, accepted) and B2 (height 2, rejected).
    // The peer reports tip_height=2 to prompt the follower to sync both heights.
    let split_brain_peer = start_split_brain_peer(vec![a1, b2]).await?;

    write_config(
        &follower_config_path,
        &follower_config(
            "node-follower-fork",
            &dir.path().join("node-follower-fork"),
            &follower_addr,
            vec![split_brain_peer.peer_config()],
            &validators,
        ),
    );

    let follower = start_from_config_path(&follower_config_path).await?;

    // The follower first accepts A1 (no error), then fetches B2. After
    // ADR-054 the reception classifier treats B2 (height 2 with
    // prev_hash ≠ local tip) as `OrphanFutureChild` and the legacy
    // HTTP sync_loop bails on this outcome (no by-hash parent fetch
    // primitive on the HTTP path) — the bail surfaces as a sync error
    // tagged "ADR-054: ... buffered as orphan, halting sync from this
    // peer". B2 itself stays in the orphan cache and ages out via TTL;
    // the canonical chain stays at height 1.
    let snapshot = wait_for_sync_error(&follower, Duration::from_secs(5)).await?;

    assert_eq!(
        snapshot.height, 1,
        "follower must have advanced to height 1 (A1 accepted) but not height 2 (B2 rejected)"
    );
    let error = snapshot
        .last_sync_error
        .as_deref()
        .unwrap_or("<missing-sync-error>");
    assert!(
        error.contains("ADR-054") && error.contains("buffered as orphan"),
        "expected ADR-054 orphan-buffered sync error from competing fork; got: {error}"
    );

    // Height must remain at 1 — the fork chain cannot replace the accepted chain.
    //
    // TASK-181 Part B: NEGATIVE persistence check; 200 ms is fixed and
    // intentional (covers ≥4 sync ticks). Switching to event-driven
    // would require a "fork-rejected" signal that the chain layer does
    // not currently emit.
    time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        follower.snapshot().await.height,
        1,
        "follower height must remain at 1 after repeated delivery of fork block B2"
    );

    follower.shutdown().await?;
    split_brain_peer.shutdown().await?;
    Ok(())
}
