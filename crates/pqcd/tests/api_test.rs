// SPDX-License-Identifier: BUSL-1.1
//! Integration tests for the read/status API.
//!
//! Uses `tower::ServiceExt::oneshot` to call the axum router in-process —
//! no TCP listener required. All assertions are against real chain data
//! produced by the same building blocks as the production node.

use std::{
    env, fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::body::Body;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use pqc_consensus::{AssemblyConfig, LocalProposer, LocalProposerConfig, RocksDbChainStore};
use pqc_crypto::{sign::StubVerifier, AlgId};
use pqc_mempool::{admission::try_admit, Mempool};
use pqc_state::StateStore;
use pqc_tx::{codec::encode_tx, compute_tx_hash, validate::FeeParams};
use pqc_types::{
    account::{Account, Address},
    block::BlockHash,
    keyset::{allowed_tx, KeyEntry, KeySet, KeyStatus},
    transaction::{MsgType, Transaction},
};

use pqcd::api::{router, ApiNodeState, SharedState};

// ── Filesystem helper ─────────────────────────────────────────────────────────

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            env::temp_dir().join(format!("pqcd-api-{label}-{}-{unique}", std::process::id()));
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

// ── Test fixtures ─────────────────────────────────────────────────────────────

fn signer_account(addr: Address) -> Account {
    Account {
        address: addr,
        balance: 50_000,
        nonce: 0,
        keys: KeySet(vec![KeyEntry {
            alg_id: AlgId::MlDsa65,
            pk_bytes: vec![0u8; 32].into(),
            key_version: 1,
            valid_from_height: 0,
            status: KeyStatus::Active,
            allowed_tx_types: allowed_tx::ALL,
        }]),
        policy_version: 0,
        policy_hash: None,
        verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
        auth_data: Vec::new(),
    }
}

fn transfer_tx(sender: Address, nonce: u64, fill: u8) -> Transaction {
    use ciborium::value::Value;
    let recipient = Address([0x22; 32]);
    let payload = {
        let entries = vec![
            (
                Value::Integer(1u64.into()),
                Value::Bytes(recipient.0.to_vec()),
            ),
            (Value::Integer(2u64.into()), Value::Integer(50u64.into())),
        ];
        let mut out = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut out).unwrap();
        out
    };
    Transaction {
        tx_version: 1,
        chain_id: vec![],
        msg_type: MsgType::TokenTransfer,
        sender,
        nonce,
        fee: 100,
        fee_tip: 0,
        gas_limit: 100_000,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![fill; 3_309],
    }
}

fn attestation_tx(sender: Address, nonce: u64, fill: u8) -> Transaction {
    use ciborium::value::Value;
    let payload = {
        let entries = vec![
            (
                Value::Integer(1u64.into()),
                Value::Bytes([0x55; 32].to_vec()),
            ),
            (Value::Integer(2u64.into()), Value::Integer(2u64.into())),
            (
                Value::Integer(3u64.into()),
                Value::Bytes([0x66; 32].to_vec()),
            ),
            (
                Value::Integer(4u64.into()),
                Value::Bytes([0x77; 32].to_vec()),
            ),
            (
                Value::Integer(5u64.into()),
                Value::Bytes([0x88; 32].to_vec()),
            ),
            (Value::Integer(6u64.into()), Value::Integer(50u64.into())),
        ];
        let mut out = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut out).unwrap();
        out
    };
    Transaction {
        tx_version: 1,
        chain_id: vec![],
        msg_type: MsgType::AttestationCreate,
        sender,
        nonce,
        fee: 100,
        fee_tip: 0,
        gas_limit: 100_000,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![fill; 3_309],
    }
}

fn key_add_tx(sender: Address, nonce: u64, fill: u8) -> Transaction {
    use ciborium::value::Value;
    let payload = {
        let entries = vec![
            (
                Value::Integer(1u64.into()),
                Value::Integer(AlgId::MlDsa44.as_u16().into()),
            ),
            (Value::Integer(2u64.into()), Value::Bytes(vec![0x99; 1_312])),
            (Value::Integer(3u64.into()), Value::Integer(2u64.into())),
            (Value::Integer(4u64.into()), Value::Integer(2u64.into())),
            (
                Value::Integer(5u64.into()),
                Value::Integer(u64::from(allowed_tx::ALL).into()),
            ),
        ];
        let mut out = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut out).unwrap();
        out
    };
    Transaction {
        tx_version: 1,
        chain_id: vec![],
        msg_type: MsgType::KeyAdd,
        sender,
        nonce,
        fee: 100,
        fee_tip: 0,
        gas_limit: 100_000,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![fill; 3_309],
    }
}

fn admit_tx(pool: &mut Mempool, store: &StateStore, tx: &Transaction) {
    let raw = encode_tx(tx).unwrap();
    try_admit(pool, raw, store, &StubVerifier, &FeeParams::default()).unwrap();
}

/// Build a 2-block chain and return the API state, the tx hash of block-1's
/// transaction (for /v1/txs/{hash} tests), and the sender address.
fn make_api_state(data_dir: &Path) -> (SharedState, [u8; 32], Address) {
    let anchor = BlockHash([0x11; 32]);
    let sender = Address([0xA1; 32]);

    let mut genesis = StateStore::new();
    genesis.insert_account(signer_account(sender.clone()));

    let mut live = genesis.clone();
    let mut disk = RocksDbChainStore::open(data_dir.join("rocksdb"), anchor.clone()).unwrap();
    let mut pool = Mempool::new();
    let mut proposer = LocalProposer::new(
        [0x99; 32],
        LocalProposerConfig {
            assembly: AssemblyConfig::default(),
            initial_prev_hash: anchor,
        },
    );

    // Block 1: one tx — capture its hash for the tx-lookup tests
    let tx1 = transfer_tx(sender.clone(), 0, 0x01);
    let raw1 = encode_tx(&tx1).unwrap();
    let tx_hash = compute_tx_hash(&raw1);
    admit_tx(&mut pool, &live, &tx1);
    let result1 = proposer
        .run_once(&mut live, &mut pool, 1_710_000_000)
        .unwrap();
    disk.append_block(&result1, None).unwrap();

    // Block 2: one tx
    let tx2 = transfer_tx(sender.clone(), 1, 0x02);
    admit_tx(&mut pool, &live, &tx2);
    let result2 = proposer
        .run_once(&mut live, &mut pool, 1_710_000_001)
        .unwrap();
    disk.append_block(&result2, None).unwrap();

    // Recover from disk (simulates a node restart)
    let recovery = disk
        .recover_tip_with_checkpoint(&genesis, FeeParams::default(), Default::default(), vec![])
        .unwrap();

    let state: SharedState = Arc::new(ApiNodeState {
        chain_id: genesis.chain_id().to_vec(),
        recovery_source: recovery.source,
        state: recovery.replay.state,
        disk,
    });

    (state, tx_hash, sender)
}

fn make_api_state_with_attestation(data_dir: &Path) -> (SharedState, [u8; 32], Address) {
    let anchor = BlockHash([0x11; 32]);
    let sender = Address([0xA1; 32]);

    let mut genesis = StateStore::new();
    genesis.insert_account(signer_account(sender.clone()));

    let mut live = genesis.clone();
    let mut disk = RocksDbChainStore::open(data_dir.join("rocksdb"), anchor.clone()).unwrap();
    let mut pool = Mempool::new();
    let mut proposer = LocalProposer::new(
        [0x99; 32],
        LocalProposerConfig {
            assembly: AssemblyConfig::default(),
            initial_prev_hash: anchor,
        },
    );

    let tx = attestation_tx(sender.clone(), 0, 0x09);
    let raw = encode_tx(&tx).unwrap();
    let attestation_id = compute_tx_hash(&raw);
    admit_tx(&mut pool, &live, &tx);
    let result = proposer
        .run_once(&mut live, &mut pool, 1_710_000_100)
        .unwrap();
    disk.append_block(&result, None).unwrap();

    let recovery = disk
        .recover_tip_with_checkpoint(&genesis, FeeParams::default(), Default::default(), vec![])
        .unwrap();

    let state: SharedState = Arc::new(ApiNodeState {
        chain_id: genesis.chain_id().to_vec(),
        recovery_source: recovery.source,
        state: recovery.replay.state,
        disk,
    });

    (state, attestation_id, sender)
}

fn make_api_state_with_key_add(data_dir: &Path) -> (SharedState, Address) {
    let anchor = BlockHash([0x11; 32]);
    let sender = Address([0xA1; 32]);

    let mut genesis = StateStore::new();
    genesis.insert_account(signer_account(sender.clone()));

    let mut live = genesis.clone();
    let mut disk = RocksDbChainStore::open(data_dir.join("rocksdb"), anchor.clone()).unwrap();
    let mut pool = Mempool::new();
    let mut proposer = LocalProposer::new(
        [0x99; 32],
        LocalProposerConfig {
            assembly: AssemblyConfig::default(),
            initial_prev_hash: anchor,
        },
    );

    let tx1 = key_add_tx(sender.clone(), 0, 0x0A);
    admit_tx(&mut pool, &live, &tx1);
    let result1 = proposer
        .run_once(&mut live, &mut pool, 1_710_000_200)
        .unwrap();
    disk.append_block(&result1, None).unwrap();

    let tx2 = transfer_tx(sender.clone(), 1, 0x0B);
    admit_tx(&mut pool, &live, &tx2);
    let result2 = proposer
        .run_once(&mut live, &mut pool, 1_710_000_201)
        .unwrap();
    disk.append_block(&result2, None).unwrap();

    let recovery = disk
        .recover_tip_with_checkpoint(&genesis, FeeParams::default(), Default::default(), vec![])
        .unwrap();

    let state: SharedState = Arc::new(ApiNodeState {
        chain_id: genesis.chain_id().to_vec(),
        recovery_source: recovery.source,
        state: recovery.replay.state,
        disk,
    });

    (state, sender)
}

fn make_api_state_with_governance_update(data_dir: &Path) -> (SharedState, [u8; 32], Address) {
    // TASK-100: GovernanceProposal no longer executes immediately; it creates a
    // PendingProposal in Voting status.  This API test only exercises the
    // /v1/governance/receipts/:id endpoint, which returns GovernanceReceipts
    // produced after a successful tally execution.  Rather than running 1 000+
    // blocks to advance past GOVERNANCE_VOTING_PERIOD, we directly insert a
    // GovernanceReceipt into the state to test the API response format.
    use pqc_crypto::Lifecycle;
    use pqc_types::{
        governance::{GovernanceProposalType, GovernanceReceipt},
        transaction::TxHash,
    };

    let anchor = BlockHash([0x11; 32]);
    let sender = Address([0xA1; 32]);
    let proposal_id = [0xDE; 32];

    let mut genesis = StateStore::new();
    genesis.insert_account(signer_account(sender.clone()));

    // Advance genesis height to 1 to match the block replay state.
    let mut live = genesis.clone();
    let mut disk = RocksDbChainStore::open(data_dir.join("rocksdb"), anchor.clone()).unwrap();
    let mut pool = Mempool::new();
    let mut proposer = LocalProposer::new(
        [0x99; 32],
        LocalProposerConfig {
            assembly: AssemblyConfig::default(),
            initial_prev_hash: anchor,
        },
    );

    // Run one empty block so the chain has height 1.
    let result = proposer
        .run_once(&mut live, &mut pool, 1_710_000_300)
        .unwrap();
    disk.append_block(&result, None).unwrap();

    let recovery = disk
        .recover_tip_with_checkpoint(&genesis, FeeParams::default(), Default::default(), vec![])
        .unwrap();

    // Directly inject a governance receipt into the recovered state to simulate
    // a proposal that was executed after tally.
    let mut final_state = recovery.replay.state;
    final_state.insert_governance_receipt(GovernanceReceipt {
        proposal_id: TxHash(proposal_id),
        proposal_type: GovernanceProposalType::RegistryUpdate,
        proposer: sender.clone(),
        target_alg_id: AlgId::MlDsa65,
        lifecycle_before: Lifecycle::Active,
        lifecycle_after: Lifecycle::Discouraged,
        min_fee_before: 0,
        min_fee_after: 500,
        rationale_hash: [0xAB; 32],
        executed_at_height: 1,
    });

    let state: SharedState = Arc::new(ApiNodeState {
        chain_id: genesis.chain_id().to_vec(),
        recovery_source: recovery.source,
        state: final_state,
        disk,
    });

    (state, proposal_id, sender)
}

// ── Body helper ───────────────────────────────────────────────────────────────

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn network_returns_chain_state() {
    let dir = TempDir::new("net");
    let (state, _tx, _sender) = make_api_state(&dir.path().join("data"));
    let app = router(state);

    let resp: axum::response::Response = app.oneshot(get("/v1/network")).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;

    assert_eq!(json["height"], 2, "network must report height 2");
    assert_eq!(json["recovery_source"], "full_replay");
    assert_eq!(
        json["tip_hash"].as_str().unwrap().len(),
        64,
        "tip_hash must be 32 bytes hex"
    );
    assert_eq!(
        json["state_root"].as_str().unwrap().len(),
        64,
        "state_root must be 32 bytes hex"
    );
}

#[tokio::test]
async fn blocks_latest_returns_tip() {
    let dir = TempDir::new("blk");
    let (state, _tx, _sender) = make_api_state(&dir.path().join("data"));
    let app = router(state);

    let resp: axum::response::Response = app.oneshot(get("/v1/blocks/latest")).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;

    assert_eq!(json["height"], 2);
    assert_eq!(json["tx_count"], 1, "block 2 must include exactly 1 tx");
    assert_eq!(json["hash"].as_str().unwrap().len(), 64);
    assert_eq!(json["prev_hash"].as_str().unwrap().len(), 64);
    assert_eq!(json["state_root"].as_str().unwrap().len(), 64);
}

#[tokio::test]
async fn txs_by_hash_returns_finalized() {
    let dir = TempDir::new("tx");
    let (state, tx_hash, sender) = make_api_state(&dir.path().join("data"));
    let hash_hex = hex::encode(tx_hash);
    let app = router(state);

    let resp: axum::response::Response = app
        .oneshot(get(&format!("/v1/txs/{hash_hex}")))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;

    assert_eq!(json["hash"], hash_hex);
    assert_eq!(json["block_height"], 1, "tx1 must be in block 1");
    assert_eq!(json["sender"], hex::encode(sender.0));
    assert_eq!(json["status"], "finalized");
    assert_eq!(json["nonce"], 0);
}

#[tokio::test]
async fn txs_unknown_hash_returns_404() {
    let dir = TempDir::new("tx-404");
    let (state, _tx, _sender) = make_api_state(&dir.path().join("data"));
    let app = router(state);

    let resp: axum::response::Response = app
        .oneshot(get(&format!("/v1/txs/{}", hex::encode([0u8; 32]))))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn txs_invalid_hash_returns_400() {
    let dir = TempDir::new("tx-400");
    let (state, _tx, _sender) = make_api_state(&dir.path().join("data"));
    let app = router(state);

    let resp: axum::response::Response =
        app.oneshot(get("/v1/txs/not-a-valid-hash")).await.unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn accounts_by_address_returns_account() {
    let dir = TempDir::new("acct");
    let (state, _tx, sender) = make_api_state(&dir.path().join("data"));
    let addr_hex = hex::encode(sender.0);
    let app = router(state);

    let resp: axum::response::Response = app
        .oneshot(get(&format!("/v1/accounts/{addr_hex}")))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;

    assert_eq!(json["address"], addr_hex);
    // AIMD fee market: base_fee_dynamic=0 in block 1 (no base fee), then
    // apply_aimd_update clamps to BASE_FEE_MIN=100 after block 1.
    // Block 1: actual_fee=0, deduction=50 (transfer). Balance: 49_950.
    // Block 2: actual_fee=100 (base), deduction=50 (transfer)+100 (fee)=150. Balance: 49_800.
    assert_eq!(json["balance"], 49_800u64);
    assert_eq!(
        json["nonce"], 2,
        "two txs committed means nonce advanced to 2"
    );
    let keys = json["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["status"], "active");
    assert_eq!(keys[0]["alg_id"], AlgId::MlDsa65.as_u16());
}

#[tokio::test]
async fn accounts_unknown_address_returns_404() {
    let dir = TempDir::new("acct-404");
    let (state, _tx, _sender) = make_api_state(&dir.path().join("data"));
    let app = router(state);

    let resp: axum::response::Response = app
        .oneshot(get(&format!("/v1/accounts/{}", hex::encode([0xFFu8; 32]))))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn accounts_reflect_key_add_after_restart_and_activation_height() {
    let dir = TempDir::new("acct-keyadd");
    let (state, sender) = make_api_state_with_key_add(&dir.path().join("data"));
    let app = router(state);
    let addr_hex = hex::encode(sender.0);

    let resp: axum::response::Response = app
        .oneshot(get(&format!("/v1/accounts/{addr_hex}")))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;

    let keys = json["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0]["key_version"], 1);
    assert_eq!(keys[0]["status"], "active");
    assert_eq!(keys[1]["alg_id"], AlgId::MlDsa44.as_u16());
    assert_eq!(keys[1]["key_version"], 2);
    assert_eq!(keys[1]["valid_from_height"], 2);
    assert_eq!(keys[1]["status"], "active");
    assert_eq!(keys[1]["allowed_tx_types"], allowed_tx::ALL);
}

#[tokio::test]
async fn attestations_by_id_returns_finalized_record() {
    let dir = TempDir::new("att");
    let (state, attestation_id, sender) = make_api_state_with_attestation(&dir.path().join("data"));
    let app = router(state);

    let resp: axum::response::Response = app
        .oneshot(get(&format!(
            "/v1/attestations/{}",
            hex::encode(attestation_id)
        )))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;

    assert_eq!(json["attestation_id"], hex::encode(attestation_id));
    assert_eq!(json["attester"], hex::encode(sender.0));
    assert_eq!(json["status"], "active");
    assert_eq!(json["attestation_type"], 2);
    assert_eq!(json["attestation_type_name"], "document_notarization");
    assert_eq!(json["subject"], hex::encode([0x55; 32]));
    assert_eq!(json["content_hash"], hex::encode([0x66; 32]));
    assert_eq!(json["schema_id"], hex::encode([0x77; 32]));
    assert_eq!(json["metadata_hash"], hex::encode([0x88; 32]));
    assert_eq!(json["anchor_height"], 1);
    assert_eq!(json["expires_at_height"], 50);
    assert!(json["revocation"].is_null());
}

#[tokio::test]
async fn attestations_unknown_id_returns_404() {
    let dir = TempDir::new("att-404");
    let (state, _attestation_id, _sender) =
        make_api_state_with_attestation(&dir.path().join("data"));
    let app = router(state);

    let resp: axum::response::Response = app
        .oneshot(get(&format!("/v1/attestations/{}", hex::encode([0u8; 32]))))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn attestations_invalid_id_returns_400() {
    let dir = TempDir::new("att-400");
    let (state, _attestation_id, _sender) =
        make_api_state_with_attestation(&dir.path().join("data"));
    let app = router(state);

    let resp: axum::response::Response = app
        .oneshot(get("/v1/attestations/not-a-valid-id"))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn governance_receipt_returns_executed_registry_update() {
    let dir = TempDir::new("gov");
    let (state, proposal_id, sender) =
        make_api_state_with_governance_update(&dir.path().join("data"));
    let app = router(state);

    let resp: axum::response::Response = app
        .oneshot(get(&format!(
            "/v1/governance/receipts/{}",
            hex::encode(proposal_id)
        )))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;

    assert_eq!(json["proposal_id"], hex::encode(proposal_id));
    assert_eq!(json["proposal_type"], 1);
    assert_eq!(json["proposal_type_name"], "registry_update");
    assert_eq!(json["proposer"], hex::encode(sender.0));
    assert_eq!(json["target_alg_id"], AlgId::MlDsa65.as_u16());
    assert_eq!(json["lifecycle_before"], "active");
    assert_eq!(json["lifecycle_after"], "discouraged");
    assert_eq!(json["min_fee_before"], 0);
    assert_eq!(json["min_fee_after"], 500);
    assert_eq!(json["rationale_hash"], hex::encode([0xAB; 32]));
    assert_eq!(json["executed_at_height"], 1);
}
