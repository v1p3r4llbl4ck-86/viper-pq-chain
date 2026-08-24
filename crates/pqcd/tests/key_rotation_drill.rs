// SPDX-License-Identifier: BUSL-1.1
//! TASK-058 + TASK-063 — Cross-algorithm key-rotation drill with post-rotation verification.
//!
//! Exercises `key_rotate` (msg_type 0x0201) end-to-end on a live single-node
//! devnet for the two drill scenarios required by SPEC-TEST-001 §3.5:
//!
//! | Drill | From | To | pk_size | allowed_tx_types |
//! |-------|------|----|---------|-----------------|
//! | 1 | ML-DSA-65 | FN-DSA-padded-512 | 897 B | 0x0F (all) |
//! | 2 | ML-DSA-65 | SLH-DSA-SHA2-128s | 32 B | 0x04 (key mgmt only) |
//!
//! ## Post-rotation verification (TASK-063)
//!
//! Drill 2 now also exercises the SLH-DSA verification path in `PqVerifier`:
//! after rotating to a real SLH-DSA-SHA2-128s key (kv=2), a canary `key_add`
//! transaction signed with the SLH-DSA key (kv=3, ML-DSA-65) is injected and
//! must be admitted. This proves PqVerifier can verify SLH-DSA signatures in
//! the live admission pipeline.
//!
//! ## FN-DSA status (GAP-01)
//!
//! Drill 1 (FN-DSA) continues to use a synthetic public key and no canary tx.
//! FIPS 206 (FN-DSA) is not yet finalized; verification is deferred per
//! AUDIT-SCOPE-001 §6, GAP-01. The state transition (key revoked, new key
//! active) is fully tested; signature verification is the only gap.
//!
//! ## alg_id values (SPEC-ACCOUNT-001 §6.3)
//!
//! | Algorithm | alg_id | pk_size |
//! |-----------|--------|---------|
//! | ML-DSA-65 | 0x0002 | 1,952 B |
//! | FN-DSA-padded-512 | 0x0010 | 897 B |
//! | SLH-DSA-SHA2-128s | 0x0020 | 32 B |

use std::{
    env, fs,
    net::TcpListener as StdTcpListener,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use ciborium::value::Value;
use pqc_crypto::{
    derive_address, ml_dsa_public_key_from_seed, ml_dsa_sign_with_seed, slh_dsa_sha2_128s_generate,
    slh_dsa_sha2_128s_sign, AlgId,
};
use pqc_tx::{codec::encode_tx, preimage::build_preimage, validate::FeeParams};
use pqc_types::{
    account::Address,
    keyset::{allowed_tx, KeyStatus},
    transaction::{MsgType, Transaction},
};
use pqcd::{
    devnet::{start_from_config_path, DevnetNodeHandle},
    node::{
        DevnetConfig, GenesisAccountConfig, GenesisKeyConfig, GenesisKeyStatus, NodeConfig,
        NodeRole, RateLimitConfig, SenderBudgetConfig, ValidatorConfig,
    },
};
use tokio::time::{self, Duration, Instant};

// ── Sender identity ───────────────────────────────────────────────────────────

const SENDER_SEED: [u8; 32] = [0xDD; 32];
const ANCHOR_PREV_HASH: [u8; 32] = [0x11; 32];
const PRODUCER_ADDRESS: [u8; 32] = [0x99; 32];
const GAS_KEY_ROTATE: u64 = 15;

fn sender_pk() -> Vec<u8> {
    ml_dsa_public_key_from_seed(AlgId::MlDsa65, &SENDER_SEED)
        .expect("sender pk derivation must succeed")
}

fn sender_address() -> Address {
    let pk = sender_pk();
    // chain_id matches the empty chain_id used in txs and node config below.
    Address(derive_address(&[], AlgId::MlDsa65, &pk))
}

fn sign_tx(tx: &Transaction) -> Vec<u8> {
    let preimage = build_preimage(&pqc_types::ForkDigest::viper_research_1(), tx)
        .expect("preimage must build");
    ml_dsa_sign_with_seed(AlgId::MlDsa65, &SENDER_SEED, &preimage).expect("signing must succeed")
}

// ── Infrastructure ────────────────────────────────────────────────────────────

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "pqcd-key-drill-{label}-{}-{unique}",
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

fn test_validators() -> Vec<ValidatorConfig> {
    [
        ([0xA1u8; 32], AlgId::MlDsa65, [0x11u8; 32]),
        ([0xA2; 32], AlgId::MlDsa65, [0x22; 32]),
        ([0xA3; 32], AlgId::MlDsa65, [0x33; 32]),
    ]
    .iter()
    .enumerate()
    .map(|(i, (address, alg, seed))| {
        let pk =
            ml_dsa_public_key_from_seed(*alg, seed).expect("validator pk derivation must succeed");
        ValidatorConfig {
            node_id: format!("validator-{}", i + 1),
            address_hex: hex::encode(address),
            sig_alg_id: alg.as_u16(),
            public_key_hex: hex::encode(&pk),
            commit_seed_hex: Some(hex::encode(seed)),
            archival_sk_hex: None,
        }
    })
    .collect()
}

fn producer_config(data_dir: &Path, p2p_addr: &str) -> NodeConfig {
    NodeConfig {
        node_id: "key-drill-producer".to_owned(),
        data_dir: data_dir.to_path_buf(),
        chain_id_hex: String::new(),
        anchor_prev_hash_hex: hex::encode(ANCHOR_PREV_HASH),
        fee_params: FeeParams::default(), // zero fees — drill focuses on state, not economics
        p2p_listen_addr: Some(p2p_addr.to_owned()),
        api_listen_addr: None,
        peers: Vec::new(),
        devnet: DevnetConfig {
            role: NodeRole::Validator,
            sync_interval_ms: 50,
            // Long block time to prevent empty blocks from racing with key_rotate injection.
            //
            // For key_rotate to succeed, the new key's valid_from_height must equal
            // store.block_height() at apply time (so I-1 invariant is satisfied: the
            // new key starts immediately Active, not Pending). We set valid_from_height
            // to the committed height at the moment of tx construction. A 2-second block
            // interval gives ~1.9 s of margin between construction and the next block
            // assembly, making it essentially impossible for a race to occur.
            block_time_ms: 2_000,
            proposer_address_hex: Some(hex::encode(PRODUCER_ADDRESS)),
            quorum_threshold: None,
            validators: test_validators(),
            snapshot_source: None,
            ..Default::default()
        },
        genesis_accounts: vec![GenesisAccountConfig {
            address_hex: hex::encode(sender_address().0),
            balance: 10_000_000,
            nonce: 0,
            keys: vec![GenesisKeyConfig {
                alg_id: AlgId::MlDsa65.as_u16(),
                pk_hex: hex::encode(sender_pk()),
                key_version: 1,
                valid_from_height: 0,
                status: GenesisKeyStatus::Active,
                allowed_tx_types: allowed_tx::ALL,
            }],
        }],
        rate_limit: RateLimitConfig {
            max_requests_per_window: 0, // disabled
            window_secs: 60,
        },
        libp2p: None,
        sender_budget: SenderBudgetConfig {
            max_txs_per_window: 0, // disabled
            window_secs: 60,
        },
        api: Default::default(),
    }
}

// ── CBOR helpers ──────────────────────────────────────────────────────────────

enum CborVal {
    Int(u64),
    Bytes(Vec<u8>),
}

fn cbor_map(pairs: Vec<(u64, CborVal)>) -> Vec<u8> {
    let entries: Vec<(Value, Value)> = pairs
        .into_iter()
        .map(|(k, v)| {
            let key = Value::Integer(k.into());
            let val = match v {
                CborVal::Int(i) => Value::Integer(i.into()),
                CborVal::Bytes(b) => Value::Bytes(b),
            };
            (key, val)
        })
        .collect();
    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(entries), &mut out).unwrap();
    out
}

/// Build a `key_rotate` payload.
///
/// CBOR fields (SPEC-OPS-001):
///   1 = new_alg_id (u16)
///   2 = new_pk_bytes (bstr)
///   3 = new_key_version (u32)
///   4 = new_valid_from_height (u64)
///   5 = new_allowed_tx_types (u32 bitmask)
///   6 = revoke_key_version (u32)
fn key_rotate_payload(
    new_alg_id: u16,
    new_pk_bytes: Vec<u8>,
    new_key_version: u32,
    new_valid_from_height: u64,
    new_allowed_tx_types: u32,
    revoke_key_version: u32,
) -> Vec<u8> {
    cbor_map(vec![
        (1, CborVal::Int(new_alg_id as u64)),
        (2, CborVal::Bytes(new_pk_bytes)),
        (3, CborVal::Int(new_key_version as u64)),
        (4, CborVal::Int(new_valid_from_height)),
        (5, CborVal::Int(new_allowed_tx_types as u64)),
        (6, CborVal::Int(revoke_key_version as u64)),
    ])
}

/// Build a `key_add` payload.
///
/// CBOR fields (SPEC-OPS-001):
///   1 = alg_id (u16)
///   2 = pk_bytes (bstr)
///   3 = key_version (u32)
///   4 = valid_from_height (u64)
///   5 = allowed_tx_types (u32 bitmask)
fn key_add_payload(
    alg_id: u16,
    pk_bytes: Vec<u8>,
    key_version: u32,
    valid_from_height: u64,
    allowed_tx_types: u32,
) -> Vec<u8> {
    cbor_map(vec![
        (1, CborVal::Int(alg_id as u64)),
        (2, CborVal::Bytes(pk_bytes)),
        (3, CborVal::Int(key_version as u64)),
        (4, CborVal::Int(valid_from_height)),
        (5, CborVal::Int(allowed_tx_types as u64)),
    ])
}

/// Build and sign a `key_rotate` transaction using the sender's ML-DSA-65 key.
///
/// `valid_from_height` must be >= the committed block height at execution time
/// (SPEC-OPS-001 activation constraint). Pass the current committed chain height
/// so the new key activates in the very block where the rotation is applied.
#[allow(clippy::too_many_arguments)]
fn key_rotate_tx(
    sender: &Address,
    nonce: u64,
    new_alg_id: u16,
    new_pk_bytes: Vec<u8>,
    new_key_version: u32,
    new_allowed_tx_types: u32,
    revoke_key_version: u32,
    valid_from_height: u64,
) -> Vec<u8> {
    let payload = key_rotate_payload(
        new_alg_id,
        new_pk_bytes,
        new_key_version,
        valid_from_height,
        new_allowed_tx_types,
        revoke_key_version,
    );
    // Fee covers standard lane after AIMD floor (BASE_FEE_MIN=100). Use 500 for headroom.
    let mut tx = Transaction {
        tx_version: 1,
        chain_id: vec![],
        msg_type: MsgType::KeyRotate,
        sender: sender.clone(),
        nonce,
        fee: 500,
        fee_tip: 0,
        gas_limit: GAS_KEY_ROTATE,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1, // signing with the OLD key (which will be revoked)
        signature: vec![],
    };
    tx.signature = sign_tx(&tx);
    encode_tx(&tx).expect("encode must succeed")
}

/// Build and sign a `key_add` transaction with an SLH-DSA-SHA2-128s key (kv=2).
///
/// This is the post-rotation canary tx that exercises `PqVerifier`'s SLH-DSA
/// verification path end-to-end in the live admission pipeline.
///
/// The canary adds a new ML-DSA-65 key (kv=3) to the account, signed by the
/// newly rotated SLH-DSA key (kv=2, allowed_tx_types=KEY_MGMT).
fn key_add_canary_tx_slh_dsa(
    sender: &Address,
    nonce: u64,
    slh_sk_bytes: &[u8],
    new_ml_dsa_pk: Vec<u8>,
    valid_from_height: u64,
) -> Vec<u8> {
    let payload = key_add_payload(
        AlgId::MlDsa65.as_u16(), // adding an ML-DSA-65 key as kv=3
        new_ml_dsa_pk,
        3, // key_version = 3
        valid_from_height,
        allowed_tx::ALL, // the new ML-DSA-65 key has no restrictions
    );
    // Fee covers standard lane after AIMD floor (BASE_FEE_MIN=100). Use 500 for headroom.
    let mut tx = Transaction {
        tx_version: 1,
        chain_id: vec![],
        msg_type: MsgType::KeyAdd,
        sender: sender.clone(),
        nonce,
        fee: 500,
        fee_tip: 0,
        gas_limit: GAS_KEY_ROTATE,
        payload,
        sig_alg_id: AlgId::SlhDsaSha2128s, // signed with the SLH-DSA kv=2 key
        sig_key_version: 2,
        signature: vec![],
    };
    let preimage = build_preimage(&pqc_types::ForkDigest::viper_research_1(), &tx)
        .expect("preimage must build");
    tx.signature =
        slh_dsa_sha2_128s_sign(slh_sk_bytes, &preimage).expect("SLH-DSA signing must succeed");
    encode_tx(&tx).expect("encode must succeed")
}

/// Build a simple proof_anchor transaction using the sender's ML-DSA-65 key.
///
/// Used as a "signing canary" before the rotation to confirm the original key works,
/// and attempted again after revocation to confirm it is rejected.
fn proof_anchor_tx(sender: &Address, nonce: u64, key_version: u32) -> Vec<u8> {
    let payload = cbor_map(vec![
        (1, CborVal::Int(0x0001)),                // claim_type = ownership
        (2, CborVal::Bytes([0xAA; 32].to_vec())), // asset_id_hash
        (3, CborVal::Bytes([0xBB; 32].to_vec())), // proof_hash
    ]);
    // Fee covers standard lane after AIMD floor (BASE_FEE_MIN=100). Use 500 for headroom.
    let mut tx = Transaction {
        tx_version: 1,
        chain_id: vec![],
        msg_type: MsgType::ProofAnchor,
        sender: sender.clone(),
        nonce,
        fee: 500,
        fee_tip: 0,
        gas_limit: 10,
        payload,
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: key_version,
        signature: vec![],
    };
    tx.signature = sign_tx(&tx);
    encode_tx(&tx).expect("encode must succeed")
}

// ── Shared drill logic ────────────────────────────────────────────────────────

/// Poll the live state until the sender's committed nonce reaches `expected`.
///
/// `wait_for_height_advance` is insufficient here because it returns as soon
/// as any block is produced — the injected tx might not have been included in
/// that block yet. Polling the account nonce directly ensures the state has
/// actually committed the tx before the next step proceeds.
async fn wait_for_committed_nonce(
    node: &DevnetNodeHandle,
    sender: &Address,
    expected: u64,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(account) = node.get_account(sender).await {
            if account.nonce >= expected {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "timeout waiting for account nonce to reach {expected} \
                 (SPEC-TEST-001 §3.5: tx must be committed before next step)"
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Run a cross-algorithm key rotation drill.
///
/// Steps:
/// 1. Confirm original key (ML-DSA-65, version 1) signs successfully.
/// 2. Submit key_rotate: revoke kv=1, register new kv=2 with target algorithm.
/// 3. Verify new key is active, old key is revoked in live state.
/// 4. Confirm attempt to sign with revoked kv=1 is rejected.
/// 5. (Optional) Inject SLH-DSA canary tx signed with kv=2 — proves PqVerifier
///    SLH-DSA path works end-to-end. Enabled only for drill 2 (slh_canary = Some).
async fn run_key_rotation_drill(
    label: &str,
    new_alg_id: u16,
    new_pk_bytes: Vec<u8>,
    new_allowed_tx_types: u32,
    // Some((slh_sk_bytes, new_ml_dsa_pk)) enables the post-rotation SLH-DSA canary tx.
    // None skips step 5 (FN-DSA drill, where verification is GAP-01).
    slh_canary: Option<(Vec<u8>, Vec<u8>)>,
) -> Result<()> {
    let dir = TempDir::new(label);
    let p2p_addr = reserve_local_addr();
    let config_path = dir.path().join("config.json");

    write_config(
        &config_path,
        &producer_config(&dir.path().join("node"), &p2p_addr),
    );

    let node = start_from_config_path(&config_path)
        .await
        .context("failed to start key-drill node")?;

    node.wait_for_height(1, Duration::from_secs(15))
        .await
        .context("node did not reach height 1")?;

    let sender = sender_address();
    let mut nonce = 0u64;

    // ── Step 1: Baseline — original key (ML-DSA-65, kv=1) signs successfully ──
    let baseline_tx = proof_anchor_tx(&sender, nonce, 1);
    node.inject_tx(baseline_tx)
        .await
        .context("baseline proof_anchor must be accepted")?;
    nonce += 1;
    // Wait until the committed state reflects nonce=1 before submitting nonce=1 tx.
    wait_for_committed_nonce(&node, &sender, nonce, Duration::from_secs(15))
        .await
        .context("state did not commit baseline proof_anchor in time")?;

    // ── Step 2: Submit key_rotate — revoke kv=1, register kv=2 ──────────────
    //
    // valid_from_height must equal store.block_height() at execution time so
    // the new key starts immediately Active (not Pending), satisfying invariant
    // I-1 (at least one Active key) after the old key is revoked (SPEC-OPS-001).
    //
    // We use the current committed height as valid_from_height. The 2-second
    // block interval gives ~1.9 s of margin between this read and the next
    // block assembly, making it essentially impossible for a race (empty block
    // advancing store.block_height before key_rotate is assembled).
    let current_height = node.snapshot().await.height;
    let rotate_tx = key_rotate_tx(
        &sender,
        nonce,
        new_alg_id,
        new_pk_bytes,
        2, // new key_version
        new_allowed_tx_types,
        1,              // revoke_key_version
        current_height, // valid_from_height = committed height → key is immediately Active
    );
    node.inject_tx(rotate_tx)
        .await
        .context("key_rotate tx must be accepted")?;
    nonce += 1;
    // Wait until the committed state reflects the key rotation.
    // The new key is immediately Active so no additional wait_for_key_active needed.
    wait_for_committed_nonce(&node, &sender, nonce, Duration::from_secs(15))
        .await
        .context("state did not commit key_rotate tx in time")?;

    // ── Step 3: Verify key state in live state ────────────────────────────────
    let account = node
        .get_account(&sender)
        .await
        .context("sender account must exist after key rotation")?;

    assert_eq!(
        account.keys.0.len(),
        2,
        "account must have exactly 2 key entries after rotation"
    );

    let old_key = account
        .keys
        .0
        .iter()
        .find(|k| k.key_version == 1)
        .expect("key_version=1 must still exist (retained for audit)");

    assert_eq!(
        old_key.status,
        KeyStatus::Revoked,
        "original ML-DSA-65 key (kv=1) must be revoked after rotation"
    );

    let new_key = account
        .keys
        .0
        .iter()
        .find(|k| k.key_version == 2)
        .expect("key_version=2 must exist after rotation");

    assert_eq!(
        new_key.status,
        KeyStatus::Active,
        "new key (kv=2) must be active after rotation"
    );
    assert_eq!(
        new_key.alg_id.as_u16(),
        new_alg_id,
        "new key must carry the target alg_id"
    );
    assert_eq!(
        new_key.allowed_tx_types, new_allowed_tx_types,
        "new key must carry the specified allowed_tx_types"
    );

    // ── Step 4: Confirm revoked key is rejected ───────────────────────────────
    //
    // A transaction signed with the revoked kv=1 must be rejected by the
    // admission pipeline (KEY_REVOKED). We use the key_version field in
    // the tx to reference kv=1 while signing with the same SENDER_SEED
    // (the signature itself is still ML-DSA-65 valid, but the key it claims
    // to use is revoked).
    let rejected_tx = proof_anchor_tx(&sender, nonce, 1 /* revoked kv */);
    let err = node
        .inject_tx(rejected_tx)
        .await
        .expect_err("tx with revoked signing key must be rejected");

    let err_str = format!("{err:?}").to_lowercase();
    assert!(
        err_str.contains("revoked") || err_str.contains("key"),
        "expected KEY_REVOKED or similar in error; got: {err}"
    );

    // ── Step 5 (optional): SLH-DSA post-rotation canary ─────────────────────
    //
    // Inject a `key_add` tx signed with the newly rotated SLH-DSA key (kv=2).
    // This exercises PqVerifier's SLH-DSA verification path in the live
    // admission pipeline, confirming GAP-01 is resolved for SLH-DSA.
    //
    // The canary adds a new ML-DSA-65 key (kv=3) using KEY_MGMT permission of
    // the SLH-DSA key. If PqVerifier cannot verify SLH-DSA signatures, this
    // step fails with a signature verification error.
    if let Some((slh_sk, new_ml_dsa_pk)) = slh_canary {
        // SLH-DSA-SHA2-128s signing takes ≈60 s on this hardware (slow signing
        // variant, ~40 000 hash invocations). Calling it directly on the async task
        // blocks the Tokio worker thread. The devnet block-production loop runs on
        // the other worker thread and continues advancing block height during the
        // block. After ~60 s of signing, store.block_height() has advanced by ≈30
        // blocks, so valid_from_height = canary_height + 20 has already expired and
        // apply_key_add fails with InvalidActivationHeight.
        //
        // Fix:
        //   1. Snapshot pre_sign_height before spawning.
        //   2. Bake valid_from_height = pre_sign_height + 200 into the signed payload
        //      (200 ≫ ≈30 worst-case blocks at 2 s/block during signing).
        //   3. Offload the slow SLH-DSA signing to a blocking thread via
        //      spawn_blocking so the Tokio runtime remains free.
        //
        // The canary key (kv=3) starts Pending until pre_sign_height+200 — that is
        // intentional:
        //  (a) kv=2 (SLH-DSA, Active) satisfies I-1 invariant.
        //  (b) the test goal is to prove PqVerifier's SLH-DSA path works end-to-end;
        //      key activation timing is orthogonal.
        // The nonce=3 commit is the correctness signal.
        let pre_sign_height = node.snapshot().await.height;
        let canary_valid_from_height = pre_sign_height + 200;
        let sender_for_sign = sender.clone();
        let nonce_val = nonce; // nonce=2; the rejected tx in step 4 did not commit
        let canary = tokio::task::spawn_blocking(move || {
            key_add_canary_tx_slh_dsa(
                &sender_for_sign,
                nonce_val,
                &slh_sk,
                new_ml_dsa_pk,
                canary_valid_from_height,
            )
        })
        .await
        .context("SLH-DSA signing task panicked")?;

        node.inject_tx(canary).await.context(
            "SLH-DSA canary key_add must be admitted \
                 (confirms PqVerifier SLH-DSA path — GAP-01 resolved for SLH-DSA)",
        )?;
        nonce += 1;
        wait_for_committed_nonce(&node, &sender, nonce, Duration::from_secs(15))
            .await
            .context("state did not commit SLH-DSA canary key_add in time")?;

        // Verify the canary key (kv=3) was registered in the account.
        // The key starts Pending (valid_from_height = pre_sign_height+200) —
        // intentional, see fix comment above. The important assertion is existence.
        let account_after = node
            .get_account(&sender)
            .await
            .context("sender account must exist after canary key_add")?;
        let canary_key = account_after
            .keys
            .0
            .iter()
            .find(|k| k.key_version == 3)
            .expect("canary kv=3 must exist after SLH-DSA key_add");
        assert_eq!(
            canary_key.alg_id,
            AlgId::MlDsa65,
            "canary key must be ML-DSA-65"
        );
        println!("[DRILL] SLH-DSA post-rotation canary admitted — PqVerifier SLH-DSA path: PASS");
    }

    // Small settling delay before shutdown.
    time::sleep(Duration::from_millis(100)).await;
    node.shutdown().await?;

    Ok(())
}

// ── Test 1: ML-DSA-65 → FN-DSA-padded-512 ───────────────────────────────────

/// SPEC-TEST-001 §3.5 drill 1: rotate from ML-DSA-65 to FN-DSA-padded-512.
///
/// FN-DSA-padded-512 (alg_id=0x0010) has pk_size=897 bytes.
/// `allowed_tx_types=0x0F` (all operations) — FN-DSA keys have no restriction.
///
/// The drill confirms:
/// - State transition is correct (old key revoked, new key active)
/// - New key carries the correct alg_id and allowed_tx_types
/// - Old key is rejected after revocation
///
/// No post-rotation canary: FIPS 206 (FN-DSA) is not yet finalized.
/// Signature verification for FN-DSA remains GAP-01 (AUDIT-SCOPE-001 §6).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn key_rotate_ml_dsa65_to_fn_dsa_padded512() -> Result<()> {
    // FN-DSA-padded-512 public key size: 897 bytes (SPEC-ACCOUNT-001 §5.3.2).
    // Synthetic key — real FN-DSA key generation is deferred until FIPS 206 is finalized.
    let fn_dsa_pk = vec![0x33u8; 897];

    run_key_rotation_drill(
        "fn-dsa-rotation",
        0x0010, // FN-DSA-padded-512
        fn_dsa_pk,
        allowed_tx::ALL, // 0x0F — FN-DSA has no per-spec tx type restriction
        None,            // GAP-01: no post-rotation canary until FIPS 206 is finalized
    )
    .await?;

    println!("[DRILL] ML-DSA-65 → FN-DSA-padded-512 rotation: PASS (state only; GAP-01 pending)");
    Ok(())
}

// ── Test 2: ML-DSA-65 → SLH-DSA-SHA2-128s ───────────────────────────────────

/// SPEC-TEST-001 §3.5 drill 2: rotate from ML-DSA-65 to SLH-DSA-SHA2-128s.
///
/// SLH-DSA-SHA2-128s (alg_id=0x0020) has pk_size=32 bytes.
/// `allowed_tx_types=0x04` (bit 2 = key management only) — SLH-DSA keys are
/// restricted to key management operations by protocol (SPEC-ACCOUNT-001 §5.3.6).
///
/// The drill confirms:
/// - State transition is correct (old key revoked, new key active)
/// - New key carries allowed_tx_types=0x04 (key management only)
/// - Old key is rejected after revocation
/// - Post-rotation canary: SLH-DSA kv=2 signs a key_add tx that is admitted,
///   proving PqVerifier's SLH-DSA verification path works end-to-end (GAP-01
///   resolved for SLH-DSA; AUDIT-SCOPE-001 §6).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn key_rotate_ml_dsa65_to_slh_dsa128s() -> Result<()> {
    // Generate a real SLH-DSA-SHA2-128s keypair: pk=32 bytes, sk=64 bytes.
    let (slh_pk, slh_sk) =
        slh_dsa_sha2_128s_generate().expect("SLH-DSA-SHA2-128s key generation must succeed");
    assert_eq!(slh_pk.len(), 32, "SLH-DSA-SHA2-128s pk must be 32 bytes");
    assert_eq!(slh_sk.len(), 64, "SLH-DSA-SHA2-128s sk must be 64 bytes");

    // The canary adds a fresh ML-DSA-65 key (kv=3) so we have something to add.
    // Any valid ML-DSA-65 public key works; derive from a fixed seed for reproducibility.
    let canary_ml_dsa_pk = ml_dsa_public_key_from_seed(AlgId::MlDsa65, &[0xCCu8; 32])
        .expect("ML-DSA-65 canary pk derivation must succeed");

    run_key_rotation_drill(
        "slh-dsa-rotation",
        0x0020, // SLH-DSA-SHA2-128s
        slh_pk,
        allowed_tx::KEY_MGMT, // 0x04 — SLH-DSA restricted to key mgmt
        Some((slh_sk, canary_ml_dsa_pk)),
    )
    .await?;

    println!("[DRILL] ML-DSA-65 → SLH-DSA-SHA2-128s rotation: PASS (state + PqVerifier SLH-DSA)");
    Ok(())
}
