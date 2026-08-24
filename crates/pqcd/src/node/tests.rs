// SPDX-License-Identifier: BUSL-1.1
//! Tests for `node`.
//!
//! Extracted from `node.rs` 2026-05-10. `use super::*;`
//! brings every private item from the parent module into scope.

use std::{
    env, fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use ciborium::value::Value;
use pqc_consensus::{AssemblyConfig, LocalProposer, LocalProposerConfig};
use pqc_consensus::{RecoverySource, RocksDbChainStore};
use pqc_crypto::{sign::StubVerifier, AlgId};
use pqc_mempool::{admission::try_admit, Mempool};
use pqc_state::StateStore;
use pqc_tx::{codec::encode_tx, validate::FeeParams};
use pqc_types::{
    account::Address,
    block::BlockHash,
    keyset::{allowed_tx, KeyEntry, KeySet, KeyStatus},
    transaction::{MsgType, Transaction},
};

use super::{
    bootstrap_from_config_path, render_status, DevnetConfig, GenesisAccountConfig,
    GenesisKeyConfig, GenesisKeyStatus, NodeConfig,
};

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            env::temp_dir().join(format!("pqcd-node-{label}-{}-{unique}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn cbor_map(pairs: Vec<(u64, CborVal)>) -> Vec<u8> {
    let entries: Vec<(Value, Value)> = pairs
        .into_iter()
        .map(|(key, value)| {
            let key = Value::Integer(key.into());
            let value = match value {
                CborVal::Int(int) => Value::Integer(int.into()),
                CborVal::Bytes(bytes) => Value::Bytes(bytes),
            };
            (key, value)
        })
        .collect();

    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(entries), &mut out).unwrap();
    out
}

enum CborVal {
    Int(u64),
    Bytes(Vec<u8>),
}

fn signer_account(
    address: Address,
    balance: u128,
    nonce: u64,
    alg_id: AlgId,
) -> pqc_types::account::Account {
    pqc_types::account::Account {
        address,
        balance,
        nonce,
        keys: KeySet(vec![KeyEntry {
            alg_id,
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

fn transfer_payload(recipient: &Address, amount: u64) -> Vec<u8> {
    cbor_map(vec![
        (1, CborVal::Bytes(recipient.0.to_vec())),
        (2, CborVal::Int(amount)),
    ])
}

fn transfer_tx(
    sender: Address,
    recipient: Address,
    nonce: u64,
    fee: u64,
    fee_tip: u64,
    signature_fill: u8,
) -> Transaction {
    Transaction {
        tx_version: 1,
        chain_id: Vec::new(),
        msg_type: MsgType::TokenTransfer,
        sender,
        nonce,
        fee,
        fee_tip,
        gas_limit: 100_000,
        payload: transfer_payload(&recipient, 100),
        sig_alg_id: AlgId::MlDsa65,
        sig_key_version: 1,
        signature: vec![signature_fill; 3_309],
    }
}

fn admit(pool: &mut Mempool, store: &StateStore, tx: &Transaction, fee_params: &FeeParams) {
    let raw = encode_tx(tx).expect("encode must succeed");
    let verifier = StubVerifier;
    try_admit(pool, raw, store, &verifier, fee_params).expect("admission must succeed");
}

fn proposer(fee_params: FeeParams) -> LocalProposer {
    LocalProposer::new(
        [0x99; 32],
        LocalProposerConfig {
            assembly: AssemblyConfig {
                fee_params,
                ..AssemblyConfig::default()
            },
            initial_prev_hash: BlockHash([0x11; 32]),
        },
    )
}

fn genesis_config_for_sender(sender: Address) -> Vec<GenesisAccountConfig> {
    vec![GenesisAccountConfig {
        address_hex: hex::encode(sender.0),
        balance: 10_000_000,
        nonce: 0,
        keys: vec![GenesisKeyConfig {
            alg_id: AlgId::MlDsa65.as_u16(),
            pk_hex: hex::encode([0u8; 32]),
            key_version: 1,
            valid_from_height: 0,
            status: GenesisKeyStatus::Active,
            allowed_tx_types: allowed_tx::ALL,
        }],
    }]
}

fn write_config(path: &Path, data_dir: &Path, sender: Address, fee_params: FeeParams) {
    let config = NodeConfig {
        node_id: "node-test".to_owned(),
        data_dir: data_dir.to_path_buf(),
        // Empty chain_id matches the test transactions which also use Vec::new().
        chain_id_hex: String::new(),
        anchor_prev_hash_hex: hex::encode([0x11; 32]),
        fee_params,
        p2p_listen_addr: None,
        api_listen_addr: None,
        peers: Vec::new(),
        devnet: DevnetConfig::default(),
        genesis_accounts: genesis_config_for_sender(sender),
        rate_limit: Default::default(),
        sender_budget: Default::default(),
        api: Default::default(),
        libp2p: None,
    };
    fs::write(path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
}

/// ADR-054 §Stage 6 — synthetic test helper that attaches a
/// length-1 stub `CommitSig` to a freshly-produced block so the
/// on-startup integrity audit does not refuse the chain. The sig
/// bytes are zero-filled (the audit only checks vec length, not
/// validity); production tests that exercise the M2 quorum path
/// build real signatures against the validator set.
fn attach_stub_commit_sig(result: &mut pqc_consensus::BlockExecutionResult) {
    result
        .block
        .commit_signatures
        .push(pqc_types::block::CommitSig {
            validator_address: vec![0u8; 32],
            sig_alg_id: pqc_crypto::AlgId::MlDsa65,
            round: 0,
            signature: vec![0u8; 8],
        });
}

fn build_persisted_chain(
    data_dir: &Path,
    write_checkpoint: bool,
    fee_params: FeeParams,
) -> (Address, StateStore, StateStore) {
    let sender = Address([0xA1; 32]);
    let recipient = Address([0x11; 32]);

    let mut genesis_state = StateStore::new();
    genesis_state.insert_account(signer_account(
        sender.clone(),
        10_000_000,
        0,
        AlgId::MlDsa65,
    ));

    let mut live_state = genesis_state.clone();
    let mut pool = Mempool::new();
    let mut proposer = proposer(fee_params.clone());
    fs::create_dir_all(data_dir.join("rocksdb")).unwrap();
    let mut disk = RocksDbChainStore::open(data_dir.join("rocksdb"), BlockHash([0x11; 32]))
        .expect("RocksDB store open must succeed");

    let tx_fee = if fee_params == FeeParams::default() {
        100
    } else {
        1_000_000
    };

    let first = transfer_tx(sender.clone(), recipient.clone(), 0, tx_fee, 0, 0x01);
    admit(&mut pool, &live_state, &first, &fee_params);
    let mut result_1 = proposer
        .run_once(&mut live_state, &mut pool, 1_710_000_000)
        .expect("first run_once must succeed");
    // ADR-054 §Stage 6 — the on-startup integrity audit refuses
    // chains whose tail blocks have empty commit_signatures.
    // The test proposer doesn't fill them, so attach a stub here
    // so `bootstrap_from_config_path` (which now runs the audit)
    // does not refuse the synthetic chain. Production paths
    // attach real precommits via the consensus loop.
    attach_stub_commit_sig(&mut result_1);
    // Test path has no validators in state → pass None, skip quorum check.
    // M2 behaviour is exercised by the integration tests that do wire
    // validators into the state store.
    disk.append_block(&result_1, None)
        .expect("disk append must succeed");

    if write_checkpoint {
        disk.write_trusted_checkpoint(&live_state)
            .expect("checkpoint write must succeed");
    }

    let second = transfer_tx(sender.clone(), recipient, 1, tx_fee, 0, 0x02);
    admit(&mut pool, &live_state, &second, &fee_params);
    let mut result_2 = proposer
        .run_once(&mut live_state, &mut pool, 1_710_000_001)
        .expect("second run_once must succeed");
    attach_stub_commit_sig(&mut result_2);
    disk.append_block(&result_2, None)
        .expect("disk append must succeed");

    (sender, genesis_state, live_state)
}

#[test]
fn bootstrap_from_config_prefers_trusted_checkpoint() {
    let dir = TestDir::new("bootstrap-ckpt");
    let data_dir = dir.path().join("data");
    let config_path = dir.path().join("node.json");
    let (sender, _genesis_state, live_state) =
        build_persisted_chain(&data_dir, true, FeeParams::default());
    write_config(&config_path, &data_dir, sender, FeeParams::default());

    let report = bootstrap_from_config_path(&config_path).expect("bootstrap must succeed");

    assert_eq!(report.chain_height, live_state.block_height());
    assert_eq!(report.recovery_source, RecoverySource::TrustedCheckpoint);
    assert_eq!(report.account_count, live_state.accounts_in_order().len());
    assert_eq!(
        report
            .checkpoint
            .as_ref()
            .map(|checkpoint| checkpoint.height),
        Some(1)
    );
}

#[test]
fn bootstrap_from_config_falls_back_to_full_replay_without_checkpoint() {
    let dir = TestDir::new("bootstrap-fallback");
    let data_dir = dir.path().join("data");
    let config_path = dir.path().join("node.json");
    // write_checkpoint=false → no checkpoint → full replay path
    let (sender, _genesis_state, live_state) =
        build_persisted_chain(&data_dir, false, FeeParams::default());
    write_config(&config_path, &data_dir, sender, FeeParams::default());

    let report = bootstrap_from_config_path(&config_path).expect("bootstrap must succeed");

    assert_eq!(report.chain_height, live_state.block_height());
    assert_eq!(report.recovery_source, RecoverySource::FullReplay);
    assert!(report.checkpoint.is_none());
}

#[test]
fn render_status_reports_height_and_recovery_source() {
    let dir = TestDir::new("status");
    let data_dir = dir.path().join("data");
    let config_path = dir.path().join("node.json");
    let (sender, _genesis_state, _live_state) =
        build_persisted_chain(&data_dir, true, FeeParams::default());
    write_config(&config_path, &data_dir, sender, FeeParams::default());

    let report = bootstrap_from_config_path(&config_path).expect("bootstrap must succeed");
    let status = render_status(&report);

    assert!(status.contains("status:          ready"));
    assert!(status.contains("chain_height:    2"));
    assert!(status.contains("recovery_source: trusted_checkpoint"));
    assert!(status.contains("checkpoint:      height=1"));
}

#[test]
fn bootstrap_from_config_uses_nonzero_fee_params_for_replay() {
    let dir = TestDir::new("bootstrap-fees");
    let data_dir = dir.path().join("data");
    let config_path = dir.path().join("node.json");
    let fee_params = FeeParams {
        base_fee: 500,
        byte_fee: 2,
        sigverify_fee_v_a: 7_000,
        sigverify_fee_v_b: 10_000,
        sigverify_fee_v_c: 580_000,
        exec_fee_per_gas: 1,
        base_fee_dynamic: 0,
    };
    let (sender, _genesis_state, live_state) =
        build_persisted_chain(&data_dir, true, fee_params.clone());
    write_config(&config_path, &data_dir, sender, fee_params);

    let report = bootstrap_from_config_path(&config_path).expect("bootstrap must succeed");

    assert_eq!(report.chain_height, live_state.block_height());
    assert_eq!(
        report.state_root,
        RocksDbChainStore::open(data_dir.join("rocksdb"), BlockHash([0x11; 32]))
            .expect("RocksDB store open must succeed")
            .chain()
            .tip()
            .expect("tip must exist")
            .metadata
            .state_root
    );
}

// TASK-219 three-network lint pin tests.

use super::{
    load_node_config, warn_on_role_api_misconfig, warn_on_three_network_misconfig, Libp2pConfig,
    NodeRole,
};

fn lint_config(role: NodeRole, libp2p_enable: bool, public_listen: Option<&str>) -> NodeConfig {
    let mut cfg = NodeConfig {
        node_id: "test".into(),
        data_dir: PathBuf::from("/tmp/test"),
        chain_id_hex: String::new(),
        anchor_prev_hash_hex: "00".repeat(32),
        fee_params: FeeParams::default(),
        p2p_listen_addr: None,
        api_listen_addr: None,
        peers: Vec::new(),
        devnet: DevnetConfig::default(),
        genesis_accounts: Vec::new(),
        rate_limit: super::RateLimitConfig::default(),
        sender_budget: super::SenderBudgetConfig::default(),
        api: super::ApiConfig::default(),
        libp2p: None,
    };
    cfg.devnet.role = role;
    if libp2p_enable {
        cfg.libp2p = Some(Libp2pConfig {
            enable: true,
            public_listen: public_listen.map(String::from),
            ..Default::default()
        });
    }
    cfg
}

#[test]
fn lint_warns_on_validator_with_public_wildcard_bind() {
    let cfg = lint_config(NodeRole::Validator, true, Some("/ip4/0.0.0.0/tcp/26676"));
    assert!(warn_on_three_network_misconfig(&cfg));
}

#[test]
fn lint_silent_on_validator_with_public_loopback_bind() {
    // Operator opted into a merged-network test rig — no warning.
    let cfg = lint_config(NodeRole::SingleNode, true, Some("/ip4/127.0.0.1/tcp/26676"));
    assert!(!warn_on_three_network_misconfig(&cfg));
}

#[test]
fn lint_silent_on_follower_role() {
    // Followers / sentries / VFNs MAY publicly bind public_listen —
    // that is the whole point of the three-network split.
    let cfg = lint_config(NodeRole::Full, true, Some("/ip4/0.0.0.0/tcp/26676"));
    assert!(!warn_on_three_network_misconfig(&cfg));
}

#[test]
fn lint_silent_when_public_listen_unset() {
    let cfg = lint_config(NodeRole::Validator, true, None);
    assert!(!warn_on_three_network_misconfig(&cfg));
}

#[test]
fn lint_silent_when_libp2p_disabled() {
    // Phase 6 transport — three-network model does not apply.
    let cfg = lint_config(NodeRole::Validator, false, Some("/ip4/0.0.0.0/tcp/26676"));
    assert!(!warn_on_three_network_misconfig(&cfg));
}

#[test]
fn lint_warns_on_v6_wildcard_bind() {
    let cfg = lint_config(NodeRole::Validator, true, Some("/ip6/::/tcp/26676"));
    assert!(warn_on_three_network_misconfig(&cfg));
}

// ── ADR-069: NodeRole ──────────────────────────────────────────────────

#[test]
fn node_role_round_trips_through_its_json_spelling() {
    for role in NodeRole::ALL {
        let json = serde_json::to_string(&role).expect("serialize");
        assert_eq!(json, format!("\"{}\"", role.as_str()), "{role:?}");
        let back: NodeRole = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, role);
    }
}

#[test]
fn node_role_accepts_the_pre_adr069_aliases_and_never_writes_them() {
    let producer: NodeRole = serde_json::from_str("\"producer\"").expect("alias");
    let follower: NodeRole = serde_json::from_str("\"follower\"").expect("alias");
    assert_eq!(producer, NodeRole::Validator);
    assert_eq!(follower, NodeRole::Full);
    assert_eq!(serde_json::to_string(&producer).unwrap(), "\"validator\"");
    assert_eq!(serde_json::to_string(&follower).unwrap(), "\"full\"");
    assert!(serde_json::from_str::<NodeRole>("\"proposer\"").is_err());
}

#[test]
fn node_role_predicate_table() {
    use pqc_p2p::config::NodeRole as P2p;
    // (role, is_validator, keeps_full_history, serves_public_tx, api_private, p2p role, listen field)
    let table = [
        (
            NodeRole::Validator,
            true,
            true,
            false,
            true,
            P2p::Validator,
            "validator_listen",
        ),
        (
            NodeRole::SingleNode,
            true,
            true,
            false,
            false,
            P2p::Validator,
            "validator_listen",
        ),
        (
            NodeRole::Sentry,
            false,
            false,
            true,
            false,
            P2p::ValidatorFullnode,
            "vfn_listen",
        ),
        (
            NodeRole::Full,
            false,
            false,
            true,
            false,
            P2p::PublicFullnode,
            "public_listen",
        ),
        (
            NodeRole::Rpc,
            false,
            false,
            true,
            false,
            P2p::PublicFullnode,
            "public_listen",
        ),
        (
            NodeRole::Archive,
            false,
            true,
            true,
            false,
            P2p::PublicFullnode,
            "public_listen",
        ),
        (
            NodeRole::Bootnode,
            false,
            false,
            false,
            true,
            P2p::PublicFullnode,
            "public_listen",
        ),
    ];
    for (role, validator, history, public_tx, private_api, p2p, field) in table {
        assert_eq!(role.is_validator(), validator, "{role:?} is_validator");
        assert_eq!(
            role.syncs_from_peers(),
            !validator,
            "{role:?} syncs_from_peers"
        );
        assert_eq!(
            role.keeps_full_history(),
            history,
            "{role:?} keeps_full_history"
        );
        assert_eq!(
            role.serves_public_tx_submission(),
            public_tx,
            "{role:?} public tx"
        );
        assert_eq!(
            role.api_is_private(),
            private_api,
            "{role:?} api_is_private"
        );
        assert_eq!(role.p2p_role(), p2p, "{role:?} p2p_role");
        assert_eq!(role.libp2p_listen_field(), field, "{role:?} listen field");
        assert_eq!(
            role.requires_validator_set(),
            role != NodeRole::SingleNode,
            "{role:?} validator set"
        );
        assert_eq!(role.requires_p2p_transport(), role != NodeRole::SingleNode);
    }
    // Only the real validator runs the BFT proposer loop; single_node has its own path.
    assert!(NodeRole::Validator.runs_bft_consensus_loop());
    assert!(!NodeRole::SingleNode.runs_bft_consensus_loop());
    assert!(!NodeRole::Sentry.runs_bft_consensus_loop());
}

#[test]
fn role_api_lint_flags_private_roles_on_the_public_path() {
    let mut cfg = lint_config(NodeRole::Validator, false, None);
    // `ApiConfig::default()` accepts public transactions, so a validator
    // that never sets `api` IS reported — that is the point of the lint.
    assert_eq!(
        warn_on_role_api_misconfig(&cfg),
        1,
        "validator on API defaults"
    );
    cfg.api.public_tx_submission = false;
    assert_eq!(warn_on_role_api_misconfig(&cfg), 0);
    cfg.api.public_tx_submission = true;
    assert_eq!(
        warn_on_role_api_misconfig(&cfg),
        1,
        "validator accepting public tx"
    );
    // A wildcard bind is NOT a finding: in the chart every pod binds
    // 0.0.0.0 for the readiness probe, and privacy is the NetworkPolicy's job.
    cfg.api.public_tx_submission = false;
    cfg.api_listen_addr = Some("0.0.0.0:26657".into());
    assert_eq!(
        warn_on_role_api_misconfig(&cfg),
        0,
        "wildcard bind alone is fine"
    );

    let mut rpc = lint_config(NodeRole::Rpc, false, None);
    rpc.api.public_tx_submission = true;
    assert_eq!(
        warn_on_role_api_misconfig(&rpc),
        0,
        "rpc is meant to be public"
    );

    let mut boot = lint_config(NodeRole::Bootnode, false, None);
    boot.api.public_tx_submission = true;
    assert_eq!(
        warn_on_role_api_misconfig(&boot),
        1,
        "bootnode does not take public tx"
    );
}

#[test]
fn viper_node_id_env_overrides_the_configured_node_id() {
    let dir = std::env::temp_dir().join(format!(
        "pqcd-node-id-override-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("node.json");
    let mut cfg = lint_config(NodeRole::Full, false, None);
    cfg.node_id = "from-file".into();
    fs::write(&path, serde_json::to_string(&cfg).unwrap()).unwrap();

    // No env → the file wins.
    env::remove_var("VIPER_NODE_ID");
    assert_eq!(load_node_config(&path).unwrap().node_id, "from-file");
    // Env set → the pod name wins.
    env::set_var("VIPER_NODE_ID", "release-pqcd-sentry-1");
    let loaded = load_node_config(&path);
    env::remove_var("VIPER_NODE_ID");
    assert_eq!(loaded.unwrap().node_id, "release-pqcd-sentry-1");
    let _ = fs::remove_dir_all(&dir);
}

/// `configs/roles/<role>.json` are the reference examples shipped with the
/// public repo: each must parse, name the role it is filed under, set the
/// libp2p listen field that role uses, and pass the role API lint.
#[test]
fn configs_roles_examples_match_their_role() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../configs/roles");
    let mut seen = 0;
    for role in NodeRole::ALL {
        if role == NodeRole::SingleNode {
            continue;
        }
        let path = dir.join(format!("{}.json", role.as_str()));
        let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let cfg: NodeConfig =
            serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(cfg.devnet.role, role, "{}", path.display());
        let libp2p = cfg.libp2p.as_ref().expect("example enables libp2p");
        assert!(libp2p.enable);
        let listen = match role.libp2p_listen_field() {
            "validator_listen" => &libp2p.validator_listen,
            "vfn_listen" => &libp2p.vfn_listen,
            _ => &libp2p.public_listen,
        };
        assert!(
            listen.is_some(),
            "{}: {} must be set",
            path.display(),
            role.libp2p_listen_field()
        );
        assert_eq!(
            cfg.api.public_tx_submission,
            role.serves_public_tx_submission(),
            "{}",
            path.display()
        );
        assert_eq!(warn_on_role_api_misconfig(&cfg), 0, "{}", path.display());
        seen += 1;
    }
    assert_eq!(seen, 6);
}
