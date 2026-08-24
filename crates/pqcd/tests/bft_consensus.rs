// SPDX-License-Identifier: BUSL-1.1
//! BFT consensus integration tests — SPEC-CONSENSUS-001 §13 Phase D.
//!
//! Tests:
//!   1. Proposer rotation: block headers carry the correct rotating proposer
//!      address as computed by `select_proposer(validators, height, 0)`.
//!   2. Equivocation detection: VoteStore detects two conflicting signed votes
//!      from the same validator at the same (height, round, step).
//!   3. View change proposer selection: `select_proposer` with increasing round
//!      advances to the next validator in the sorted set.
//!
//! The proposer rotation test uses the `consensus_loop` path, which is activated
//! when a producer node is configured with ≥ 2 validators. All validators sign
//! locally (single-node BFT simulation — full P2P vote exchange is TASK future).

use std::{
    env, fs, net::TcpListener as StdTcpListener, path::Path, time::SystemTime, time::UNIX_EPOCH,
};

use pqc_consensus::{
    select_proposer, vote_preimage, ConsensusRound, ConsensusVote, RoundAction, VoteStep,
    VoteStore, NIL_HASH,
};
use pqc_crypto::{ml_dsa_public_key_from_seed, AlgId};
use pqcd::{
    devnet::{start_from_config_path, DevnetNodeHandle, DevnetNodeSnapshot},
    node::{DevnetConfig, NodeConfig, NodeRole, ValidatorConfig},
};
use tokio::time::{self, Duration, Instant};

// ── Helpers ───────────────────────────────────────────────────────────────────

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            env::temp_dir().join(format!("pqcd-bft-{label}-{}-{unique}", std::process::id()));
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

/// Three test validators with deterministic keys.
#[derive(Clone)]
struct TestValidator {
    node_id: String,
    address: [u8; 32],
    commit_seed: [u8; 32],
    public_key: Vec<u8>,
}

fn test_validators() -> Vec<TestValidator> {
    // Addresses are chosen so that their lexicographic sort order is:
    //   0x01... < 0x02... < 0x03...
    // which means select_proposer at height H, round 0 yields:
    //   H%3=0 → address [0x01;32]
    //   H%3=1 → address [0x02;32]
    //   H%3=2 → address [0x03;32]
    [
        ([0x01u8; 32], [0x11u8; 32]),
        ([0x02u8; 32], [0x22u8; 32]),
        ([0x03u8; 32], [0x33u8; 32]),
    ]
    .into_iter()
    .enumerate()
    .map(|(i, (address, seed))| TestValidator {
        node_id: format!("bft-validator-{}", i + 1),
        address,
        commit_seed: seed,
        public_key: ml_dsa_public_key_from_seed(AlgId::MlDsa65, &seed)
            .expect("public key derivation must succeed"),
    })
    .collect()
}

fn to_validator_config(v: &TestValidator, include_seed: bool) -> ValidatorConfig {
    ValidatorConfig {
        node_id: v.node_id.clone(),
        address_hex: hex::encode(v.address),
        sig_alg_id: AlgId::MlDsa65.as_u16(),
        public_key_hex: hex::encode(&v.public_key),
        commit_seed_hex: include_seed.then(|| hex::encode(v.commit_seed)),
        archival_sk_hex: None,
    }
}

/// Build a single-node producer config with 3 validators (consensus_loop path).
fn consensus_producer_config(data_dir: &Path, validators: &[TestValidator]) -> NodeConfig {
    // Producer role requires p2p_listen_addr.
    let p2p_addr = reserve_local_addr();
    NodeConfig {
        node_id: "bft-producer".to_owned(),
        data_dir: data_dir.to_path_buf(),
        chain_id_hex: String::new(),
        anchor_prev_hash_hex: hex::encode([0x11u8; 32]),
        fee_params: Default::default(),
        p2p_listen_addr: Some(p2p_addr),
        api_listen_addr: None,
        peers: Vec::new(),
        devnet: DevnetConfig {
            role: NodeRole::Validator,
            block_time_ms: 300, // fast for tests
            // proposer_address_hex is the initial address used by LocalProposer at startup;
            // consensus_loop overrides it each height via select_proposer (TASK-084).
            proposer_address_hex: Some(hex::encode(validators[0].address)),
            validators: validators
                .iter()
                .map(|v| to_validator_config(v, true)) // include seeds for local signing
                .collect(),
            ..Default::default()
        },
        genesis_accounts: Vec::new(),
        rate_limit: Default::default(),
        libp2p: None,
        sender_budget: Default::default(),
        api: Default::default(),
    }
}

/// Poll until the node reaches at least `target_height`, with a timeout.
async fn wait_for_height(handle: &DevnetNodeHandle, target: u64, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let snap: DevnetNodeSnapshot = handle.snapshot().await;
        if snap.height >= target {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "node did not reach height {target} within {:?} (current height: {})",
                timeout, snap.height
            );
        }
        time::sleep(Duration::from_millis(100)).await;
    }
}

// ── Test 1: Proposer rotation ─────────────────────────────────────────────────

/// Verify that the `consensus_loop` sets the correct rotating proposer address
/// in each block header, matching `select_proposer(validators, height, 0)`.
///
/// SPEC-CONSENSUS-001 §5.1: proposer(h, r) = sorted_validators[(h + r) % len]
#[tokio::test]
async fn proposer_rotates_across_heights() {
    let dir = TempDir::new("proposer-rotation");
    let validators = test_validators();

    // Build the sorted validator address list exactly as consensus_loop does.
    let mut sorted_addrs: Vec<[u8; 32]> = validators.iter().map(|v| v.address).collect();
    sorted_addrs.sort();

    let config_path = dir.path().join("config.json");
    fs::write(
        &config_path,
        serde_json::to_vec_pretty(&consensus_producer_config(dir.path(), &validators)).unwrap(),
    )
    .unwrap();

    let handle = start_from_config_path(&config_path)
        .await
        .expect("node startup must succeed");

    // Wait for 9 blocks so we see at least 3 full rotations.
    wait_for_height(&handle, 9, Duration::from_secs(15)).await;

    // Verify proposer rotation for heights 1 through 9.
    for height in 1u64..=9 {
        let proposer = handle
            .block_proposer_at(height)
            .await
            .unwrap_or_else(|| panic!("block {height} not found"));

        let expected = select_proposer(&sorted_addrs, height, 0, None)
            .expect("sorted_addrs must be non-empty");
        assert_eq!(
            proposer.as_slice(),
            expected.as_slice(),
            "height {height}: expected proposer {}, got {}",
            hex::encode(expected),
            hex::encode(&proposer),
        );
    }

    // shutdown() returns Result; a best-effort shutdown at test-teardown
    // ignores the error (the test body already asserted on the chain
    // state before this line).
    let _ = handle.shutdown().await;
}

// ── Test 2: Equivocation detection ───────────────────────────────────────────

/// Verify that VoteStore detects a double-sign (two prevotes with different
/// block hashes at the same (height, round, step)) as equivocation.
///
/// SPEC-CONSENSUS-001 §10: equivocation evidence must be detectable and reportable.
#[test]
fn equivocation_detected_on_conflicting_precommits() {
    let validator = [0xA0u8; 32];
    let hash_a = [0xAAu8; 32];
    let hash_b = [0xBBu8; 32];

    let mut store = VoteStore::new();

    // First precommit — accepted.
    let first = store.record(ConsensusVote {
        height: 10,
        round: 0,
        step: VoteStep::Precommit,
        block_hash: hash_a,
        validator_address: validator,
        signature: Vec::new(), // not verified by VoteStore
    });
    assert!(first.is_none(), "first vote must not be equivocation");

    // Second precommit with a different block hash — equivocation.
    let second = store.record(ConsensusVote {
        height: 10,
        round: 0,
        step: VoteStep::Precommit,
        block_hash: hash_b,
        validator_address: validator,
        signature: Vec::new(),
    });
    let evidence = second.expect("conflicting precommit must produce equivocation evidence");

    assert_eq!(evidence.validator_address, validator);
    assert_eq!(evidence.height, 10);
    assert_eq!(evidence.round, 0);
    assert_eq!(evidence.step, VoteStep::Precommit);
    assert_eq!(evidence.vote_a.block_hash, hash_a);
    assert_eq!(evidence.vote_b.block_hash, hash_b);
    assert_eq!(store.equivocation_count(), 1);

    // A third vote with the same hash as the first is a duplicate — not equivocation.
    let dup = store.record(ConsensusVote {
        height: 10,
        round: 0,
        step: VoteStep::Precommit,
        block_hash: hash_a,
        validator_address: validator,
        signature: Vec::new(),
    });
    assert!(
        dup.is_none(),
        "duplicate vote must not increment equivocation count"
    );
    assert_eq!(
        store.equivocation_count(),
        1,
        "count must not change on duplicate"
    );
}

/// Two nil-votes at the same (v, h, r, step) are NOT equivocation.
/// A validator may send nil in the same step when retrying due to network conditions.
///
/// SPEC-CONSENSUS-001 §10.1: "at least one must be non-nil" for equivocation.
#[test]
fn two_nil_votes_are_not_equivocation() {
    let validator = [0xBEu8; 32];
    let mut store = VoteStore::new();

    store.record(ConsensusVote {
        height: 5,
        round: 1,
        step: VoteStep::Prevote,
        block_hash: NIL_HASH,
        validator_address: validator,
        signature: Vec::new(),
    });
    let result = store.record(ConsensusVote {
        height: 5,
        round: 1,
        step: VoteStep::Prevote,
        block_hash: NIL_HASH,
        validator_address: validator,
        signature: Vec::new(),
    });
    assert!(
        result.is_none(),
        "two nil votes must not be flagged as equivocation"
    );
    assert_eq!(store.equivocation_count(), 0);
}

/// Different validators at the same (h, r, step) with different hashes is not equivocation.
#[test]
fn different_validators_different_hash_is_not_equivocation() {
    let v0 = [0x00u8; 32];
    let v1 = [0x01u8; 32];
    let hash_a = [0xAAu8; 32];
    let hash_b = [0xBBu8; 32];
    let mut store = VoteStore::new();

    store.record(ConsensusVote {
        height: 1,
        round: 0,
        step: VoteStep::Prevote,
        block_hash: hash_a,
        validator_address: v0,
        signature: Vec::new(),
    });
    let result = store.record(ConsensusVote {
        height: 1,
        round: 0,
        step: VoteStep::Prevote,
        block_hash: hash_b,
        validator_address: v1,
        signature: Vec::new(),
    });
    assert!(
        result.is_none(),
        "different validators voting for different blocks is not equivocation"
    );
}

// ── Test 3: View change proposer selection ────────────────────────────────────

/// Verify that incrementing the round advances the proposer to the next validator.
///
/// SPEC-CONSENSUS-001 §5.1 + §6.4: on propose timeout, round increments;
/// the next proposer is select_proposer(validators, height, round+1).
#[test]
fn view_change_selects_next_proposer() {
    let v0 = [0x00u8; 32];
    let v1 = [0x01u8; 32];
    let v2 = [0x02u8; 32];
    let validators = [v0, v1, v2];

    // height=1, round=0 → sorted[(1+0)%3] = sorted[1] = 0x01
    let p0 = select_proposer(&validators, 1, 0, None).unwrap();
    // height=1, round=1 → sorted[(1+1)%3] = sorted[2] = 0x02
    let p1 = select_proposer(&validators, 1, 1, None).unwrap();
    // height=1, round=2 → sorted[(1+2)%3] = sorted[0] = 0x00
    let p2 = select_proposer(&validators, 1, 2, None).unwrap();

    assert_eq!(p0, v1, "round 0: sorted[1]");
    assert_eq!(p1, v2, "round 1: sorted[2]");
    assert_eq!(p2, v0, "round 2: sorted[0] (wrap)");

    // Three consecutive view changes must cycle through all 3 validators.
    let all_proposers: std::collections::HashSet<[u8; 32]> = [p0, p1, p2].into_iter().collect();
    assert_eq!(
        all_proposers.len(),
        3,
        "view changes must cover all 3 validators before repeating"
    );
}

/// Verify that ConsensusRound increments round on precommit timeout (view change).
///
/// SPEC-CONSENSUS-001 §6.5: if quorum is not reached before precommit_timeout,
/// advance to NewRound(h, r+1).
#[test]
fn consensus_round_advances_round_on_timeout() {
    let mut r = ConsensusRound::new(1, 3);
    assert_eq!(r.round, 0);
    assert_eq!(r.phase, pqc_consensus::RoundPhase::Propose);

    // Simulate propose timeout (no proposal received).
    let _ = r.on_propose_timeout();
    // Simulate prevote timeout (no polka).
    let _ = r.on_prevote_timeout();
    // Simulate precommit timeout (no commit quorum).
    let actions = r.on_precommit_timeout();

    assert_eq!(
        actions,
        vec![RoundAction::NextRound],
        "precommit timeout must return NextRound"
    );
    assert_eq!(r.round, 1, "round must increment after timeout");
    assert_eq!(
        r.phase,
        pqc_consensus::RoundPhase::Propose,
        "phase must reset to Propose"
    );
}

// ── Test 4: Vote preimage domain separation ───────────────────────────────────

/// Verify that vote preimages are unique per (height, round, step, hash).
/// This ensures that commit signatures from the legacy PQC-COMMIT-V1 preimage
/// cannot be replayed as BFT vote signatures.
///
/// SPEC-CONSENSUS-001 §7.4.
#[test]
fn vote_preimages_have_unique_domain_separation() {
    let fd = pqc_types::ForkDigest::viper_research_1();
    let hash = [0x42u8; 32];

    let prevote_h1_r0 = vote_preimage(&fd, 1, 0, VoteStep::Prevote, &hash);
    let prevote_h2_r0 = vote_preimage(&fd, 2, 0, VoteStep::Prevote, &hash);
    let prevote_h1_r1 = vote_preimage(&fd, 1, 1, VoteStep::Prevote, &hash);
    let precommit_h1_r0 = vote_preimage(&fd, 1, 0, VoteStep::Precommit, &hash);
    let prevote_nil = vote_preimage(&fd, 1, 0, VoteStep::Prevote, &NIL_HASH);

    // All five must be distinct.
    let preimages = [
        prevote_h1_r0,
        prevote_h2_r0,
        prevote_h1_r1,
        precommit_h1_r0,
        prevote_nil,
    ];
    let unique: std::collections::HashSet<[u8; 32]> = preimages.into_iter().collect();
    assert_eq!(unique.len(), 5, "all vote preimages must be distinct");
}
