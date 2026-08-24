// SPDX-License-Identifier: BUSL-1.1
//! Integration tests for distributed snapshot state-sync (TASK-050).
//!
//! These tests cover the full snapshot lifecycle:
//!
//! 1. **Export/import roundtrip** — exported checkpoint bytes can be imported to a
//!    fresh data directory and recovered with the same height and state_root.
//! 2. **Replay equivalence** — snapshot bootstrap + tail replay converges to the
//!    same `state_root` as full genesis replay from block 1. This is the invariant
//!    that makes state-sync safe.
//! 3. **Corruption rejection** — truncated or byte-flipped snapshot bytes are
//!    rejected by both `import_external_snapshot` and `bootstrap_from_external_snapshot`
//!    before any data is written.
//! 4. **Network cold-start** — a follower node with an empty data directory and
//!    `snapshot_source` configured downloads the producer's checkpoint via the
//!    authenticated P2P snapshot endpoint, tail-syncs, and converges with the
//!    producer to the same `state_root`.

use std::{
    env, fs,
    net::TcpListener as StdTcpListener,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use pqc_consensus::{
    AssemblyConfig, LocalProposer, LocalProposerConfig, RecoverySource, RocksDbChainStore,
};
use pqc_mempool::Mempool;
use pqc_state::StateStore;
use pqc_tx::validate::FeeParams;
use pqc_types::block::BlockHash;
use pqcd::{
    devnet::{start_from_config_path, DevnetNodeHandle, DevnetNodeSnapshot},
    node::{DevnetConfig, Libp2pConfig, NodeConfig, NodeRole, PeerConfig},
};
use tokio::time::{self, Duration, Instant};

// ── Shared constants ──────────────────────────────────────────────────────────

const ANCHOR_PREV_HASH: [u8; 32] = [0x11; 32];
const PROPOSER_ADDRESS: [u8; 32] = [0x99; 32];

// ── Utilities ─────────────────────────────────────────────────────────────────

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            env::temp_dir().join(format!("pqcd-snap-{label}-{}-{unique}", std::process::id()));
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

/// Build a chain in `data_dir` with `num_blocks` empty blocks.
///
/// A trusted checkpoint is written after the block at `checkpoint_after_height`.
/// Returns the `StateStore` at the final height (for comparison).
///
/// Quorum policy is left unset on `append_block`, but each block carries a
/// **dummy non-empty `commit_signatures`** so the post-2026-04-26 ADR-054
/// §Stage 6 integrity audit (`verify_quick_finality_invariants`, refuses
/// open() if any post-checkpoint tail block has empty commit_signatures)
/// does not refuse to open the test data dir on follower bootstrap. The
/// signature bytes are syntactically present but cryptographically
/// nonsense; the audit only checks emptiness, not validity, so the
/// stub is sufficient. A future fixture upgrade can swap to real
/// ML-DSA signatures once the test harness gains a multi-validator
/// keystore — TASK-156 §Step 6 territory.
fn build_chain_with_checkpoint(
    data_dir: &Path,
    num_blocks: usize,
    checkpoint_after_height: u64,
) -> StateStore {
    use pqc_crypto::AlgId;
    use pqc_types::block::CommitSig;

    let anchor = BlockHash(ANCHOR_PREV_HASH);
    let mut disk = RocksDbChainStore::open(data_dir.join("rocksdb"), anchor.clone())
        .expect("disk store open must succeed");
    let mut proposer = LocalProposer::new(
        PROPOSER_ADDRESS,
        LocalProposerConfig {
            assembly: AssemblyConfig::default(),
            initial_prev_hash: anchor,
        },
    );
    let mut state = StateStore::new();
    let mut pool = Mempool::new();

    for i in 0..num_blocks {
        let mut result = proposer
            .run_once(&mut state, &mut pool, 1_710_000_000 + i as u64)
            .expect("block production must succeed");
        // Stub commit_signatures so ADR-054 §Stage 6 audit accepts the
        // tail at recover_tip_with_checkpoint time. Signature bytes
        // are syntactic-only — no validator verification runs in this
        // test path (policy=None on append_block). `append_block`
        // re-derives the block_hash internally so mutating
        // `commit_signatures` here is safe regardless of whether the
        // hash preimage covers the field (compute_block_hash is the
        // single source of truth).
        result.block.commit_signatures = vec![CommitSig {
            validator_address: PROPOSER_ADDRESS.to_vec(),
            sig_alg_id: AlgId::MlDsa65,
            round: 0,
            signature: vec![0xCC; 32],
        }];
        disk.append_block(&result, None)
            .expect("disk append must succeed");
        if result.new_height == checkpoint_after_height {
            disk.write_trusted_checkpoint(&state)
                .expect("checkpoint write must succeed");
        }
    }

    state
}

/// Node config for the snapshot source.
///
/// Uses `SingleNode` role (no block production, no commit-quorum requirements) so
/// the pre-built chain data can be loaded without validator configuration.  The
/// node serves its pre-built blocks and checkpoint via the P2P endpoints.
fn source_node_config(data_dir: &Path, p2p_listen_addr: &str) -> NodeConfig {
    NodeConfig {
        node_id: "snap-source".to_owned(),
        data_dir: data_dir.to_path_buf(),
        chain_id_hex: String::new(),
        anchor_prev_hash_hex: hex::encode(ANCHOR_PREV_HASH),
        fee_params: FeeParams::default(),
        p2p_listen_addr: Some(p2p_listen_addr.to_owned()),
        api_listen_addr: None,
        peers: Vec::new(),
        devnet: DevnetConfig {
            role: NodeRole::SingleNode,
            sync_interval_ms: 50,
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

/// Node config for the cold-start follower.
///
/// Uses `SingleNode` role so no commit-quorum validator configuration is required
/// (the test exercises the snapshot bootstrap mechanism, not commit-quorum validation —
/// that is covered by `multi_node_devnet` tests).  The `snapshot_source` triggers
/// cold-start bootstrap from the source node's checkpoint on first startup.
fn cold_start_follower_config(
    data_dir: &Path,
    p2p_listen_addr: &str,
    source_peer: PeerConfig,
    snapshot_source_addr: &str,
) -> NodeConfig {
    NodeConfig {
        node_id: "snap-follower".to_owned(),
        data_dir: data_dir.to_path_buf(),
        chain_id_hex: String::new(),
        anchor_prev_hash_hex: hex::encode(ANCHOR_PREV_HASH),
        fee_params: FeeParams::default(),
        p2p_listen_addr: Some(p2p_listen_addr.to_owned()),
        api_listen_addr: None,
        peers: vec![source_peer],
        devnet: DevnetConfig {
            role: NodeRole::SingleNode,
            sync_interval_ms: 50,
            block_time_ms: 500,
            proposer_address_hex: None,
            quorum_threshold: None,
            validators: Vec::new(),
            snapshot_source: Some(snapshot_source_addr.to_owned()),
            ..Default::default()
        },
        genesis_accounts: Vec::new(),
        rate_limit: Default::default(),
        libp2p: None,
        sender_budget: Default::default(),
        api: Default::default(),
    }
}

/// Wait until all handles report the same height ≥ `min_height` and the same `state_root`.
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
            && last
                .iter()
                .all(|s| s.height == first.height && s.state_root == first.state_root)
        {
            return Ok(last.clone());
        }
        if Instant::now() >= deadline {
            let diag = last
                .iter()
                .map(|s| {
                    format!(
                        "{}@{} root={} err={:?}",
                        s.node_id,
                        s.height,
                        hex::encode(s.state_root.0),
                        s.last_sync_error
                    )
                })
                .collect::<Vec<_>>()
                .join(" | ");
            anyhow::bail!("timed out waiting for convergence at height >= {min_height}: {diag}");
        }
        time::sleep(Duration::from_millis(25)).await;
    }
}

// ── Unit tests (no network) ────────────────────────────────────────────────────

/// Export a checkpoint from a source directory, import it to a fresh directory,
/// then recover from the imported snapshot and verify that height and state_root
/// match the original.
#[test]
fn snapshot_export_import_roundtrip() {
    let dir = TempDir::new("roundtrip");
    let source_dir = dir.path().join("source");
    let import_dir = dir.path().join("import");

    // Build a 3-block chain with checkpoint at height 2.
    build_chain_with_checkpoint(&source_dir, 3, 2);

    // Export the checkpoint from the source.
    let snapshot_bytes = {
        let source_disk =
            RocksDbChainStore::open(source_dir.join("rocksdb"), BlockHash(ANCHOR_PREV_HASH))
                .expect("source disk open must succeed");
        source_disk
            .export_checkpoint_bytes()
            .expect("export must succeed")
            .expect("checkpoint must exist")
    };

    // Verify decode_snapshot_metadata.
    let (snap_height, _snap_tip) = RocksDbChainStore::decode_snapshot_metadata(&snapshot_bytes)
        .expect("decode_snapshot_metadata must succeed");
    assert_eq!(snap_height, 2, "snapshot metadata must report height 2");

    // Import into a fresh directory.
    let metadata = {
        let import_disk =
            RocksDbChainStore::open(import_dir.join("rocksdb"), BlockHash(ANCHOR_PREV_HASH))
                .expect("import disk open must succeed");
        let chain_id: Vec<u8> = Vec::new(); // empty chain_id matches test
        import_disk
            .import_external_snapshot(&snapshot_bytes, &chain_id)
            .expect("import must succeed")
    };

    assert_eq!(metadata.height, 2);

    // Recover from the imported snapshot — should use TrustedCheckpoint path.
    // The import_dir has only the checkpoint (no tail blocks), so recovery height = 2.
    let genesis_state = StateStore::new();
    let import_disk2 =
        RocksDbChainStore::open(import_dir.join("rocksdb"), BlockHash(ANCHOR_PREV_HASH))
            .expect("re-open after import must succeed");
    let recovery = import_disk2
        .recover_tip_with_checkpoint(
            &genesis_state,
            FeeParams::default(),
            Default::default(),
            vec![],
        )
        .expect("recover_tip_with_checkpoint must succeed");

    assert_eq!(
        recovery.source,
        RecoverySource::TrustedCheckpoint,
        "recovery after snapshot import must use trusted checkpoint"
    );
    assert_eq!(
        recovery.replay.height, 2,
        "recovered height must match snapshot height"
    );
    // The state_root from recovery must match what the snapshot metadata recorded.
    assert_eq!(
        recovery.replay.state_root, metadata.state_root,
        "recovered state_root must match the snapshot's recorded state_root"
    );
}

/// A node bootstrapped from a snapshot plus tail replay must reach the same
/// `state_root` as a node that replayed the full chain from genesis.
///
/// This is the replay-equivalence invariant: both paths produce identical state.
#[test]
fn snapshot_full_replay_equivalence() {
    let dir = TempDir::new("equivalence");
    let full_dir = dir.path().join("full");
    let snap_dir = dir.path().join("snap");
    let import_dir = dir.path().join("import");

    // Build an identical 4-block chain in both dirs.  Checkpoint after block 2.
    let _state_full = build_chain_with_checkpoint(&full_dir, 4, 2);
    let _state_snap = build_chain_with_checkpoint(&snap_dir, 4, 2);

    // Full-replay path: open the full chain with no checkpoint bias.
    let genesis_state = StateStore::new();
    let full_root = {
        let full_disk =
            RocksDbChainStore::open(full_dir.join("rocksdb"), BlockHash(ANCHOR_PREV_HASH))
                .expect("full disk open must succeed");
        let full_recovery = full_disk
            .recover_tip_with_checkpoint(
                &genesis_state,
                FeeParams::default(),
                Default::default(),
                vec![],
            )
            .expect("full recovery must succeed");
        assert_eq!(
            full_recovery.replay.height, 4,
            "full replay must reach height 4"
        );
        full_recovery.replay.state_root.clone()
    };

    // Snapshot bootstrap path:
    // 1. Export checkpoint from snap_dir (height 2).
    // 2. Export tail blocks 3 and 4.
    // 3. bootstrap_from_external_snapshot into import_dir.
    let (snapshot_bytes, tail_bytes) = {
        let snap_disk =
            RocksDbChainStore::open(snap_dir.join("rocksdb"), BlockHash(ANCHOR_PREV_HASH))
                .expect("snap disk open must succeed");
        let snapshot_bytes = snap_disk
            .export_checkpoint_bytes()
            .expect("export must succeed")
            .expect("checkpoint must exist after building chain");
        // Retrieve tail blocks (height 3 and 4) as encoded bytes.
        let tail_bytes: Vec<Vec<u8>> = [3u64, 4u64]
            .iter()
            .map(|&h| {
                let stored = snap_disk
                    .chain()
                    .get_stored_block_by_height(h)
                    .unwrap_or_else(|| panic!("tail block at height {h} must exist"));
                RocksDbChainStore::encode_block_bytes(stored).expect("encode must succeed")
            })
            .collect();
        (snapshot_bytes, tail_bytes)
    };

    {
        let mut import_disk =
            RocksDbChainStore::open(import_dir.join("rocksdb"), BlockHash(ANCHOR_PREV_HASH))
                .expect("import disk open must succeed");
        let chain_id: Vec<u8> = Vec::new();
        import_disk
            .bootstrap_from_external_snapshot(&snapshot_bytes, &tail_bytes, &chain_id)
            .expect("bootstrap_from_external_snapshot must succeed");
    }

    // Recover from the snapshot-bootstrapped store.
    let import_disk2 =
        RocksDbChainStore::open(import_dir.join("rocksdb"), BlockHash(ANCHOR_PREV_HASH))
            .expect("re-open of snap-bootstrapped store must succeed");
    let snap_recovery = import_disk2
        .recover_tip_with_checkpoint(
            &genesis_state,
            FeeParams::default(),
            Default::default(),
            vec![],
        )
        .expect("snapshot recovery must succeed");

    assert_eq!(
        snap_recovery.source,
        RecoverySource::TrustedCheckpoint,
        "bootstrapped store must use trusted checkpoint path"
    );
    assert_eq!(
        snap_recovery.replay.height, 4,
        "snapshot bootstrap + tail replay must reach height 4"
    );
    assert_eq!(
        snap_recovery.replay.state_root, full_root,
        "snapshot bootstrap + tail replay must reach the same state_root as full replay"
    );
}

/// Truncated or byte-flipped snapshot bytes must be rejected without writing
/// any data to the destination directory.
#[test]
fn snapshot_corrupted_bytes_rejected() {
    let dir = TempDir::new("corrupt");
    let source_dir = dir.path().join("source");
    let import_dir = dir.path().join("import");

    build_chain_with_checkpoint(&source_dir, 2, 1);

    let snapshot_bytes = {
        let source_disk =
            RocksDbChainStore::open(source_dir.join("rocksdb"), BlockHash(ANCHOR_PREV_HASH))
                .expect("source disk open must succeed");
        source_disk
            .export_checkpoint_bytes()
            .expect("export must succeed")
            .expect("checkpoint must exist")
    };
    let chain_id: Vec<u8> = Vec::new();

    // --- Truncated bytes ---
    let truncated = snapshot_bytes[..snapshot_bytes.len() / 2].to_vec();
    {
        let import_disk =
            RocksDbChainStore::open(import_dir.join("rocksdb"), BlockHash(ANCHOR_PREV_HASH))
                .expect("import disk open must succeed");
        assert!(
            import_disk
                .import_external_snapshot(&truncated, &chain_id)
                .is_err(),
            "truncated snapshot must be rejected"
        );
    }

    // --- Single byte flip in the payload (not the CBOR header) ---
    let mut flipped = snapshot_bytes.clone();
    let flip_pos = flipped.len() / 2;
    flipped[flip_pos] ^= 0xFF;
    // This will either fail CBOR decode or state_root consistency check.
    {
        let import_disk2 =
            RocksDbChainStore::open(import_dir.join("rocksdb"), BlockHash(ANCHOR_PREV_HASH))
                .expect("import disk open must succeed");
        assert!(
            import_disk2
                .import_external_snapshot(&flipped, &chain_id)
                .is_err(),
            "byte-flipped snapshot must be rejected"
        );
    }

    // --- Completely wrong bytes ---
    {
        let import_disk3 =
            RocksDbChainStore::open(import_dir.join("rocksdb"), BlockHash(ANCHOR_PREV_HASH))
                .expect("import disk open must succeed");
        assert!(
            import_disk3
                .import_external_snapshot(b"not-a-cbor-snapshot", &chain_id)
                .is_err(),
            "garbage bytes must be rejected"
        );
    }

    // Verify nothing was written: the store has no checkpoint.
    let check_disk =
        RocksDbChainStore::open(import_dir.join("rocksdb"), BlockHash(ANCHOR_PREV_HASH))
            .expect("check disk open must succeed");
    assert!(
        !check_disk.has_checkpoint(),
        "no checkpoint must be written after all-rejected import attempts"
    );
}

/// `bootstrap_from_external_snapshot` must reject corrupt snapshot bytes
/// without writing any data.
#[test]
fn bootstrap_corrupted_snapshot_rejected() {
    let dir = TempDir::new("boot-corrupt");
    let source_dir = dir.path().join("source");
    let target_dir = dir.path().join("target");

    build_chain_with_checkpoint(&source_dir, 2, 1);
    let snapshot_bytes = {
        let source_disk =
            RocksDbChainStore::open(source_dir.join("rocksdb"), BlockHash(ANCHOR_PREV_HASH))
                .expect("source disk open must succeed");
        source_disk
            .export_checkpoint_bytes()
            .expect("export must succeed")
            .expect("checkpoint must exist")
    };
    let chain_id: Vec<u8> = Vec::new();

    // Corrupt the snapshot bytes.
    let mut bad_bytes = snapshot_bytes.clone();
    let pos = bad_bytes.len() / 2;
    bad_bytes[pos] ^= 0xFF;

    {
        let mut disk =
            RocksDbChainStore::open(target_dir.join("rocksdb"), BlockHash(ANCHOR_PREV_HASH))
                .expect("target disk open must succeed");
        assert!(
            disk.bootstrap_from_external_snapshot(&bad_bytes, &[], &chain_id)
                .is_err(),
            "bootstrap_from_external_snapshot must reject corrupt snapshot"
        );
    }

    // Nothing written.
    let check_disk =
        RocksDbChainStore::open(target_dir.join("rocksdb"), BlockHash(ANCHOR_PREV_HASH))
            .expect("check disk open must succeed");
    assert!(
        !check_disk.has_checkpoint(),
        "no checkpoint must be written after rejected bootstrap"
    );
}

// ── Network tests ─────────────────────────────────────────────────────────────

/// A follower node with `snapshot_source` configured and an empty data directory
/// must cold-start from the source node's checkpoint, tail-sync to the current tip,
/// and converge to the same `state_root` as the source node.
///
/// Flow:
/// 1. Pre-build a source data directory with 2 blocks and a checkpoint at height 1.
/// 2. Start the source devnet node on that pre-built directory.
/// 3. Start a follower with `snapshot_source` pointing at the source's P2P address
///    and an empty data directory.
/// 4. Wait for both nodes to converge at the same height and state_root.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_cold_start_network() -> Result<()> {
    let dir = TempDir::new("cold-start");
    let source_data_dir = dir.path().join("source");
    let follower_data_dir = dir.path().join("follower");

    // Pre-build the source data directory.
    // 3 blocks total; checkpoint at height 1 so the snapshot is at height 1 and
    // blocks 2–3 form the initial tail.
    build_chain_with_checkpoint(&source_data_dir, 3, 1);

    let source_addr = reserve_local_addr();
    let follower_addr = reserve_local_addr();

    let source_config_path = dir.path().join("source.json");
    let follower_config_path = dir.path().join("follower.json");

    write_config(
        &source_config_path,
        &source_node_config(&source_data_dir, &source_addr),
    );

    write_config(
        &follower_config_path,
        &cold_start_follower_config(
            &follower_data_dir,
            &follower_addr,
            PeerConfig {
                node_id: "snap-source".to_owned(),
                p2p_addr: source_addr.clone(),
            },
            &source_addr,
        ),
    );

    // Start source first so it is reachable when the follower cold-starts.
    let source = start_from_config_path(&source_config_path).await?;
    // Give the source a moment to bind its P2P listener.
    time::sleep(Duration::from_millis(100)).await;

    let follower = start_from_config_path(&follower_config_path).await?;

    // Both must converge at the same height (at least the source's pre-built tip)
    // and the same state_root.
    let snapshots = wait_for_cluster_convergence(&[&source, &follower], 3, Duration::from_secs(15))
        .await
        .context("nodes did not converge after snapshot cold-start")?;

    assert!(
        snapshots.iter().all(|s| s.last_sync_error.is_none()),
        "no sync errors expected after cold-start convergence: {:?}",
        snapshots
            .iter()
            .map(|s| &s.last_sync_error)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        snapshots[0].state_root, snapshots[1].state_root,
        "source and follower must agree on state_root after snapshot cold-start"
    );
    assert_eq!(
        snapshots[0].tip_hash, snapshots[1].tip_hash,
        "source and follower must agree on tip_hash after snapshot cold-start"
    );

    follower.shutdown().await?;
    source.shutdown().await?;
    Ok(())
}

/// A node that performed a snapshot cold-start must survive a restart and
/// continue syncing — verifying that `open_internal` correctly handles a
/// snapshot-bootstrapped store on subsequent opens.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_cold_start_survives_restart() -> Result<()> {
    let dir = TempDir::new("cold-restart");
    let source_data_dir = dir.path().join("source");
    let follower_data_dir = dir.path().join("follower");

    build_chain_with_checkpoint(&source_data_dir, 2, 1);

    let source_addr = reserve_local_addr();
    let follower_addr = reserve_local_addr();

    let source_config_path = dir.path().join("source.json");
    let follower_config_path = dir.path().join("follower.json");

    write_config(
        &source_config_path,
        &source_node_config(&source_data_dir, &source_addr),
    );
    write_config(
        &follower_config_path,
        &cold_start_follower_config(
            &follower_data_dir,
            &follower_addr,
            PeerConfig {
                node_id: "snap-source".to_owned(),
                p2p_addr: source_addr.clone(),
            },
            &source_addr,
        ),
    );

    let source = start_from_config_path(&source_config_path).await?;
    time::sleep(Duration::from_millis(100)).await;

    // First start: cold bootstrap from snapshot.
    let follower = start_from_config_path(&follower_config_path).await?;
    let initial = wait_for_cluster_convergence(&[&source, &follower], 2, Duration::from_secs(12))
        .await
        .context("initial convergence after cold-start failed")?;
    let _initial_root = initial[0].state_root.clone();
    let initial_height = initial[0].height;

    // Shut down follower, then restart it from its persisted state.
    follower.shutdown().await?;
    let follower2 = start_from_config_path(&follower_config_path).await?;

    // Both must converge again (at the same or higher height).
    let final_snapshots = wait_for_cluster_convergence(
        &[&source, &follower2],
        initial_height,
        Duration::from_secs(12),
    )
    .await
    .context("convergence after follower restart failed")?;

    assert_eq!(
        final_snapshots[0].state_root, final_snapshots[1].state_root,
        "source and restarted follower must agree on state_root"
    );
    assert!(
        final_snapshots[0].height >= initial_height,
        "height must not regress after restart"
    );

    follower2.shutdown().await?;
    source.shutdown().await?;
    Ok(())
}

// ── Phase 8 M1 — libp2p cold-start via /viper/<chain>/snapshot/1.0.0 ──

/// Build a single-node source config with libp2p enabled on a fixed
/// validator-listen port. Mirrors `source_node_config` but flips the
/// libp2p master switch + n=2 mesh tuning so a single follower peer
/// stabilises the gossipsub mesh without additional nodes.
fn source_node_libp2p_config(
    data_dir: &Path,
    p2p_listen_addr: &str,
    libp2p_listen_addr: &str,
) -> NodeConfig {
    NodeConfig {
        node_id: "snap-source-libp2p".to_owned(),
        data_dir: data_dir.to_path_buf(),
        chain_id_hex: String::new(),
        anchor_prev_hash_hex: hex::encode(ANCHOR_PREV_HASH),
        fee_params: FeeParams::default(),
        p2p_listen_addr: Some(p2p_listen_addr.to_owned()),
        api_listen_addr: None,
        peers: Vec::new(),
        devnet: DevnetConfig {
            role: NodeRole::SingleNode,
            sync_interval_ms: 50,
            block_time_ms: 500,
            proposer_address_hex: None,
            quorum_threshold: None,
            validators: Vec::new(),
            snapshot_source: None,
            ..Default::default()
        },
        genesis_accounts: Vec::new(),
        rate_limit: Default::default(),
        libp2p: Some(Libp2pConfig {
            enable: true,
            validator_listen: Some(libp2p_listen_addr.to_owned()),
            vfn_listen: None,
            public_listen: None,
            bootstrap_peers: Vec::new(),
            gossip_mesh_n: Some(1),
            gossip_mesh_n_low: Some(1),
            gossip_mesh_n_high: Some(2),
            // Force TCP only on loopback — QUIC needs an IP stack that
            // tolerates the loopback mtu and reserve-port collisions
            // are less common on TCP.
            quic_enabled: Some(false),
            tcp_tls_fallback: Some(true),
            max_peers_per_asn: Some(8),
            validator_peer_ids: Vec::new(),
        }),
        sender_budget: Default::default(),
        api: Default::default(),
    }
}

/// Follower config with libp2p enabled and the source's deterministic
/// PeerId pinned in `bootstrap_peers`. Critically `snapshot_source`
/// stays `None` so the three-way cold-start gate takes the libp2p
/// branch (TASK-135 step 13 / snapshot cold-start refactor).
fn cold_start_follower_libp2p_config(
    data_dir: &Path,
    p2p_listen_addr: &str,
    libp2p_listen_addr: &str,
    bootstrap_multiaddr: String,
) -> NodeConfig {
    NodeConfig {
        node_id: "snap-follower-libp2p".to_owned(),
        data_dir: data_dir.to_path_buf(),
        chain_id_hex: String::new(),
        anchor_prev_hash_hex: hex::encode(ANCHOR_PREV_HASH),
        fee_params: FeeParams::default(),
        p2p_listen_addr: Some(p2p_listen_addr.to_owned()),
        api_listen_addr: None,
        peers: Vec::new(),
        devnet: DevnetConfig {
            role: NodeRole::SingleNode,
            sync_interval_ms: 50,
            block_time_ms: 500,
            proposer_address_hex: None,
            quorum_threshold: None,
            validators: Vec::new(),
            snapshot_source: None,
            ..Default::default()
        },
        genesis_accounts: Vec::new(),
        rate_limit: Default::default(),
        libp2p: Some(Libp2pConfig {
            enable: true,
            validator_listen: Some(libp2p_listen_addr.to_owned()),
            vfn_listen: None,
            public_listen: None,
            bootstrap_peers: vec![bootstrap_multiaddr],
            gossip_mesh_n: Some(1),
            gossip_mesh_n_low: Some(1),
            gossip_mesh_n_high: Some(2),
            quic_enabled: Some(false),
            tcp_tls_fallback: Some(true),
            max_peers_per_asn: Some(8),
            validator_peer_ids: Vec::new(),
        }),
        sender_budget: Default::default(),
        api: Default::default(),
    }
}

fn reserve_libp2p_addr() -> String {
    // Same reserve-port trick as reserve_local_addr (bind + drop to
    // race-free reserve) but returns in `<ip>:<port>` form that
    // Libp2pConfig.validator_listen parses via `SocketAddr::parse`.
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    format!("127.0.0.1:{port}")
}

/// TASK-135 / Phase 8 M1 — A follower booting with `libp2p.enable=true`
/// and a single bootstrap peer MUST cold-start by fetching the
/// trusted checkpoint over `/viper/<chain>/snapshot/1.0.0`, NOT over
/// the Phase 6 HTTP endpoint. This test drives the libp2p branch of
/// the three-way cold-start gate end-to-end against a real pqcd source
/// with a real RocksDB chain store, catching any regression in the
/// build_devnet_node reordering (libp2p must start before the
/// cold-start check) or in `cold_start_from_libp2p_snapshot` itself.
///
/// Scope: ingest-through-snapshot only. We assert the follower reached
/// the source's checkpoint height (1 — the pre-built checkpoint) and
/// that `snapshot_source` was NOT needed (libp2p branch taken). Full
/// tail catch-up (heights 2+) depends on gossipsub mesh formation
/// timing and is covered operationally by the TASK-144 3-node soak
/// rather than a flaky CI assertion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn libp2p_snapshot_cold_start_applies_checkpoint() -> Result<()> {
    let dir = TempDir::new("libp2p-cold-start");
    let source_data_dir = dir.path().join("source");
    let follower_data_dir = dir.path().join("follower");

    // 3 blocks with a checkpoint at height 1 — matches the HTTP
    // `snapshot_cold_start_network` scenario for parity.
    build_chain_with_checkpoint(&source_data_dir, 3, 1);

    let source_p2p_addr = reserve_local_addr();
    let source_libp2p_addr = reserve_libp2p_addr();
    let follower_p2p_addr = reserve_local_addr();
    let follower_libp2p_addr = reserve_libp2p_addr();

    // Compute the source's deterministic PeerId ahead of its boot so
    // the follower's config can pin the bootstrap multiaddr. Mirrors
    // the SHA3-256 domain-separated derivation inside pqcd::p2p.
    let source_peer_id = pqcd::p2p::deterministic_peer_id("snap-source-libp2p", None);
    let bootstrap_ma = format!(
        "/ip4/127.0.0.1/tcp/{}/p2p/{}",
        source_libp2p_addr.rsplit(':').next().expect("port suffix"),
        source_peer_id
    );

    let source_config_path = dir.path().join("source-libp2p.json");
    let follower_config_path = dir.path().join("follower-libp2p.json");

    write_config(
        &source_config_path,
        &source_node_libp2p_config(&source_data_dir, &source_p2p_addr, &source_libp2p_addr),
    );
    write_config(
        &follower_config_path,
        &cold_start_follower_libp2p_config(
            &follower_data_dir,
            &follower_p2p_addr,
            &follower_libp2p_addr,
            bootstrap_ma,
        ),
    );

    // Source first so its libp2p listener is up when the follower dials.
    let source = start_from_config_path(&source_config_path).await?;
    // Small grace window: libp2p's listen-address binding is async
    // inside the driver task; 300 ms is empirically enough on loopback.
    time::sleep(Duration::from_millis(300)).await;

    // Follower boot drives `cold_start_from_libp2p_snapshot` to
    // completion before returning, so by the time this await resolves
    // the checkpoint has already been written to disk (or the libp2p
    // path bailed and we fell through to genesis — either way
    // start_from_config_path returns Ok).
    let follower = start_from_config_path(&follower_config_path).await?;

    let snap = follower.snapshot().await;
    assert!(
        snap.height >= 1,
        "follower did not apply the libp2p snapshot — height {} < 1 (pre-built checkpoint height)",
        snap.height
    );

    follower.shutdown().await?;
    source.shutdown().await?;
    Ok(())
}
