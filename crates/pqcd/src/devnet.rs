// SPDX-License-Identifier: BUSL-1.1
//! pqcd devnet runtime — block production, gossip, REST API.
//!
//! # Panic strategy (CONCERNS A4 + A7)
//!
//! Two classes of `expect()` appear throughout this module by design:
//!
//! 1. **`expect("keystore RwLock poisoned …")`** — the keystore is held
//!    behind `std::sync::RwLock`. Poison means another thread panicked
//!    while holding the write lock; we cannot prove the lock-protected
//!    state is consistent. Continuing risks signing a precommit with
//!    half-applied keystore mutations, which would either generate an
//!    invalid signature (peers reject) or — worse — equivocate against
//!    a previous round (slashing risk). Crashing and letting the
//!    supervisor (`systemd Restart=on-failure`, k8s `restartPolicy`)
//!    rebuild the state from disk is the safe failure mode.
//!
//! 2. **`expect("StateStore yields a valid CommitQuorumPolicy …")`** —
//!    `CommitQuorumPolicy::from_state_store` is a pure projection of
//!    the validator set already validated at block-apply time (every
//!    `pk_hex` decoded, every `sig_alg_id` checked, no duplicate
//!    addresses). A failure here means the state store is corrupt or
//!    a downstream invariant broke; producing a block under a corrupt
//!    quorum policy could finalise an unsigned block.
//!
//! Both classes are unrecoverable in the consensus hot path. The doc
//! is a single-source-of-truth so we don't repeat the rationale at
//! every call site (~12 of them); the inline `expect()` message names
//! the invariant, this comment explains the WHY.

use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context, Result};
use axum::{
    extract::{ConnectInfo, Path as AxumPath, State},
    http::{header, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use pqc_consensus::{
    replay_blocks_from_state, select_proposer, AssemblyConfig, CommitQuorumPolicy, EpochConfig,
    LocalProposer, LocalProposerConfig, RecoverySource, RocksDbChainStore, StoredBlock,
};
use pqc_crypto::{
    kem_encapsulate, ml_dsa_public_key_from_seed, ml_dsa_sign_with_seed, shake256_32,
    sign::SignatureVerifier, AlgId, PqVerifier, KEM_CT_LEN, KEM_PK_LEN,
};
use pqc_mempool::{admission::try_admit, error::MempoolError, Mempool};
use pqc_state::StateStore;
use pqc_tx::validate::FeeParams;
use pqc_tx::{codec::decode_tx, TxError};
use pqc_types::{
    account::Address,
    block::{BlockHash, CommitSig},
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::{
    net::TcpListener,
    sync::{watch, Mutex},
    task::JoinHandle,
    time::{self, MissedTickBehavior},
};

use crate::keystore::Keystore;
use crate::node::{
    build_commit_quorum_policy, build_genesis_state, decode_hex_array, decode_hex_bytes,
    load_node_config, open_disk_store_from_config, NodeConfig, PeerConfig, RateLimitConfig,
    SenderBudgetConfig, ValidatorConfig,
};

/// Write a trusted checkpoint every this many committed blocks.
/// On the next startup, only blocks after the checkpoint height are loaded into the
/// in-memory ChainStore, bounding RSS to roughly CHECKPOINT_INTERVAL × ~6 KB per block.
const CHECKPOINT_INTERVAL: u64 = 1_000;

type SharedLiveNodeState = Arc<Mutex<LiveNodeState>>;

pub struct DevnetNodeHandle {
    config_path: PathBuf,
    state: SharedLiveNodeState,
    shutdown_tx: watch::Sender<bool>,
    tasks: Vec<JoinHandle<Result<()>>>,
    /// Resolved public API address if `api_listen_addr` was set in the config.
    /// Useful in tests to discover the actual bound port when `:0` is used.
    pub api_addr: Option<std::net::SocketAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevnetNodeSnapshot {
    pub node_id: String,
    pub height: u64,
    pub tip_hash: BlockHash,
    pub state_root: BlockHash,
    pub recovery_source: RecoverySource,
    pub peer_count: usize,
    pub last_sync_error: Option<String>,
}

struct LiveNodeState {
    config: NodeConfig,
    fee_params: FeeParams,
    /// All active validator addresses used for block-fee pool distribution.
    /// Derived from `config.devnet.validators` at startup; updated when the
    /// on-chain validator set changes (TASK-049 Phase 3 groundwork).
    validator_pool: Vec<pqc_types::account::Address>,
    recovery_source: RecoverySource,
    state: StateStore,
    mempool: Mempool,
    disk: RocksDbChainStore,
    proposer: Option<LocalProposer>,
    /// D-06: per-validator signing material, queried per-block by the
    /// producer/consensus loops against the currently-Active validator
    /// set (which grows dynamically via `ValidatorRegister`). Replaces
    /// the fixed-at-startup `Vec<LocalCommitSigner>` that was the
    /// TASK-156 Step 6 / TASK-151 blocker. A missing entry for an Active
    /// validator means the producer skips signing for that validator on
    /// this round — see `pqcd::keystore` for the full contract.
    keystore: Arc<std::sync::RwLock<Keystore>>,
    last_sync_error: Option<String>,
    /// Verifier used for mempool admission. `MlDsaVerifier` in production;
    /// `StubVerifier` may be injected via tests that use pre-signed test txs.
    verifier: std::sync::Arc<dyn SignatureVerifier + Send + Sync>,
    /// ML-KEM-768 long-term identity-keypair material for the devnet HTTP
    /// P2P session-bootstrap channel (`GET /internal/p2p/kem-pubkey` +
    /// `POST /internal/p2p/session`).
    ///
    /// Wraps the active keypair AND optionally a one-epoch-stale keypair
    /// retained for the grace window across an epoch boundary. See
    /// `KemKeyset` doc for the rotation semantics — closes Gap B from
    /// the private design notes. The `KemSeed` inside
    /// each `KemKeyMaterial` is `ZeroizeOnDrop`; a rotation that drops
    /// the previous slot also wipes the seed bytes.
    kem_keyset: KemKeyset,
    /// Decoded 32-byte ML-KEM seed salt from `devnet.kem_seed_salt_hex`,
    /// cached at startup so the per-epoch rotation hook can re-derive
    /// without re-parsing hex on every boundary. `None` when the legacy
    /// no-salt back-compat path is in effect — every rotation under the
    /// legacy path remains a `node_id`-only derivation, matching the
    /// pre-fix behaviour for nodes that have not yet run
    /// `pqcd wallet kem-init`.
    kem_secret_salt: Option<[u8; 32]>,
    /// Active P2P sessions: session_id → shared secret (32 bytes).
    p2p_sessions: HashMap<String, [u8; 32]>,
    /// Application-side handle to the libp2p Swarm driver (Phase 8 M1).
    /// `None` when libp2p is disabled in config — consensus/block/tx
    /// emit paths MUST tolerate this via `p2p::publish_if_enabled`.
    p2p_handle: Option<pqc_p2p::SwarmHandle>,
    // ── Per-IP rate limiter for POST /v1/txs ────────────────────────────────
    /// Request counts per source IP within the current window.
    /// Entry: (count_in_window, window_start).
    ip_rate_limiter: HashMap<IpAddr, (u32, Instant)>,
    rate_limit: RateLimitConfig,
    // ── Per-sender admission budget ──────────────────────────────────────────
    /// Admitted tx counts per sender address within the current window.
    /// Only transactions that pass the full admission pipeline consume budget.
    /// Entry: (count_in_window, window_start).
    sender_admit_budget: HashMap<Address, (u32, Instant)>,
    sender_budget: SenderBudgetConfig,
    // ── Observability counters (monotonically increasing since node start) ────
    blocks_produced: u64,
    blocks_imported: u64,
    txs_admitted: u64,
    txs_rejected: u64,
    /// Per-reason breakdown of `txs_rejected`. Keys are the stable labels
    /// returned by `mempool_error_code(...)` plus the literal
    /// `"SENDER_RATE_LIMITED"` used by the per-sender budget gate (which
    /// fires before `try_admit`, so there is no `MempoolError` to map).
    /// The sum of the values equals `txs_rejected`. Exposed at
    /// `/v1/metrics` as `pqchain_txs_rejected_by_reason_total{reason="..."}`.
    txs_rejected_by_reason: HashMap<&'static str, u64>,
    peer_sync_errors: u64,
    /// UNIX timestamp (seconds) when this node process started.
    node_start_unix_secs: u64,
    /// Precommit vote buffer for distributed_signing mode — keyed by
    /// `(height, block_hash)` → `(validator_address → SignedVote)`.
    ///
    /// Populated by `handle_inbound_precommit` on every libp2p
    /// ConsensusVote Precommit received. Drained by the producer/
    /// consensus loop when it is the proposer, to assemble the final
    /// `commit_signatures` set before persistence. Entries for heights
    /// at or below the current tip are evicted on insert to keep the
    /// map bounded at O(active_validators × in-flight_rounds).
    pending_precommits: HashMap<(u64, BlockHash), HashMap<[u8; 32], pqc_types::SignedVote>>,
    /// Dedup set for own-precommit emissions — `(height, block_hash,
    /// validator_address)` tuples this node has already signed+gossiped
    /// as Precommits.
    ///
    /// Used by the non-proposer `handle_inbound_block` branch (TASK-167
    /// Step 3) so a node that receives the same proposal block twice
    /// from different peers does not re-sign and re-gossip. Cleared on
    /// block commit at that height (the key is effectively a
    /// height-scoped resource that can be compacted once the height is
    /// finalized).
    own_precommits_emitted: std::collections::HashSet<(u64, BlockHash, [u8; 32])>,
    /// ADR-054 §Stage 4 — orphan-block buffer. Holds blocks whose
    /// parent is unknown locally; populated by the Stage-4 dispatch
    /// for `OrphanFutureChild` candidates and drained once the parent
    /// arrives via the `block-fetch-by-hash/1.0.0` request-response
    /// protocol or the height-ranged catch-up. Bounded by capacity +
    /// TTL so a misbehaving peer cannot grow it without limit.
    orphan_cache: pqc_consensus::BlockTreeCache,
    /// TASK-187 — sliding window of `(scrape_instant, chain_data_bytes)`
    /// samples used to compute `pqchain_chain_growth_rate_bytes_per_hour`
    /// at scrape time. Bounded to roughly the last 65 minutes (samples
    /// older than the cutoff are popped from the front on every scrape)
    /// so the structure is O(1) memory regardless of process uptime —
    /// at a 30-s scrape interval the deque holds ~130 entries (each
    /// `(Instant, u64)` ≈ 24 B → < 4 KB total). Empty until the first
    /// `/v1/metrics` scrape.
    chain_size_samples: VecDeque<(Instant, u64)>,
}

/// ADR-054 §Stage 4 — outcome of a single `import_remote_block` call.
///
/// Async callers map this to the action they take next: dispatch a
/// by-hash fetch for the missing parent, drain the orphan cache after
/// a successful link, or just log and move on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ImportOutcome {
    /// Block was applied (LinkAtTip) or atomically swapped
    /// (state-equivalent SiblingAtTip).
    Imported,
    /// Block hash was already on the local chain at the same height —
    /// idempotent ok, no state change.
    Duplicate,
    /// Block could not link directly: its parent is unknown locally.
    /// Caller MUST dispatch `BlockFetchByHashRequest { hash: parent_hash }`
    /// to a peer (typically the source of the orphaned block) so the
    /// parent can be retrieved and the child unblocked.
    OrphanedNeedsParent { parent_hash: BlockHash },
}

/// Per-peer KEM-authenticated P2P session maintained by the follower sync loop.
struct PeerSession {
    session_id: String,
    shared_secret: [u8; 32],
}

mod kem_session;
use kem_session::{derive_kem_keypair, KemKeyset};

#[derive(Clone)]
struct LocalCommitSigner {
    validator_address: Vec<u8>,
    sig_alg_id: AlgId,
    commit_seed: [u8; 32],
}

// HSM phase-plan integration — `LocalCommitSigner` doubles as the
// concrete trait object for the in-process commit-signing path.
// `snapshot_block_signers_dyn` (defined alongside `snapshot_block_signers`)
// returns these as `Box<dyn CommitSigner>` so future SoftHSM /
// CloudHSM signers slot into the same call sites.
//
// The pre-existing concrete-`Vec<LocalCommitSigner>` call sites remain
// in this commit (they touch `commit_seed` directly to drive the p2p
// precommit `build_signed_precommit` path); migrating those is the
// next phase once `pqc_p2p::build_signed_precommit` is itself migrated
// to `&dyn CommitSigner`. See the private design notes
// and `crates/pqc-hsm/src/lib.rs`.
impl pqc_hsm::CommitSigner for LocalCommitSigner {
    fn validator_address(&self) -> &[u8] {
        &self.validator_address
    }

    fn public_key(&self) -> &[u8] {
        // The view struct mirrors the pre-trait shape kept for
        // back-compat and does NOT cache a pubkey. Callers needing the
        // pubkey go through the `pqc-hsm::LocalKeystoreSigner` (which
        // caches it) or look it up in the keystore. The trait surface
        // returns an empty slice here so the trait remains
        // object-safe.
        &[]
    }

    fn sign_commit(&self, preimage: &[u8]) -> Result<Vec<u8>, pqc_hsm::SignerError> {
        ml_dsa_sign_with_seed(self.sig_alg_id, &self.commit_seed, preimage).map_err(|e| {
            pqc_hsm::SignerError::Other(anyhow!("ML-DSA commit signing failed: {e:?}"))
        })
    }

    fn alg_id(&self) -> AlgId {
        self.sig_alg_id
    }

    fn kind(&self) -> pqc_hsm::SignerKind {
        pqc_hsm::SignerKind::LocalKeystore
    }

    fn self_test(&self) -> Result<(), pqc_hsm::SignerError> {
        // The trait's default `self_test` verifies via `MlDsaVerifier`
        // against `public_key()`. The view struct returns an empty
        // slice for `public_key()` (see above), so the default would
        // fail. Boot-time canary self-test runs against
        // `pqc-hsm::LocalKeystoreSigner` instead — that impl caches
        // the pubkey end-to-end. This view's self-test is a no-op.
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PeerStatusResponse {
    node_id: String,
    height: u64,
    tip_hash: String,
    state_root: String,
}

struct DevnetHttpError(StatusCode, String);

impl IntoResponse for DevnetHttpError {
    fn into_response(self) -> Response {
        (self.0, self.1).into_response()
    }
}

impl DevnetNodeHandle {
    pub async fn snapshot(&self) -> DevnetNodeSnapshot {
        let guard = self.state.lock().await;
        guard.snapshot()
    }

    /// Submit a raw-encoded transaction to the node's mempool.
    ///
    /// Signature verification uses the verifier wired at node construction
    /// (`MlDsaVerifier` in production, injectable in tests). Commit signatures
    /// use real ML-DSA-65 independently of this setting.
    ///
    /// Returns an error if the transaction is malformed, a duplicate, or fails
    /// the mempool admission pipeline (e.g. sender not found, invalid signature,
    /// insufficient fee).
    pub async fn inject_tx(&self, raw_tx: Vec<u8>) -> Result<()> {
        // Clone upfront so we can gossip the exact wire bytes after
        // admission. Cheap: tx envelopes are typically < 2 KB.
        let raw_tx_for_gossip = raw_tx.clone();
        let mut guard = self.state.lock().await;

        // Structural decode (no crypto) to extract sender for budget check.
        let maybe_sender = decode_tx(&raw_tx).ok().map(|tx| tx.sender);

        // Per-sender admission budget — checked before expensive sig verify.
        if let Some(ref sender) = maybe_sender {
            if guard.check_sender_budget(sender) {
                guard.record_rejection("SENDER_RATE_LIMITED");
                bail!(
                    "per-sender admission budget exhausted for this window \
                     (SPEC-FEE-001 §10.1)"
                );
            }
        }

        let verifier = guard.verifier.clone();
        let result = {
            let LiveNodeState {
                state,
                mempool,
                fee_params,
                ..
            } = &mut *guard;
            try_admit(mempool, raw_tx, state, verifier.as_ref(), fee_params)
        };
        // Capture emit inputs while the lock is held; publish after drop.
        let emit_inputs = match &result {
            Ok(_) => {
                guard.txs_admitted += 1;
                // Only admitted txs consume sender budget.
                if let Some(sender) = maybe_sender {
                    guard.record_sender_admission(&sender);
                }
                Some((guard.p2p_handle.clone(), guard.config.chain_id_hex.clone()))
            }
            Err(err) => {
                let (reason, _) = mempool_error_code(err);
                guard.record_rejection(reason);
                None
            }
        };
        drop(guard);
        if let Some((handle, chain_id)) = emit_inputs {
            let envelope = crate::p2p::tx_envelope(&chain_id, raw_tx_for_gossip);
            crate::p2p::publish_if_enabled(handle.as_ref(), envelope).await;
        }
        result.context("transaction injection failed")?;
        Ok(())
    }

    /// Return the number of commit signatures on the current chain tip block.
    /// Returns `None` if the chain has no committed blocks yet.
    pub async fn tip_commit_sig_count(&self) -> Option<usize> {
        let guard = self.state.lock().await;
        guard
            .disk
            .chain()
            .tip()
            .map(|stored| stored.block.commit_signatures.len())
    }

    /// Return the balance of an account in the live state, or `None` if not found.
    pub async fn account_balance(&self, address: &pqc_types::account::Address) -> Option<u128> {
        let guard = self.state.lock().await;
        guard.state.get_account(address).map(|a| a.balance)
    }

    /// Return a cloned account from the live state, or `None` if not found.
    ///
    /// Used by integration tests to inspect key lifecycle state without going
    /// through the HTTP API.
    pub async fn get_account(
        &self,
        address: &pqc_types::account::Address,
    ) -> Option<pqc_types::account::Account> {
        let guard = self.state.lock().await;
        guard.state.get_account(address).cloned()
    }

    /// Return the current mempool depth (number of pending transactions).
    pub async fn mempool_depth(&self) -> usize {
        let guard = self.state.lock().await;
        guard.mempool.len()
    }

    /// Return the total number of transactions admitted since node start.
    pub async fn txs_admitted_count(&self) -> u64 {
        let guard = self.state.lock().await;
        guard.txs_admitted
    }

    /// Return the number of accounts in the live state (for diagnostics).
    pub async fn account_count(&self) -> usize {
        let guard = self.state.lock().await;
        guard.state.accounts_in_order().len()
    }

    /// Return all account addresses in the live state (for diagnostics).
    pub async fn all_account_addresses(&self) -> Vec<pqc_types::account::Address> {
        let guard = self.state.lock().await;
        guard
            .state
            .accounts_in_order()
            .iter()
            .map(|a| a.address.clone())
            .collect()
    }

    /// Return the operator addresses of all currently-Active validators
    /// in this node's view of chain state. Sorted by operator address
    /// (the deterministic order `StateStore::active_validators()` pins).
    ///
    /// Phase 8 M2 (TASK-113) introduced state-driven validator-set
    /// dynamics — this accessor lets integration tests assert on
    /// validator join / leave / churn scenarios directly against the
    /// node's live view, without polling the HTTP API or parsing
    /// metrics.
    pub async fn active_validator_addresses(&self) -> Vec<pqc_types::account::Address> {
        let guard = self.state.lock().await;
        guard
            .state
            .active_validators()
            .iter()
            .map(|v| v.operator.clone())
            .collect()
    }

    /// Return the number of included transactions in the latest committed block (for diagnostics).
    pub async fn tip_included_count(&self) -> usize {
        let guard = self.state.lock().await;
        guard
            .disk
            .chain()
            .tip()
            .map(|s| s.metadata.included_count)
            .unwrap_or(0)
    }

    /// Return true if an `ArchivalRecord` exists in state for `epoch_number`.
    ///
    /// M4.4 / TASK-163 acceptance probe: lets integration tests assert that
    /// the epoch-boundary archival hook landed a record without reaching
    /// into the store directly.
    pub async fn has_archival_record_for_epoch(&self, epoch_number: u64) -> bool {
        let guard = self.state.lock().await;
        guard.state.get_archival_record(epoch_number).is_some()
    }

    /// Return the archival signer addresses for `epoch_number`, if a record
    /// has landed; `None` when none has been submitted yet.
    pub async fn archival_record_signers(&self, epoch_number: u64) -> Option<Vec<[u8; 32]>> {
        let guard = self.state.lock().await;
        guard
            .state
            .get_archival_record(epoch_number)
            .map(|r| r.signer_addresses.clone())
    }

    /// Return the proposer address from the block at `height`, or `None` if not found.
    ///
    /// Used by BFT consensus tests (TASK-085) to verify proposer rotation: each
    /// committed block header carries the validator address selected by
    /// `select_proposer(validators, height, round)`.
    pub async fn block_proposer_at(&self, height: u64) -> Option<Vec<u8>> {
        let guard = self.state.lock().await;
        guard
            .disk
            .chain()
            .get_block_by_height(height)
            .map(|block| block.header.proposer.clone())
    }

    /// Return true if an attestation with the given id exists in the live state.
    pub async fn attestation_exists(&self, id: &pqc_types::attestation::AttestationId) -> bool {
        let guard = self.state.lock().await;
        guard.state.get_attestation(id).is_some()
    }

    /// Return the status of an attestation, or `None` if it does not exist.
    pub async fn attestation_status(
        &self,
        id: &pqc_types::attestation::AttestationId,
    ) -> Option<pqc_types::attestation::AttestationStatus> {
        let guard = self.state.lock().await;
        guard.state.get_attestation(id).map(|a| a.status)
    }

    /// Return the current lifecycle state of an algorithm in the registry, or `None`
    /// if the algorithm id is not known.
    pub async fn alg_lifecycle(&self, alg_id: pqc_crypto::AlgId) -> Option<pqc_crypto::Lifecycle> {
        let guard = self.state.lock().await;
        guard.state.alg_entry(alg_id).map(|e| e.lifecycle)
    }

    /// Return a cloned proof anchor record for the given anchor id, or `None`.
    pub async fn proof_anchor_record(
        &self,
        id: &pqc_types::proof_anchor::AnchorId,
    ) -> Option<pqc_types::proof_anchor::ProofAnchor> {
        let guard = self.state.lock().await;
        guard.state.get_proof_anchor(id).cloned()
    }

    /// Return the tip hash after waiting for all pending blocks at the current
    /// mempool depth to be committed. Waits for height to advance by at least
    /// `min_height_advance` from the current height, or times out.
    pub async fn wait_for_height_advance(
        &self,
        min_height_advance: u64,
        timeout: Duration,
    ) -> Result<DevnetNodeSnapshot> {
        let base_height = self.snapshot().await.height;
        self.wait_for_height(base_height + min_height_advance, timeout)
            .await
    }

    pub async fn wait_for_height(
        &self,
        target_height: u64,
        timeout: Duration,
    ) -> Result<DevnetNodeSnapshot> {
        let deadline = time::Instant::now() + timeout;
        loop {
            let snapshot = self.snapshot().await;
            if snapshot.height >= target_height {
                return Ok(snapshot);
            }

            if time::Instant::now() >= deadline {
                bail!(
                    "timed out waiting for node {} to reach height {} (current {})",
                    snapshot.node_id,
                    target_height,
                    snapshot.height
                );
            }

            time::sleep(Duration::from_millis(25)).await;
        }
    }

    pub async fn shutdown(self) -> Result<()> {
        let _ = self.shutdown_tx.send(true);
        for task in self.tasks {
            task.await.context("devnet task join failed")??;
        }
        Ok(())
    }

    pub fn config_path(&self) -> &Path {
        &self.config_path
    }
}

impl LiveNodeState {
    /// Check and record a tx submission request from `ip`.
    ///
    /// Returns `true` (rate limited — caller must return 429) if the source IP has
    /// exceeded `rate_limit.max_requests_per_window` requests within the rolling
    /// `rate_limit.window_secs` window. Returns `false` if the request is allowed.
    ///
    /// If `max_requests_per_window == 0`, rate limiting is disabled and this
    /// function always returns `false`.
    fn check_and_record_ip_request(&mut self, ip: IpAddr) -> bool {
        let max = self.rate_limit.max_requests_per_window;
        if max == 0 {
            return false; // rate limiting disabled
        }
        let window = Duration::from_secs(self.rate_limit.window_secs);
        let now = Instant::now();
        let entry = self.ip_rate_limiter.entry(ip).or_insert((0, now));
        // Reset the window if it has expired.
        if now.duration_since(entry.1) >= window {
            *entry = (0, now);
        }
        entry.0 += 1;
        entry.0 > max
    }

    /// Check whether `sender` has exhausted their per-window admission budget.
    ///
    /// Returns `true` (budget exceeded — caller must reject) if the sender has
    /// reached `sender_budget.max_txs_per_window` admitted txs within the current
    /// rolling window. Returns `false` if the sender may proceed.
    ///
    /// Read-only: does NOT update the budget map. Call `record_sender_admission`
    /// after a successful `try_admit` to update the count.
    ///
    /// If `max_txs_per_window == 0`, per-sender budget is disabled and this
    /// function always returns `false`.
    fn check_sender_budget(&self, sender: &Address) -> bool {
        let max = self.sender_budget.max_txs_per_window;
        if max == 0 {
            return false; // per-sender budget disabled
        }
        let window = Duration::from_secs(self.sender_budget.window_secs);
        let now = Instant::now();
        if let Some(&(count, window_start)) = self.sender_admit_budget.get(sender) {
            // If the window has not expired, check against the cap.
            if now.duration_since(window_start) < window {
                return count >= max;
            }
        }
        false
    }

    /// Record a successful admission for `sender`.
    ///
    /// Must only be called after a tx from `sender` successfully passes the full
    /// mempool admission pipeline (`try_admit` returned `Ok`). Rejected txs must
    /// NOT call this — only admitted transactions consume sender budget.
    fn record_sender_admission(&mut self, sender: &Address) {
        let max = self.sender_budget.max_txs_per_window;
        if max == 0 {
            return; // per-sender budget disabled — nothing to track
        }
        let window = Duration::from_secs(self.sender_budget.window_secs);
        let now = Instant::now();
        let entry = self
            .sender_admit_budget
            .entry(sender.clone())
            .or_insert((0, now));
        if now.duration_since(entry.1) >= window {
            // Window expired: start a fresh window with count=1.
            *entry = (1, now);
        } else {
            entry.0 += 1;
        }
    }

    /// Increment the aggregate `txs_rejected` counter and the per-reason
    /// breakdown for `reason`. Reasons must come from `mempool_error_code`
    /// (so the labels stay aligned with the API error codes returned to
    /// clients) or be the literal `"SENDER_RATE_LIMITED"` used by the
    /// per-sender budget gate that fires before `try_admit`.
    fn record_rejection(&mut self, reason: &'static str) {
        self.txs_rejected += 1;
        *self.txs_rejected_by_reason.entry(reason).or_insert(0) += 1;
    }

    fn snapshot(&self) -> DevnetNodeSnapshot {
        let tip_hash = self
            .disk
            .tip_hash()
            .cloned()
            .unwrap_or_else(|| self.disk.chain().anchor_prev_hash().clone());
        let state_root = self
            .disk
            .chain()
            .tip()
            .map(|stored| stored.metadata.state_root.clone())
            .unwrap_or_else(|| BlockHash([0u8; 32]));

        DevnetNodeSnapshot {
            node_id: self.config.node_id.clone(),
            height: self.disk.height(),
            tip_hash,
            state_root,
            recovery_source: self.recovery_source,
            peer_count: self.config.peers.len(),
            last_sync_error: self.last_sync_error.clone(),
        }
    }

    /// ADR-054 §Stage 1-4 reception pipeline.
    ///
    /// The legacy implementation conflated structural validation, the
    /// quorum gate, tip linkage, and persistence into one open-coded
    /// flow that bailed on parent-hash mismatch — the exact failure
    /// mode that produced the 2026-04-25 follower-1 incident. This
    /// function now routes every inbound block through the four
    /// explicit stages defined in DECISIONS.md §ADR-054.
    ///
    /// Stage 1 (structural) is implicit in the type — `StoredBlock`
    /// can only be constructed via `decode_block_bytes`, which already
    /// runs hash-recompute and metadata-consistency checks; the
    /// classifier fires a final defense-in-depth check.
    /// Stage 2 (strict finality gate) runs at the storage boundary
    /// (`append_stored_block` / `replace_canonical_at_height`) when
    /// `policy_from_state` is `Some`.
    /// Stage 3 (classifier) is `pqc_consensus::classify_incoming_block`.
    /// Stage 4 (resolution dispatch) lives below. The returned
    /// [`ImportOutcome`] lets async callers dispatch a parent fetch
    /// for `OrphanedNeedsParent` outcomes (TASK-212 orphan-resolution
    /// loop) without `import_remote_block` itself becoming async.
    fn import_remote_block(&mut self, stored: StoredBlock) -> Result<ImportOutcome> {
        use pqc_consensus::{classify_incoming_block, BlockReceptionClass};

        let local_height = self.disk.height();
        let local_tip_meta = self
            .disk
            .chain()
            .tip_hash()
            .and_then(|h| self.disk.chain().get_metadata_by_hash(h))
            .cloned();

        // Take a snapshot of the height→metadata map for the heights
        // we actually need so the closure passed into the classifier
        // does not borrow `self.disk` (which we mutate later in the
        // sibling-swap branch).
        let candidate_height = stored.metadata.height;
        let canonical_at_candidate_height = self
            .disk
            .chain()
            .get_metadata_by_height(candidate_height)
            .cloned();

        let class = classify_incoming_block(&stored, local_height, local_tip_meta.as_ref(), |h| {
            if h == candidate_height {
                canonical_at_candidate_height.clone()
            } else {
                None
            }
        })
        .map_err(|e| anyhow::anyhow!("ADR-054 stage-1 classifier rejected: {e}"))?;

        match class {
            BlockReceptionClass::Duplicate => Ok(ImportOutcome::Duplicate),
            BlockReceptionClass::BelowFinalized => bail!(
                "ADR-054: refusing block at height {} below local tip {}",
                stored.metadata.height,
                local_height
            ),
            BlockReceptionClass::SiblingAtTip { local } => {
                self.resolve_sibling_at_tip(stored, local)?;
                Ok(ImportOutcome::Imported)
            }
            BlockReceptionClass::OrphanFutureChild => {
                // TASK-212: cache the child + signal the caller to
                // dispatch a by-hash fetch for the parent. Returning
                // Ok(OrphanedNeedsParent) means the caller does NOT
                // bail the batch — the key behavioural change vs.
                // the pre-ADR-054 path that aborted on first
                // parent-mismatch.
                let parent_hash = stored.metadata.prev_hash.clone();
                let candidate_hash = stored.metadata.block_hash.clone();
                let candidate_height = stored.metadata.height;
                self.orphan_cache.insert(stored);
                tracing::info!(
                    height = candidate_height,
                    candidate_hash = %hex::encode(candidate_hash.0),
                    parent_hash = %hex::encode(parent_hash.0),
                    cache_len = self.orphan_cache.len(),
                    "ADR-054 §Stage 4: buffered OrphanFutureChild — caller will fetch parent"
                );
                Ok(ImportOutcome::OrphanedNeedsParent { parent_hash })
            }
            BlockReceptionClass::LinkAtTip => {
                self.append_canonical_link_at_tip(stored)?;
                Ok(ImportOutcome::Imported)
            }
        }
    }

    /// ADR-054 §Stage 4 — drain `orphan_cache.children_of(parent)` and
    /// re-import each child. Recursive: a re-imported child may itself
    /// unlock a grandchild. Bounded because each iteration extends the
    /// chain by one and the cache is finite. Children that re-classify
    /// as `OrphanedNeedsParent` (because their grandparent is also
    /// missing) emit a fetch-needed list the caller dispatches.
    fn drain_orphan_children(&mut self, parent_hash: &BlockHash) -> Vec<BlockHash> {
        let mut needs_fetch: Vec<BlockHash> = Vec::new();
        // Collect first so we don't borrow the cache while mutating
        // self via import_remote_block.
        let children: Vec<StoredBlock> = self
            .orphan_cache
            .children_of(parent_hash)
            .into_iter()
            .cloned()
            .collect();
        for child in children {
            let child_hash = child.metadata.block_hash.clone();
            // Best-effort remove; if the child has aged out it's
            // already gone.
            self.orphan_cache.remove(&child_hash);
            match self.import_remote_block(child) {
                Ok(ImportOutcome::Imported) => {
                    tracing::info!(
                        child_hash = %hex::encode(child_hash.0),
                        "ADR-054 §Stage 4: orphan child resolved via parent arrival"
                    );
                }
                Ok(ImportOutcome::Duplicate) => {
                    // Already handled — silently OK.
                }
                Ok(ImportOutcome::OrphanedNeedsParent { parent_hash }) => {
                    needs_fetch.push(parent_hash);
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        child_hash = %hex::encode(child_hash.0),
                        "ADR-054 §Stage 4: orphan child re-import failed"
                    );
                }
            }
        }
        needs_fetch
    }

    /// ADR-054 §Stage 4 (LinkAtTip) — the historical happy path.
    fn append_canonical_link_at_tip(&mut self, stored: StoredBlock) -> Result<()> {
        let prev_hash = self
            .disk
            .tip_hash()
            .cloned()
            .unwrap_or_else(|| self.disk.chain().anchor_prev_hash().clone());
        let replay = replay_blocks_from_state(
            &self.state,
            &prev_hash,
            std::slice::from_ref(&stored),
            self.fee_params.clone(),
            Default::default(),
            self.validator_pool.clone(),
        )
        .context("remote block replay failed")?;

        let imported_height = stored.metadata.height;
        let imported_hash = hex::encode(stored.metadata.block_hash.0);
        // Phase 8 M2 (TASK-113): derive commit-quorum policy from the
        // PRE-block state — `self.state` still reflects the state
        // before we assign `replay.state` below, which is exactly the
        // set the remote peer used when it signed this block's commit
        // proof. Passing `None` on an isolated-test path where the
        // state has no validators yet is safe (the append skips quorum
        // validation — block-inherent hash + parent checks still run).
        let policy_from_state = CommitQuorumPolicy::from_state_store(&self.state, None)
            .expect("StateStore yields a valid CommitQuorumPolicy (M2 invariant)");
        // ADR-051: flip the verifier into Distributed mode when the node's
        // config opts into multi-node BFT. The signing side of this path
        // uses the same §8.4 Precommit preimage (see producer_loop /
        // consensus_loop phase 2 branches when distributed_signing=true).
        let policy_from_state = policy_from_state.map(|p| {
            if self.config.devnet.distributed_signing {
                p.with_distributed_preimage(0)
            } else {
                p
            }
        });
        let imported_block_hash = stored.metadata.block_hash.clone();
        self.disk
            .append_stored_block(stored, policy_from_state.as_ref())
            .context("persisting remote block failed")?;
        self.state = replay.state;
        self.last_sync_error = None;
        self.blocks_imported += 1;
        // ADR-051 / TASK-170 fix: sync LocalProposer's internal tip_hash
        // to the imported block. Without this, the next round when this
        // node is elected proposer would build a block whose `prev_hash`
        // points to the stale pre-import tip → `ParentHashMismatch` on
        // append → chain stalls at whichever height the first proposer
        // change happens.
        if let Some(proposer) = self.proposer.as_mut() {
            proposer.advance_tip(imported_block_hash);
        }
        if imported_height.is_multiple_of(CHECKPOINT_INTERVAL) {
            match self.disk.write_trusted_checkpoint(&self.state) {
                Ok(meta) => {
                    self.disk
                        .compact_chain_to_checkpoint(meta.height, meta.tip_hash);
                    tracing::info!(
                        checkpoint_height = meta.height,
                        "trusted checkpoint written"
                    );
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to write trusted checkpoint (non-fatal)")
                }
            }
        }
        tracing::info!(
            height = imported_height,
            block_hash = %imported_hash,
            "block imported from peer"
        );

        Ok(())
    }

    /// ADR-054 §Stage 4 (SiblingAtTip) — same height as the local tip,
    /// different `block_hash`. Two sub-cases:
    ///
    /// (a) **State-equivalent sibling.** The candidate has identical
    /// `prev_hash`, `state_root`, `tx_root` to the local tip — only
    /// the timestamp / signature mix differs. Atomic swap via
    /// `RocksDbChainStore::replace_canonical_at_height`. State stays
    /// untouched (the candidate's apply produces the same `state_root`
    /// by construction). The `LocalProposer.tip_hash` is re-synced so
    /// the next proposer rotation does not build on the stale variant.
    ///
    /// (b) **State-divergent sibling.** Different `state_root`/`tx_root`/
    /// `prev_hash` at the same height with both blocks carrying valid
    /// 2f+1 quorums is a 2f+1 double-sign — a slashable safety
    /// violation under SPEC-CONSENSUS-001 §16. TASK-213 builds
    /// `EquivocationEvidence` for every (validator, round) pair that
    /// signed BOTH variants and submits each via the slashing-evidence
    /// pool; reception is then halted on this height pending operator
    /// review.
    fn resolve_sibling_at_tip(
        &mut self,
        candidate: StoredBlock,
        local: pqc_consensus::BlockMetadata,
    ) -> Result<()> {
        let height = candidate.metadata.height;
        let local_hash = local.block_hash.clone();
        let candidate_hash = candidate.metadata.block_hash.clone();

        // Stage 2 (strict finality gate) runs implicitly in
        // `replace_canonical_at_height` when `policy_from_state` is
        // `Some` — but we also want the gate to fire for the bail()
        // branch below where we emit equivocation evidence. Build the
        // policy here so both branches share the same source.
        let policy_from_state = CommitQuorumPolicy::from_state_store(&self.state, None)
            .expect("StateStore yields a valid CommitQuorumPolicy (M2 invariant)");
        let policy_from_state = policy_from_state.map(|p| {
            if self.config.devnet.distributed_signing {
                p.with_distributed_preimage(0)
            } else {
                p
            }
        });

        // (a) State-equivalent sibling-swap. The store-side guard
        // re-checks the same fields; failures at that boundary fall
        // through to the divergent branch.
        let state_equivalent = candidate.metadata.prev_hash == local.prev_hash
            && candidate.metadata.state_root == local.state_root
            && candidate.metadata.tx_root == local.tx_root;

        if state_equivalent {
            let displaced = self
                .disk
                .replace_canonical_at_height(candidate.clone(), policy_from_state.as_ref())
                .context("ADR-054 §Stage 4 sibling-swap: storage replace failed")?;

            // Sync the in-process LocalProposer tip so the next
            // round picks up the canonical hash — same load-bearing
            // fix as TASK-170 for the LinkAtTip path.
            if let Some(proposer) = self.proposer.as_mut() {
                proposer.advance_tip(candidate_hash.clone());
            }
            // State is unchanged (sibling has identical state_root by
            // pre-condition), so we do NOT touch self.state here.
            self.last_sync_error = None;
            self.blocks_imported += 1;
            tracing::warn!(
                height,
                old_tip = %hex::encode(displaced.metadata.block_hash.0),
                new_tip = %hex::encode(candidate_hash.0),
                old_timestamp = displaced.metadata.timestamp,
                new_timestamp = candidate.metadata.timestamp,
                "ADR-054 §Stage 4: canonical sibling-swap committed (state-equivalent)",
            );
            return Ok(());
        }

        // (b) State-divergent sibling — slashable. TASK-213.
        //
        // Look up the local block's full body so we can read its
        // `commit_signatures`. Without those we cannot build evidence
        // for the slashing path; bail with the original
        // EQUIVOCATION_DETECTED line so operators are still alerted.
        let local_block = match self.disk.read_stored_block_at_height(height) {
            Ok(Some(b)) => b,
            Ok(None) | Err(_) => {
                bail!(
                    "ADR-054 §Stage 4 EQUIVOCATION_DETECTED (no local body for height {h}): \
                     local={local} new={new}. Reception halted; operator review required.",
                    h = height,
                    local = hex::encode(local_hash.0),
                    new = hex::encode(candidate_hash.0),
                );
            }
        };

        let submitted =
            self.submit_equivocation_evidence_for_sibling_pair(height, &local_block, &candidate);

        // Whether or not we emitted any evidence (a coincidence of
        // disjoint validator sets is possible), reception MUST halt
        // on this height — both branches are quorum-signed under our
        // local view, and applying either is a safety violation.
        bail!(
            "ADR-054 §Stage 4 EQUIVOCATION_DETECTED: height {h} has two quorum-signed blocks \
             with divergent state-effects (local={local} new={new}). \
             {n} equivocation evidence record(s) submitted for slashing. \
             Block reception halted; operator review required.",
            h = height,
            local = hex::encode(local_hash.0),
            new = hex::encode(candidate_hash.0),
            n = submitted,
        );
    }

    /// ADR-054 §Stage 4 (b) — TASK-213.
    ///
    /// Walk the cross-product of `local.commit_signatures` and
    /// `candidate.commit_signatures` to find double-signers: any
    /// validator that signed Precommit at the same `(height, round)`
    /// for both block_hashes. For each such pair, construct an
    /// `EquivocationEvidence` with both vote-A and vote-B Precommit
    /// signatures and apply it through `apply_submit_equivocation_evidence`.
    ///
    /// Returns the count of evidence records successfully submitted.
    /// Failures (validator not on-chain, malformed sig, already
    /// tombstoned, …) are logged but do not abort the loop —
    /// individual rejections are expected when the validator set has
    /// drifted between sibling-emission times.
    fn submit_equivocation_evidence_for_sibling_pair(
        &mut self,
        height: u64,
        local_block: &StoredBlock,
        candidate: &StoredBlock,
    ) -> usize {
        use pqc_types::slashing::{
            encode_equivocation_evidence, EquivocationEvidence, EquivocationVote,
        };

        const STEP_PRECOMMIT: u8 = 0x02;

        // Build a (validator_address, round) → CommitSig lookup for
        // the local side; then iterate the candidate side and emit
        // evidence on every match.
        let local_index: HashMap<(Vec<u8>, u32), &pqc_types::block::CommitSig> = local_block
            .block
            .commit_signatures
            .iter()
            .map(|sig| ((sig.validator_address.clone(), sig.round), sig))
            .collect();

        // Sender of the synthetic SubmitEquivocationEvidence tx — use
        // the treasury placeholder so the slashing apply path runs
        // under a known account; the reward is credited there per
        // SPEC-SLASH-001 §11.
        let sender = pqc_types::account::Address([0x01u8; 32]);
        let verifier = self.verifier.clone();
        let mut submitted = 0usize;

        for sig_b in &candidate.block.commit_signatures {
            let key = (sig_b.validator_address.clone(), sig_b.round);
            let Some(sig_a) = local_index.get(&key) else {
                continue;
            };
            // Same (validator, round) signed both block_hashes →
            // double-sign. Build EquivocationEvidence.
            let mut validator_address = [0u8; 32];
            if sig_b.validator_address.len() != 32 {
                tracing::warn!(
                    height,
                    addr_len = sig_b.validator_address.len(),
                    "TASK-213: skipping non-32-byte validator address"
                );
                continue;
            }
            validator_address.copy_from_slice(&sig_b.validator_address);

            let evidence = EquivocationEvidence {
                validator_address,
                height,
                vote_a: EquivocationVote {
                    height,
                    round: sig_a.round,
                    block_hash: local_block.metadata.block_hash.0,
                    step: STEP_PRECOMMIT,
                    signature: sig_a.signature.clone(),
                },
                vote_b: EquivocationVote {
                    height,
                    round: sig_b.round,
                    block_hash: candidate.metadata.block_hash.0,
                    step: STEP_PRECOMMIT,
                    signature: sig_b.signature.clone(),
                },
            };
            let payload = encode_equivocation_evidence(&evidence);

            // The slashing apply path is generic over `V: SignatureVerifier`.
            // We hold an `Arc<dyn SignatureVerifier>` because the verifier
            // is selected at runtime — wrap it so the generic monomorphises
            // against a concrete reference.
            struct DynVerifierRef<'a>(&'a (dyn pqc_crypto::sign::SignatureVerifier + 'a));
            impl<'a> pqc_crypto::sign::SignatureVerifier for DynVerifierRef<'a> {
                fn verify(
                    &self,
                    pk: &pqc_crypto::sign::PublicKey,
                    msg: &[u8],
                    sig: &pqc_crypto::sign::Signature,
                ) -> Result<(), pqc_crypto::CryptoError> {
                    self.0.verify(pk, msg, sig)
                }
            }
            let verifier_ref = DynVerifierRef(verifier.as_ref());

            match pqc_state::apply::slashing::apply_submit_equivocation_evidence(
                &mut self.state,
                &sender,
                &payload,
                self.disk.height(),
                &verifier_ref,
            ) {
                Ok(()) => {
                    submitted += 1;
                    tracing::warn!(
                        height,
                        validator = %hex::encode(validator_address),
                        round = sig_b.round,
                        "TASK-213: equivocation evidence submitted for slashing"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        height,
                        validator = %hex::encode(validator_address),
                        round = sig_b.round,
                        error = ?e,
                        "TASK-213: apply_submit_equivocation_evidence rejected pair"
                    );
                }
            }
        }

        submitted
    }
}

pub async fn start_from_config_path(config_path: &Path) -> Result<DevnetNodeHandle> {
    let config = load_node_config(config_path)?;
    let genesis_state = build_genesis_state(&config)?;
    let commit_policy = build_commit_quorum_policy(&config)?;
    let anchor_prev_hash = BlockHash(decode_hex_array::<32>(
        &config.anchor_prev_hash_hex,
        "anchor_prev_hash_hex",
    )?);

    if config.devnet.role.requires_validator_set() && commit_policy.is_none() {
        bail!(
            "node {} uses devnet role {:?} but has no static validator set configured",
            config.node_id,
            config.devnet.role
        );
    }

    // Build validator pool from static config (Phase 3: static set, no on-chain staking).
    let validator_pool: Vec<pqc_types::account::Address> = config
        .devnet
        .validators
        .iter()
        .filter_map(|v| {
            crate::node::decode_hex_array::<32>(&v.address_hex, "devnet.validators[].address_hex")
                .ok()
                .map(pqc_types::account::Address)
        })
        .collect();

    let mut disk = open_disk_store_from_config(&config, anchor_prev_hash.clone())?;

    // ADR-054 §Stage 6 — fast-fail integrity audit. Catches the
    // 2026-04-25 bug class (silent persistence of an unfinalized
    // block) before any further startup work; failure refuses
    // start and points the operator at `pqcd snapshot-import`.
    disk.verify_quick_finality_invariants().context(
        "ADR-054 §Stage 6 integrity audit refused startup — recover via snapshot-import",
    )?;

    // Phase 8 libp2p Swarm is started BEFORE the cold-start check so a
    // libp2p-configured follower can fetch its initial snapshot via
    // `/viper/<chain>/snapshot/1.0.0` request-response instead of the
    // Phase 6 HTTP `/internal/p2p/snapshot` endpoint. The shutdown
    // channel + task vec move up here for the same reason — the
    // libp2p driver task wants a shutdown receiver at spawn time.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut tasks = Vec::new();

    let libp2p_start = crate::p2p::start_libp2p(&config, shutdown_rx.clone()).await?;
    let p2p_handle = libp2p_start.handle;
    // Captured before `p2p_handle` is moved into LiveNodeState so the
    // TASK-135 step 13 sync_loop gate below can decide whether to spawn
    // the HTTP poller without reaching back into the state guard.
    let libp2p_enabled = p2p_handle.is_some();
    let mut inbound_block_rx = libp2p_start.inbound_rx;
    if let Some(task) = libp2p_start.task {
        tasks.push(task);
    }

    // Cold-start snapshot bootstrap: if local disk is empty (no blocks,
    // no checkpoint) and a snapshot source is available, download the
    // peer's checkpoint before the normal recovery path runs.
    //
    // Branching (never both — the two paths write the same
    // checkpoint CF and a race would corrupt the store):
    //   * libp2p enabled + at least one bootstrap_peer → libp2p path
    //     (`/viper/<chain>/snapshot/1.0.0`).
    //   * otherwise, if `config.devnet.snapshot_source` is set → HTTP
    //     path (Phase 6 fallback; preserved verbatim when libp2p is
    //     off).
    //   * otherwise skip (node genesis-replays from scratch).
    if disk.height() == 0 && !disk.has_checkpoint() {
        let chain_id = decode_hex_bytes(&config.chain_id_hex, "chain_id_hex")?;
        if libp2p_enabled {
            if let (Some(handle), Some(rx), Some(libp2p_cfg)) = (
                p2p_handle.as_ref(),
                inbound_block_rx.as_mut(),
                config.libp2p.as_ref(),
            ) {
                if !libp2p_cfg.bootstrap_peers.is_empty() {
                    if let Err(e) = cold_start_from_libp2p_snapshot(
                        &mut disk, handle, rx, libp2p_cfg, &chain_id,
                    )
                    .await
                    {
                        // A libp2p cold-start failure is non-fatal: the
                        // node continues with genesis replay, then the
                        // steady-state gossip + block-fetch path closes
                        // the resulting gap incrementally. A cascade of
                        // these in logs is the signal to check
                        // bootstrap_peer health.
                        tracing::warn!(
                            error = %e,
                            "libp2p cold-start failed — falling back to genesis replay"
                        );
                    }
                } else {
                    tracing::info!(
                        "libp2p enabled but no bootstrap_peers configured — skipping snapshot cold-start"
                    );
                }
            }
        } else if let Some(ref snapshot_source_addr) = config.devnet.snapshot_source {
            cold_start_from_snapshot(&mut disk, snapshot_source_addr, &chain_id)
                .await
                .context("cold-start snapshot bootstrap failed")?;
        }
    }

    let recovery = disk
        .recover_tip_with_checkpoint(
            &genesis_state,
            config.fee_params.clone(),
            Default::default(),
            validator_pool.clone(),
        )
        .context("failed to recover devnet node state from persisted chain history")?;
    if recovery.replay.height < disk.height() {
        bail!(
            "devnet bootstrap height mismatch: recovered {}, chain store {}",
            recovery.replay.height,
            disk.height()
        );
    }

    // Phase 6 required an HTTP P2P endpoint for every multi-node role
    // (the producer served blocks + snapshots over /internal/p2p/*,
    // followers polled it). Phase 8 M1 replaces that with libp2p gossip
    // + request-response, so `p2p_listen_addr` becomes purely advisory
    // when `libp2p.enable = true` — drop the hard requirement in that
    // case. Legacy Phase 6 deployments (libp2p off) still bail out if
    // the HTTP endpoint is missing.
    let libp2p_on = libp2p_enabled;
    if config.devnet.role.requires_p2p_transport() && config.p2p_listen_addr.is_none() && !libp2p_on
    {
        bail!(
            "node {} uses devnet role {:?} but has no p2p_listen_addr \
             (and `libp2p.enable` is false — one of the two transports \
             must be configured for a multi-node role)",
            config.node_id,
            config.devnet.role
        );
    }

    let keystore = Arc::new(std::sync::RwLock::new(build_initial_keystore(
        &config,
        commit_policy.as_ref(),
    )?));

    // HSM phase-plan boot-time self-test — the private design notes
    // §"Boot-time validation". For every keystore entry, construct a
    // `pqc_hsm::CommitSigner` of the configured kind and ask it to sign
    // the canary preimage `b"VIPER-HSM-CANARY-V1"`; the signature MUST
    // verify against the cached pubkey. A failure here surfaces a
    // mis-wired HSM credential, a stale seed, or a seed/pubkey
    // disagreement — all of which would otherwise show up as a
    // quorum-loss with no actionable diagnostic at first block production.
    //
    // Currently only `SignerKind::LocalKeystore` is supported; SoftHSM
    // / AwsCloudHsm canary paths land alongside their respective
    // signer impls. Any other kind produces a hard error at boot.
    {
        let canary_kind = config.devnet.signer_kind;
        if !config.devnet.signer_config.matches_kind(canary_kind) {
            bail!(
                "node {} signer_kind = {:?} but signer_config.kind disagrees — \
                 align them in node.json (HSM-PHASE-PLAN §Selection at runtime)",
                config.node_id,
                canary_kind,
            );
        }
        match canary_kind {
            pqc_hsm::SignerKind::LocalKeystore => {
                let ks_guard = keystore
                    .read()
                    .expect("keystore RwLock poisoned at boot self-test");
                run_local_keystore_self_test(&config.node_id, &ks_guard)?;
            }
            other => {
                bail!(
                    "node {} configured for signer_kind = {:?} but that backend is \
                     not yet implemented — only `LocalKeystore` is supported in \
                     the current scope. See HSM-PHASE-PLAN.md.",
                    config.node_id,
                    other,
                );
            }
        }
    }

    // ADR-051 §Decision item 5/6 — every active validator with signing
    // material in the local keystore participates in proposer-rotation
    // and per-block precommit emission, regardless of `devnet.role`.
    // Pre-ADR-051 (legacy): only `role == Producer` ran the consensus
    // loop. Post-ADR-051 (`distributed_signing == true`): any node with
    // a seed for an active validator runs it. The per-tick gate inside
    // `should_build_as_proposer` already restricts block building to
    // the elected proposer for the height; non-proposer ticks are
    // no-ops on build, and `handle_non_proposer_proposal_if_applicable`
    // emits the precommit when a sub-quorum PROPOSAL arrives via gossip.
    let has_local_signing_material = !keystore
        .read()
        .expect("keystore RwLock poisoned at startup")
        .is_empty();
    let runs_consensus_loop = config.devnet.role.runs_bft_consensus_loop()
        || (config.devnet.distributed_signing && has_local_signing_material);

    // Derive a deterministic ML-KEM-768 keypair from `(node_id, salt, epoch)`
    // — Strategy 1 + secret salt per `PHASE-4-KEY-ROTATION-RESEARCH.md` §2.4.
    //
    // Closes Gap B from the private design notes: prior
    // to this code path the derivation was `node_id`-only (`shake256_32(
    // node_id || "-kem-d")`), and `node_id` is publicly observable, so
    // any attacker who knew it could recompute the long-term ML-KEM
    // secret. The salt is a 32-byte hex value in `node.json` (mode 0600)
    // generated by `pqcd wallet kem-init`; epoch is the chain-aligned
    // block-height / `epoch_duration`.
    //
    // The legacy (no-salt) derivation is retained as a back-compat
    // fallback — pre-fix `node.json` files boot without operator action,
    // but pqcd emits a startup `warn!` flagging the residual exposure.
    let initial_epoch_number = pqc_consensus::epoch::epoch_for_height(
        recovery.replay.height,
        config.devnet.epoch_duration,
    );
    let kem_secret_salt: Option<[u8; 32]> = match &config.devnet.kem_seed_salt_hex {
        Some(hex_str) => {
            let bytes = hex::decode(hex_str.trim()).with_context(|| {
                format!(
                    "node {} `devnet.kem_seed_salt_hex` is not valid hex",
                    config.node_id
                )
            })?;
            let salt: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
                anyhow!(
                    "node {} `devnet.kem_seed_salt_hex` decoded to {} bytes; expected 32. \
                     Regenerate with `pqcd wallet kem-init --node-config <path>`.",
                    config.node_id,
                    v.len()
                )
            })?;
            Some(salt)
        }
        None => {
            tracing::warn!(
                node_id = %config.node_id,
                "ML-KEM identity keypair derived from node_id ONLY (no `devnet.kem_seed_salt_hex` \
                 in node.json) — legacy back-compat path. node_id is publicly observable, so \
                 the long-term KEM secret is recomputable by any attacker who knows it. \
                 See CONCERNS-DECISIONS.md Gap B. Generate a salt with \
                 `pqcd wallet kem-init --node-config <path>` and restart to close this gap."
            );
            None
        }
    };
    let initial_kem = derive_kem_keypair(
        &config.node_id,
        kem_secret_salt.as_ref(),
        initial_epoch_number,
    );
    let kem_keyset = KemKeyset::new(initial_kem);

    let proposer = if runs_consensus_loop {
        // The initial `proposer` address is overwritten on every loop
        // iteration via `LocalProposer::set_proposer` based on per-height
        // RANDAO rotation, so it is structurally a placeholder. For
        // legacy `role == Producer` we keep `resolve_proposer_address`
        // (which requires `proposer_address_hex` in node.json) for
        // backwards compatibility with operator runbooks; for signing
        // followers we use the zero address as the placeholder.
        let initial_proposer_addr = if config.devnet.role.runs_bft_consensus_loop() {
            resolve_proposer_address(&config)?
        } else {
            [0u8; 32]
        };
        Some(LocalProposer::new(
            initial_proposer_addr,
            LocalProposerConfig {
                assembly: AssemblyConfig {
                    fee_params: config.fee_params.clone(),
                    validator_pool: validator_pool.clone(),
                    epoch_config: EpochConfig {
                        epoch_duration: config.devnet.epoch_duration,
                        unbonding_period: config.devnet.unbonding_period,
                        ..EpochConfig::devnet()
                    },
                    ..AssemblyConfig::default()
                },
                initial_prev_hash: disk
                    .tip_hash()
                    .cloned()
                    .unwrap_or_else(|| anchor_prev_hash.clone()),
            },
        ))
    } else {
        None
    };

    // `shutdown_tx`, `tasks`, `p2p_handle`, `libp2p_enabled`, and
    // `inbound_block_rx` were all initialised above (before the
    // cold-start check) so the libp2p Swarm is available to bootstrap
    // from a peer via `/viper/<chain>/snapshot/1.0.0`.

    let state = Arc::new(Mutex::new(LiveNodeState {
        config: config.clone(),
        fee_params: config.fee_params.clone(),
        validator_pool,
        recovery_source: recovery.source,
        state: recovery.replay.state,
        mempool: Mempool::new(),
        disk,
        proposer,
        keystore,
        last_sync_error: None,
        verifier: std::sync::Arc::new(PqVerifier),
        kem_keyset,
        kem_secret_salt,
        p2p_sessions: HashMap::new(),
        p2p_handle,
        ip_rate_limiter: HashMap::new(),
        rate_limit: config.rate_limit.clone(),
        sender_admit_budget: HashMap::new(),
        sender_budget: config.sender_budget.clone(),
        blocks_produced: 0,
        blocks_imported: 0,
        txs_admitted: 0,
        txs_rejected: 0,
        txs_rejected_by_reason: HashMap::new(),
        peer_sync_errors: 0,
        node_start_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        pending_precommits: HashMap::new(),
        own_precommits_emitted: std::collections::HashSet::new(),
        orphan_cache: pqc_consensus::BlockTreeCache::new(
            pqc_consensus::BLOCK_TREE_CACHE_CAPACITY,
            pqc_consensus::BLOCK_TREE_CACHE_TTL,
        ),
        chain_size_samples: VecDeque::new(),
    }));

    // TASK-135 step 11: inbound-block consumer. Decoded Block envelopes
    // arrive from the swarm driver via `inbound_block_rx`; we compare
    // each height against the local chain tip and log/count any gap.
    // No ingest yet — the feeder lands in step 13. Spawned only when
    // libp2p is enabled (the receiver is `None` otherwise).
    let libp2p_enabled = inbound_block_rx.is_some();
    if let Some(rx) = inbound_block_rx {
        tasks.push(tokio::spawn(block_inbound_loop(
            state.clone(),
            shutdown_rx.clone(),
            rx,
        )));
    }

    // Stale-tip self-heal: closes the gossip-driven catch-up gap that
    // halts the chain when a single node falls one block behind under
    // N=3 quorum=3 (zero BFT). See `stale_tip_recovery_loop` doc.
    // Spawned only when libp2p is enabled — without a SwarmHandle we
    // have no out-of-band channel to recover on.
    if libp2p_enabled {
        tasks.push(tokio::spawn(stale_tip_recovery_loop(
            state.clone(),
            shutdown_rx.clone(),
        )));
    }

    if let Some(addr) = config.p2p_listen_addr.clone() {
        tasks.push(start_p2p_server(state.clone(), addr, shutdown_rx.clone()).await?);
    }

    let mut api_addr: Option<std::net::SocketAddr> = None;
    if let Some(addr) = config.api_listen_addr.clone() {
        let (task, bound) = start_api_server(state.clone(), addr, shutdown_rx.clone()).await?;
        tasks.push(task);
        api_addr = Some(bound);
    }

    if runs_consensus_loop {
        // Phase 8 M2 Step 3 (TASK-113): the consensus loop no longer
        // captures the validator-address vector at startup — it reads
        // `state.active_validators()` on each iteration so a validator
        // joining (or exiting) at an epoch boundary is visible to
        // proposer rotation on the very next block. The decision here
        // (which loop to spawn) still uses the genesis-config count
        // as a proxy — picking `consensus_loop` for ≥ 2 validators —
        // because at boot time the state may not yet be populated (it
        // gets seeded from config in the bootstrap path elsewhere).
        //
        // ADR-051 §Decision item 5/6 (R-10 fix, 2026-04-26): the gate
        // here was `role == Producer` until the live debug session of
        // 2026-04-26 19:17 confirmed that `distributed_signing = true`
        // with seeds redistributed across hosts halts the chain — the
        // followers' precommit-emission path was unreachable because
        // they never spawned the loop. The condition is now keystore-
        // presence-driven (`runs_consensus_loop` set above), matching
        // SPEC-CONSENSUS-001 §11 line 480 ("every active validator
        // independently signs Precommit").
        if config.devnet.validators.len() >= 2 {
            tasks.push(tokio::spawn(consensus_loop(
                state.clone(),
                shutdown_rx.clone(),
            )));
        } else {
            tasks.push(tokio::spawn(producer_loop(
                state.clone(),
                shutdown_rx.clone(),
            )));
        }
    }

    // TASK-135 step 13 — never both at once: the HTTP sync_loop and the
    // libp2p gossip+block-fetch catch-up path both ingest blocks into
    // the same chain store via `import_remote_block`. Running them in
    // parallel would race on the "fetch next height" decision and could
    // double-insert (first import races with import_remote_block's
    // duplicate check). The libp2p path owns catch-up when enabled;
    // otherwise the HTTP path (Phase 6) stays authoritative.
    if config.devnet.role.syncs_from_peers() && !config.peers.is_empty() && !libp2p_enabled {
        tasks.push(tokio::spawn(sync_loop(
            state.clone(),
            shutdown_rx.clone(),
            config.peers.clone(),
        )));
    } else if config.devnet.role.syncs_from_peers() && libp2p_enabled {
        tracing::info!(
            "libp2p enabled: skipping HTTP sync_loop (catch-up via gossip+block-fetch, TASK-135 step 13)"
        );
    }

    Ok(DevnetNodeHandle {
        config_path: config_path.to_path_buf(),
        state,
        shutdown_tx,
        tasks,
        api_addr,
    })
}

/// Print the DEMO / single-operator / no-audit banner on every node start.
///
/// `viper-pq-1` is currently a single-operator development chain — no
/// external security audit has been performed, the validator set is N=3
/// (quorum = 3/3 → no Byzantine fault tolerance until N≥4 with independent
/// operators), and the validator-key passphrases are dev-grade. The
/// chain_id naming (`viper-pq-1`) and the tagged release stream
/// (`viper-pq-1-v0.1.x`) communicate a maturity that the operational
/// posture does not yet match. The banner makes that explicit at every
/// node start so a casual reader of the systemd journal cannot mistake
/// the cluster for a production L1.
///
/// Removal is gated by the P-COMPAT-001 "binding window" milestone:
/// when (a) an external auditor has reviewed the consensus + crypto
/// layers, (b) the validator set has reached N≥4 with independent
/// operators, and (c) HSM / threshold-sig key custody is in place,
/// the calling site flips this to a single-line "production node up"
/// message. See `AGENTS.md` "Mainnet-discipline rules — Binding window"
/// and `docs/security-testing-roadmap.md` for the gating list.
pub fn print_demo_chain_banner() {
    let banner = r#"
╔════════════════════════════════════════════════════════════════════════╗
║  ⚠  VIPER-PQ-1 IS A DEMO / DEV CHAIN — NOT AUDITED PRODUCTION L1       ║
║                                                                        ║
║   • Single operator (no independent validators yet)                    ║
║   • N=3 validator set with 3/3 quorum: ZERO Byzantine fault tolerance  ║
║   • No external security audit (consensus / crypto / p2p)              ║
║   • Validator passphrases are dev-grade; keys live on disk, no HSM     ║
║   • SDK + frontend exist for ergonomics — DO NOT trust receipts as     ║
║     production-grade attestations until the binding window opens       ║
║                                                                        ║
║  See AGENTS.md → "Mainnet-discipline rules — Binding window"           ║
║  See docs/security-testing-roadmap.md for the gating items             ║
╚════════════════════════════════════════════════════════════════════════╝
"#;
    eprintln!("{banner}");
    tracing::warn!(
        target: "viper.demo_banner",
        "viper-pq-1 is a DEMO / single-operator / no-audit chain — not a production L1. \
         See AGENTS.md 'Binding window' for the gating items."
    );
}

pub async fn run_from_config_path(config_path: &Path) -> Result<()> {
    let handle = start_from_config_path(config_path).await?;
    print_demo_chain_banner();
    println!(
        "devnet node {} running from {}",
        handle.snapshot().await.node_id,
        handle.config_path().display()
    );
    tokio::signal::ctrl_c()
        .await
        .context("failed while waiting for ctrl-c")?;
    handle.shutdown().await
}

async fn start_p2p_server(
    state: SharedLiveNodeState,
    addr: String,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<JoinHandle<Result<()>>> {
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("failed to bind p2p listener to {addr}"))?;
    let bound_addr = listener
        .local_addr()
        .context("failed to inspect p2p listener")?;
    let node_id = {
        let guard = state.lock().await;
        guard.config.node_id.clone()
    };

    tracing::info!(node_id = %node_id, p2p_addr = %bound_addr, "p2p listener ready");

    let app = p2p_router(state);
    Ok(tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.changed().await;
            })
            .await
            .context("p2p server error")
    }))
}

mod consensus_loops;
use consensus_loops::{consensus_loop, producer_loop};

mod p2p_internal;
use p2p_internal::*;

mod metrics;
use metrics::*;

// ── GET /v1/proofs/{anchor_id} ────────────────────────────────────────────────
// Handler moved to crates/pqcd/src/devnet/proof_anchor.rs (2026-05-10).
mod proof_anchor;
use proof_anchor::handle_get_proof_anchor;

// ── Public API server (POST /v1/txs + read endpoints) ────────────────────────

async fn start_api_server(
    state: SharedLiveNodeState,
    addr: String,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(JoinHandle<Result<()>>, std::net::SocketAddr)> {
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("failed to bind api listener to {addr}"))?;
    let bound_addr = listener
        .local_addr()
        .context("failed to inspect api listener")?;
    let (node_id, api_cfg) = {
        let guard = state.lock().await;
        (guard.config.node_id.clone(), guard.config.api.clone())
    };

    tracing::info!(
        node_id = %node_id,
        api_addr = %bound_addr,
        public_tx_submission = api_cfg.public_tx_submission,
        expose_token_state = api_cfg.expose_token_state,
        expose_notary_routes = api_cfg.expose_notary_routes,
        "public api listener ready"
    );

    let app = api_router(state, api_cfg);
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.changed().await;
        })
        .await
        .context("api server error")
    });
    Ok((task, bound_addr))
}

/// Build the public API router with route registration gated by the
/// `[api]` section of node-config.json. Always-on routes live in the base
/// builder; gated routes are added conditionally below.
///
/// Defaults preserve viper-pq-1 behaviour (every route registered).
/// Tokenless deployments (viper-research-1) flip the flags to false to
/// drop POST /v1/txs, /v1/accounts/*, /v1/fee-market, and the
/// /api/credentials/* + /api/proofs/* notary overlay. See
/// the private planning notes §3 Fase 2.
fn api_router(state: SharedLiveNodeState, api: crate::node::ApiConfig) -> Router {
    let mut r = Router::new()
        // ── Always-on read endpoints (tokenless-safe) ────────────────────────
        .route("/v1/txs/{hash}", get(handle_tx_lookup))
        .route("/v1/metrics", get(handle_metrics))
        .route("/v1/status", get(handle_status))
        .route("/v1/validators", get(handle_validators))
        .route("/v1/validators/{address}", get(handle_validator_get))
        .route("/v1/blocks/{height}", get(handle_block))
        .route("/v1/attestations/{id}", get(handle_attestation))
        .route("/v1/proofs/{anchor_id}", get(handle_get_proof_anchor))
        .route("/v1/algorithms", get(handle_algorithms_list))
        .route("/v1/algorithms/{alg_id}", get(handle_algorithm_get))
        .route("/v1/governance/proposals", get(handle_proposals_list))
        .route(
            "/v1/governance/proposals/{proposal_id}",
            get(handle_proposal_get),
        )
        .route(
            "/v1/governance/proposals/{proposal_id}/votes",
            get(handle_proposal_votes),
        )
        .route("/v1/archival/records", get(handle_archival_records_list))
        .route(
            "/v1/archival/records/{epoch}",
            get(handle_archival_record_by_epoch),
        )
        // ── Always-on operational ────────────────────────────────────────────
        .route("/api/health", get(handle_health))
        .route("/openapi.yaml", get(handle_openapi_yaml))
        .route("/docs", get(handle_swagger_ui));

    // ── Public tx submission ─────────────────────────────────────────────────
    // Tokenless deployments disable this — validators produce blocks without
    // external tx submission.
    if api.public_tx_submission {
        r = r.route("/v1/txs", post(handle_tx_submit));
    }

    // ── Token-state endpoints ────────────────────────────────────────────────
    // Account balance lookup, fee market state, and per-account attestation
    // lookup all live under the same flag — they presuppose an account/balance
    // model that doesn't apply on tokenless substrates.
    if api.expose_token_state {
        r = r
            .route("/v1/fee-market", get(handle_fee_market))
            .route("/v1/accounts/{address}", get(handle_account_nonce))
            .route(
                "/v1/accounts/{address}/attestations",
                get(handle_account_attestations),
            );
    }

    // ── Notary overlay routes hosted inside pqcd ─────────────────────────────
    // On viper-research-1 these move to a separate the notary service (private)
    // deployment (private repo, not publicly served).
    if api.expose_notary_routes {
        r = r
            .route("/api/credentials/issue", post(handle_credential_issue))
            .route("/api/credentials/{id}", get(handle_credential_get))
            .route("/api/proofs/anchor", post(handle_proof_anchor_api))
            .route("/api/proofs/{id}", get(handle_proof_get));
    }

    r.with_state(state)
}

mod read_api;
use read_api::{
    handle_account_attestations, handle_account_nonce, handle_algorithm_get,
    handle_algorithms_list, handle_archival_record_by_epoch, handle_archival_records_list,
    handle_attestation, handle_block, handle_fee_market, handle_proposal_get,
    handle_proposal_votes, handle_proposals_list, handle_status, handle_tx_lookup,
    handle_validator_get, handle_validators,
};

mod tx_submit;
use tx_submit::*;

// ── OpenAPI / Swagger UI serving (moved to devnet/openapi.rs 2026-05-10) ────
mod openapi;
use openapi::{handle_openapi_yaml, handle_swagger_ui};

// ── Service API moved to devnet/service_api.rs (2026-05-10) ────────────
mod service_api;
use service_api::{
    handle_credential_get, handle_credential_issue, handle_health, handle_proof_anchor_api,
    handle_proof_get,
};

fn resolve_proposer_address(config: &NodeConfig) -> Result<[u8; 32]> {
    if let Some(raw) = &config.devnet.proposer_address_hex {
        return decode_hex_array::<32>(raw, "devnet.proposer_address_hex");
    }

    bail!(
        "node {} is a producer but devnet.proposer_address_hex is not configured",
        config.node_id
    );
}

mod dispatch;
// Glob-import every dispatch item into the parent so that
// `use super::*;` in consensus_loops.rs / sibling submodules continues
// to resolve helper calls like `should_build_as_proposer(...)` without
// threading `super::dispatch::` at every call site. The dispatch module
// is the canonical owner of these fns; this glob is the parent's
// re-export shim.
use dispatch::*;

mod keystore_lifecycle;
pub use keystore_lifecycle::snapshot_block_signers_dyn;
use keystore_lifecycle::*;

// ── ADR-051 / TASK-167 Step 2 — per-role proposer dispatch tests ─────────────
