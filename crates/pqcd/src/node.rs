// SPDX-License-Identifier: BUSL-1.1
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{anyhow, bail, Context, Result};
use pqc_consensus::{
    CommitQuorumPolicy, CommitValidator, DiskChainStore, RecoverySource, RocksDbChainStore,
    TrustedCheckpointMetadata, EPOCH_DURATION_DEVNET,
};
use pqc_crypto::AlgId;
use pqc_state::StateStore;
use pqc_tx::validate::FeeParams;

use crate::api::{ApiNodeState, SharedState};
use pqc_types::{
    account::{Account, Address},
    block::BlockHash,
    keyset::{KeyEntry, KeySet, KeyStatus},
    validator::{ValidatorRecord, ValidatorStatus, VALIDATOR_UNBONDING_PERIOD},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    #[serde(default = "default_node_id")]
    pub node_id: String,
    pub data_dir: PathBuf,
    /// Canonical chain identifier — must match the chain_id field in every
    /// transaction accepted by this node. Hex-encoded; use "" for local
    /// devnet / test environments where chain_id isolation is not required.
    pub chain_id_hex: String,
    pub anchor_prev_hash_hex: String,
    #[serde(default)]
    pub fee_params: FeeParams,
    #[serde(default)]
    pub p2p_listen_addr: Option<String>,
    /// Optional public API listen address for `POST /v1/txs` tx submission and
    /// read endpoints. If absent, no public API server is started.
    /// Format: `"127.0.0.1:26657"` or `"0.0.0.0:26657"`.
    #[serde(default)]
    pub api_listen_addr: Option<String>,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    #[serde(default)]
    pub devnet: DevnetConfig,
    #[serde(default)]
    pub genesis_accounts: Vec<GenesisAccountConfig>,
    /// Per-IP rate limit for `POST /v1/txs`. Absent or `{}` in config uses defaults
    /// (100 requests per 60 s). Set `max_requests_per_window: 0` to disable rate limiting.
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    /// Public API surface configuration — gates which routes are registered
    /// at startup. Defaults preserve viper-pq-1 behaviour (all surfaces
    /// exposed). Tokenless deployments (viper-research-1) flip these flags
    /// to false to drop POST /v1/txs, /v1/accounts/*, /v1/fee-market, and
    /// the /api/credentials/* + /api/proofs/* notary overlay from the
    /// public API. See the private planning notes §3 Fase 2.
    #[serde(default)]
    pub api: ApiConfig,
    /// Per-sender admission budget for the mempool.
    /// Set `max_txs_per_window: 0` to disable. Default: 50 txs per 60 s.
    #[serde(default)]
    pub sender_budget: SenderBudgetConfig,
    /// Phase 8 libp2p transport section — ADR-041 / SPEC-P2P-002.
    ///
    /// Absent or `{}` (with `enable` unset / false): Phase 6 transport only
    /// (SSH tunnel + HTTP polling). Set `enable: true` to start the libp2p
    /// Swarm in parallel. Full HTTP-path removal happens in TASK-141 cutover.
    #[serde(default)]
    pub libp2p: Option<Libp2pConfig>,
}

/// Phase 8 libp2p transport configuration — ADR-041.
///
/// Each field is optional so a partial `libp2p:` section in config.yaml
/// inherits reasonable defaults. The node role (Validator / Fullnode) is
/// derived from `devnet.role` — only the listen address for the matching
/// role needs to be set for a single-network deployment.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Libp2pConfig {
    /// Master switch. Default: false (Phase 6 behaviour preserved).
    #[serde(default)]
    pub enable: bool,
    /// Listen address for validator-private network (port 26656 default).
    #[serde(default)]
    pub validator_listen: Option<String>,
    /// Listen address for trusted VFN network (port 26666 default).
    #[serde(default)]
    pub vfn_listen: Option<String>,
    /// Listen address for public network (port 26676 default).
    #[serde(default)]
    pub public_listen: Option<String>,
    /// Bootstrap peer multiaddrs (with `/p2p/<peer_id>` suffix).
    #[serde(default)]
    pub bootstrap_peers: Vec<String>,
    /// GossipSub mesh parameters (D, D_low, D_high). Default (2, 1, 3) is
    /// tuned for the 3-node devnet-2 cutover.
    #[serde(default)]
    pub gossip_mesh_n: Option<usize>,
    #[serde(default)]
    pub gossip_mesh_n_low: Option<usize>,
    #[serde(default)]
    pub gossip_mesh_n_high: Option<usize>,
    /// Enable QUIC (primary transport). Default: true.
    #[serde(default)]
    pub quic_enabled: Option<bool>,
    /// Enable TCP/TLS 1.3 fallback. Default: true.
    #[serde(default)]
    pub tcp_tls_fallback: Option<bool>,
    /// Max peers per ASN (/24 diversity enforcement). Default: 3.
    #[serde(default)]
    pub max_peers_per_asn: Option<usize>,
    /// Allow-list of validator libp2p PeerIds (base58) whose Transaction
    /// gossip this node will treat as admissible on the validator-private
    /// topic. Pinned in config for M1 — ADR-041 addendum defers the
    /// on-chain `ValidatorPeerId` registry to M2. An empty list disables
    /// the binding check, which is the current devnet-2 default; operators
    /// opt in once cutover to libp2p-only is complete. SPEC-P2P-002 §4.4.
    #[serde(default)]
    pub validator_peer_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    pub node_id: String,
    pub p2p_addr: String,
}

/// Per-IP request rate limit for the public transaction submission API.
///
/// Applied to `POST /v1/txs` only. Read endpoints and internal P2P endpoints
/// are not subject to this limit. The limiter tracks request counts per source
/// IP address within a rolling time window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum requests from a single IP within `window_secs`. Default: 100.
    #[serde(default = "default_rate_limit_max")]
    pub max_requests_per_window: u32,
    /// Rolling window duration in seconds. Default: 60.
    #[serde(default = "default_rate_limit_window_secs")]
    pub window_secs: u64,
}

fn default_rate_limit_max() -> u32 {
    100
}
fn default_rate_limit_window_secs() -> u64 {
    60
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests_per_window: default_rate_limit_max(),
            window_secs: default_rate_limit_window_secs(),
        }
    }
}

/// Public API surface configuration — controls which routes the public
/// HTTP API server registers at startup.
///
/// All flags default to `true` so existing chains (viper-pq-1) continue
/// to expose every endpoint. Tokenless / research-substrate deployments
/// (viper-research-1) set these to `false` to drop endpoints that have
/// no semantic value without a token economy.
///
/// Routes that are NEVER gated (always registered): /v1/status,
/// /v1/network, /v1/blocks/*, /v1/txs/{hash} (read), /v1/validators*,
/// /v1/algorithms*, /v1/governance*, /v1/archival*, /v1/metrics,
/// /v1/attestations*, /v1/proofs/{anchor_id} (chain proof anchor read),
/// /api/health, /openapi.yaml, /docs.
///
/// Changing flags requires a node restart — routes are static once the
/// router is built.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Allow unauthenticated `POST /v1/txs` submission from the public
    /// API surface. Default: `true`.
    ///
    /// On viper-research-1 set to `false` — validators produce blocks
    /// without external transaction submission. The chain remains
    /// readable via the GET endpoints.
    #[serde(default = "default_true")]
    pub public_tx_submission: bool,
    /// Expose token-state endpoints: `/v1/accounts/{address}`,
    /// `/v1/accounts/{address}/attestations`, and `/v1/fee-market`.
    /// Default: `true`.
    ///
    /// On viper-research-1 set to `false` — accounts have no balance
    /// to query and no fee market exists.
    #[serde(default = "default_true")]
    pub expose_token_state: bool,
    /// Expose the notary overlay routes hosted inside `pqcd`:
    /// `/api/credentials/issue`, `/api/credentials/{id}`,
    /// `/api/proofs/anchor`, `/api/proofs/{id}`. Default: `true`.
    ///
    /// On viper-research-1 set to `false` — notary services move out of
    /// the public RPC into a separate the notary service (private) deployment
    /// (private repo, not deployed publicly).
    #[serde(default = "default_true")]
    pub expose_notary_routes: bool,
}

fn default_true() -> bool {
    true
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            public_tx_submission: true,
            expose_token_state: true,
            expose_notary_routes: true,
        }
    }
}

/// Per-sender admission budget enforced in the mempool.
///
/// Tracks the number of successfully admitted transactions per sender address
/// within a rolling time window. Only transactions that pass the full admission
/// pipeline (including signature verification) consume budget — rejected
/// transactions are free and do not count against the sender.
///
/// Applied to both `inject_tx` (direct injection) and `POST /v1/txs` (API
/// submission). Set `max_txs_per_window: 0` to disable enforcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderBudgetConfig {
    /// Maximum admitted transactions from a single sender within `window_secs`.
    /// Default: 50.
    #[serde(default = "default_sender_budget_max")]
    pub max_txs_per_window: u32,
    /// Rolling window duration in seconds. Default: 60.
    #[serde(default = "default_sender_budget_window_secs")]
    pub window_secs: u64,
}

fn default_sender_budget_max() -> u32 {
    50
}
fn default_sender_budget_window_secs() -> u64 {
    60
}

impl Default for SenderBudgetConfig {
    fn default() -> Self {
        Self {
            max_txs_per_window: default_sender_budget_max(),
            window_secs: default_sender_budget_window_secs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevnetConfig {
    #[serde(default)]
    pub role: NodeRole,
    #[serde(default = "default_sync_interval_ms")]
    pub sync_interval_ms: u64,
    #[serde(default = "default_block_time_ms")]
    pub block_time_ms: u64,
    #[serde(default)]
    pub proposer_address_hex: Option<String>,
    #[serde(default)]
    pub quorum_threshold: Option<usize>,
    #[serde(default)]
    pub validators: Vec<ValidatorConfig>,
    /// Optional P2P address of a peer to download an initial snapshot from on cold start.
    ///
    /// When set AND the local data directory is empty (no blocks, no checkpoint), the
    /// node downloads the peer's current checkpoint via `GET /internal/p2p/snapshot` and
    /// uses it as the bootstrap state, then tail-syncs to the peer's current height.
    /// This replaces full genesis replay for follower cold-start on a long-running testnet.
    ///
    /// Format: `"host:port"` matching the peer's `p2p_listen_addr`.
    #[serde(default)]
    pub snapshot_source: Option<String>,
    /// Epoch duration in blocks — ADR-042.
    /// Devnet default: 60 blocks (~30s). Testnet: 43200. Mainnet: 7200.
    #[serde(default = "default_epoch_duration")]
    pub epoch_duration: u64,
    /// Unbonding period in blocks — ADR-042.
    /// Devnet default: 120 blocks (~60s). Mainnet: 3_628_800 (~21 days).
    #[serde(default = "default_unbonding_period")]
    pub unbonding_period: u64,
    /// Optional path to a keystore JSON file (D-06 / `pqcd::keystore`).
    ///
    /// When set, the producer merges this file's entries into its
    /// in-memory signing keystore once per block (mtime-gated, so the
    /// steady-state cost is a stat() call). The format is documented in
    /// `pqcd::keystore` — each entry is an `(address_hex, sig_alg_id,
    /// commit_seed_hex)` triple, and entries for newly-registered
    /// validators let the producer sign commits for them without a
    /// process restart. Absent in the 3-validator static devnet.
    #[serde(default)]
    pub keystore_path: Option<PathBuf>,
    /// Distributed BFT signing — TASK-113 Step 6 closure, Phase 9+ /
    /// pre-cohort-onboarding.
    ///
    /// **Default: false** (legacy / devnet-2 behaviour). The producer
    /// signs commit material for every validator it holds a seed for in
    /// its keystore — the 3-genesis-seed static devnet pattern.
    ///
    /// **When true**: each node signs ONLY for its OWN operator's seed,
    /// gossips its precommit via the existing libp2p vote topic, and the
    /// block's producer waits up to `distributed_signing_quorum_wait_ms`
    /// for ≥threshold precommits from peers before finalizing. External
    /// operators running a single pqcd with a single seed can thus
    /// participate in quorum without the producer needing their seed.
    /// A node whose precommits never arrive simply contributes no
    /// signature weight for that block — no halt; the next proposer
    /// round-robins through.
    ///
    /// The flag is per-node — every validator in a network must flip it
    /// together at a coordinated cutover, OR each operator's pqcd must
    /// opt-in when joining an already-running distributed network.
    /// Mixed mode where some nodes self-sign for peers while others wait
    /// for gossip is NOT supported and will produce diverging block
    /// histories.
    #[serde(default)]
    pub distributed_signing: bool,
    /// Max milliseconds the proposer waits for gossip precommits before
    /// finalizing a block (distributed_signing mode only).
    ///
    /// Default 1500 ms — three ticks of the default 500 ms block_time.
    /// If the chain runs at a tighter cadence, shrink proportionally.
    /// Timeout without threshold drops the proposal; the next proposer
    /// round-robins through at the next tick.
    #[serde(default = "default_distributed_signing_quorum_wait_ms")]
    pub distributed_signing_quorum_wait_ms: u64,

    /// TASK-219 / L3 — attack-mode runtime flag. ONLY honoured when the
    /// pqcd binary is built with `--features attack-modes` (off in every
    /// release build per `Cargo.toml`). Used by the malicious-node
    /// integration test (`crates/pqcd/tests/malicious_node.rs`) and by
    /// security-research operators running an explicit pentest fixture.
    /// In a release binary this field deserialises but the consensus loop
    /// ignores it — verified by the cold-sync replay gate (TASK-198).
    ///
    /// Recognised values (all other strings are silently ignored):
    ///   - `"WithholdPrecommit"` — never gossip a precommit even when
    ///     elected to sign for a validator. Drives chain-halt branch
    ///     under quorum=3/3 N=3; in larger quorums the honest peers
    ///     close without us. Useful for verifying liveness boundaries.
    ///   - `"InvalidParentHash"` — when elected proposer, build a block
    ///     whose `prev_hash` is random bytes. Honest peers must reject
    ///     via PARENT_HASH_MISMATCH (devnet.rs::handle_inbound_block).
    ///     [DEFERRED — sub-task TASK-219b.]
    ///   - `"DoubleProposeAtHeight"` — emit two distinct blocks at the
    ///     same height. Drives the equivocation-evidence path
    ///     (TASK-213) which slashes the malicious validator's stake by
    ///     5% per ADR-024. [DEFERRED — sub-task TASK-219c.]
    ///   - `"ReplayFinalizedBlock"` — re-emit a sealed block from an
    ///     earlier height as if new. Honest peers reject via
    ///     `BlockInboundClass::BelowFinalized`. [DEFERRED — sub-task
    ///     TASK-219d.]
    #[serde(default)]
    pub attack_mode: Option<String>,

    /// 32-byte secret salt (hex-encoded, 64 chars) included in the ML-KEM
    /// long-term identity-keypair derivation — closes the public-from-public
    /// recompute bug flagged in the private design notes
    /// "Gap B" and `PHASE-4-KEY-ROTATION-RESEARCH.md` §2 (Strategy 1 + salt).
    ///
    /// The bug: prior to this field, `kem_d`/`kem_z` were derived from
    /// `node_id` ALONE — and `node_id` is publicly observable (logs,
    /// `/v1/status`, peer-info responses). An attacker who knew `node_id`
    /// could recompute the long-term ML-KEM secret without ever touching
    /// the disk. Scope: the devnet HTTP P2P session-bootstrap channel
    /// (`/internal/p2p/session`) — NOT the libp2p TLS 1.3 production
    /// transport (which uses ephemeral KEM keys per connection).
    ///
    /// The fix: include this 32-byte secret in the SHAKE-256 derivation
    /// inputs. Combined with chain-aligned `epoch_number`, the KEM
    /// keypair becomes a function of (public node_id, secret salt,
    /// public epoch) and rotates at every epoch boundary.
    ///
    /// Generate with `pqcd wallet kem-init --node-config <path>`. Stored
    /// in `node.json` mode 0600.
    ///
    /// **Optional for back-compat**: when absent, derivation falls back
    /// to the legacy `node_id`-only path AND pqcd emits a startup `warn!`
    /// flagging the residual exposure. New deployments MUST set this.
    /// The legacy path is retained so existing tests + a 3-node devnet
    /// running pre-fix node.json still boots without operator action;
    /// it is not the recommended steady state.
    #[serde(default)]
    pub kem_seed_salt_hex: Option<String>,

    /// 32-byte secret salt (hex-encoded, 64 chars) mixed into the libp2p
    /// **Ed25519 identity** keypair derivation — closes the same
    /// public-from-public shape of bug that `kem_seed_salt_hex` closed
    /// for ML-KEM. See the private design notes
    /// §2 ("The blocker — `derive_keypair` has no salt seam") and R-14
    /// in `KNOWN-ISSUES.md`.
    ///
    /// The bug shape: prior to this field, the libp2p Keypair was derived
    /// from `node_id` ALONE in `crates/pqcd/src/p2p.rs::derive_keypair`.
    /// `node_id` is publicly observable (logs, `/v1/status`, peer-info),
    /// so anyone who knew it could recompute the long-term libp2p identity
    /// secret. Scope: the libp2p TLS production transport uses **ephemeral**
    /// KEM keys per connection (channel confidentiality is unaffected),
    /// but the long-term Ed25519 identity is used for GossipSub envelope
    /// `MessageAuthenticity::Signed` attribution — see R-14 for the
    /// harm framing under CRQC.
    ///
    /// The fix: include this 32-byte secret in the SHA3-256 derivation
    /// inputs. The libp2p Keypair becomes a function of (public node_id,
    /// secret salt) — non-recoverable from `node_id` alone. Rotating
    /// this salt + restarting pqcd is the mechanism behind the 90-day
    /// rotation cadence scoped for R-14 (operational guardrail).
    ///
    /// **Optional for back-compat**: when absent, derivation falls back
    /// to the legacy `node_id`-only path AND pqcd emits a startup `warn!`
    /// flagging the residual exposure. New deployments MUST set this.
    /// The legacy path is retained so existing tests + the 3-node
    /// viper-pq-1 running pre-fix node.json still boot without operator
    /// action; it is not the recommended steady state.
    #[serde(default)]
    pub libp2p_seed_salt_hex: Option<String>,

    /// HSM phase-plan integration — which `CommitSigner` backend to
    /// instantiate at startup. Default = `LocalKeystore` (zero-config
    /// back-compat with every existing devnet, testnet, and viper-pq-1
    /// deployment). See the private design notes and
    /// `crates/pqc-hsm`.
    #[serde(default)]
    pub signer_kind: pqc_hsm::SignerKind,

    /// HSM phase-plan integration — backend-specific connection params
    /// for the selected `signer_kind`. Default = `LocalKeystore` (no
    /// extra params). pqcd refuses to start if `signer_config.kind`
    /// disagrees with `signer_kind`.
    #[serde(default)]
    pub signer_config: pqc_hsm::SignerConfig,
}

fn default_epoch_duration() -> u64 {
    EPOCH_DURATION_DEVNET
}

fn default_unbonding_period() -> u64 {
    VALIDATOR_UNBONDING_PERIOD
}

fn default_distributed_signing_quorum_wait_ms() -> u64 {
    1500
}

impl Default for DevnetConfig {
    fn default() -> Self {
        Self {
            role: NodeRole::default(),
            sync_interval_ms: default_sync_interval_ms(),
            block_time_ms: default_block_time_ms(),
            proposer_address_hex: None,
            quorum_threshold: None,
            validators: Vec::new(),
            snapshot_source: None,
            epoch_duration: default_epoch_duration(),
            unbonding_period: default_unbonding_period(),
            keystore_path: None,
            distributed_signing: false,
            distributed_signing_quorum_wait_ms: default_distributed_signing_quorum_wait_ms(),
            attack_mode: None,
            kem_seed_salt_hex: None,
            libp2p_seed_salt_hex: None,
            signer_kind: pqc_hsm::SignerKind::default(),
            signer_config: pqc_hsm::SignerConfig::default(),
        }
    }
}

/// What this node is for — ADR-069.
///
/// The vocabulary is the Helm chart's (one StatefulSet per role) plus
/// `single_node` for the local quick-start. Behaviour is derived from
/// the predicates below, never from `matches!` at call sites, so a new
/// role is added in one place.
///
/// `producer` and `follower` are the pre-ADR-069 names; they are still
/// accepted when a `node.json` is read (as `validator` and `full`) and
/// are never written back. They go away at the first public minor
/// release after `viper-testnet-1` genesis.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    /// Local quick-start: one process is the whole chain. No validator
    /// set, no transport required.
    #[default]
    SingleNode,
    /// Signs and proposes blocks; holds the consensus key. Its API is
    /// private by contract (sentries front it).
    #[serde(alias = "producer")]
    Validator,
    /// Bridge between the validator and the public network: dials the
    /// validator on the VFN network, relays gossip, never signs.
    Sentry,
    /// Validates everything, signs nothing, serves the read API.
    #[serde(alias = "follower")]
    Full,
    /// A full node whose only job is the public read API (HPA-friendly).
    Rpc,
    /// A full node that keeps the whole history and feeds the archival
    /// sidecar. `snapshot-prune` refuses to touch it.
    Archive,
    /// DNS-stable seed peer: public P2P only, private API.
    Bootnode,
}

/// Pre-ADR-069 name of [`NodeRole`], kept for the call sites and tests
/// that still spell it this way.
pub type DevnetRole = NodeRole;

impl NodeRole {
    /// The `node.json` spelling of this role.
    pub const fn as_str(self) -> &'static str {
        match self {
            NodeRole::SingleNode => "single_node",
            NodeRole::Validator => "validator",
            NodeRole::Sentry => "sentry",
            NodeRole::Full => "full",
            NodeRole::Rpc => "rpc",
            NodeRole::Archive => "archive",
            NodeRole::Bootnode => "bootnode",
        }
    }

    /// Every role, in the order the chart lists them, then `single_node`.
    pub const ALL: [NodeRole; 7] = [
        NodeRole::Validator,
        NodeRole::Sentry,
        NodeRole::Full,
        NodeRole::Rpc,
        NodeRole::Archive,
        NodeRole::Bootnode,
        NodeRole::SingleNode,
    ];

    /// Holds signing material and takes part in block production.
    pub const fn is_validator(self) -> bool {
        matches!(self, NodeRole::Validator | NodeRole::SingleNode)
    }

    /// Runs the multi-node BFT consensus loop as an elected proposer.
    /// `single_node` produces blocks through its own path, so it is
    /// deliberately not included here.
    pub const fn runs_bft_consensus_loop(self) -> bool {
        matches!(self, NodeRole::Validator)
    }

    /// Must be given a static validator set (`devnet.validators`).
    pub const fn requires_validator_set(self) -> bool {
        !matches!(self, NodeRole::SingleNode)
    }

    /// Must have at least one transport (`p2p_listen_addr` or libp2p).
    pub const fn requires_p2p_transport(self) -> bool {
        !matches!(self, NodeRole::SingleNode)
    }

    /// Catches up from peers instead of producing blocks.
    pub const fn syncs_from_peers(self) -> bool {
        !self.is_validator()
    }

    /// `snapshot-prune` refuses this role without `--force`.
    pub const fn keeps_full_history(self) -> bool {
        matches!(
            self,
            NodeRole::Validator | NodeRole::SingleNode | NodeRole::Archive
        )
    }

    /// Whether `api.public_tx_submission` is expected to be on. A
    /// validator or a bootnode accepting public transactions is
    /// reported by the startup lint.
    pub const fn serves_public_tx_submission(self) -> bool {
        !matches!(
            self,
            NodeRole::Validator | NodeRole::Bootnode | NodeRole::SingleNode
        )
    }

    /// Whether the API is meant to be reachable beyond the pod / host.
    pub const fn api_is_private(self) -> bool {
        matches!(self, NodeRole::Validator | NodeRole::Bootnode)
    }

    /// Which libp2p network this role joins (ADR-041): decides the
    /// `libp2p.*_listen` field that must be set.
    pub fn p2p_role(self) -> pqc_p2p::config::NodeRole {
        use pqc_p2p::config::NodeRole as P2p;
        match self {
            NodeRole::Validator | NodeRole::SingleNode => P2p::Validator,
            NodeRole::Sentry => P2p::ValidatorFullnode,
            NodeRole::Full | NodeRole::Rpc | NodeRole::Archive | NodeRole::Bootnode => {
                P2p::PublicFullnode
            }
        }
    }

    /// The `libp2p` config field that carries this role's listen address.
    pub const fn libp2p_listen_field(self) -> &'static str {
        match self {
            NodeRole::Validator | NodeRole::SingleNode => "validator_listen",
            NodeRole::Sentry => "vfn_listen",
            NodeRole::Full | NodeRole::Rpc | NodeRole::Archive | NodeRole::Bootnode => {
                "public_listen"
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorConfig {
    pub node_id: String,
    pub address_hex: String,
    pub sig_alg_id: u16,
    pub public_key_hex: String,
    #[serde(default)]
    pub commit_seed_hex: Option<String>,
    /// Optional SLH-DSA-SHAKE-256s secret key (hex, 128 bytes) for the M4.4
    /// archival-overlay signer path. Kept alongside `commit_seed_hex` so a
    /// devnet genesis config can pin a full signing operator in one place;
    /// production deployments should prefer the runtime `keystore_path` file
    /// (see `Keystore::load_from_file`) so the archival key never enters
    /// source-controlled JSON.
    #[serde(default)]
    pub archival_sk_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisAccountConfig {
    pub address_hex: String,
    pub balance: u128,
    pub nonce: u64,
    #[serde(default)]
    pub keys: Vec<GenesisKeyConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisKeyConfig {
    pub alg_id: u16,
    pub pk_hex: String,
    pub key_version: u32,
    pub valid_from_height: u64,
    pub status: GenesisKeyStatus,
    pub allowed_tx_types: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenesisKeyStatus {
    Pending,
    Active,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeBootstrapReport {
    pub config_path: PathBuf,
    pub data_dir: PathBuf,
    pub chain_height: u64,
    pub tip_hash: BlockHash,
    pub state_root: BlockHash,
    pub recovery_source: RecoverySource,
    pub checkpoint: Option<TrustedCheckpointMetadata>,
    pub account_count: usize,
}

pub fn bootstrap_from_config_path(config_path: &Path) -> Result<NodeBootstrapReport> {
    let config = load_node_config(config_path)?;
    let genesis_state = build_genesis_state(&config)?;
    let anchor_prev_hash = BlockHash(decode_hex_array::<32>(
        &config.anchor_prev_hash_hex,
        "anchor_prev_hash_hex",
    )?);

    let disk = open_disk_store_from_config(&config, anchor_prev_hash.clone())?;
    // ADR-054 §Stage 6 — fast-fail integrity audit BEFORE we attempt
    // a state-replay recovery. Catches the 2026-04-25 bug class
    // (silent persistence of an unfinalized block) at the cheapest
    // possible point: a single linear scan of `commit_signatures`
    // over the in-memory tail, no state machine execution.
    disk.verify_quick_finality_invariants().context(
        "ADR-054 §Stage 6 integrity audit refused startup — recover via snapshot-import",
    )?;
    let recovery = disk
        .recover_tip_with_checkpoint(
            &genesis_state,
            config.fee_params.clone(),
            Default::default(),
            vec![],
        )
        .context("failed to bootstrap node state from persisted chain history")?;

    if recovery.replay.height != disk.height() {
        bail!(
            "bootstrap height mismatch: recovered {}, chain store {}",
            recovery.replay.height,
            disk.height()
        );
    }

    let report = NodeBootstrapReport {
        config_path: config_path.to_path_buf(),
        data_dir: config.data_dir,
        chain_height: recovery.replay.height,
        tip_hash: recovery.replay.tip_hash,
        state_root: recovery.replay.state_root,
        recovery_source: recovery.source,
        checkpoint: recovery.checkpoint,
        account_count: recovery.replay.state.accounts_in_order().len(),
    };

    tracing::info!(
        height = report.chain_height,
        accounts = report.account_count,
        recovery_source = render_recovery_source(report.recovery_source),
        tip_hash = %hex::encode(report.tip_hash.0),
        "node bootstrap complete",
    );

    Ok(report)
}

/// Bootstrap the node and return a ready-to-serve `SharedState` for the API.
///
/// Unlike `bootstrap_from_config_path`, this function keeps the `RocksDbChainStore`
/// open so the API handlers can query committed blocks and transactions.
pub fn open_node_state(config_path: &Path) -> Result<SharedState> {
    let config = load_node_config(config_path)?;
    let genesis_state = build_genesis_state(&config)?;
    let anchor_prev_hash = BlockHash(decode_hex_array::<32>(
        &config.anchor_prev_hash_hex,
        "anchor_prev_hash_hex",
    )?);

    let disk = open_disk_store_from_config(&config, anchor_prev_hash)?;
    // ADR-054 §Stage 6 — same fast-fail audit as in
    // `bootstrap_from_config_path`. Both API and devnet entry points
    // run it so neither path can start on a chain that has a
    // non-finalized block on disk.
    disk.verify_quick_finality_invariants().context(
        "ADR-054 §Stage 6 integrity audit refused startup — recover via snapshot-import",
    )?;
    let recovery = disk
        .recover_tip_with_checkpoint(
            &genesis_state,
            config.fee_params.clone(),
            Default::default(),
            vec![],
        )
        .context("failed to recover node state from persisted chain history")?;

    let chain_id = genesis_state.chain_id().to_vec();

    tracing::info!(
        height = recovery.replay.height,
        recovery_source = match recovery.source {
            RecoverySource::FullReplay => "full_replay",
            RecoverySource::TrustedCheckpoint => "trusted_checkpoint",
        },
        "api node state ready",
    );

    Ok(Arc::new(ApiNodeState {
        chain_id,
        recovery_source: recovery.source,
        state: recovery.replay.state,
        disk,
    }))
}

/// Export the node's current trusted checkpoint as portable snapshot bytes.
///
/// Returns `(height, cbor_bytes)` or an error if no checkpoint exists.
pub fn snapshot_export(config_path: &Path) -> Result<(u64, Vec<u8>)> {
    let config = load_node_config(config_path)?;
    let anchor_prev_hash = BlockHash(decode_hex_array::<32>(
        &config.anchor_prev_hash_hex,
        "anchor_prev_hash_hex",
    )?);
    let disk = open_disk_store_from_config(&config, anchor_prev_hash)?;
    let bytes = disk
        .export_checkpoint_bytes()
        .context("failed to read checkpoint from disk")?
        .context("no checkpoint found — run the node at least once to write a checkpoint")?;
    let (height, _) = RocksDbChainStore::decode_snapshot_metadata(&bytes)
        .context("failed to decode checkpoint metadata")?;
    Ok((height, bytes))
}

/// Import a snapshot file as the trusted checkpoint for this node's data directory.
///
/// The node must be stopped. Returns the imported checkpoint metadata on success.
/// Trust boundary: the caller vouches for the snapshot source.
pub fn snapshot_import(
    config_path: &Path,
    snapshot_bytes: &[u8],
) -> Result<TrustedCheckpointMetadata> {
    let config = load_node_config(config_path)?;
    let genesis_state = build_genesis_state(&config)?;
    let anchor_prev_hash = BlockHash(decode_hex_array::<32>(
        &config.anchor_prev_hash_hex,
        "anchor_prev_hash_hex",
    )?);
    let mut disk = open_disk_store_from_config(&config, anchor_prev_hash)?;
    let chain_id = genesis_state.chain_id().to_vec();
    disk.bootstrap_from_external_snapshot(snapshot_bytes, &[], &chain_id)
        .context("snapshot import failed")
}

/// TASK-187a — permanently delete blocks below `tip - keep_tail_blocks` from
/// the on-disk RocksDB chain store, keeping the most recent trusted checkpoint
/// + a tail of `keep_tail_blocks` blocks for disaster recovery.
///
/// The node MUST be stopped before calling this — RocksDB is opened
/// exclusively. Returns the [`PruneStats`] from
/// [`RocksDbChainStore::prune_blocks_below`] so the caller can log
/// per-CF deletion counts to the operator's `prune.log`.
///
/// Refuses to run on roles that hold full chain history (`producer`,
/// `archive`) regardless of the configured `keep_tail_blocks` — those
/// nodes should never prune. Pass `force = true` to override the role
/// guard during incident-response only (logged at WARN level).
pub fn snapshot_prune(
    config_path: &Path,
    keep_tail_blocks: u64,
    force: bool,
) -> Result<pqc_consensus::PruneStats> {
    let config = load_node_config(config_path)?;

    // Role guard — Producer + SingleNode keep full chain history; only
    // Follower-roled nodes are eligible. The `archive` k8s role is a
    // sidecar concept the binary does not track internally; that policy
    // is enforced by the Ansible inventory variable `viper_prune_enabled`
    // gating the systemd timer (see deploy/ansible/roles/configure).
    let role = config.devnet.role;
    let role_str = role.as_str();
    if role.keeps_full_history() && !force {
        anyhow::bail!(
            "snapshot-prune refused: node role '{role_str}' must keep full chain history. \
             Pass --force only for incident-response and only on a node you intend to \
             rebuild from a producer's data dir afterwards."
        );
    }

    let anchor_prev_hash = BlockHash(decode_hex_array::<32>(
        &config.anchor_prev_hash_hex,
        "anchor_prev_hash_hex",
    )?);
    let mut disk = open_disk_store_from_config(&config, anchor_prev_hash)?;

    let tip = disk.height();
    if tip == 0 {
        anyhow::bail!("snapshot-prune refused: chain store is empty (tip = 0)");
    }
    if keep_tail_blocks >= tip {
        // Nothing to prune — the entire chain is within the tail window.
        tracing::info!(
            tip_height = tip,
            keep_tail_blocks,
            "snapshot-prune: tail window covers the whole chain — no-op",
        );
        return Ok(pqc_consensus::PruneStats::default());
    }
    let cutoff = tip.saturating_sub(keep_tail_blocks);

    if force && role.keeps_full_history() {
        tracing::warn!(
            role = role_str,
            cutoff,
            tip_height = tip,
            "snapshot-prune force-overriding role guard",
        );
    }

    disk.prune_blocks_below(cutoff)
        .context("prune_blocks_below failed")
}

/// TASK-188 / TASK-188b — cold-storage export driver. Opens the chain
/// store no_wal (pqcd must be stopped while this runs, same as
/// snapshot-prune), reads heights `1..=cutoff` and writes them as
/// zstd-compressed batches + a manifest JSON to `output_dir`. When the
/// caller passes `--sign-with-operator`, the manifest is also signed
/// with the operator's archival_sk slot from the configured keystore.
/// When `--anchor-tsa` is set, the manifest is anchored against an
/// RFC 3161 TSA.
pub fn cold_storage_export(
    config_path: &Path,
    cutoff: u64,
    batch_size: u64,
    output_dir: &Path,
    opts: &crate::cold_storage::ExportOptions,
) -> Result<crate::cold_storage::ColdStorageManifest> {
    let config = load_node_config(config_path)?;
    let anchor_prev_hash = BlockHash(decode_hex_array::<32>(
        &config.anchor_prev_hash_hex,
        "anchor_prev_hash_hex",
    )?);
    let disk = open_disk_store_from_config(&config, anchor_prev_hash)?;

    // Build a keystore only when signing was requested. Using
    // `Keystore::from_validators` covers the genesis-bundled-seed path
    // (devnet); a configured `keystore_path` adds dynamically-registered
    // operators on top. Both fall back to None when signing is off so
    // an unsigned export does not fail because of an absent keystore.
    let keystore = if opts.sign_with_operator_hex.is_some() {
        let mut ks = crate::keystore::Keystore::from_validators(&config.devnet.validators, true)
            .context("failed to load keystore from devnet.validators[]")?;
        if let Some(path) = config.devnet.keystore_path.as_ref() {
            // Best-effort merge: missing file is "no extra seeds".
            ks.reload_if_changed(path)
                .with_context(|| format!("failed to load keystore from {}", path.display()))?;
        }
        Some(ks)
    } else {
        None
    };

    crate::cold_storage::export_cold_storage(
        &disk,
        config.chain_id_hex,
        cutoff,
        batch_size,
        output_dir,
        keystore.as_ref(),
        opts,
    )
}

/// TASK-188b — cold-storage import driver. Opens the chain store
/// (must be empty / freshly-bootstrapped — see
/// `import_cold_storage` for the precondition), reads
/// `manifest.json` + the per-batch `.zst` files from `input_dir`,
/// verifies the manifest signature unless `opts.insecure_no_verify`,
/// and replays each block via `append_stored_block` with no
/// quorum policy (the manifest signature already attests authenticity).
pub fn cold_storage_import(
    config_path: &Path,
    input_dir: &Path,
    opts: &crate::cold_storage::ImportOptions,
) -> Result<crate::cold_storage::ImportSummary> {
    let config = load_node_config(config_path)?;
    let anchor_prev_hash = BlockHash(decode_hex_array::<32>(
        &config.anchor_prev_hash_hex,
        "anchor_prev_hash_hex",
    )?);
    let mut disk = open_disk_store_from_config(&config, anchor_prev_hash)?;
    crate::cold_storage::import_cold_storage(&mut disk, input_dir, opts)
}

pub fn render_status(report: &NodeBootstrapReport) -> String {
    let checkpoint_line = report
        .checkpoint
        .as_ref()
        .map(|checkpoint| {
            format!(
                "height={} tip_hash={} state_root={}",
                checkpoint.height,
                hex::encode(checkpoint.tip_hash.0),
                hex::encode(checkpoint.state_root.0)
            )
        })
        .unwrap_or_else(|| "none".to_owned());

    format!(
        "status:          ready\nconfig:          {}\ndata_dir:        {}\nchain_height:    {}\ntip_hash:        {}\nstate_root:      {}\naccounts:        {}\nrecovery_source: {}\ncheckpoint:      {}",
        report.config_path.display(),
        report.data_dir.display(),
        report.chain_height,
        hex::encode(report.tip_hash.0),
        hex::encode(report.state_root.0),
        report.account_count,
        render_recovery_source(report.recovery_source),
        checkpoint_line,
    )
}

pub(crate) fn load_node_config(config_path: &Path) -> Result<NodeConfig> {
    let raw = fs::read_to_string(config_path)
        .with_context(|| format!("failed to read node config {}", config_path.display()))?;
    let is_toml = config_path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("toml"))
        .unwrap_or(false);
    let mut config: NodeConfig = if is_toml {
        toml::from_str(&raw)
            .with_context(|| format!("failed to parse TOML config {}", config_path.display()))?
    } else {
        serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse JSON config {}", config_path.display()))?
    };
    // ADR-069 §3: `$VIPER_NODE_ID` overrides `node_id`. The chart sets it
    // from the pod name so replicas of one role get distinct libp2p / KEM
    // identities; `node_id` is not a consensus identity (validators are
    // known by address), it only seeds the transport keys and the logs.
    if let Ok(id) = std::env::var("VIPER_NODE_ID") {
        let id = id.trim();
        if !id.is_empty() && id != config.node_id {
            tracing::info!(
                configured = %config.node_id,
                effective = id,
                "node_id overridden by $VIPER_NODE_ID"
            );
            config.node_id = id.to_string();
        }
    }
    let _ = warn_on_three_network_misconfig(&config);
    warn_on_role_api_misconfig(&config);

    // FREE-KEY-ISOLATION-PHASE-PLAN.md Path 1: `$VIPER_KEYSTORE_PATH`
    // overrides `devnet.keystore_path` when set. This lets operators
    // inject the path to a credential-decrypted keystore exposed by
    // systemd's `LoadCredentialEncrypted=` directive (path =
    // `$CREDENTIALS_DIRECTORY/keystore`, set automatically by systemd
    // when the unit declares the credential). The on-disk node.json
    // does not need to be edited — the override is purely runtime.
    //
    // When VIPER_KEYSTORE_PATH is unset or empty, the field falls
    // through to whatever node.json declared (back-compat).
    if let Ok(env_path) = std::env::var("VIPER_KEYSTORE_PATH") {
        let trimmed = env_path.trim();
        if !trimmed.is_empty() {
            tracing::info!(
                keystore_path = %trimmed,
                "VIPER_KEYSTORE_PATH override: bypassing devnet.keystore_path from node.json"
            );
            config.devnet.keystore_path = Some(std::path::PathBuf::from(trimmed));
        }
    }

    Ok(config)
}

/// ADR-069 §2: the API posture a role is meant to have. Reports (never
/// fails) a validator, bootnode or single node whose `api.public_tx_submission`
/// is on: those roles are fronted by sentries / rpc nodes, they do not take
/// transactions from the public. The bind address is deliberately not judged
/// here — in the chart every pod binds a wildcard for the readiness probe and
/// privacy is the NetworkPolicy's job. Returns the number of findings.
pub(crate) fn warn_on_role_api_misconfig(config: &NodeConfig) -> usize {
    let role = config.devnet.role;
    let mut findings = 0;
    if !role.serves_public_tx_submission() && config.api.public_tx_submission {
        findings += 1;
        tracing::warn!(
            role = role.as_str(),
            "role does not serve public transaction submission but `api.public_tx_submission` \
             is true — front this node with a sentry or an rpc node instead"
        );
    }
    findings
}

/// TASK-219 — three-network architecture lint.
///
/// Validators MUST listen only on the validator-private network; a
/// validator that also listens on a publicly-bound `public_listen`
/// address is exposing the consensus signing path to the open
/// internet (the eclipse-attack vector this ADR pattern guards
/// against). Emit a WARN at config-load so operators see the
/// mis-config in their boot logs without forcing a hard failure
/// — devnets and single-host test rigs intentionally collapse all
/// three networks onto one binding and we don't want to break those.
///
/// The lint is purely informational; pqcd never refuses to start
/// based on this check. Operators that *want* the merged-network
/// topology silence the warning by setting `libp2p.public_listen` to
/// a loopback address (`127.0.0.1` / `::1`) — explicit "yes I know"
/// rather than a default-permissive bypass flag.
/// Returns `true` when the lint emitted a warning. Surfaced for unit
/// tests; the production caller drops the value.
fn warn_on_three_network_misconfig(config: &NodeConfig) -> bool {
    let Some(libp2p) = config.libp2p.as_ref() else {
        return false;
    };
    if !libp2p.enable {
        return false;
    }
    let role = config.devnet.role;
    let role_str = role.as_str();
    let is_validator_role = role.is_validator();
    if !is_validator_role {
        return false;
    }
    let Some(public_listen) = libp2p.public_listen.as_deref() else {
        return false;
    };
    // Bound to a wildcard (0.0.0.0 / ::) is the case we warn on. Loopback
    // bindings (127.0.0.1, ::1) are explicit "this listener is local-only".
    let is_publicly_bound = public_listen.contains("0.0.0.0")
        || public_listen.contains("[::]")
        || public_listen.contains("/ip4/0.0.0.0/")
        || public_listen.contains("/ip6/::/");
    if !is_publicly_bound {
        return false;
    }
    tracing::warn!(
        role = role_str,
        public_listen = %public_listen,
        "TASK-219 three-network lint: validator-class role with a publicly-bound \
         libp2p.public_listen exposes the consensus signing path to the open \
         internet. Recommended topology: validators bind only validator_listen, \
         VFN bridges, public RPC on a sentry node. See docs/operators/RUNBOOK.md §11.3.",
    );
    true
}

pub(crate) fn open_disk_store_from_config(
    config: &NodeConfig,
    anchor_prev_hash: BlockHash,
) -> Result<RocksDbChainStore> {
    // Phase 8 M2 (TASK-113): the storage backend no longer carries a
    // static commit-quorum policy. Quorum validation happens at the
    // append-block caller, which derives the policy per-block from
    // `StateStore::active_validators()`. `build_commit_quorum_policy`
    // is still called so config-validation errors surface here (e.g.
    // duplicate validator addresses in node.json); the resulting
    // policy is dropped — state is the source of truth.
    let _commit_policy = build_commit_quorum_policy(config)?;
    let rocksdb_path = config.data_dir.join("rocksdb");
    // In test builds, always disable the WAL to avoid fsync overhead that causes
    // throughput regressions in debug mode (load_test CI threshold: ≥10 TPS).
    // Production builds always use WAL (durability required).
    #[cfg(test)]
    let disable_wal = true;
    #[cfg(not(test))]
    let disable_wal = false;
    // Policy P-COMPAT-001 §(3) — chain_id pre-flight guard (ADR-052).
    // The configured `chain_id_hex` is written to the store on first open
    // and enforced on every subsequent open; mismatch is a hard failure
    // that prevents the 2026-04-24 rc1 scenario (binary built for chain X
    // restarting against a data directory from chain Y and falling
    // through to full_replay).
    let configured_chain_id = decode_hex_bytes(&config.chain_id_hex, "chain_id_hex")?;
    let open_result = if disable_wal {
        RocksDbChainStore::open_no_wal_with_chain_id(
            &rocksdb_path,
            anchor_prev_hash,
            &configured_chain_id,
        )
    } else {
        RocksDbChainStore::open_with_chain_id(&rocksdb_path, anchor_prev_hash, &configured_chain_id)
    };
    let store = open_result.with_context(|| {
        format!(
            "failed to open RocksDB chain store at {}",
            rocksdb_path.display()
        )
    })?;

    // ADR-031 / TASK-102: run state-format migrations automatically on boot.
    // If the checkpoint was written by an older binary, the handler chain
    // transforms the state and rewrites the checkpoint with the current version.
    let registry = pqc_state::global_registry();
    store
        .apply_upgrade_chain(&registry)
        .with_context(|| "state migration failed — see logs for details")?;

    Ok(store)
}

/// Migrate a legacy `DiskChainStore` data directory to a `RocksDbChainStore`.
///
/// Reads all blocks from the legacy flat-file store at `legacy_data_dir` and writes
/// them to a new RocksDB store at `<new_data_dir>/rocksdb`.  Also migrates the
/// trusted checkpoint if one exists.  The tx_index CF is populated from block data.
///
/// Prerequisites:
/// - The node must be stopped.
/// - `legacy_data_dir` must contain a valid `DiskChainStore` (blocks/, hashes/, etc.).
/// - `new_data_dir` must be writable and distinct from `legacy_data_dir`.
pub fn migrate_store(config_path: &Path) -> Result<()> {
    let config = load_node_config(config_path)?;
    let anchor_prev_hash = BlockHash(decode_hex_array::<32>(
        &config.anchor_prev_hash_hex,
        "anchor_prev_hash_hex",
    )?);

    // Open the legacy store.
    let commit_policy = build_commit_quorum_policy(&config)?;
    let legacy = match &commit_policy {
        Some(policy) => DiskChainStore::open_with_commit_policy(
            &config.data_dir,
            anchor_prev_hash.clone(),
            policy.clone(),
        ),
        None => DiskChainStore::open(&config.data_dir, anchor_prev_hash.clone()),
    }
    .context("failed to open legacy DiskChainStore")?;

    let tip_height = legacy.height();
    println!("migrate-store: legacy tip_height={tip_height}");

    // Open (create) the new RocksDB store.
    let rocksdb_path = config.data_dir.join("rocksdb");
    std::fs::create_dir_all(&rocksdb_path)
        .with_context(|| format!("cannot create {}", rocksdb_path.display()))?;
    let mut rdb = RocksDbChainStore::open(&rocksdb_path, anchor_prev_hash)
        .context("failed to create RocksDB store")?;

    // Migrate all blocks.
    for h in 1..=tip_height {
        let stored = legacy
            .read_stored_block_at_height(h)
            .with_context(|| format!("read legacy block at height {h}"))?
            .with_context(|| format!("missing block at height {h} in legacy store"))?;
        // Phase 8 M2 migration path: no quorum policy — the blocks
        // being copied were already validated when first produced on
        // the legacy store. Policy-less append mirrors the post-M2
        // restore-from-disk semantics (trust-on-disk).
        rdb.append_stored_block(stored, None)
            .with_context(|| format!("write block at height {h} to RocksDB"))?;
        if h.is_multiple_of(1000) {
            println!("  migrated {h}/{tip_height} blocks …");
        }
    }

    // Migrate checkpoint if present.
    if let Some(checkpoint_bytes) = legacy
        .export_checkpoint_bytes()
        .context("read legacy checkpoint")?
    {
        rdb.import_checkpoint_for_migration(&checkpoint_bytes)
            .context("import checkpoint into RocksDB")?;
        println!("migrate-store: checkpoint migrated");
    }

    println!(
        "migrate-store: done — {tip_height} blocks written to {}",
        rocksdb_path.display()
    );
    println!(
        "migrate-store: the legacy files in {} are preserved; remove manually after verification",
        config.data_dir.display()
    );
    Ok(())
}

pub(crate) fn build_genesis_state(config: &NodeConfig) -> Result<StateStore> {
    let chain_id = decode_hex_bytes(&config.chain_id_hex, "chain_id_hex")?;
    let accounts = config
        .genesis_accounts
        .iter()
        .map(account_from_config)
        .collect::<Result<Vec<_>>>()?;
    let mut store = StateStore::from_snapshot_accounts(accounts, 0, chain_id);

    // Seed on-chain validator registry from genesis config (TASK-064, GAP-04 closure).
    // Genesis validators are inserted with status Active at height 0.
    for v in &config.devnet.validators {
        let alg_id = AlgId::from_u16(v.sig_alg_id)
            .ok_or_else(|| anyhow!("unknown devnet validator alg_id 0x{:04x}", v.sig_alg_id))?;
        let pk = decode_hex_bytes(&v.public_key_hex, "devnet.validators[].public_key_hex")?;
        let operator_bytes =
            decode_hex_array::<32>(&v.address_hex, "devnet.validators[].address_hex")?;
        store.insert_validator(ValidatorRecord {
            operator: Address(operator_bytes),
            node_id: v.node_id.clone(),
            consensus_alg_id: alg_id,
            consensus_pk: pk,
            self_bond: 0, // genesis validators have no self-bond; staking is Phase 2
            status: ValidatorStatus::Active,
            registered_height: 0,
            tombstoned: false,
        });
    }

    Ok(store)
}

pub(crate) fn build_commit_quorum_policy(
    config: &NodeConfig,
) -> Result<Option<CommitQuorumPolicy>> {
    if config.devnet.validators.is_empty() {
        return Ok(None);
    }

    let validators = config
        .devnet
        .validators
        .iter()
        .map(commit_validator_from_config)
        .collect::<Result<Vec<_>>>()?;
    CommitQuorumPolicy::new(validators, config.devnet.quorum_threshold)
        .map(Some)
        .map_err(|err| anyhow!("invalid devnet validator config: {err}"))
}

fn commit_validator_from_config(config: &ValidatorConfig) -> Result<CommitValidator> {
    Ok(CommitValidator {
        node_id: config.node_id.clone(),
        address: decode_hex_bytes(&config.address_hex, "devnet.validators[].address_hex")?,
        sig_alg_id: AlgId::from_u16(config.sig_alg_id).ok_or_else(|| {
            anyhow!(
                "unknown devnet validator alg_id 0x{:04x}",
                config.sig_alg_id
            )
        })?,
        public_key: decode_hex_bytes(&config.public_key_hex, "devnet.validators[].public_key_hex")?,
    })
}

fn account_from_config(config: &GenesisAccountConfig) -> Result<Account> {
    let keys = config
        .keys
        .iter()
        .map(key_from_config)
        .collect::<Result<Vec<_>>>()?;

    let account = Account {
        address: Address(decode_hex_array::<32>(&config.address_hex, "address_hex")?),
        balance: config.balance,
        nonce: config.nonce,
        keys: KeySet(keys),
        policy_version: 0,
        policy_hash: None,
        verifier_template_id: pqc_types::account::VERIFIER_TEMPLATE_ID_EOA,
        auth_data: Vec::new(),
    };
    account
        .check_invariants()
        .map_err(|detail| anyhow!("invalid genesis account {}: {detail}", account.address))?;
    Ok(account)
}

fn key_from_config(config: &GenesisKeyConfig) -> Result<KeyEntry> {
    let alg_id = AlgId::from_u16(config.alg_id)
        .ok_or_else(|| anyhow!("unknown genesis alg_id 0x{:04x}", config.alg_id))?;

    Ok(KeyEntry {
        alg_id,
        pk_bytes: decode_hex_bytes(&config.pk_hex, "pk_hex")?.into(),
        key_version: config.key_version,
        valid_from_height: config.valid_from_height,
        status: match config.status {
            GenesisKeyStatus::Pending => KeyStatus::Pending,
            GenesisKeyStatus::Active => KeyStatus::Active,
            GenesisKeyStatus::Revoked => KeyStatus::Revoked,
        },
        allowed_tx_types: config.allowed_tx_types,
    })
}

pub(crate) fn decode_hex_array<const N: usize>(raw: &str, field: &str) -> Result<[u8; N]> {
    let bytes = decode_hex_bytes(raw, field)?;
    let actual = bytes.len();
    bytes
        .try_into()
        .map_err(|_: Vec<u8>| anyhow!("{field} must decode to exactly {N} bytes, got {actual}"))
}

pub(crate) fn decode_hex_bytes(raw: &str, field: &str) -> Result<Vec<u8>> {
    let trimmed = raw.trim();
    let normalized = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    hex::decode(normalized).with_context(|| format!("{field} is not valid hex"))
}

fn render_recovery_source(source: RecoverySource) -> &'static str {
    match source {
        RecoverySource::FullReplay => "full_replay",
        RecoverySource::TrustedCheckpoint => "trusted_checkpoint",
    }
}

fn default_node_id() -> String {
    "node-local".to_owned()
}

fn default_sync_interval_ms() -> u64 {
    250
}

fn default_block_time_ms() -> u64 {
    1_000
}

#[cfg(test)]
mod tests;
