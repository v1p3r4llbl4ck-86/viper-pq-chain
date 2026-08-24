// SPDX-License-Identifier: BUSL-1.1
//! TASK-233 — chart ceremony tooling.
//!
//! Generates a Helm values file ready for
//!     helm install ./charts/viper-pq-chain -f values-ceremony.json
//! that brings up a working dev/test chain on a fresh cluster (kind, GKE,
//! EKS, on-prem) with no manual ceremony work. Closes the gap between
//! the chart's structural completeness and the operator's "I want to
//! deploy a chain in five minutes on a new cluster" request that
//! surfaced during the 2026-05-05 kind smoke-test of the chart.
//!
//! What this module produces (per `CeremonyConfig`):
//!
//!   - Per-validator commit_seed (32 random bytes from the OS CSPRNG)
//!     embedded in `kubernetes.secrets[*]` of the Helm values so the
//!     same `helm install` provisions both the data Secrets AND wires
//!     them into the StatefulSets via `consensusKey.secretName`.
//!
//!   - chain_id_hex computed as the UTF-8 byte hex of `chain_id`
//!     (matches the Ansible role `configure/tasks/main.yml::Compute
//!     chain_id_hex from chain_id string` task and the SPEC-GENESIS-001
//!     §0 contract).
//!
//!   - Per-validator `address_hex` + `public_key_hex` derived from the
//!     seed via the same code path the binary uses at runtime
//!     (`pqc_crypto::ml_dsa_public_key_from_seed` + ADR-053 §T1.3 +
//!     §T2.4 `derive_address(chain_id, alg_id, pk_bytes)`). The values
//!     bind to the `chain_id`, so a re-run with a different chain_id
//!     yields different addresses for the same seed — preventing
//!     cross-chain replay (which is the entire point of §T1.3).
//!
//!   - A complete `node.json` per enabled role (validator / sentry / full)
//!     with all fields the pqcd binary requires at boot — the schema
//!     mirrors `deploy/ansible/roles/configure/templates/node-config.json.j2`
//!     populated from `deploy/ansible/group_vars/all/defaults.yml` so
//!     follower / sentry / full nodes converge on the same fee_market,
//!     rate_limit, sender_budget, and devnet config the live
//!     viper-pq-1 hosts run.
//!
//!   - A `genesis.json` per SPEC-GENESIS-001 (chain_id, chain_id_hex,
//!     fork_version, distributed_signing config, genesis_validators[]
//!     with the derived addresses + pubkeys). Some computed fields
//!     (`genesis_validators_root`, `genesis_block.extension_root`,
//!     `genesis_block.timestamp_ns`) are emitted as descriptive
//!     placeholders because pqcd computes them at first run — same
//!     contract as `deploy/ansible/files/genesis-viper-pq-1.json`.
//!
//!   - Helm `image.pullSecrets` wiring + a Secret manifest for the
//!     deploy token if the operator passes `--deploy-token`.
//!
//! What this module does NOT produce:
//!
//!   - A full alg_registry / hash_registry / auth_template_registry /
//!     fee_market reference like genesis-viper-pq-1.json. pqcd does not
//!     yet read those from genesis.json (per the `genesis_loader_status`
//!     note in genesis-viper-pq-1.json `_operator_notes`); the
//!     authoritative source is still per-role node.json. We keep this
//!     module aligned with what pqcd actually consumes and skip the
//!     decorative blocks until the genesis loader is wired.
//!
//!   - SPEC-GENESIS-001 §3 BIP340 double-tagged `genesis_hash`. pqcd
//!     computes it deterministically at block-0 finalisation; emitting
//!     a placeholder here matches the live launch artefact's behaviour.

use crate::node::NodeRole;
use anyhow::{anyhow, Context, Result};
use pqc_crypto::{address::derive_address, ml_dsa_public_key_from_seed, AlgId};
use pqc_types::{account::Address, fork::compute_genesis_validators_root};
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Inputs to `generate_ceremony_values`. Built by the `pqcd ceremony`
/// subcommand from CLI flags + sensible defaults.
#[derive(Debug, Clone)]
pub struct CeremonyConfig {
    /// Logical chain id (UTF-8 string, no separators). Becomes
    /// `chain.id` in the Helm values and `chain_id` in node.json /
    /// genesis.json. The hex form is computed from this.
    pub chain_id: String,
    /// Number of genesis validators (≥ 1). The chart enables the
    /// `validator` role with replicas=1 and the `sentry` role with
    /// replicas=`validators`-aware count; any number > 1 also pins
    /// extra `validator-N` entries in `genesis_validators[]`.
    pub validators: u32,
    /// Block-target time in ms. Default 500 (matches viper-pq-1).
    pub block_time_ms: u64,
    /// Initial bonded stake (in venom = smallest unit) per genesis
    /// validator. Symmetric across the cohort to keep stake-weighted
    /// math (T1.5 churn limit) on the simplest possible distribution.
    pub genesis_balance: u128,
    /// Image repo (registry/group/project). Default
    /// `ghcr.io/v1p3r4llbl4ck-86`.
    pub image_repository: String,
    /// Image tag for pqcd / notary / archival-sidecar. Default `main`.
    pub image_tag: String,
    /// Helm release name the operator will pass to `helm install`.
    /// Used to construct the in-cluster DNS for the validator's
    /// headless service (`<release>-viper-pq-chain-pqcd-validator-headless.<ns>.svc.cluster.local`)
    /// embedded in the sentry / full nodes' `libp2p.bootstrap_peers`.
    /// Default `viper-test` matches the chart README's quick-install
    /// example. Mismatched release name → bootstrap dial fails →
    /// followers stay at height 0 (the gap the 2026-05-05 smoke caught).
    pub release_name: String,
    /// Kubernetes namespace the chart will land in. Same role as
    /// `release_name`: feeds the cluster-DNS multiaddr for libp2p
    /// bootstrap peers.
    pub namespace: String,
    /// Optional GitLab deploy-token credentials. If `Some`, the values
    /// file emits a `kubernetes.imagePullSecret` block + a referenced
    /// `image.pullSecrets[]` entry so the chart can pull from a
    /// private registry without manual `kubectl create secret`.
    pub deploy_token: Option<DeployToken>,
}

/// GitLab deploy-token credentials embedded in a Kubernetes
/// `dockerconfigjson` secret. Stored verbatim in the values file —
/// the operator is expected to keep the values file private (mode
/// 0600) until `helm install` consumes it.
#[derive(Debug, Clone)]
pub struct DeployToken {
    pub registry: String,
    pub username: String,
    pub password: String,
}

/// Output of `generate_ceremony_values` — the full Helm values tree
/// rendered as `serde_json::Value`. Serialise to a string with
/// `serde_json::to_string_pretty` and write to disk; Helm accepts
/// JSON values files transparently (YAML is a superset).
pub type CeremonyValues = serde_json::Value;

/// One line of the operator-facing ceremony summary printed to stderr
/// alongside the values file. Captures the seed → address derivation
/// in a form the operator can paste into runbooks for incident
/// response without re-running the ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorEntry {
    pub node_id: String,
    pub address_hex: String,
    pub public_key_hex: String,
    pub commit_seed_hex: String,
    pub consensus_alg_id: u16,
}

/// SPEC-GENESIS-001 §0 — chain_id_hex is the UTF-8 byte hex of the
/// chain_id string, no separators. Pure function, deterministic, the
/// inverse of `hex::decode`.
pub fn compute_chain_id_hex(chain_id: &str) -> String {
    hex::encode(chain_id.as_bytes())
}

/// Derive the genesis-validator entry for a given seed. Wraps
/// [`pqc_crypto::ml_dsa_public_key_from_seed`] + [`derive_address`]
/// so callers don't drift from the binary's runtime path.
pub fn derive_validator_entry(
    node_id: String,
    chain_id_bytes: &[u8],
    seed: &[u8; 32],
    alg_id: AlgId,
) -> Result<ValidatorEntry> {
    let pk_bytes = ml_dsa_public_key_from_seed(alg_id, seed)
        .map_err(|e| anyhow!("ml_dsa_public_key_from_seed failed: {e}"))?;
    let address = derive_address(chain_id_bytes, alg_id, &pk_bytes);
    Ok(ValidatorEntry {
        node_id,
        address_hex: hex::encode(address),
        public_key_hex: hex::encode(&pk_bytes),
        commit_seed_hex: hex::encode(seed),
        consensus_alg_id: alg_id.as_u16(),
    })
}

/// Generate `n` cryptographically random 32-byte seeds from the OS
/// CSPRNG. Each seed is fresh on every call — re-running the ceremony
/// produces a different validator cohort (idempotency is a non-goal;
/// rotation is the point).
pub fn generate_seeds(n: u32) -> Vec<[u8; 32]> {
    let mut rng = rand::rng();
    (0..n)
        .map(|_| {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            seed
        })
        .collect()
}

/// libp2p config bundle emitted into a per-role `node.json`. ADR-041
/// §3 — each role gets exactly one of `validator_listen` /
/// `vfn_listen` / `public_listen` set; `bootstrap_peers` is populated
/// for non-validator roles so they can find the validator inside the
/// k8s cluster on first boot. Discovered as the load-bearing gap from
/// the 2026-05-05 kind smoke (validator-only chain, sentries stuck at
/// height 0 because nothing connected them to the validator).
#[derive(Debug, Clone)]
struct Libp2pSection {
    /// `validator_listen`, `vfn_listen`, or `public_listen` per ADR-041.
    listen_field: &'static str,
    listen_addr: String,
    bootstrap_peers: Vec<String>,
}

/// G-01: the per-role identity salts. They never enter `node.json` (a
/// ConfigMap); the ceremony writes them into one Secret per role
/// (`<fullname>-pqcd-<role>-identity`, keys `libp2p_seed_salt_hex` and
/// `kem_seed_salt_hex`) and the chart hands them to pqcd as
/// `VIPER_LIBP2P_SEED_SALT_HEX` / `VIPER_KEM_SEED_SALT_HEX`.
#[derive(Debug, Clone)]
pub struct RoleIdentitySalts {
    pub role: NodeRole,
    pub secret_name: String,
    pub libp2p_seed_salt_hex: String,
    pub kem_seed_salt_hex: String,
}

/// Mirror of the chart's `viper-pq-chain.fullname` helper: `<release>-viper-pq-chain`,
/// or just `<release>` when the release name already contains the chart name.
fn chart_fullname(release: &str) -> String {
    if release.contains("viper-pq-chain") {
        release.to_string()
    } else {
        format!("{release}-viper-pq-chain")
    }
}

/// `<fullname>-pqcd-<role>-<ordinal>` — the StatefulSet pod name, which is
/// also the pod's `node_id` (ADR-069 §3) and therefore what its PeerId is
/// derived from.
fn pod_name(fullname: &str, role: &str, ordinal: u32) -> String {
    format!("{fullname}-pqcd-{role}-{ordinal}")
}

/// Multiaddr of a role's headless Service (resolves to every pod of the
/// role); the PeerId is the one of ordinal 0, which is what a single-replica
/// role (the validator) runs as.
fn headless_multiaddr(fullname: &str, role: &str, ns: &str, salt: Option<&[u8; 32]>) -> String {
    let peer_id = crate::p2p::deterministic_peer_id(&pod_name(fullname, role, 0), salt);
    format!("/dns4/{fullname}-pqcd-{role}-headless.{ns}.svc.cluster.local/tcp/26656/p2p/{peer_id}")
}

/// Multiaddr of one specific pod through its headless Service
/// (`<pod>.<headless>.<ns>.svc.cluster.local`).
fn pod_multiaddr(
    fullname: &str,
    role: &str,
    ordinal: u32,
    ns: &str,
    salt: Option<&[u8; 32]>,
) -> String {
    let pod = pod_name(fullname, role, ordinal);
    let peer_id = crate::p2p::deterministic_peer_id(&pod, salt);
    format!("/dns4/{pod}.{fullname}-pqcd-{role}-headless.{ns}.svc.cluster.local/tcp/26656/p2p/{peer_id}")
}

/// Emit the per-role `node.json` blob the pqcd binary expects at
/// `/etc/pqchain/node.json` — schema mirrors the Ansible template
/// `deploy/ansible/roles/configure/templates/node-config.json.j2`
/// and the defaults from `group_vars/all/defaults.yml`.
#[allow(clippy::too_many_arguments)]
fn build_node_json(
    cfg: &CeremonyConfig,
    chain_id_hex: &str,
    role: NodeRole,
    node_id: &str,
    validators: &[ValidatorEntry],
    proposer_address_hex: &str,
    api_bind_addr: &str,
    // p2p_bind_addr was the legacy Phase-6 HTTP gossip endpoint (now
    // serialised as null since libp2p replaces it). Kept in the
    // signature for symmetry with future per-role overrides; suppress
    // the "unused" warning explicitly.
    _p2p_bind_addr: &str,
    libp2p: &Libp2pSection,
) -> serde_json::Value {
    let mut libp2p_obj = serde_json::Map::new();
    libp2p_obj.insert("enable".into(), serde_json::Value::Bool(true));
    libp2p_obj.insert(
        libp2p.listen_field.to_string(),
        serde_json::Value::String(libp2p.listen_addr.clone()),
    );
    libp2p_obj.insert(
        "bootstrap_peers".into(),
        serde_json::Value::Array(
            libp2p
                .bootstrap_peers
                .iter()
                .map(|s| serde_json::Value::String(s.clone()))
                .collect(),
        ),
    );
    // Mesh + transport defaults track `viper_libp2p_common` from
    // `deploy/ansible/group_vars/all/defaults.yml`.
    libp2p_obj.insert("gossip_mesh_n".into(), serde_json::Value::from(2));
    libp2p_obj.insert("gossip_mesh_n_low".into(), serde_json::Value::from(1));
    libp2p_obj.insert("gossip_mesh_n_high".into(), serde_json::Value::from(3));
    libp2p_obj.insert("quic_enabled".into(), serde_json::Value::Bool(false));
    libp2p_obj.insert("tcp_tls_fallback".into(), serde_json::Value::Bool(true));
    libp2p_obj.insert("max_peers_per_asn".into(), serde_json::Value::from(3));
    libp2p_obj.insert(
        "validator_peer_ids".into(),
        serde_json::Value::Array(vec![]),
    );
    serde_json::json!({
        "_comment": "Generated by `pqcd ceremony` (TASK-233). Mirrors the schema of deploy/ansible/roles/configure/templates/node-config.json.j2.",
        "node_id": node_id,
        "chain_id_hex": chain_id_hex,
        "data_dir": "/var/lib/pqchain/data",
        "anchor_prev_hash_hex": "0000000000000000000000000000000000000000000000000000000000000000",
        "fee_params": {
            "base_fee":          100,
            "byte_fee":          1,
            "sigverify_fee_v_a": 500,
            "sigverify_fee_v_b": 1000,
            "sigverify_fee_v_c": 58000,
            "exec_fee_per_gas":  10,
        },
        // p2p_listen_addr is the legacy Phase-6 HTTP gossip endpoint —
        // when libp2p is enabled (the only path the ceremony emits)
        // pqcd's `start_p2p_server` would still try to bind it,
        // colliding on the same port as the libp2p listener
        // (`Address already in use`, observed on 2026-05-05). Drop the
        // field entirely; pqcd's Phase-8 multi-node logic accepts a
        // missing p2p_listen_addr when `libp2p.enable: true`.
        "p2p_listen_addr": serde_json::Value::Null,
        "api_listen_addr": api_bind_addr,
        "peers": [],
        // ADR-069 §2: the API posture follows the role.
        "api": {
            "public_tx_submission": role.serves_public_tx_submission(),
        },
        "devnet": {
            "role": role.as_str(),
            "sync_interval_ms":  if role.is_validator() { 500u64 } else { 100u64 },
            "block_time_ms":     cfg.block_time_ms,
            "proposer_address_hex": proposer_address_hex,
            "epoch_duration":    60u64,
            "unbonding_period":  120u64,
            "validators": validators.iter().map(|v| serde_json::json!({
                "node_id":         v.node_id,
                "address_hex":     v.address_hex,
                "sig_alg_id":      v.consensus_alg_id,
                "public_key_hex":  v.public_key_hex,
                // Every node ships every validator's commit_seed_hex so the
                // distributed-signing path can sign on behalf of any locally-
                // resident validator (mirrors the legacy producer-falls-through
                // branch of the Ansible template; tighten to per-host seed
                // distribution when ADR-051 N+2 lands operationally).
                "commit_seed_hex": v.commit_seed_hex,
            })).collect::<Vec<_>>(),
        },
        "genesis_accounts": validators.iter().map(|v| serde_json::json!({
            "address_hex": v.address_hex,
            "balance":     cfg.genesis_balance,
            "nonce":       0,
            "keys": [{
                "alg_id":           v.consensus_alg_id,
                "pk_hex":           v.public_key_hex,
                "key_version":      1,
                "valid_from_height": 0,
                "status":           "active",
                // SPEC-ACCOUNT-001 §3.6 — u32 bitmask, NOT a list of names
                // (the Ansible template emits the integer literal directly,
                // which is also what the binary's CBOR layer expects). The
                // value 0xF = VAULT|ATTESTATION|KEY_MGMT|GOVERNANCE matches
                // `pqc_types::keyset::allowed_tx::ALL` for ML-DSA keys.
                "allowed_tx_types": 0xFu32,
            }],
        })).collect::<Vec<_>>(),
        "rate_limit": {
            "max_requests_per_window": 100,
            "window_secs": 60,
        },
        "sender_budget": {
            "max_admits_per_window": 50,
            "window_secs": 60,
        },
        "libp2p": serde_json::Value::Object(libp2p_obj),
    })
}

/// Emit the genesis.json blob for the chart's `chain.genesis.inline`
/// field. Subset of `deploy/ansible/files/genesis-viper-pq-1.json`
/// limited to what pqcd actually consumes today (per the
/// `genesis_loader_status` note in that file).
fn build_genesis_json(
    cfg: &CeremonyConfig,
    chain_id_hex: &str,
    validators: &[ValidatorEntry],
) -> serde_json::Value {
    let genesis_root_hex = hex::encode(compute_ceremony_genesis_validators_root(validators));
    serde_json::json!({
        "_schema_version": "viper-pq-ceremony-genesis-v1",
        "_purpose": "Generated by `pqcd ceremony` (TASK-233). Aligned to SPEC-GENESIS-001 v2.0; subset of deploy/ansible/files/genesis-viper-pq-1.json — fields not yet read by pqcd at boot are omitted to keep this file honest. The genesis_validators[] entries are the authoritative validator set; per-role node.json carries the same set redundantly until the genesis_path validator-set loader lands.",
        "chain_id": cfg.chain_id,
        "chain_id_hex": chain_id_hex,
        "fork_version": 1,
        "_fork_version_doc": "Initial fork version. Bumps on a hard-fork that semantically alters consensus rules.",
        "block_time_ms": cfg.block_time_ms,
        "distributed_signing": true,
        "distributed_signing_quorum_wait_ms": cfg.block_time_ms.saturating_mul(3),
        "_distributed_signing_doc": "ADR-051 — every validator signs precommits under their own seed.",
        "genesis_block": {
            "header_version": 1,
            "height": 0,
            "timestamp_ns": "<filled by pqcd at first run>",
            "extension_root": "<filled by pqcd at first run from empty_extension_root()>",
            "extension_root_reserved_keys": ["exec_payload_root", "builder_bid_commitment"],
            "hash_id": 1,
            "_hash_id_doc": "0x01 = SHAKE-256 (FIPS 202).",
        },
        "genesis_validators_root": genesis_root_hex,
        "_genesis_validators_root_doc": "Deterministic commitment to the genesis_validators[] below (TASK-191 closure 2026-05-11). Computed via pqc_types::fork::compute_genesis_validators_root over (address, alg_id, pk) tuples; sort by address ascending; per-validator leaf is tagged_hash(\"VIPER-VALIDATOR-GENESIS-LEAF-V1\", ...); aggregate is tagged_hash(\"VIPER-VALIDATORS-ROOT-V1\", ...). Wired into every signing preimage via ForkDigest::compute(fork_version, genesis_validators_root). Any change to the validator set above moves this value.",
        "genesis_validators": validators.iter().map(|v| serde_json::json!({
            "node_id":          v.node_id,
            "address":          v.address_hex,
            "consensus_alg_id": v.consensus_alg_id,
            "consensus_pk":     v.public_key_hex,
            "bond":             cfg.genesis_balance,
        })).collect::<Vec<_>>(),
    })
}

/// Project ceremony-generated `ValidatorEntry` rows onto the
/// `(Address, AlgId, pk_bytes)` triple consumed by
/// [`pqc_types::fork::compute_genesis_validators_root`] and compute the root.
///
/// Skips entries whose hex fields fail to decode or whose alg_id is unknown —
/// caller is expected to feed only validators that already passed
/// [`derive_validator_entry`], so this is defensive rather than a real error
/// surface.
fn compute_ceremony_genesis_validators_root(validators: &[ValidatorEntry]) -> [u8; 32] {
    let triples: Vec<(Address, AlgId, Vec<u8>)> = validators
        .iter()
        .filter_map(|v| {
            let addr_bytes = hex::decode(&v.address_hex).ok()?;
            if addr_bytes.len() != 32 {
                return None;
            }
            let mut addr_arr = [0u8; 32];
            addr_arr.copy_from_slice(&addr_bytes);
            let alg = AlgId::from_u16(v.consensus_alg_id)?;
            let pk = hex::decode(&v.public_key_hex).ok()?;
            Some((Address(addr_arr), alg, pk))
        })
        .collect();
    compute_genesis_validators_root(&triples)
}

/// Emit the Kubernetes Secret manifest YAML the operator applies
/// alongside the Helm values file. One manifest holds the validator
/// consensus seed (referenced by the chart's
/// `consensusKey.secretName`); a second manifest is appended if the
/// operator passed `--deploy-token` so the chart's
/// `image.pullSecrets[]` resolves on a private registry. Returns the
/// raw YAML string ready for `kubectl apply -f`.
pub fn build_secrets_manifest(
    cfg: &CeremonyConfig,
    namespace: &str,
    validators: &[ValidatorEntry],
    identity_salts: &[RoleIdentitySalts],
) -> Result<String> {
    use std::fmt::Write;
    let mut yaml = String::new();
    writeln!(
        yaml,
        "# Generated by `pqcd ceremony` (TASK-233). Apply with:\n\
         #   kubectl apply -n {namespace} -f <this file>\n\
         # before `helm install ./charts/viper-pq-chain -f values-ceremony.json`.\n\
         # The seeds below are stored verbatim — keep this file private (chmod 600)."
    )?;
    // Validator consensus seed Secret (chart key: consensus_seed).
    writeln!(yaml, "---")?;
    writeln!(yaml, "apiVersion: v1")?;
    writeln!(yaml, "kind: Secret")?;
    writeln!(yaml, "metadata:")?;
    writeln!(yaml, "  name: viper-validator-1-consensus")?;
    writeln!(yaml, "  namespace: {namespace}")?;
    writeln!(yaml, "type: Opaque")?;
    writeln!(yaml, "stringData:")?;
    writeln!(yaml, "  consensus_seed: {}", validators[0].commit_seed_hex)?;
    // G-01: one identity Secret per role (libp2p + ML-KEM salts). The chart
    // references them through `chainNode.<role>.identitySalts.secretName`.
    for s in identity_salts {
        writeln!(yaml, "---")?;
        writeln!(yaml, "apiVersion: v1")?;
        writeln!(yaml, "kind: Secret")?;
        writeln!(yaml, "metadata:")?;
        writeln!(yaml, "  name: {}", s.secret_name)?;
        writeln!(yaml, "  namespace: {namespace}")?;
        writeln!(yaml, "type: Opaque")?;
        writeln!(yaml, "stringData:")?;
        writeln!(yaml, "  libp2p_seed_salt_hex: {}", s.libp2p_seed_salt_hex)?;
        writeln!(yaml, "  kem_seed_salt_hex: {}", s.kem_seed_salt_hex)?;
    }
    // Optional dockerconfigjson Secret for the registry pull credentials.
    if let Some(tok) = &cfg.deploy_token {
        let auth = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{}:{}", tok.username, tok.password),
        );
        let docker_cfg = serde_json::json!({
            "auths": {
                tok.registry.clone(): {
                    "username": tok.username,
                    "password": tok.password,
                    "auth": auth,
                }
            }
        });
        let docker_cfg_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            serde_json::to_vec(&docker_cfg)?,
        );
        writeln!(yaml, "---")?;
        writeln!(yaml, "apiVersion: v1")?;
        writeln!(yaml, "kind: Secret")?;
        writeln!(yaml, "metadata:")?;
        writeln!(yaml, "  name: viper-registry-pull")?;
        writeln!(yaml, "  namespace: {namespace}")?;
        writeln!(yaml, "type: kubernetes.io/dockerconfigjson")?;
        writeln!(yaml, "data:")?;
        writeln!(yaml, "  .dockerconfigjson: {docker_cfg_b64}")?;
    }
    Ok(yaml)
}

/// End-to-end ceremony — generate seeds, derive addresses + pubkeys,
/// compose per-role node.json + genesis.json, wrap into a Helm values
/// tree compatible with `charts/viper-pq-chain` (v0.1.0).
pub fn generate_ceremony_values(
    cfg: &CeremonyConfig,
) -> Result<(CeremonyValues, Vec<ValidatorEntry>, Vec<RoleIdentitySalts>)> {
    if cfg.validators == 0 {
        anyhow::bail!("ceremony requires --validators >= 1");
    }
    let chain_id_hex = compute_chain_id_hex(&cfg.chain_id);
    let chain_id_bytes = cfg.chain_id.as_bytes();
    let alg_id = AlgId::MlDsa65;

    // 1. Generate seeds + derive validator entries.
    let seeds = generate_seeds(cfg.validators);
    let validators: Vec<ValidatorEntry> = seeds
        .iter()
        .enumerate()
        .map(|(i, s)| {
            derive_validator_entry(format!("validator-{}", i + 1), chain_id_bytes, s, alg_id)
        })
        .collect::<Result<Vec<_>>>()?;

    let proposer_address_hex = validators[0].address_hex.clone();

    // 2. Topology (ADR-069 §4). Every pod takes its node_id from its own
    // name (`VIPER_NODE_ID`, set by the chart), so the libp2p PeerId of a
    // pod is `pqcd peer-id <pod-name>` and the ceremony can compute the
    // multiaddrs the followers dial on first boot:
    //   sentry-N                        → the validator
    //   full / rpc / archive / bootnode → the sentries
    // The validator dials nobody; sentries reach it. The release name and
    // namespace are embedded in these names, which is why the chart
    // refuses to render values generated for another release (`_release_name`).
    let fullname = chart_fullname(&cfg.release_name);
    // G-01: one (libp2p salt, KEM salt) pair per role. Replicas of a role
    // share the pair and differ by pod name, so their PeerIds stay
    // distinct and computable here.
    const ROLES: [NodeRole; 6] = [
        NodeRole::Validator,
        NodeRole::Sentry,
        NodeRole::Full,
        NodeRole::Rpc,
        NodeRole::Archive,
        NodeRole::Bootnode,
    ];
    let raw_salts = generate_seeds(2 * ROLES.len() as u32);
    let salts_for = |role: NodeRole| -> ([u8; 32], [u8; 32]) {
        let i = ROLES.iter().position(|r| *r == role).unwrap_or(0);
        (raw_salts[2 * i], raw_salts[2 * i + 1])
    };
    let (validator_libp2p_salt, _) = salts_for(NodeRole::Validator);
    let (sentry_libp2p_salt, _) = salts_for(NodeRole::Sentry);
    let identity_salts: Vec<RoleIdentitySalts> = ROLES
        .iter()
        .map(|&role| {
            let (l, k) = salts_for(role);
            RoleIdentitySalts {
                role,
                secret_name: format!("{fullname}-pqcd-{}-identity", role.as_str()),
                libp2p_seed_salt_hex: hex::encode(l),
                kem_seed_salt_hex: hex::encode(k),
            }
        })
        .collect();
    let identity_secret = |role: NodeRole| -> serde_json::Value {
        let name = identity_salts
            .iter()
            .find(|s| s.role == role)
            .map(|s| s.secret_name.clone())
            .unwrap_or_default();
        serde_json::json!({ "secretName": name })
    };
    let validator_multiaddr = headless_multiaddr(
        &fullname,
        "validator",
        &cfg.namespace,
        Some(&validator_libp2p_salt),
    );
    let sentry_replicas: u32 = 2;
    let sentry_multiaddrs: Vec<String> = (0..sentry_replicas)
        .map(|i| {
            pod_multiaddr(
                &fullname,
                "sentry",
                i,
                &cfg.namespace,
                Some(&sentry_libp2p_salt),
            )
        })
        .collect();

    // 3. Build per-role node.json — one per chart role. Every API binds
    // 0.0.0.0 (not 127.0.0.1) so the kubelet readiness probe, which reaches
    // the pod IP from outside the container, can connect; "the validator
    // API is private" is enforced by the chart's NetworkPolicy + Service
    // contract, not by the bind address (verified on the 2026-05-05 kind
    // smoke: with 127.0.0.1 the probe fails with "connection refused").
    let libp2p_for = |role: NodeRole| -> Libp2pSection {
        let bootstrap_peers = match role {
            NodeRole::Validator | NodeRole::SingleNode => vec![],
            NodeRole::Sentry => vec![validator_multiaddr.clone()],
            NodeRole::Full | NodeRole::Rpc | NodeRole::Archive | NodeRole::Bootnode => {
                sentry_multiaddrs.clone()
            }
        };
        Libp2pSection {
            listen_field: role.libp2p_listen_field(),
            listen_addr: "0.0.0.0:26656".to_string(),
            bootstrap_peers,
        }
    };
    let node_json_for = |role: NodeRole| -> serde_json::Value {
        build_node_json(
            cfg,
            &chain_id_hex,
            role,
            role.as_str(),
            &validators,
            &proposer_address_hex,
            "0.0.0.0:26657",
            "0.0.0.0:26656",
            &libp2p_for(role),
        )
    };
    let validator_node_json = node_json_for(NodeRole::Validator);
    let sentry_node_json = node_json_for(NodeRole::Sentry);
    let full_node_json = node_json_for(NodeRole::Full);
    let rpc_node_json = node_json_for(NodeRole::Rpc);
    let archive_node_json = node_json_for(NodeRole::Archive);
    let bootnode_node_json = node_json_for(NodeRole::Bootnode);
    // 3. Build genesis.json.
    let genesis_json = build_genesis_json(cfg, &chain_id_hex, &validators);
    let genesis_inline =
        serde_json::to_string_pretty(&genesis_json).context("failed to serialise genesis.json")?;

    // 4. Compose Helm values tree. Inline the consensus-key Secret for
    // each validator under `kubernetes.secrets[]` (the chart references
    // it via `consensusKey.secretName`); inline the dockerconfigjson
    // Secret if the operator passed --deploy-token.
    let validator_secret_name = "viper-validator-1-consensus";
    let mut secrets = vec![serde_json::json!({
        "name": validator_secret_name,
        "type": "Opaque",
        "data": {
            "consensus_seed": validators[0].commit_seed_hex,
        },
    })];
    let mut image_pull_secrets = serde_json::Value::Array(vec![]);
    if let Some(tok) = &cfg.deploy_token {
        let auth = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{}:{}", tok.username, tok.password),
        );
        let docker_cfg = serde_json::json!({
            "auths": {
                tok.registry.clone(): {
                    "username": tok.username,
                    "password": tok.password,
                    "auth": auth,
                }
            }
        });
        let docker_cfg_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            serde_json::to_vec(&docker_cfg)?,
        );
        secrets.push(serde_json::json!({
            "name": "viper-registry-pull",
            "type": "kubernetes.io/dockerconfigjson",
            "data": {
                ".dockerconfigjson": docker_cfg_b64,
            },
        }));
        image_pull_secrets = serde_json::json!([{ "name": "viper-registry-pull" }]);
    }

    let values = serde_json::json!({
        "_generated_by": "pqcd ceremony (TASK-233)",
        "_chain_id": cfg.chain_id,
        "_chain_id_hex": chain_id_hex,
        // ADR-069 §4: the chart refuses to render when these differ from
        // `.Release.Name` / `.Release.Namespace` — the bootstrap multiaddrs
        // in the per-role node.json embed them.
        "_release_name": cfg.release_name,
        "_namespace": cfg.namespace,
        "image": {
            "registry": cfg.image_repository.split('/').next().unwrap_or("registry.example.com"),
            "repository": cfg.image_repository
                .split_once('/')
                .map(|(_, rest)| rest.to_string())
                .unwrap_or_else(|| cfg.image_repository.clone()),
            "pullPolicy": "IfNotPresent",
            "pullSecrets": image_pull_secrets,
            "tags": {
                "pqcd": cfg.image_tag,
                "notary": cfg.image_tag,
                "archivalSidecar": cfg.image_tag,
            },
        },
        "chain": {
            "id": cfg.chain_id,
            "blockTimeMs": cfg.block_time_ms,
            "genesis": {
                "inline": genesis_inline,
            },
        },
        "chainNode": {
            "validator": {
                "enabled": true,
                "consensusKey": {
                    "secretName": validator_secret_name,
                },
                "identitySalts": identity_secret(NodeRole::Validator),
                "config": {
                    "nodeJson": serde_json::to_string_pretty(&validator_node_json)?,
                },
            },
            "sentry": {
                "enabled": true,
                "replicas": sentry_replicas,
                "identitySalts": identity_secret(NodeRole::Sentry),
                "config": {
                    "nodeJson": serde_json::to_string_pretty(&sentry_node_json)?,
                },
            },
            "full": {
                "enabled": true,
                "replicas": 1,
                "identitySalts": identity_secret(NodeRole::Full),
                "config": {
                    "nodeJson": serde_json::to_string_pretty(&full_node_json)?,
                },
            },
            // Off by default, but ready: enabling any of these needs no
            // further ceremony work (ADR-069 §4).
            "rpc": {
                "enabled": false,
                "identitySalts": identity_secret(NodeRole::Rpc),
                "config": {
                    "nodeJson": serde_json::to_string_pretty(&rpc_node_json)?,
                },
            },
            "archive": {
                "enabled": false,
                "identitySalts": identity_secret(NodeRole::Archive),
                "config": {
                    "nodeJson": serde_json::to_string_pretty(&archive_node_json)?,
                },
            },
            "bootnode": {
                "enabled": false,
                "identitySalts": identity_secret(NodeRole::Bootnode),
                "config": {
                    "nodeJson": serde_json::to_string_pretty(&bootnode_node_json)?,
                },
            },
        },
        "notary": {
            "enabled": true,
            "replicas": 2,
        },
        "kubernetes": {
            "secrets": secrets,
        },
    });

    Ok((values, validators, identity_salts))
}

#[cfg(test)]
mod tests;
