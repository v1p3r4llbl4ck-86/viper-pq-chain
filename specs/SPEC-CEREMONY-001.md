# Chart Ceremony Tooling Specification

**Spec ID**: SPEC-CEREMONY-001
**Version**: 0.1
**Status**: Draft
**Date**: 2026-05-06
**Implements**: TASK-233 (`pqcd ceremony` subcommand; commit `9d810a6`), per-role libp2p binding wiring (commit `213c34c`), and the 2026-05-05 kind smoke schema fixes (commit `451dd53`)
**Decision authority**: ADR-053 §T1.3 (chain-id-bound address derivation), ADR-041 §3 (per-role libp2p listen contract), ADR-051 (distributed signing), Policy P-COMPAT-001
**Depends on**: SPEC-GENESIS-001 §0 (`chain_id_hex` UTF-8 hex contract), SPEC-GENESIS-001 §2 (genesis subset), SPEC-ACCOUNT-001 §3.6 (`allowed_tx_types` u32 bitmask), SPEC-NODE-001 (`node.json` schema)
**References**: `crates/pqcd/src/ceremony.rs`, `crates/pqcd/src/main.rs::cmd_ceremony`, `deploy/ansible/roles/configure/templates/node-config.json.j2`, `deploy/ansible/group_vars/all/defaults.yml`, `charts/viper-pq-chain`

---

## Revision history

| Version | Date       | Notes |
|---------|-----------|-------|
| 0.1     | 2026-05-06 | Initial draft. Pins the `pqcd ceremony` subcommand contract, per-validator derivation, output schema, and the three schema rules surfaced by the 2026-05-05 kind smoke fixes (commit `451dd53`). |

---

## 0. Status banner

The chart ceremony tool exists to close a single operator gap: after a fresh-cluster `helm install ./charts/viper-pq-chain`, what genesis material does the chart need so that height 1 finalises? The 2026-04-25 launch of the (since retired) `viper-pq-1` chain was a hand-orchestrated air-gapped ceremony per SPEC-GENESIS-001 §4; that path remains appropriate for a public mainnet but is operator-overhead-heavy for the iterative dev / kind / staging clusters that run before a launch, and `pqcd ceremony` is also the tool that creates the public chain `viper-testnet-2` at genesis. `pqcd ceremony` produces a Helm values JSON + Kubernetes Secret manifests in one invocation, so a fresh cluster reaches block-1 finality in five minutes without manual key handling.

This spec governs the v0.1 contract. Like SPEC-COLD-STORAGE-001, future fields ride P-COMPAT-001 — additive schema evolution, no breaking renames inside `viper-pq-ceremony-genesis-v1`.

---

## 1. Scope

This specification defines:

- the `pqcd ceremony` CLI flag set, defaults, and outputs,
- the per-validator key-material derivation (seed → ML-DSA-65 keypair → chain-id-bound address),
- the per-role `node.json` produced for validator / sentry / full,
- the per-role libp2p binding under ADR-041 §3,
- the in-cluster libp2p bootstrap multiaddr DNS form,
- the genesis JSON subset emitted (a subset of SPEC-GENESIS-001 §2 limited to what `pqcd` reads at boot today),
- three schema rules — pinned by the 2026-05-05 smoke fixes — that distinguish a working chart deploy from a dead-on-arrival one.

Out of scope:
- The full `alg_registry` / `hash_registry` / `auth_template_registry` / `slashing_verifier_registry` / `fee_market` reference blocks of the historical `genesis-viper-pq-1.json`. `pqcd` does not yet read those from genesis.json (the authoritative source remains per-role `node.json`); emitting them would be decorative drift between the artefact and the binary's actual behaviour.
- SPEC-GENESIS-001 §3 BIP340 double-tagged `genesis_hash`. `pqcd` computes this deterministically at block-0 finalisation; the ceremony emits a placeholder string, matching the historical `genesis-viper-pq-1.json` artefact.
- Deploy-token credential rotation. The ceremony embeds the operator-supplied `--deploy-token` verbatim; rotation is an operator concern outside this spec.
- The chart contract itself (`charts/viper-pq-chain` v0.1.0). This spec defines the values **producer**; the chart defines the values **consumer**. The two are co-versioned but separately specified.

---

## 2. Normative Language

RFC 2119. MUST / SHOULD / MAY carry their usual meaning.

---

## 3. CLI Subcommand Contract

### 3.1 Invocation

```
pqcd ceremony [--chain-id S] [--validators N] [--block-time-ms M]
              [--genesis-balance B] [--image-repository R]
              [--image-tag T] [--namespace NS] [--release-name R]
              [--deploy-token user:pass@registry] [--output FILE]
              [--secrets-output FILE]
```

### 3.2 Flag set and defaults

| Flag | Type | Default | Notes |
|------|------|---------|-------|
| `--chain-id` | string | `viper-pq-kind-test` | UTF-8 string; `chain_id_hex` is computed from this per SPEC-GENESIS-001 §0. Pinned ceremony test vector: `viper-pq-kind-test` → `76697065722d70712d6b696e642d74657374`. |
| `--validators` | u32 | `3` | MUST be ≥ 1. Symmetric stake across the cohort (§4.3). |
| `--block-time-ms` | u64 | `500` | Genesis `block_time_ms`; same value as the retired `viper-pq-1` chain. |
| `--genesis-balance` | u128 | `1_000_000_000` | Per-validator bond (in venom). Symmetric across the cohort to keep T1.5 churn-limit math on the simplest possible distribution. |
| `--image-repository` | string | the maintainer's container registry | Full repository path (`<registry-host>/<namespace>/<image>`); the registry hostname is split off the first slash for Helm's `image.registry`. |
| `--image-tag` | string | `main` | Applied to `pqcd`, `notary`, and `archivalSidecar` images uniformly. |
| `--namespace` | string | `viper` | Kubernetes namespace; feeds the libp2p bootstrap DNS multiaddr (§5.2). |
| `--release-name` | string | `viper-test` | Helm release name; feeds the libp2p bootstrap DNS multiaddr (§5.2). Mismatched value at `helm install` time → sentries and full nodes cannot dial the validator → height-0 islands. This was the load-bearing gap caught by the 2026-05-05 kind smoke. |
| `--deploy-token` | `user:pass@registry` | none | Optional. Triggers a `dockerconfigjson` Secret + `image.pullSecrets[]` reference for private-registry pulls. |
| `--output` | path | `values-ceremony.json` | Helm values JSON output path. `-` streams to stdout (in which case `--secrets-output` is bypassed). |
| `--secrets-output` | path | `secrets-ceremony.yaml` | Kubernetes Secret manifests output path. |

### 3.3 Outputs

The subcommand produces exactly two on-disk artefacts (when `--output` is not `-`):

1. **`values-ceremony.json`** — Helm values tree (§6) consumable by `helm install ./charts/viper-pq-chain -f values-ceremony.json`.
2. **`secrets-ceremony.yaml`** — Kubernetes Secret manifests (§7) applied via `kubectl apply -n <namespace> -f secrets-ceremony.yaml` BEFORE `helm install`. File mode is tightened to `0600` best-effort (the file carries the validator's `consensus_seed` in stringData).

A paste-friendly summary of the validator cohort (`node_id`, `address_hex`, first 16 bytes of `public_key_hex`) is emitted to stderr regardless of `--output`, so the operator's runbook entry is always populated even when stdout is piped.

---

## 4. Per-Validator Derivation

### 4.1 Seed generation

Each validator gets a fresh **32-byte commit_seed** drawn from the OS CSPRNG via `rand::rng().fill_bytes`. Seeds are independent across validators in the cohort and across re-runs of the ceremony — idempotency is a non-goal; rotation is the point.

### 4.2 Public key

```
pk_bytes = pqc_crypto::ml_dsa_public_key_from_seed(AlgId::MlDsa65, &commit_seed)
```

ML-DSA-65 (FIPS 204) is the consensus algorithm at launch; `alg_id = 0x0002` per SPEC-ACCOUNT-001 §6.3. The seed-to-pk derivation is the same code path the binary uses at runtime, so a re-run of `pqcd ceremony` and a `pqcd start` against the same seed produce byte-identical public keys.

### 4.3 Address (chain-id-bound)

Per ADR-053 §T1.3 / TASK-192 / SPEC-GENESIS-001 §2.5:

```
address = derive_address(chain_id_bytes, alg_id, pk_bytes)
        = tagged_hash("VIPER-ADDR-V1", chain_id_bytes || u16_be(alg_id) || pk_bytes)
```

`chain_id_bytes` is the UTF-8 encoding of the `--chain-id` flag (NOT the hex form). The chain-id binding ensures a re-run of the ceremony with a different `--chain-id` yields a different address for the same seed — preventing cross-chain replay even when an operator reuses an old seed. This invariant is unit-tested in `ceremony.rs::tests::derive_validator_entry_is_chain_id_bound_per_adr_053_t1_3`.

The seed-derivation pipeline is consolidated in `ceremony::derive_validator_entry` so the ceremony, the runtime, and any future tooling (e.g. SPEC-COLD-STORAGE-001 v2 manifest signer registration) all share a single source of truth.

### 4.4 Validator entry

The per-validator record returned by `derive_validator_entry`:

```
ValidatorEntry {
    node_id:           "validator-{i}",        // 1-indexed
    address_hex:       hex(address),           // 64 hex chars
    public_key_hex:    hex(pk_bytes),          // 1952-byte ML-DSA-65 pk
    commit_seed_hex:   hex(commit_seed),       // 64 hex chars (32 bytes)
    consensus_alg_id:  0x0002,                 // ML-DSA-65
}
```

Every node in the cohort ships every validator's `commit_seed_hex` inside its `node.json::devnet.validators[]`. This mirrors the legacy producer-falls-through branch of the Ansible template; tightening to per-host seed distribution (so only the producing host knows its seed) lands when ADR-051 N+2 is operationalised.

---

## 5. Per-Role libp2p Binding (ADR-041 §3)

### 5.1 Listen-field selection

Each role gets exactly one of three ADR-041 §3 listen fields, mutually exclusive:

| Role | `listen_field` | Bind | Rationale |
|------|---------------|------|-----------|
| `validator` | `validator_listen` | `0.0.0.0:26656` | Validator-tier binding. Distinct field so the chart's NetworkPolicy can match traffic class. |
| `sentry` | `vfn_listen` | `0.0.0.0:26656` | "Validator Full Node" sentry tier — public-facing peer between validators and the open p2p mesh. |
| `full` | `public_listen` | `0.0.0.0:26656` | Public archival / read-only full node. |

The validator binds on `0.0.0.0` (not `127.0.0.1`) so the chart's kubelet readiness probe — which reaches the pod IP from outside the container — can connect on port 26657. The "validator API is private" guarantee is enforced by the chart's NetworkPolicy + Service contract, not by the binding address itself. (This is one of the three rules pinned by §8.)

### 5.2 Bootstrap multiaddr DNS form

Sentry and full nodes are pre-wired with exactly one bootstrap peer: the validator's in-cluster headless-Service DNS multiaddr.

```
/dns4/<release>-viper-pq-chain-pqcd-validator-headless.<ns>.svc.cluster.local/tcp/26656/p2p/<peer_id>
```

Where:
- `<release>` is `--release-name`,
- `<ns>` is `--namespace`,
- `<peer_id>` is `pqcd::p2p::deterministic_peer_id("validator-1").to_string()` — the same value `pqcd peer-id validator-1` returns at the operator's CLI.

Re-using `deterministic_peer_id` ties the ceremony's bootstrap address to the value `pqcd start` will register at runtime. A future operator running `pqcd peer-id validator-1` against this chain gets the byte-identical PeerId the ceremony emitted.

The validator itself has an empty `bootstrap_peers` array — it does not dial itself; sentries dial **to** it on first boot, which is what the directional asymmetry of an L1 validator topology requires. Empty-vs-self-loop matters because libp2p Identify treats a self-dial as a misconfiguration warning that consumes log noise during boot.

### 5.3 Mesh and transport defaults

The remaining libp2p fields track `viper_libp2p_common` from `deploy/ansible/group_vars/all/defaults.yml`:

| Field | Value | Notes |
|-------|-------|-------|
| `gossip_mesh_n` | 2 | Conservative for a 3-node dev cohort. |
| `gossip_mesh_n_low` | 1 | |
| `gossip_mesh_n_high` | 3 | |
| `quic_enabled` | `false` | Default off; TCP+TLS is the boring choice for kind. |
| `tcp_tls_fallback` | `true` | |
| `max_peers_per_asn` | 3 | |
| `validator_peer_ids` | `[]` | Populated by the runtime via Identify; not a ceremony concern. |

---

## 6. Helm Values Tree

### 6.1 Top-level shape

```
{
  "_generated_by":   "pqcd ceremony (TASK-233)",
  "_chain_id":       "<chain_id>",
  "_chain_id_hex":   "<hex>",
  "image":           { ... },
  "chain":           { "id": ..., "blockTimeMs": ..., "genesis": { "inline": "<json string>" } },
  "chainNode":       { "validator": { ... }, "sentry": { ... }, "full": { ... } },
  "notary":          { "enabled": true, "replicas": 2 },
  "kubernetes":      { "secrets": [ ... ] }
}
```

The leading underscore-prefixed keys are operator-facing breadcrumbs; the chart ignores them. `chain.genesis.inline` carries the §6.4 genesis JSON as a single pretty-printed string the chart wraps verbatim into a ConfigMap.

### 6.2 Per-role node.json under `chainNode`

Each enabled role exposes its `node.json` at `chainNode.<role>.config.nodeJson` as a JSON string. The chart hands this string to a per-role ConfigMap → projected volume → `/etc/pqchain/node.json` inside the container.

### 6.3 `node.json` schema (per role)

The schema mirrors `deploy/ansible/roles/configure/templates/node-config.json.j2`:

| Field | Type | Source |
|-------|------|--------|
| `_comment` | string | Provenance breadcrumb. |
| `node_id` | string | Per-role node id (`validator-1`, `sentry`, `full`). |
| `chain_id_hex` | string | Computed from `--chain-id` per §3.2 / SPEC-GENESIS-001 §0. |
| `data_dir` | string | `/var/lib/pqchain/data`. |
| `anchor_prev_hash_hex` | string | `0x00 × 32` — genesis null anchor. |
| `fee_params` | object | Five-field block (`base_fee`, `byte_fee`, `sigverify_fee_v_a`, `_v_b`, `_v_c`, `exec_fee_per_gas`); defaults track `defaults.yml`. |
| `p2p_listen_addr` | null | Legacy Phase-6 HTTP gossip endpoint; explicitly null when libp2p is enabled. See §8 / commit `213c34c`. |
| `api_listen_addr` | string | `0.0.0.0:26657` for all roles (§8 rule 3). |
| `peers` | array | Empty; libp2p replaces the legacy peer-list path. |
| `devnet` | object | `role`, `sync_interval_ms`, `block_time_ms`, `proposer_address_hex`, `epoch_duration`, `unbonding_period`, `validators[]`. |
| `genesis_accounts` | array | One entry per validator (§6.4.1). |
| `rate_limit` | object | `{ max_requests_per_window: 100, window_secs: 60 }`. |
| `sender_budget` | object | `{ max_admits_per_window: 50, window_secs: 60 }`. |
| `libp2p` | object | Per-role binding (§5). |

Per-role differences:
- `validator` runs as `role: validator` with `sync_interval_ms: 500`.
- `sentry` and `full` run as `role: sentry` / `role: full` with `sync_interval_ms: 100` (faster polling for headless non-signing nodes). The pre-ADR-069 role names `producer` / `follower` are still read as aliases but are never written.

### 6.4 Genesis subset under `chain.genesis.inline`

```
{
  "_schema_version":                       "viper-pq-ceremony-genesis-v1",
  "_purpose":                              "...",
  "chain_id":                              "<--chain-id>",
  "chain_id_hex":                          "<utf8 hex>",
  "fork_version":                          1,
  "block_time_ms":                         <block_time_ms>,
  "distributed_signing":                   true,
  "distributed_signing_quorum_wait_ms":    <block_time_ms × 3>,
  "genesis_block": {
    "header_version":               1,
    "height":                       0,
    "timestamp_ns":                 "<filled by pqcd at first run>",
    "extension_root":               "<filled by pqcd at first run from empty_extension_root()>",
    "extension_root_reserved_keys": ["exec_payload_root", "builder_bid_commitment"],
    "hash_id":                      1
  },
  "genesis_validators_root":               "<computed by pqcd at block-0 finalisation>",
  "genesis_validators":                    [ ... ]
}
```

This is a strict subset of SPEC-GENESIS-001 §2:

- `fork_version = 1`, `header_version = 1`, `hash_id = 1` (SHAKE-256), and `extension_root_reserved_keys = ["exec_payload_root", "builder_bid_commitment"]` mirror SPEC-GENESIS-001 §1 / §2.0 verbatim.
- `distributed_signing = true` is mandatory per ADR-051. `distributed_signing_quorum_wait_ms = 3 × block_time_ms` matches the ratio used in the historical `genesis-viper-pq-1.json`.
- `timestamp_ns`, `extension_root`, and `genesis_validators_root` are placeholders. `pqcd` computes them deterministically at block-0 finalisation per SPEC-GENESIS-001 §3 (BIP340 double-tagged `genesis_hash` derivation). Emitting placeholders here matches the live launch artefact's behaviour.
- The `alg_registry`, `hash_registry`, `auth_template_registry`, `slashing_verifier_registry`, `fee_market`, `storage_fund`, and `light_client` blocks of SPEC-GENESIS-001 §2 are deliberately omitted — `pqcd` does not yet read them from the genesis JSON path; they are seeded from code (`phase1_registry()`, `phase1_hash_registry()`, etc.). Adding them to the ceremony output would be decorative drift; they are reserved for the v2 schema bump under §10.

### 6.4.1 Per-validator genesis_accounts entry

Each genesis-validator account is emitted with one ML-DSA-65 KeyEntry:

```
{
  "address_hex": "<address_hex>",
  "balance":     <genesis_balance>,
  "nonce":       0,
  "keys": [{
    "alg_id":            0x0002,
    "pk_hex":            "<public_key_hex>",
    "key_version":       1,
    "valid_from_height": 0,
    "status":            "active",            // §8 rule 2
    "allowed_tx_types":  0xFu32                // §8 rule 1
  }]
}
```

`0xF = VAULT | ATTESTATION | KEY_MGMT | GOVERNANCE` — equals `pqc_types::keyset::allowed_tx::ALL` for ML-DSA keys.

---

## 7. Kubernetes Secret Manifests

`secrets-ceremony.yaml` carries two manifests, the second appearing only when `--deploy-token` is supplied.

### 7.1 Validator consensus seed

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: viper-validator-1-consensus
  namespace: <namespace>
type: Opaque
stringData:
  consensus_seed: <validators[0].commit_seed_hex>
```

Referenced by the chart's `chainNode.validator.consensusKey.secretName`. The 64-hex-char string is the literal value `pqcd start --consensus-seed-hex` consumes at boot.

### 7.2 Registry pull secret (optional, `--deploy-token` only)

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: viper-registry-pull
  namespace: <namespace>
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: <base64-encoded { auths: { <registry>: { username, password, auth } } }>
```

The `auth` field is `base64(username:password)` per the dockerconfigjson convention. The chart references this Secret via `image.pullSecrets[].name = "viper-registry-pull"`.

The whole file is written with mode `0600` best-effort to discourage casual inspection.

---

## 8. Three Schema Rules Pinned by the 2026-05-05 Smoke Fixes (commit `451dd53`)

The 2026-05-05 kind smoke surfaced three schema gaps between the chart's expectations and the binary's CBOR layer. Each is now part of the ceremony output contract; deviations cause the binary to refuse to start or the readiness probe to fail.

### 8.1 Rule 1 — `allowed_tx_types` MUST be a u32 bitmask, not an array of strings

```
"allowed_tx_types": 0xFu32        // CORRECT — pinned by SPEC-ACCOUNT-001 §3.6
"allowed_tx_types": ["VAULT", ...] // WRONG  — silently accepted by JSON, rejected by CBOR layer
```

The Ansible template emits the integer literal directly. The CBOR codec on the binary side expects a `u32` and rejects any non-integer value at decode time. A list-of-strings form was a recurring drift in hand-written devnet config files; the ceremony pins the correct form to prevent the regression.

### 8.2 Rule 2 — `genesis_accounts[].keys[].status` MUST be lowercase

```
"status": "active"   // CORRECT — pqc_types::keyset::KeyStatus serde tag
"status": "Active"   // WRONG  — fails KeyStatus deserialisation, account rejected at genesis load
```

`pqc_types::keyset::KeyStatus` is annotated `#[serde(rename_all = "lowercase")]`. The CBOR layer is case-sensitive. The Ansible template's filter set capitalises field names by default, which is why this rule needs explicit pinning at the ceremony layer.

### 8.3 Rule 3 — Validator's `api_listen_addr` MUST bind `0.0.0.0`

```
"api_listen_addr": "0.0.0.0:26657"   // CORRECT — kubelet readiness probe reaches pod IP
"api_listen_addr": "127.0.0.1:26657" // WRONG  — readiness probe HTTP-GET fails with "connect: connection refused"
```

The chart's readiness probe runs from outside the container (kubelet) and dials the **pod IP**, not loopback. A `127.0.0.1` bind makes the probe fail and the StatefulSet never reaches `Ready`. The "validator API is private" guarantee is enforced by the chart's NetworkPolicy + Service contract — production isolation is a network-policy concern, not a binding-address concern. This rule is one of the load-bearing reasons commit `213c34c` exists.

---

## 9. Worked Example

Operator invocation:

```
pqcd ceremony \
    --chain-id viper-pq-staging-1 \
    --validators 3 \
    --release-name staging-1 \
    --namespace viper-staging \
    --deploy-token <username>:<token>@<registry-host>
```

Produces:

- `values-ceremony.json` (~ 8 KB) with three roles, three genesis validators, registry-pull secret reference, and a pinned bootstrap multiaddr `/dns4/staging-1-viper-pq-chain-pqcd-validator-headless.viper-staging.svc.cluster.local/tcp/26656/p2p/<deterministic_peer_id>`.
- `secrets-ceremony.yaml` (~ 1 KB) with the validator's consensus seed Secret + a `dockerconfigjson` Secret for the deploy token.

Operator deploy:

```
kubectl create namespace viper-staging
kubectl apply -n viper-staging -f secrets-ceremony.yaml
helm install staging-1 ./charts/viper-pq-chain -n viper-staging -f values-ceremony.json
```

Expected outcome: validator pod becomes `Ready` within ~30 s, sentry pods follow within ~60 s after libp2p Identify completes the handshake, height begins advancing within ~90 s.

---

## 10. Open Follow-Ups

| # | Item | Target |
|---|------|--------|
| O1 | Emit the full `alg_registry` / `hash_registry` / `auth_template_registry` / `slashing_verifier_registry` / `fee_market` / `storage_fund` / `light_client` blocks in `chain.genesis.inline` once `pqcd`'s genesis loader reads them at boot. Decorative until the loader lands. | TASK-tbd (post-launch) |
| O2 | Compute and emit SPEC-GENESIS-001 §3 BIP340 double-tagged `genesis_hash` directly (mirror what `pqcd` will compute at first run) so the operator can pre-publish the value in advance of cluster deployment. | TASK-tbd |
| O3 | Per-host seed distribution: only the producing host receives its own `commit_seed_hex`, sentries / full nodes receive the public material only. Requires ADR-051 N+2 operationalisation. | TASK-tbd |
| O4 | Chain-id collision guard at chart-install time (refuse `helm install` when an existing release in the namespace declares a conflicting chain id). | chart-side |
| O5 | RFC 3161 TSA anchor over the values JSON's SHA-256 (matches the SPEC-COLD-STORAGE-001 §9 reservation pattern; would let the operator timestamp the ceremony output for audit). | TASK-tbd |

---

## 11. Invariants

The following invariants MUST hold for any ceremony output:

| Invariant | Check |
|-----------|-------|
| `chain_id_hex == hex(chain_id.as_bytes())` | SPEC-GENESIS-001 §0; round-trips through `hex::decode`. |
| `address == tagged_hash("VIPER-ADDR-V1", chain_id_bytes \|\| u16_be(0x0002) \|\| pk_bytes)` | ADR-053 §T1.3; cross-chain replay invariant. |
| `validators >= 1` | §3.2; rejected at CLI parse. |
| Each role's `node.json` has `chain_id_hex`, `fee_params`, `devnet`, `devnet.validators[]`, `devnet.proposer_address_hex` | Tested in `ceremony.rs::tests::ceremony_values_have_expected_top_level_keys`. |
| Sentry + full nodes have exactly one bootstrap peer (the validator multiaddr) | Tested in `libp2p_wires_validator_multiaddr_into_sentry_and_full_bootstrap_peers`. |
| Validator has empty `bootstrap_peers` | Same test. |
| `validator` uses `validator_listen`; `sentry` uses `vfn_listen`; `full` uses `public_listen` | ADR-041 §3; same test. |
| `genesis_accounts[].keys[].allowed_tx_types` is a u32 integer | §8.1. |
| `genesis_accounts[].keys[].status == "active"` | §8.2. |
| Validator's `api_listen_addr` binds `0.0.0.0` | §8.3. |
| `distributed_signing == true` and `distributed_signing_quorum_wait_ms == 3 × block_time_ms` | ADR-051. |
| `chain.genesis.inline` is valid JSON when re-parsed | Tested in `ceremony_values_have_expected_top_level_keys`. |

---

## 12. Test Strategy

| Layer | Test ID | Coverage | Location |
|-------|---------|----------|----------|
| Unit | T1 | `chain_id_hex` round-trips through `hex::decode` for `viper-pq-1` | `ceremony.rs::tests::chain_id_hex_round_trips_through_hex_decode` |
| Unit | T2 | `chain_id_hex` pinned for the kind smoke chain | `chain_id_hex_kind_test` |
| Unit | T3 | Same seed + same chain → same address (determinism) | `derive_validator_entry_is_deterministic_for_same_seed_and_chain` |
| Unit | T4 | Same seed + different chain → different address (ADR-053 §T1.3 binding) | `derive_validator_entry_is_chain_id_bound_per_adr_053_t1_3` |
| Unit | T5 | `generate_seeds(n)` emits `n` distinct seeds | `generate_seeds_emits_n_distinct_seeds` |
| Integration | T6 | Top-level Helm keys + per-role `node.json` schema completeness | `ceremony_values_have_expected_top_level_keys` |
| Integration | T7 | Validator consensus seed Secret emitted in YAML | `build_secrets_manifest_emits_validator_consensus_secret` |
| Integration | T8 | dockerconfigjson Secret appended for `--deploy-token` | `build_secrets_manifest_appends_dockerconfigjson_for_deploy_token` |
| Integration | T9 | Per-role libp2p binding + bootstrap multiaddr DNS form | `libp2p_wires_validator_multiaddr_into_sentry_and_full_bootstrap_peers` |
| Integration | T10 | `image.pullSecrets[]` block emitted for `--deploy-token` | `deploy_token_emits_pull_secret_block` |

---

## 13. References

- ADR-053 §T1.3 — chain-id-bound address derivation (`tagged_hash("VIPER-ADDR-V1", chain_id_bytes ‖ u16_be(alg_id) ‖ pk_bytes)`)
- ADR-053 §T2.4 — BIP340 double-tagged hashing (the `tagged_hash` primitive)
- ADR-041 §3 — per-role libp2p listen field contract (`validator_listen` / `vfn_listen` / `public_listen`)
- ADR-051 — distributed signing (mandatory at launch; no producer-falls-through fallback)
- SPEC-GENESIS-001 — genesis spec (especially §0 `chain_id_hex` contract, §2 genesis state composition, §3 `genesis_hash` derivation)
- SPEC-NODE-001 — `node.json` schema (the binary's authoritative boot config)
- SPEC-ACCOUNT-001 §3.6 — `allowed_tx_types` u32 bitmask contract
- SPEC-COLD-STORAGE-001 — sister deliverable in the same 2026-05-05/06 window (§9 reservation pattern this spec mirrors for the future TSA anchor option)
- Policy P-COMPAT-001 — additive schema evolution; `viper-pq-ceremony-genesis-v1` extends additively
- `crates/pqcd/src/ceremony.rs` — implementation source of truth
- `crates/pqcd/src/main.rs::cmd_ceremony` — CLI flag plumbing
- `deploy/ansible/roles/configure/templates/node-config.json.j2` — the `node.json` schema this ceremony output mirrors
- `deploy/ansible/group_vars/all/defaults.yml` — `viper_libp2p_common` defaults
- `deploy/ansible/files/genesis-viper-pq-1.json` — the historical `viper-pq-1` launch artefact (genesis subset alignment target); the `viper-testnet-2` genesis is produced by this tool and its values are assigned at genesis
- `charts/viper-pq-chain` v0.1.0 — the values consumer this spec's output is shaped to
- Commits `9d810a6` (TASK-233 ceremony tooling), `451dd53` (2026-05-05 schema fixes), `213c34c` (per-role libp2p binding wiring)
