# SPEC-GENESIS-001: Viper PQ Chain Genesis Block Specification

**Spec ID**: SPEC-GENESIS-001
**Version**: 2.0
**Status**: Normative
**Date**: 2026-04-25
**Produced by**: TASK-205 (`viper-pq-1` launch under ADR-053)
**Decision authority**: ADR-025 (genesis structure), ADR-053 (Tier-1 / Tier-2 / Tier-3 launch fields), Policy P-COMPAT-001 (every breaking change rides an activation height — no resets)

---

## Revision history

| Version | Date       | Notes |
|---------|-----------|-------|
| 1.0     | 2026-04-12 | Initial Phase-5 ceremony spec (`viper-mainnet-1` framing, single-tag SHAKE-256 genesis hash, no Tier-1 fields). Superseded by 2.0. |
| 2.0     | 2026-04-25 | Realigned to the live `viper-pq-1` launch artefact at `deploy/ansible/files/genesis-viper-pq-1.json`. ADR-053 §T1.1 / §T1.3 / §T1.4 / §T2.1 / §T2.2 / §T2.4 / §T3.4 / §T3.5 / §T3.6 fields added. Genesis hash migrated to BIP340 double-tagged form (TASK-202). Timestamps now `uint64` ns. The historical `viper-mainnet-1` ceremony moves to Appendix A. |

---

## 0. Status banner

There is no live network at the time of the public release. This specification was written for `viper-pq-1`, launched on 2026-04-25 from commit `879ce62` and since retired (archived at height 33,976); its `chain_id_hex` = `76697065722d70712d31` (the ASCII bytes of `"viper-pq-1"`, no separator) and the `genesis-viper-pq-1.json` artefact referenced throughout are kept as the historical worked example. The tokenless successors `viper-research-1` and `viper-lab-1` are retired as well. The public chain **`viper-testnet-2`** is created after the public release with `pqcd ceremony` (SPEC-CEREMONY-001); its `chain_id_hex`, `genesis_validators_root`, `genesis_hash` and validator roster are assigned at genesis and published with the genesis file. `viper-testnet-2` has no native token: the genesis account balances, founder / treasury / reserved tranches and the storage fund described below belong to the `token_economics` Cargo feature (see SPEC-TOKEN-002, status Reserved) and are compiled out of the public chain build. The previous chain id `viper-mainnet-1` from the v1.0 ceremony plan was never launched; its design context survives in Appendix A and in `DECISIONS.md` ADR-025 / ADR-053. Per Policy P-COMPAT-001, every breaking change on a running chain rides an activation height (ADR-053 §T2.3, code path: `crates/pqc-state/src/store.rs::pending_upgrades`), never a reset.

---

## 1. Genesis Block Fields

The genesis block is height 0. It contains no transactions. Its sole purpose is to establish the initial chain state and anchor all subsequent blocks.

| Field | Value | Notes |
|-------|-------|-------|
| `header_version` | `1` (u16) | ADR-053 §T1.1 / TASK-190. First u16 of every BlockHeader. Bumps only on a layout change; the preferred extension path is `extension_root` keys. |
| `height` | 0 | Genesis does not increment height. |
| `prev_hash` | `[0x00; 32]` | Null anchor — no predecessor block. |
| `timestamp_ns` | uint64 nanoseconds UTC | ADR-053 §T1.1 — Bitcoin-2106-immune; agreed out-of-band before the genesis ceremony, substituted at signing time. |
| `proposer` | Ceremony coordinator address | 32-byte address of the party running `pqcd genesis-init`. |
| `tx_hashes` | `[]` | Empty — no transactions in genesis block. |
| `commit_signatures` | `[]` | Empty — BFT commit applies from height 1 onward. |
| `state_root` | computed | BIP340 double-tagged binary Merkle state root (ADR-053 §T2.4 / §T3.1 / TASK-202; see `crates/pqc-state/src/store.rs:48-100` for the leaf/branch domains `VIPER-STATE-LEAF-V1` and `VIPER-STATE-BRANCH-V1`). |
| `extension_root` | `tagged_hash("VIPER-EXT-EMPTY-V1", &[])` at genesis | ADR-053 §T3.4 / TASK-200. Reserved CBOR keys: `exec_payload_root`, `builder_bid_commitment` (ePBS / EIP-7732 forward-compat name claim only — neither key is present in v1 blocks). |
| `hash_id` | `0x01` (SHAKE-256) | ADR-053 §T1.4 / TASK-193. Selector into the on-chain hash registry; every callsite dispatches on this id. |
| `genesis_hash` | computed | BIP340 double-tagged hash, see §3. |

The genesis block is NOT subject to commit quorum validation. It is trusted by definition — any node that accepts the published genesis config will independently compute the same `genesis_hash`.

---

## 2. Genesis State Composition

The initial state is deterministically constructed from the genesis config file (`deploy/ansible/files/genesis-viper-pq-1.json`). Components below are listed in the order they affect `state_root`. The state root is derived as a binary Merkle tree under the leaf/branch domains above; per-category leaves carry the category discriminants enumerated in `StateCategory` (`crates/pqc-state/src/store.rs:62-83`).

### 2.0 Tier-1 fields at genesis

These fields are protocol-level invariants pinned at height 0. They mirror the live JSON 1:1.

- **`header_version: u16` — initial value `1`.** ADR-053 §T1.1 / TASK-190. Encoded as the first field of every `BlockHeader`. Future mandatory fields land via `extension_root` keys; the version number bumps only on a layout change, which Policy P-COMPAT-001 strongly discourages.
- **`extension_root: [u8; 32]` — empty-extension sentinel `tagged_hash("VIPER-EXT-EMPTY-V1", &[])`.** ADR-053 §T3.4 / TASK-200. The two CBOR keys `exec_payload_root` and `builder_bid_commitment` are reserved at genesis for a future ePBS (enshrined proposer-builder separation) activation. Reservation is a name-claim only; activation rides an activation height under P-COMPAT-001.
- **`hash_id: u8` — initial value `0x01` = SHAKE-256 (FIPS 202).** ADR-053 §T1.4 / TASK-193. The on-chain `hash_registry` (see `crates/pqc-crypto/src/hash_registry.rs::phase1_hash_registry()`) seeds a single entry. Sentinel `0x00` is rejected. Reserved range `0x01..=0x0F` is code-governed; AddHash governance proposals targeting the reserved range are rejected at decode time.
- **`auth_template_registry: BTreeMap<u16, AuthTemplate>` — seeded `{0x0001 → EOA}`.** ADR-053 §T3.5 / TASK-196. Every Account at genesis carries `verifier_template_id = 0x0001` and `auth_data = []`, which is semantically identical to an Ethereum EOA. Future templates land via `ProposalEffect::AddAuthTemplate` (governance type `0x08`). The id `0x0001` is genesis-immutable. Mirrors `crates/pqc-types/src/account.rs::VERIFIER_TEMPLATE_ID_EOA`.
- **`slashing_verifier_registry: BTreeMap<u8, SlashingVerifier>` — seeded `{0x01 → Equivocation, slash_fraction_bps = 500}`.** ADR-050 / SPEC-SLASH-001 §10. 5 % bond burn on equivocation; mirrors `SLASH_FRACTION_BPS = 500` in `crates/pqc-state/src/apply/slashing.rs`. Future offences (downtime `0x02`, double-proposal `0x03`, …) land via `ProposalEffect::AddSlashingVerifier` (governance type `0x06`).
- **`fee_market: FeeMarketState` — 4-dimensional EIP-4844 exponential.** ADR-053 §T2.1 / TASK-201. See SPEC-FEE-002 v0.2 (`specs/fee-market.md`). At launch, only `compute` is wired to real tx activity; `storage`, `witness`, and `contention` are reserved slots (`target = 0`) pinned at `reserve_floor = 100`. Genesis values mirror `FeeMarketState::default()` in `crates/pqc-state/src/store.rs:311-321`.
- **`storage_fund: StorageFundState` — Sui-style upfront perpetual storage.** ADR-053 §T2.2 / §T3.3 / TASK-199. Defaults: `balance = 0`, `perpetual_cost_per_byte = 1`, `rebate_fraction_bps = 9_900` (99 %). Mirrors `StorageFundState::default()` in `crates/pqc-state/src/storage_fund.rs:65-73`. Tx-path debits / delete-path rebates are a follow-up activation under P-COMPAT-001.
- **`light_client: LightClientConfig` — sync committee size 16, quorum 11, gossip topic `viper-light-client-attestations-v1`.** ADR-053 §T3.6 / TASK-197 / SPEC-LIGHT-CLIENT-001. The gossip topic name is verbatim from `crates/pqc-consensus/src/light_client.rs::SYNC_COMMITTEE_GOSSIP_TOPIC`. Quorum = `16 − ⌊(16 − 1) / 3⌋ = 16 − 5 = 11`. At launch, the genesis set has 3 validators, so the first committee is exactly those 3 sampled; the size cap binds at the next epoch when more validators register. Sync committee members are slashable for signing invalid headers (the Altair flaw is fixed at `viper-pq-1` launch).
- **Timestamps in `uint64` nanoseconds UTC.** ADR-053 §T1.1. Replaces the Phase-5 plan's `uint64` seconds. Bitcoin-2106-immune by construction.

### 2.1 Account Table

Accounts are inserted in the order defined by ADR-025 and SPEC-TOKEN-002 §4. The state root is deterministic regardless of insertion order — leaf hashes are sorted before folding into the binary Merkle tree (ADR-053 §T3.1 / TASK-195).

| Account | Balance (venom) | Key type | Notes |
|---------|----------------|---------|-------|
| Founder | 2 × 10^26 | ML-DSA-65 | 4-year vesting, off-chain custody |
| Treasury | 3 × 10^26 | ML-DSA-65 | Governance-controlled; key held by multi-sig (Phase 6) |
| Genesis validator accounts | 10^24 each (1,000,000 VPR) | ML-DSA-65 | One account per genesis validator; balance equals `min_stake` |
| Reserved | 4 × 10^26 | ML-DSA-65 | Governance-locked; no disbursement without governance vote |

Every Account at genesis carries `verifier_template_id = 0x0001` (EOA) and `auth_data = []` (ADR-053 §T3.5). The genesis validator account balances above are in addition to any amounts allocated from the 10 % genesis-validator share; validators commit their `min_stake` as `self_bond` at registration.

Total genesis balance check:

```
200,000,000 + 300,000,000 + 100,000,000 + 400,000,000 = 1,000,000,000 VPR
= 10^27 venom
```

Note on the `viper-pq-1` dev launch (historical): at the 2026-04-25 ceremony the three genesis hosts launched with `bond_amount = 1_000_000_000` venom per validator (symmetric across the 3 genesis validators), and the founder/treasury/reserved tranches are deferred to the public mainnet ceremony per Policy P-COMPAT-001.

### 2.2 Algorithm Registry

Initial Algorithm Registry state per SPEC-ACCOUNT-001 §6.3, mirroring `crates/pqc-crypto/src/registry.rs::phase1_registry()`:

| Algorithm | `alg_id` | Initial lifecycle | Notes |
|-----------|---------|-----------------|-------|
| ML-DSA-44 | 0x0001 | Active | FIPS 204 |
| ML-DSA-65 | 0x0002 | Active | FIPS 204 — default |
| ML-DSA-87 | 0x0003 | Active | FIPS 204 |
| FN-DSA-PADDED-512 | 0x0010 | Active | FIPS 206 (draft) — signing deferred until FIPS 206 finalized |
| SLH-DSA-SHA2-128s | 0x0020 | Active | FIPS 205 |
| SLH-DSA-SHAKE-128s | 0x0021 | Active | FIPS 205 |
| SLH-DSA-SHAKE-192s | 0x0022 | Active | FIPS 205 |
| SLH-DSA-SHAKE-256s | 0x0023 | Active | FIPS 205 |
| ML-KEM-768 | 0x0100 | Active | FIPS 203 — KEM (P2P transport only) |

Sentinel `0x0000` is reserved (rejected at every entry point). Lifecycle transitions Active → Discouraged → Deprecated → Banned are governed by ADR-049; AddAlgorithm proposals land through this registry.

### 2.3 Hash Registry

Single seed entry — ADR-053 §T1.4 / TASK-193. Mirrors `crates/pqc-crypto/src/hash_registry.rs::phase1_hash_registry()`:

| Hash | `hash_id` | Lifecycle | Notes |
|------|-----------|-----------|-------|
| SHAKE-256 | 0x01 | Active | FIPS 202; 32-byte canonical digest. |

### 2.4 Governance Parameters

Initial on-chain governed parameters:

| Parameter | Initial value | Source |
|-----------|-------------|--------|
| `compute.base_fee` | 0 venom (floored at `reserve_floor = 100`) | SPEC-FEE-002 §6 / ADR-053 §T2.1 |
| `compute.reserve_floor` | 100 venom | `COMPUTE_RESERVE_FLOOR` in `crates/pqc-state/src/store.rs:179` |
| `compute.target` | 5,000,000 gas (`DEFAULT_BLOCK_GAS_LIMIT / 2`) | `DEFAULT_COMPUTE_TARGET` |
| `compute.update_fraction` | 3,338,477 | `COMPUTE_FEE_UPDATE_FRACTION` (matches EIP-4844 `BLOB_BASE_FEE_UPDATE_FRACTION`) |
| `compute.limit` | 10,000,000 gas | `DEFAULT_BLOCK_GAS_LIMIT` |
| `byte_fee` | 2 venom | SPEC-FEE-001 §6.4 / ADR-024 |
| `sigverify_fee_v_b` | 14,000 venom | SPEC-FEE-001 §6.4 / ADR-024 |
| `exec_fee_per_gas` | 43 venom | SPEC-FEE-001 §6.4 / ADR-024 |
| `min_stake` | 10^24 venom (1 M VPR) | SPEC-TOKEN-002 §5 |
| `max_active_set_size` | 24 | ADR-013 |
| `unbonding_period_blocks` | 120 | `crates/pqc-consensus/src/epoch.rs` (ADR-042 / ADR-053 §T1.5) |
| `epoch_duration_blocks` | 60 | `crates/pqc-consensus/src/epoch.rs` |
| `validator_churn_limit` | stake-weighted: `max(active_stake_frac_min_bps, active_stake_frac_target_bps × active_stake) / 10000` | ADR-053 §T1.5 / TASK-194 (replaces legacy count-based `max(4, active/256)`). |
| `block_time_ms` | 500 | TASK-186 may revise pre-public-mainnet under P-COMPAT-001. |
| `distributed_signing` | `true` | ADR-051 — mandatory at launch (no legacy "producer-signs-for-everyone" fallback). |
| `distributed_signing_quorum_wait_ms` | 1,500 (3 × `block_time_ms`) | ADR-051. |
| `fork_version` | `1` (u32) | ADR-053 §T1.2 / TASK-191 — input to ForkDigest derivation. |

### 2.5 Validator Set

Genesis validators are those who completed the ceremony procedure (§4). Each is inserted into the on-chain validator registry (TASK-064) with:

- `status = Active`
- `self_bond = bond_amount` from the genesis JSON
- `consensus_alg_id = 0x0002` (ML-DSA-65)
- `registered_height = 0`

The validator set is seeded from the genesis config file. The roster is published through the `viper-pq-1-roster.json.example` schema (see `docs/validator-onboarding.md` §0) once filled by the air-gapped key ceremony. **Address derivation is chain-id-bound** per ADR-053 §T1.3 / TASK-192:

```
address = tagged_hash("VIPER-ADDR-V1", chain_id_bytes || u16_be(sig_alg_id) || pk_bytes)
```

implemented in `crates/pqc-crypto/src/address.rs:33` via the BIP340 double-tagged primitive (T2.4). This ensures an address derived for `viper-pq-1` is structurally distinct from the same key's address on any other Viper chain id, eliminating cross-chain replay even for plain key reuse.

---

## 3. Genesis Hash Derivation

```
genesis_hash = tagged_hash(
    tag       = b"VIPER-GENESIS-V1",
    body      = chain_id_bytes || state_root || timestamp_ns_be64
)
```

Where:

- `tagged_hash` is the BIP340 double-tagged primitive `H(H(tag) || H(tag) || data)` defined in `crates/pqc-crypto/src/hash.rs:111` (ADR-053 §T2.4 / TASK-202). The double-tag construction is immune to the CVE-2012-2459 class of attacks.
- `b"VIPER-GENESIS-V1"` is the domain string. The 16-byte ASCII tag is hashed twice and prefixed inside `tagged_hash`; the caller passes the raw tag bytes.
- `chain_id_bytes` is the UTF-8 encoding of the chain id string (`viper-pq-1` → `0x76 0x69 0x70 0x65 0x72 0x2d 0x70 0x71 0x2d 0x31`, hex `76697065722d70712d31`).
- `state_root` is the 32-byte BIP340 double-tagged binary Merkle root over the genesis state (§2), under the `VIPER-STATE-LEAF-V1` / `VIPER-STATE-BRANCH-V1` domains.
- `timestamp_ns_be64` is the genesis nanosecond UTC timestamp as an 8-byte big-endian unsigned integer (ADR-053 §T1.1).

The domain tag `"VIPER-GENESIS-V1"` is unique within the protocol and cannot collide with any block hash, transaction hash, signing preimage, or commit preimage (see `crates/pqc-crypto/src/address.rs::ADDRESS_DOMAIN_V1`, `crates/pqc-state/src/store.rs::STATE_LEAF_DOMAIN`, etc.).

**Implementation note**: the `pqcd genesis-init` and `pqcd genesis-verify` CLI commands must implement this formula. As of the TASK-205 launch commit, `pqcd` does not yet have a top-level genesis-JSON loader (validator set + accounts live inside `node.json`); the genesis JSON is the canonical source of record for ADR-053 launch state and is referenced by the launch playbook at `deploy/ansible/playbooks/launch-viper-pq-1.yml`. A true `genesis_path` reader lands as a follow-up under P-COMPAT-001.

---

## 4. Genesis Ceremony Procedure

The ceremony is the process by which the genesis block is produced and independently verified by all participants. It must be executed exactly once.

### Step 1 — Validator key generation

Each genesis validator independently generates an ML-DSA-65 keypair offline:

- Recommended: air-gapped hardware
- Minimum: encrypted disk, never exported to networked machine
- Output: operator address (32 bytes — derived via the chain-id-bound formula in §2.5), consensus public key (ML-DSA-65, 1952 bytes), node ID

The signing seed must never be committed to a repository, transmitted over a network in plaintext, or logged by any software.

### Step 2 — Key collection

The ceremony coordinator collects from each genesis validator and writes them into the `viper-pq-1-roster.json.example` schema:

- `node_id` (string)
- `address_hex` (64 hex characters = 32 bytes — chain-id-bound, see §2.5)
- `sig_alg_id` (`0x0002` for ML-DSA-65)
- `public_key_hex` (hex-encoded consensus public key)

### Step 3 — Genesis config construction

The coordinator builds `deploy/ansible/files/genesis-viper-pq-1.json` with:

- All genesis accounts (founder, treasury, validators, reserved) with balances
- All validators from Step 2
- Initial fee market parameters (§2.4)
- Initial `auth_template_registry`, `slashing_verifier_registry`, `hash_registry`, `alg_registry` (§2.0–§2.3)
- `chain_id`: `viper-pq-1`; `chain_id_hex`: `76697065722d70712d31`
- `fork_version`: `1`
- `header_version`: `1`
- `hash_id`: `0x01`
- `block_time_ms`, `distributed_signing*`, `light_client`, `epoch`, `storage_fund`, `fee_market` per the live JSON

The genesis config is published publicly before Step 4.

### Step 4 — Genesis block production

The coordinator runs:

```
pqcd genesis-init deploy/ansible/files/genesis-viper-pq-1.json
```

This command (once implemented end-to-end — see §3 implementation note) produces:

1. The genesis `state_root` by constructing the initial `StateStore` and calling `state_root()` (binary Merkle, BIP340 double-tagged).
2. The genesis `extension_root` by calling `tagged_hash("VIPER-EXT-EMPTY-V1", &[])`.
3. The genesis `timestamp_ns` (out-of-band agreed UTC nanoseconds at ceremony execution).
4. The `genesis_hash` using the formula in §3.
5. The genesis block file.

The coordinator publishes the `genesis_hash`, `state_root`, `extension_root`, and `timestamp_ns`.

### Step 5 — Independent verification

Every candidate validator independently runs:

```
pqcd genesis-verify deploy/ansible/files/genesis-viper-pq-1.json
```

This command recomputes `state_root` and `genesis_hash` from the published config and asserts they match the coordinator's published values. Chain launch proceeds only when **all genesis validators** confirm the same `genesis_hash`.

Any discrepancy indicates either a config mismatch or a bug in `genesis-verify` — both must be resolved before launch.

### Step 6 — Node launch

Validators start their nodes with:

```
pqcd start --config deploy/ansible/files/genesis-viper-pq-1.json
```

The first block (height 1) requires a commit quorum from ≥ ⌈2/3 × N⌉ + 1 genesis validators (ADR-007). With distributed signing on (ADR-051), the proposer waits up to `distributed_signing_quorum_wait_ms = 1500` ms for gossiped precommits before finalising.

---

## 5. Verification Procedure

Any operator can verify that their node has the correct genesis at any time:

```
GET /v1/status
```

Response includes `chain_id`, `state_root`, `tip_hash`, `height`, `base_fee`, `epoch_number`, `epoch_length_blocks`. At height 0 the `tip_hash` will equal the published `genesis_hash`.

For full independent verification:

1. Obtain the published genesis config from the official source (for `viper-testnet-2`: the genesis file published at genesis; historical example: `deploy/ansible/files/genesis-viper-pq-1.json`).
2. Run `pqcd genesis-verify deploy/ansible/files/genesis-viper-pq-1.json`.
3. Confirm the computed hash matches the published `genesis_hash`.
4. If starting a new node: the node will refuse to sync from peers whose genesis hash does not match (parent hash mismatch at height 1 — detected by `ChainStore::validate_stored_block`).

---

## 6. Invariants

The following invariants must hold at and after genesis:

| Invariant | Check |
|-----------|-------|
| `header_version == 1` | First u16 of `BlockHeader` at height 0. |
| `hash_id == 0x01` | Single-entry `hash_registry` seed. |
| `auth_template_registry[0x0001] == EOA` | Genesis-immutable; cannot be removed by governance. |
| `slashing_verifier_registry[0x01] == Equivocation (slash_bps = 500)` | Mirrors `SLASH_FRACTION_BPS = 500`. |
| Total balance = 10^27 venom (mainnet ceremony) | Sum of all account balances at genesis. |
| All validator stakes = `bond_amount` from JSON | Each genesis validator has `self_bond` matching the published value. |
| State root determinism | Any two operators with the same genesis config compute the same `state_root` under the BIP340 double-tagged Merkle topology. |
| Genesis hash uniqueness | `genesis_hash` is unique to this genesis config; changing any input field changes the hash. |
| No transactions at genesis | `block.tx_hashes` is empty; `block.commit_signatures` is empty. |
| `extension_root == tagged_hash("VIPER-EXT-EMPTY-V1", &[])` | Empty-extension sentinel at height 0; reserved keys (`exec_payload_root`, `builder_bid_commitment`) are name-claims only and must not be present in v1 blocks. |
| Address chain-id binding | Every genesis validator address satisfies `addr == tagged_hash("VIPER-ADDR-V1", chain_id_bytes || u16_be(alg_id) || pk_bytes)`. |

---

## 7. Reference

- ADR-025 — Genesis block specification decision
- ADR-024 — Viper token economics (supply, distribution, staking parameters)
- ADR-013 — Maximum active validator set size (24)
- ADR-053 — `viper-pq-1` launch architecture (Tier-1 / Tier-2 / Tier-3 fields, BIP340 double-tagged hashing, multi-dim fee market, storage fund, ePBS reservations, smart-account templates, sync committee)
- Policy P-COMPAT-001 — every breaking change rides an activation height; no chain resets
- SPEC-TOKEN-002 (`specs/tokenomics.md`) — numeric token parameters
- SPEC-ACCOUNT-001 (`specs/account-keyset-registry.md`) — account structure and Algorithm Registry initial state
- SPEC-FEE-001 §6.4 — calibrated fee coefficients (byte / sigverify / exec)
- SPEC-FEE-002 (`specs/fee-market.md`) v0.2 — multi-dim EIP-4844 fee market
- SPEC-LIGHT-CLIENT-001 (`specs/SPEC-LIGHT-CLIENT-001.md`) — sync committee
- SPEC-SLASH-001 (`specs/slashing.md`) — equivocation slashing (verifier id 0x01)
- `deploy/ansible/files/genesis-viper-pq-1.json` — **historical genesis JSON of the retired `viper-pq-1` chain** with `_audit_provenance` mapping every ADR-053 commit to its tier
- `deploy/ansible/playbooks/launch-viper-pq-1.yml` — launch playbook (TASK-205)
- `docs/validator-onboarding.md` §0 — bootstrap roster schema (`viper-pq-1-roster.json.example`)
- `crates/pqcd/src/node.rs::build_genesis_state()` — current genesis bootstrap implementation
- `crates/pqc-state/src/store.rs::state_root()` — binary Merkle state root (ADR-053 §T3.1)
- `crates/pqc-crypto/src/hash.rs::tagged_hash` — BIP340 double-tagged primitive (ADR-053 §T2.4)
- `crates/pqc-crypto/src/address.rs:33` — chain-id-bound address derivation (ADR-053 §T1.3)
- `crates/pqc-crypto/src/registry.rs::phase1_registry` — Algorithm Registry seed
- `crates/pqc-crypto/src/hash_registry.rs::phase1_hash_registry` — Hash Registry seed
- `crates/pqc-state/src/storage_fund.rs::StorageFundState` — storage fund framework (ADR-053 §T2.2)
- `crates/pqc-consensus/src/light_client.rs` — sync committee wiring (ADR-053 §T3.6)

---

## Appendix A — Historical chains

### A.1 `viper-mainnet-1` (planned 2026-04-12, never launched)

The Phase-5 v1.0 of this spec described a `viper-mainnet-1` ceremony with a single-tag SHAKE-256 genesis hash:

```
genesis_hash = SHAKE-256("VIPER-GENESIS-V1" || chain_id_bytes || state_root || timestamp_be64, 32)
```

That ceremony was superseded by ADR-053 before ever being executed. The `viper-mainnet-1` chain id is reserved for a future public mainnet ceremony and was never used. Every Tier-1 / Tier-2 / Tier-3 commitment in ADR-053 (BIP340 double-tagged hashing, chain-id-bound addresses, header_version + extension_root, hash_id registry, multi-dim fee market, storage fund, smart-account templates, light-client sync committee) is a launch invariant of every chain from `viper-pq-1` forward, including `viper-testnet-2`. The historical TASK-106 air-gapped ML-DSA-65 key ceremony procedure remains the template for future launches.

### A.2 `viper-devnet-2` (deprecated, archived 2026-04-25)

The 637 172-block `viper-devnet-2` chain was archived at the launch of `viper-pq-1` per the operator's authorisation. Any reference in this repository to `viper-devnet-2` outside of historical-fact statements is drift; see `KNOWN-ISSUES.md` R-09 for the rc1 incident on the same chain id.
