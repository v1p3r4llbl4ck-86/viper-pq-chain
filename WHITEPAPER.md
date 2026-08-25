# Viper PQ Chain — Whitepaper

**Status**: v0.3 framing (2026-08) on the v0.2 text (2026-04-25). The thesis, threat model,
cryptographic architecture, account model, transaction format, consensus and fee model below are
the design as built. Two sections are framed differently from the original: §12 — the validator set
is operator-run proof of authority with no stake; §13 — the token utility is a **reserve** design
behind the dormant `token_economics` feature, not a live mechanism and not an offer. There is no
public network yet; `viper-testnet-2` is created at genesis after the first public release.

**Version**: 0.3 framing / 0.2 text

---

## 1. Abstract

Viper PQ Chain is a post-quantum-native Layer 1 blockchain designed from genesis for long-term cryptographic resilience, algorithm agility, and institutional-grade trust. Unlike legacy chains constrained by classical signature assumptions, Viper starts with post-quantum signatures in every critical protocol path — transactions, consensus, and peer-to-peer transport. Its initial product is not generic programmability but a narrow, high-assurance trust layer: secure digital vault accounts, cryptographic attestations, identity-linked proofs, and policy-controlled key management. The protocol treats signature size, verification cost, and key rotation as first-class design inputs from day one.

---

## 2. Motivation

### 2.1 The Legacy Chain Problem

Current major blockchains — Bitcoin, Ethereum, and their derivatives — were designed around classical signature assumptions (ECDSA, Schnorr). They now face a structural migration problem:

- no native key rotation at the protocol level
- backward compatibility constraints that make algorithm changes disruptive
- massive installed base that must be coordinated through governance
- wallet and custody fragmentation that slows any cryptographic transition

Even if these chains successfully migrate to post-quantum signatures, they do so under enormous legacy weight. A new chain has no such constraint.

### 2.2 Why Now

Post-quantum cryptography is no longer theoretical. NIST has published the first finalized standards:

- **FIPS 203** — ML-KEM (key encapsulation)
- **FIPS 204** — ML-DSA (signatures, lattice-based)
- **FIPS 205** — SLH-DSA (signatures, hash-based)
- **FIPS 206** (in progress) — FN-DSA (signatures, Falcon)

The question is no longer "will post-quantum cryptography matter" but "which infrastructure will be built natively around it."

### 2.3 The Opportunity

PQ Chain exists to answer that question with a purpose-built trust layer, not a generic chain competing on throughput.

---

## 3. Threat Model

*Formal evaluation: [specs/threat-model.md](specs/threat-model.md) (TASK-061, Phase 4)*

### 3.1 Attacker Classes

PQ Chain models two attacker classes simultaneously:

- **Classical attacker** — present today; exploits key theft, malware, replay, DoS, network-level attacks
- **Quantum attacker** — anticipated; a cryptographically relevant quantum computer (CRQC) that can break ECDSA/RSA-based signatures and classical key agreement

### 3.2 Harvest-Now-Decrypt-Later

An adversary can record encrypted traffic or signed payloads today and decrypt or forge them later once a CRQC becomes available. This is the primary driver for requiring post-quantum cryptography in all critical paths from genesis, not as a future migration.

### 3.3 Attack Surfaces

| Surface | Classical risk | Quantum risk | Mitigation |
|---------|---------------|-------------|------------|
| Transaction signatures | key theft, replay, malleability | signature forgery if classical algorithm | ML-DSA default; SLH-DSA fallback; account nonce; canonical encoding |
| Consensus votes and commits | equivocation, long-range attacks | identity/vote forgery | PQ signatures on all vote and commit material |
| P2P transport | MITM, eclipse, Sybil | harvest-now-decrypt-later on session traffic | ML-KEM-768 for key agreement |
| Serialization | encoding ambiguity, malleability | — | deterministic CBOR; reject non-canonical inputs |
| Economic DoS | underpriced large or expensive signatures | PQ signatures amplify DoS surface | fee per byte + fee per verify; mempool admission budget |

### 3.4 Out of Threat Model Scope (Phase 1)

- privacy beyond transport hygiene and key confidentiality
- cross-chain attacks
- application-layer vulnerabilities in wallets or custody systems

---

## 4. Design Principles

1. **Security before feature sprawl** — the trust layer must be proven before scope expands
2. **Protocol clarity before ecosystem expansion** — specs come before ecosystem tooling
3. **Crypto agility before cryptographic lock-in** — every algorithm choice is explicit and replaceable
4. **Trust-first UX over speculative UX** — the product is safety, integrity, and evolvability
5. **Narrow and defensible wedge before generalization** — vault + attestations before programmability
6. **Institutional credibility without enterprise bloat** — high assurance, minimal governance theater
7. **Long-term value over short-term hype** — fee levels justified by trust value, not cheap throughput

---

## 5. Cryptographic Architecture

### 5.1 Algorithm Baseline

| Role | Algorithm | alg_id | Rationale |
|------|-----------|--------|-----------|
| Default transaction signatures | ML-DSA-65 (FIPS 204, NIST L3) | `0x0002` | finalized standard, ~55k verify/s, mature pure-Rust implementation |
| Higher-security transactions and consensus | ML-DSA-87 (FIPS 204, NIST L5) | `0x0003` | NIST L5 lattice signature for high-value paths |
| Hash-based consensus fallback | SLH-DSA-SHAKE-192s (FIPS 205, NIST L3) | `0x0021` | family-diversification fallback if a lattice break is announced (ADR-043); also the M4 archival overlay signing algorithm |
| AA accounts and key recovery | SLH-DSA-SHA2-128s / SLH-DSA-SHAKE-128s (FIPS 205, NIST L1) | `0x0020` / `0x0023` | conservative hash-based, restricted to low-frequency operations |
| Archival overlay (M4 only) | SLH-DSA-SHAKE-256s (FIPS 205, NIST L5) | `0x0022` | RFC 3161 / RFC 4998 archival anchors (ADR-045) |
| Reduced-fee non-consensus signatures | FN-DSA-padded-512 (future FIPS 206) | `0x0010` | 666 B signature; registered as a reduced-fee class but **not consensus-eligible** under ADR-046 (NIST L1 < required L3 for consensus keys) |
| P2P key agreement | ML-KEM-768 (FIPS 203, NIST L3) | `0x0100` | protects transport against harvest-now-decrypt-later |

ML-DSA-44 (`0x0001`) is registered for transactions but explicitly forbidden for consensus keys by ADR-046 (NIST Level 2 < the required Level 3 floor). The full enum lives at `crates/pqc-crypto/src/alg.rs::AlgId`.

### 5.2 Algorithm Registry

Every algorithm is registered on-chain with an explicit identifier and a lifecycle status. No algorithm is ever implicitly assumed.

Each entry: `alg_id → (spec_ref, param_set, allowed_use_cases, min_fee, lifecycle_status)`

Lifecycle states: `active` → `discouraged` → `deprecated` → `banned`

See Section 10 (Crypto Agility) for the full deprecation process.

### 5.3 Key Encoding

All signed payloads use deterministic CBOR (RFC 8949). Protobuf and other non-canonical formats are excluded from signing paths. Domain separation is required on all signed preimages.

---

## 6. Account Model

*Formal spec: [specs/account-keyset-registry.md](specs/account-keyset-registry.md)*

### 6.1 Account Structure

Each account holds:

- `address` — 32-byte identifier derived from initial public key and `alg_id` per [SPEC-ADDRESS-001](specs/address.md): `SHAKE-256(sig_alg_id_be16 || pk_bytes, 32)`, displayed as Bech32m (`vpr1...` mainnet, `vpt1...` testnet). Wallet key management and keystore format defined in [SPEC-WALLET-001](specs/wallet.md)
- `balance` — u128
- `nonce` — u64, monotonically increasing, anti-replay
- `keys[]` — the account's KeySet

### 6.2 KeySet

Each key entry in the KeySet:

| Field | Type | Description |
|-------|------|-------------|
| `alg_id` | u16 | algorithm identifier |
| `pk_bytes` | bytes | raw public key |
| `key_version` | u32 | monotonically increasing; used by verifier to select the correct key |
| `valid_from_height` | u64 | block height from which this key is active |
| `status` | enum | `active`, `rotating`, `revoked` |
| `allowed_tx_types` | u32 mask | restricts which operation types may be signed with this key |

Default policy: SLH-DSA keys are restricted to rotation and recovery operations only (`allowed_tx_types` excludes standard vault and attestation operations).

### 6.3 Key Rotation

Key rotation is a first-class protocol operation. An account can register a new key, set its `valid_from_height`, and revoke old keys — all without resetting account space or losing history. Rotation transactions must themselves be signed by an active key with rotation permission.

---

## 7. Transaction Format

*Formal spec: [specs/transaction-envelope.md](specs/transaction-envelope.md)*

### 7.1 Envelope

All transactions use a canonical CBOR-encoded envelope:

| Field | Type | Size | Description |
|-------|------|------|-------------|
| `tx_version` | u8 | 1 B | protocol version |
| `chain_id` | bytes | 4–16 B | network identifier |
| `msg_type` | u16 | 2 B | operation routing |
| `sender` | bytes | 32 B | account address |
| `nonce` | u64 | 8 B | anti-replay |
| `fee` | u64 | 8 B | fee in base units |
| `fee_tip` | u64 | 8 B | optional priority tip |
| `gas_limit` | u64 | 8 B | execution budget |
| `payload` | bytes | variable | operation-specific CBOR |
| `sig_alg_id` | u16 | 2 B | signing algorithm |
| `sig_key_version` | u32 | 4 B | key selector |
| `signature` | bytes | variable | e.g. 3,309 B for ML-DSA-65 |

### 7.2 Signed Preimage

The signed preimage is the deterministic CBOR encoding of all fields except `signature`, prefixed with a domain separator (e.g. `"TX"`). The domain separator prevents cross-context signature reuse.

### 7.3 Mempool Admission

Before entering the mempool, a transaction must pass:

- canonical encoding check (reject non-deterministic CBOR)
- `alg_id` active in Algorithm Registry
- `sig_key_version` resolves to an active key with sufficient `allowed_tx_types`
- signature validity
- nonce check (no replay)
- fee sufficiency: `fee ≥ base_fee + byte_fee × tx_bytes + sigverify_fee[alg_id]`
- per-sender verify budget not exceeded

---

## 8. Consensus

*Formal spec: [specs/consensus.md](specs/consensus.md) (SPEC-CONSENSUS-001, ADR-027)*

### 8.1 Model

Viper PQ Chain uses a Tendermint-like three-phase BFT consensus protocol: Prevote → Precommit → Commit, with proposer rotation across the active validator set.

Each block height proceeds through independent rounds. The proposer for each round is selected deterministically (round-robin weighted by stake). If the proposer does not produce a valid block before the timeout, the round increments and the next validator becomes the proposer — the chain does not halt on a single proposer failure.

Finality is deterministic and irreversible. A block committed at height `h` cannot be rolled back or reorganized.

HotStuff-like linear communication complexity (`O(n)` vs. `O(n²)` for Tendermint all-to-all) is an explicit later path once the validator set exceeds the Phase 1 ceiling of 50. The all-to-all model is manageable and simpler to implement and audit at ≤24 validators.

### 8.2 Three-Phase Voting

| Phase | What validators do | Condition to advance |
|-------|-------------------|---------------------|
| **Prevote** | Vote for the proposed block (or nil if proposal not received) | ≥2/3 prevotes seen, or timeout |
| **Precommit** | Vote to commit if a polka (≥2/3 prevotes) was observed; nil otherwise | ≥2/3+1 precommits seen, or timeout |
| **Commit** | Block is final; commit material recorded; advance to next height | ≥2/3+1 precommits for same block hash |

### 8.3 Validator Set

| Topology | Validator count | Quorum (2/3+1) | ML-DSA-65 commit | SLH-DSA-SHAKE-192s commit |
|-------|----------------|----------------|-----------------|---------------|
| `viper-testnet-2` at genesis | 3 | 3 | ~10 KB | ~49 KB |
| Forward: controlled growth (ADR-013) | 24 | ~17 | ~56 KB | ~276 KB |
| Forward: stress ceiling | 50 | ~34 | ~110 KB | ~552 KB |

### 8.4 PQ-Aware Consensus Constraints

- all vote and commit signatures use an active PQ algorithm with NIST L≥3 (ADR-046): ML-DSA-65 / ML-DSA-87 default lattice signatures; SLH-DSA-SHAKE-192s permitted as the hash-based fallback (ADR-043); ML-DSA-44, FN-DSA-padded-512, and the SLH-DSA-128s variants are registered but **not** consensus-eligible
- commit material (the quorum of Precommit signatures) is stored in the block body; the block header contains only `commit_hash = SHAKE-256("VIPER-COMMIT-V1" || sorted_precommits, 32)`, keeping headers compact
- at 17 quorum signers (ML-DSA-65), commit overhead is ~56 KB per block and verification costs ~4 ms — both well within the Phase 1 block budget
- SNARK-based signature aggregation is tracked as a future path to reduce commit overhead at validator set sizes above 50

### 8.5 Safety and Fault Tolerance

The protocol tolerates up to `f < n/3` Byzantine validators. With the Phase 1 devnet of 24 validators, this means the protocol is safe even if up to 7 validators are compromised. Equivocation (double-signing) is detectable on-chain and triggers automatic slashing.

---

## 9. Fee Model

*Formal spec: [specs/fee-model.md](specs/fee-model.md)*

### 9.1 Formula

```
fee = base_fee + byte_fee × tx_bytes + sigverify_fee[alg_id] + exec_fee × gas_used
```

### 9.2 Components

| Component | What it prices |
|-----------|---------------|
| `base_fee` | minimum per-transaction network cost |
| `byte_fee × tx_bytes` | bandwidth and storage cost of the raw transaction |
| `sigverify_fee[alg_id]` | CPU cost of verifying the signature; calibrated to measured cycles on reference hardware; updatable via governance |
| `exec_fee × gas_used` | execution cost of the state transition |

### 9.3 Fee Classes

Registry-baseline coefficients (`crates/pqc-crypto/src/registry.rs`):

| Algorithm | Sig size | Verify throughput | Fee class | Consensus-eligible |
|-----------|----------|------------------|-----------|-------------------|
| ML-DSA-44 | 2,420 B | ~89,000/s | V-B standard | No (ADR-046) |
| ML-DSA-65 | 3,309 B | ~55,000/s | V-B standard | Yes |
| ML-DSA-87 | 4,627 B | ~37,000/s | V-B standard | Yes |
| FN-DSA-padded-512 | 666 B | ~62,000/s | V-A reduced | No (ADR-046) |
| SLH-DSA-SHA2-128s | 7,856 B | ~951/s | V-C premium | No (AA accounts) |
| SLH-DSA-SHAKE-128s | 7,856 B | ~951/s | V-C premium | No (AA accounts) |
| SLH-DSA-SHAKE-192s | 16,224 B | ~312/s | V-C premium | Yes (ADR-043) |
| SLH-DSA-SHAKE-256s | 29,792 B | ~132/s | V-C premium | No (archival only, ADR-045) |

### 9.4 Mempool Anti-DoS

- per-sender `max_sigverify_budget_per_minute` to prevent CPU exhaustion
- `min_fee_per_alg_id` enforced at admission; raised via governance for discouraged algorithms

---

## 10. Crypto Agility Framework

### 10.1 Algorithm Registry

The Algorithm Registry is the on-chain source of truth for which algorithms are permitted, at what fee class, and in what lifecycle state. It is governed, not hardcoded.

### 10.2 Deprecation Process (ADR-011)

Algorithm deprecation follows four steps, each requiring explicit governance action:

1. **Announcement** — intent declared; timeline published
2. **Dual-accept** — algorithm still accepted; ecosystem notified to begin migration
3. **Discouraged** — `min_fee` raised; new accounts cannot register this algorithm
4. **Banned** — `lifecycle_status = banned`; transactions rejected at mempool

Account space is never reset. Rotation flows allow migration within the same account.

### 10.3 Additional Signature Tracking

NIST's "Additional Digital Signature Schemes" process (14 round-2 candidates as of 2024, including CROSS, MAYO, SNOVA, UOV) is tracked as a research path. None are baseline until further standardization.

---

## 11. Initial Use Cases (Phase 1)

*Formal spec: [specs/operations.md](specs/operations.md)*

Phase 1 is not a general-purpose platform. The supported operation types are:

| Operation | Description |
|-----------|-------------|
| Vault account management | create, update, and manage high-security on-chain accounts |
| Attestation anchoring | anchor a cryptographic hash or statement permanently on-chain |
| Notarization | record a timestamped, signed proof of existence for a document or event |
| Identity-linked proof | associate a signing key with an identity claim or credential |
| Proof of ownership / custody | anchor off-chain asset ownership or custody evidence |
| Asset metadata anchoring | record off-chain asset metadata hash for long-term verifiability |
| Key rotation | register a new key, set validity height, revoke old key |
| Signing policy update | update `allowed_tx_types` for a key entry |

Explicitly excluded from Phase 1: native RWA tokenization (issuance, transfer restrictions, redemption, corporate actions, on-chain compliance engine). See ADR-012.

---

## 12. Validator Model

> **As deployed**: the validator set of `viper-testnet-2` is operator-run (proof of authority):
> validators are admitted by the existing set, there is no stake, no bond and no token. The
> staking, churn and slashing mechanics below are the reserve design behind the `token_economics`
> feature (see §13) and are compiled out.

*Formal spec: [specs/validator-staking.md](specs/validator-staking.md) (revised by ADR-042 dynamic validator set, ADR-051 distributed BFT signing, ADR-053 §T1.5 stake-weighted churn)*

### 12.1 Responsibilities

- propose and vote on blocks using PQ signatures (ML-DSA-65 default; SLH-DSA-SHAKE-192s fallback)
- maintain full node state and storage
- participate in governance votes
- respect slashing conditions for equivocation and downtime
- co-sign every commit under ADR-051 distributed BFT signing

### 12.2 Parameters (live values — SPEC-TOKEN-002 / ADR-024)

- minimum stake to become a validator: **1,000,000 VPR** (0.1% of total supply; governance-mutable)
- unbonding period: **14 days** in blocks at target block time (governance-mutable)
- evidence validity window: **28 days** (2× unbonding period; governance-mutable)
- slashing conditions and amounts (SPEC-TOKEN-002 §6):
  - equivocation: **5%** of stake (jail + bond reduction)
  - liveness failure (extended downtime): **0.5%** of stake
  - invalid vote: **2%** of stake
- reward structure: proposer priority share + validator-pool split of fee revenue (SPEC-FEE-001)
- launch validator set size: **3** on `viper-testnet-2` (the author's validator plus admitted operators); growth path to 24 → 50 without redesign

### 12.3 Operator API

Validator operators have access to an internal operator API (health, metrics, maintenance, snapshot controls). This surface is not publicly exposed at the first testnet. A minimal public status endpoint (chain status, height, sync state) is part of the read API. See ADR-014.

---

## 13. Token Utility

> **Reserved — not active.** Viper PQ Chain has **no native token**. Everything in this section
> is a design kept for a possible future decision, implemented behind the dormant `token_economics`
> Cargo feature and compiled out of the public chain. Nothing here is an offer, a sale or a promise
> of anything.

*Formal spec: [specs/token-utility.md](specs/token-utility.md) (roles and mechanisms)*
*Numeric parameters: [specs/tokenomics.md](specs/tokenomics.md) (SPEC-TOKEN-002, ADR-024)*

### 13.1 Token Identity

| Property | Value |
|---|---|
| Name | Viper |
| Ticker | VPR |
| Decimals | 18 |
| Atomic unit | venom (1 VPR = 10^18 venom) |
| Total supply | 1,000,000,000 VPR (fixed, no inflation) |

### 13.2 Genesis Distribution

| Allocation | VPR | Purpose |
|---|---|---|
| Founder | 200,000,000 (20%) | 4-year vesting, 1-year cliff |
| Treasury | 300,000,000 (30%) | Governance-controlled |
| Genesis validators | 100,000,000 (10%) | Bootstrap consensus stake |
| Reserved | 400,000,000 (40%) | Future distribution (governance vote required) |

### 13.3 Economic Roles

| Role | Description |
|------|-------------|
| Transaction fees | pay for bytes, signature verification, and execution (SPEC-FEE-001) |
| Attestation anchoring fees | pay for durable on-chain storage of attestations |
| Staking | validators bond ≥1,000,000 VPR to participate in consensus; subject to slashing |
| Governance | token holders participate in protocol governance (algorithm registry, fee parameters, treasury) |

### 13.4 Principles

- the network monetizes security, trust, finality, and verifiability — not throughput claims
- fee levels are justified by the value of long-term trust, not retail payment competition
- slashing: 5% equivocation, 0.5% liveness failure, 2% invalid vote (see SPEC-TOKEN-002 §6)

### 13.5 Genesis Block

- Chain ID: assigned to `viper-testnet-2` at the genesis ceremony (`pqcd ceremony`, ADR-053 chain-id-bound derivation); the retired private chains used `viper-pq-1` and `viper-research-1`
- Deployment: Kubernetes (Helm chart, one StatefulSet per role) or systemd hosts (Ansible); see `docs/operators/RUNBOOK.md`
- Genesis hash derivation (BIP340 double-tagged, ADR-053 §T2.4): `tagged_hash("VIPER-GENESIS-V1", chain_id_bytes || state_root || timestamp_ns_be64)` where `tagged_hash(t, d) = SHAKE-256(SHAKE-256(t) || SHAKE-256(t) || d)`
- Tier-1 genesis fields: `header_version: u16` (initial 1), `extension_root: [u8;32]` empty-extension sentinel reserving CBOR keys `exec_payload_root` + `builder_bid_commitment` (ADR-053 §T3.4), `hash_id` initial `0x01` SHAKE-256 (ADR-053 §T1.4), `auth_template_registry` seeded `{0x0001: EOA}` (ADR-053 §T3.5), 4-dim `fee_market` (ADR-053 §T2.1), `storage_fund` (ADR-053 §T2.2), `light_client` size=16 quorum=11 (ADR-053 §T3.6 / SPEC-LIGHT-CLIENT-001), `uint64` ns timestamps
- Full specification: [specs/genesis-spec.md](specs/genesis-spec.md) (SPEC-GENESIS-001 + ADR-025 + ADR-053)
- Genesis artefact: published at genesis as `genesis/viper-testnet-2.json` together with the validator root
- Historical: original `viper-mainnet-1` ceremony (ADR-040, 2026-04-20) and `viper-devnet-2` lineage are preserved as audit trail in CHANGELOG / DECISIONS / KNOWN-ISSUES; they are no longer the operational target

---

## 14. Governance

*Status: principles defined — full governance spec is TASK-010*

*Formal spec: [specs/governance-module.md](specs/governance-module.md)*

### 14.1 Governance Scope

Governance controls:

- Algorithm Registry updates (additions, status changes, fee class changes)
- fee coefficient updates (based on hardware benchmark evolution)
- protocol upgrades and deprecation timelines
- validator set rules and slashing parameters

### 14.2 Principles

- governance must be able to deprecate algorithms without resetting account space
- upgrade handlers must be deterministic and auditable
- protocol changes require explicit on-chain record, not implicit convention
- EU regulatory context (MiCA, FATF R.15 Travel Rule) informs the audit trail and governance transparency requirements

---

## 15. Roadmap

> The live plan is [ROADMAP.md](ROADMAP.md); the table below is the original phase plan, kept as
> written. Phases 0–8.5 were completed on the private chains that preceded the public release.

| Phase | Objective | Key deliverables |
|-------|-----------|-----------------|
| 0 — Foundations | coherent product and protocol baseline | documentation set, ADR log, whitepaper skeleton, core specs |
| 1 — Cryptographic and Protocol Specification | minimum protocol surface for safe implementation | transaction envelope spec, account and keyset spec, algorithm registry and lifecycle rules, fee model v0.1, validator model draft, vault and attestation operation definitions |
| 2 — Prototype Node and Controlled Devnet | validate architecture end-to-end | signature pipeline, mempool, block production, state persistence, observability, devnet with 24 validators |
| 3 — Public Testnet | realistic operator and user workflows | public testnet, snapshots and state sync, public read API, validator onboarding, key rotation and algorithm lifecycle drills; testnet exit criteria per SPEC-TEST-001 |
| 4 — Hardening and Audit Readiness | external review and production planning | cryptographic audit, threat review, performance tuning, governance playbooks, launch readiness checklist |
| 5 — Mainnet Economics and Genesis Preparation | finalize economic parameters and production genesis specification | rebranding to Viper PQ Chain (TASK-069); tokenomics ADR-024 + SPEC-TOKEN-002 (1B VPR, 20/30/10/40 distribution); genesis spec ADR-025 + SPEC-GENESIS-001; validator onboarding guide; dress rehearsal procedure |
| 6 — Mainnet Launch and Stabilization | produce genesis block, bring validators online, sustain 30-day stabilization | dress rehearsal execution; genesis ceremony (`viper-mainnet-1`); coordinated launch; 30-day no-upgrade stabilization window; production incident-response drills |
| 7 — Product Layer and First Users | make the trust layer accessible to developers and end users | TypeScript and Python SDKs, block explorer, first vertical product spec, public documentation site |
| 8 — Hardening and devnet-3 cutover | landing libp2p auth, M2 dynamic validator set, M2b distributed BFT signing, M4 archival overlay (RFC 3161 / RFC 4998), Phase-8 audit readiness | ML-KEM authenticated transport (ADR-041), `CommitQuorumPolicy::from_state_store()` (ADR-051), `viper-archival-sidecar` crate, internal audit kickoff |
| 8.5 — `viper-pq-1` launch and mainnet-discipline pivot | replace the `phase-N-devnet-M-rcK` reset pattern with a permanent, forward-compatible chain | ADR-052 Policy P-COMPAT-001 (no resets, every breaking change ships with ADR + activation height + dual-path decoder + cold-sync test); ADR-053 Tier 1+2+3 (BlockHeader v1, ForkDigest signing domains, chain-id-bound addresses, hash registry, stake-weighted churn, multi-dim fee market, storage fund, BIP340 double-tagged hashing, binary Merkle state tree, ePBS-ready extension keys, unified smart-account, sync committee scaffolding); `launch-viper-pq-1.yml` ceremony executed 2026-04-25; SDKs `@v1p3r4llbl4ck/sdk@0.2.0` + `viper-pqchain==0.2.0` published; public site shell at `pqchain.agwswebconsulting.it` (landing + docs + explorer + notary) |

Phases 0–5 are complete (Phase 5 closed 2026-04-12, ADR-026). Phase 6 (`viper-mainnet-1` ceremony) executed 2026-04-20 (ADR-040) and was subsequently superseded operationally by the Phase 8 + 8.5 lineage on the same hosts. Phase 7 SDK publication landed in lockstep — current registry pins are 0.2.0 (post-launch). Phase 8 closed 2026-04-23 (audit readiness) → 2026-04-24 (rc1 incident, KNOWN-ISSUES R-09) → Phase 8.5 launch 2026-04-25.

Phase 9+ (post-launch soak): final `block_time_ms` decision, follower prune script, cold-storage rotation, external operator onboarding validation, fee-revenue 30-day window, external cryptographic audit engagement, dress rehearsal with the live validator set. See `TASKS.md` open list for the per-task pointers.

---

*This document is the vision-and-overview reference for the design as built; `viper-testnet-2` is created at genesis after the first public release. Section-level normative detail lives in the `specs/` corpus referenced inline. Forward-looking items are tagged "Forward:" or marked with a referenced ADR; sections with no such tag describe the as-built protocol.*
