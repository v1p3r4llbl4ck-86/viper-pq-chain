# Architecture Decision Records

## Status Guide

- Accepted: current baseline unless replaced
- Proposed: preferred direction, still open to change
- Deferred: intentionally postponed
- Rejected: considered and not pursued

## ADR-001 - Position PQ Chain As Post-Quantum Trust Infrastructure

**Date**: 2026-04-09  
**Status**: Accepted

### Context

The project needs a reason to exist beyond being another speculative L1. The strongest common thread across the foundation and research documents is long-term trust, not generic chain competition.

### Decision

PQ Chain will position itself as post-quantum trust infrastructure focused on long-term value, identity, and attestations.

### Consequences

- creates a clear thesis and a defensible category
- avoids competing head-on with generic L1 ecosystems too early
- narrows product scope in a way that supports higher assurance
- reduces room for vague or hype-driven roadmap expansion

## ADR-002 - Start With Digital Vault And Attestations As The First Wedge

**Date**: 2026-04-09  
**Status**: Accepted

### Context

A full smart-contract ecosystem would expand scope before the trust layer is stable. The research material suggests that lower-throughput, high-value workflows are a better first fit for PQ cost structures.

### Decision

Phase 1 will prioritize digital vault accounts, attestation anchoring, identity-linked proofs, and policy-driven key management.

### Consequences

- lowers initial TPS pressure
- aligns better with the trust-first thesis
- makes fee levels easier to justify
- postpones broader programmability and related ecosystem expectations

## ADR-003 - Make Crypto Agility A Protocol Requirement

**Date**: 2026-04-09  
**Status**: Accepted

### Context

Post-quantum standards are improving, and signature trade-offs vary significantly across size, performance, and implementation maturity. A single hard-coded algorithm path would make the chain brittle.

### Decision

Accounts and transactions must be algorithm-aware from day one. The protocol will include explicit `alg_id`, `key_version`, and an algorithm lifecycle model.

### Consequences

- supports key rotation and controlled migration
- makes deprecation and recovery flows possible without resetting account space
- adds design complexity to accounts, fees, and transaction validation

## ADR-004 - Use Deterministic CBOR For Signed Transaction Encoding

**Date**: 2026-04-09  
**Status**: Accepted

### Context

Signed payloads must be canonical byte-for-byte across implementations. The research material explicitly rejects non-canonical serialization approaches for this role.

### Decision

PQ Chain will treat deterministic CBOR as the baseline encoding for signed transaction envelopes and related canonical payloads.

### Consequences

- reduces ambiguity in signing and verification
- makes cross-implementation conformance easier to test
- requires strict parser behavior and strong negative testing

## ADR-005 - Price Bytes And Signature Verification Explicitly

**Date**: 2026-04-09  
**Status**: Accepted

### Context

PQ signatures increase bandwidth, storage, and verification costs. A fee model that only prices execution would create avoidable DoS surfaces.

### Decision

The baseline fee model will include byte cost, signature verification cost, and execution cost as separate concerns.

### Consequences

- aligns network economics with actual resource consumption
- protects the mempool and block space from underpriced large signatures
- requires benchmark-informed fee classes and governance updates over time

## ADR-006 - Use ML-DSA As The Default Signature Baseline And Reserve SLH-DSA For Special Flows

**Date**: 2026-04-09  
**Status**: Accepted

### Context

The research points to ML-DSA as the most practical default for a general-purpose PQ signature baseline today, while SLH-DSA is better suited as a conservative fallback because of its signature size.

### Decision

Use ML-DSA as the baseline transaction signature family. Reserve SLH-DSA for special-purpose operations such as recovery or emergency migration. Continue monitoring FN-DSA for future targeted use where smaller signatures materially matter.

### Consequences

- gives the project a realistic baseline with current standards support
- avoids putting very large signatures on the common path
- keeps the door open for future optimization through crypto agility
- still requires careful policy around which algorithms are allowed for which operations

## ADR-007 - Keep Consensus PQ-Aware And Start With A Constrained Validator Set

**Date**: 2026-04-09  
**Status**: Proposed

### Context

In BFT-style consensus, commit material scales with the number of validators and the size of each signature. The research shows that this can quickly dominate block overhead.

### Decision

The current direction is a PoS BFT model with an intentionally constrained initial validator set. A Tendermint or CometBFT-like approach is preferred for the first implementation phase, with HotStuff-like evolution evaluated later.

### Consequences

- improves time-to-first-prototype
- keeps PQ commit overhead manageable in early phases
- accepts stronger limits on validator-set size at the start
- leaves room for future rework if consensus priorities change

## ADR-008 - Delay Generic Smart Contracts Until The Trust Layer Is Stable

**Date**: 2026-04-09  
**Status**: Accepted

### Context

Generic programmability would multiply complexity across execution, tooling, security review, and ecosystem expectations before the chain's core trust model is proven.

### Decision

Phase 1 will not target a generic smart-contract VM. The protocol will focus on a narrow set of built-in operations aligned with vault, attestation, governance, and key-management use cases.

### Consequences

- reduces scope and audit burden
- strengthens the project's differentiation
- may reduce short-term developer excitement
- leaves open a future expansion path if the trust layer succeeds

## ADR-010 - Use ML-KEM For P2P Transport Key Agreement

**Date**: 2026-04-09  
**Status**: Accepted

### Context

P2P connections using classical key agreement (e.g. ECDH) are vulnerable to harvest-now-decrypt-later attacks. An adversary can record encrypted peer traffic today and decrypt it once a cryptographically relevant quantum computer is available. This is particularly relevant for a chain designed to hold long-lived assets and attestations.

### Decision

PQ Chain will use ML-KEM-768 (FIPS 203, NIST Level 3) for P2P transport key agreement. Node identity keys must also avoid classical signature schemes.

### Consequences

- protects peer traffic against harvest-now-decrypt-later from the first deployment
- adds implementation dependency on ML-KEM in the networking layer, not only in transaction signing
- aligns the P2P layer with the same post-quantum-native posture as the transaction and consensus layers
- ML-KEM-768 is a finalized NIST standard with mature open-source implementations (mlkem-native, liboqs)

## ADR-011 - Four-Step Algorithm Deprecation Process

**Date**: 2026-04-09  
**Status**: Accepted

### Context

Crypto agility requires a safe, predictable path for deprecating algorithms without breaking existing accounts or creating panic migrations. A sudden ban would strand users; no process at all would leave dangerous algorithms active indefinitely.

### Decision

Algorithm deprecation follows four steps, each requiring explicit governance action:

1. **Announcement** — governance signals intent to deprecate; ecosystem is put on notice with a timeline.
2. **Dual-accept** — transactions signed with the targeted algorithm are still accepted, but nodes may flag them. Ecosystem migration begins.
3. **Discouraged** — the algorithm's `min_fee` in the Algorithm Registry is raised to penalize use. New accounts should not register this algorithm. Existing users are incentivized to rotate.
4. **Banned** — after a grace period, the algorithm's `lifecycle_status` is set to `banned`. Transactions signed with this algorithm are rejected at mempool admission.

At no step is account space reset. Key rotation flows allow users to migrate to a new algorithm within the same account.

### Consequences

- gives users a predictable and auditable migration path
- requires governance to define and enforce timelines at each step
- the `min_fee` mechanism creates economic pressure to migrate without hard enforcement
- banned algorithm rejection must be tested in a crypto agility drill before mainnet

## ADR-012 - Phase 1 Scope Is Strictly Vault And Attestations, No Native RWA Tokenization

**Date**: 2026-04-09  
**Status**: Accepted

### Context

The Digital Vault + Attestations wedge is already the accepted Phase 1 direction. The question was whether to extend Phase 1 to include full real-world asset (RWA) tokenization primitives — issuance, transfer restrictions, redemption, corporate actions, on-chain compliance engines. Doing so would expand execution scope, API surface, compliance burden, and governance complexity before the trust layer is stable.

### Decision

Phase 1 does not include native RWA tokenization. The scope is:

- vault accounts
- attestation anchoring and notarization
- identity-linked proofs and signing policies
- auditable key rotation and recovery flows
- asset-proof anchoring: proof of ownership, proof of custody, asset metadata anchoring against off-chain records

Explicitly excluded from Phase 1:

- RWA issuance primitives
- on-chain transfer restrictions
- redemption and corporate action flows
- on-chain compliance engine

### Consequences

- keeps execution scope narrow and auditable
- avoids premature API and governance complexity
- asset-proof anchoring covers the most compelling institutional use cases without triggering full RWA scope
- prepares the ground for RWA in a future phase without making it a Phase 1 commitment

## ADR-013 - Initial Validator Set: 24 For Prototype, 32 For Testnet, 50 As Stress Ceiling

**Date**: 2026-04-09  
**Status**: Superseded by ADR-066 (hard caps replaced by the permissionless-eligibility transition; kept as the historical record)

### Context

BFT commit proof size scales with validator count and signature size. With ML-DSA-65 (3,309 B/sig), a 50-validator set produces ~110 KB of commit material per block. This is manageable but pushes the prototype toward measuring consensus overhead rather than the application protocol. A smaller initial set allows cleaner measurement of the core flows.

### Decision

| Phase | Validator count | Quorum (2/3+1) | ML-DSA-65 commit | FN-DSA commit |
|-------|----------------|----------------|-----------------|---------------|
| Prototype / devnet v1 | 24 | ~17 | ~56 KB | ~11 KB |
| Controlled testnet | 32 | ~22 | ~71 KB | ~14 KB |
| Stress target / documented ceiling | 50 | ~34 | ~110 KB | ~22 KB |

The architecture must support growth to 32 and then 50 without requiring a protocol redesign.

### Consequences

- prototype commit overhead remains below 60 KB with ML-DSA-65, well within a 1s block budget
- gives a measurable progression path without committing to a large validator set before benchmarks exist
- 24 is large enough to avoid appearing centralized while keeping PQ commit costs clearly bounded
- 50 as stress ceiling aligns with ADR-007 (constrained validator set) and leaves room for future rework if consensus priorities change

## ADR-014 - Operator API Remains Internal At First Public Testnet

**Date**: 2026-04-09  
**Status**: Accepted

### Context

The API surface splits into three families: public read API, transaction submission API, and operator API (health, metrics, maintenance, snapshot controls). The first public testnet is a pre-hardening environment. Exposing an immature operator API early would increase attack surface, create premature support burden, and risk freezing an unstable contract.

### Decision

At the first public testnet (Phase 3), only the following are publicly exposed:

- read API (network, blocks, accounts, attestations, validators)
- transaction submission API

The operator API (health checks, metrics, maintenance, snapshot controls) remains internal to node operators only, protected by strong operator authentication.

Exception: a minimal public network status endpoint — chain status, current height, sync state, network id — is exposed as part of the read API, not as part of the operator API.

### Consequences

- reduces attack surface during the pre-hardening testnet phase
- avoids premature stabilization of the operator API contract before it is mature
- operators get full internal tooling; public users get status visibility through the read API
- operator API exposure can be revisited as a Phase 4 decision once the surface is hardened

## ADR-015 - Token Economics: Structure And Mechanisms In Phase 1, Concrete Parameters In Phase 2

**Date**: 2026-04-09  
**Status**: Accepted

### Context

Token economics require two separate things: a model (what roles the token plays, what mechanisms exist) and parameters (the actual numbers). Defining parameters before real benchmark data exists produces arbitrary numbers that will need to change, damaging credibility. Deferring the model entirely leaves Phase 1 spec work underspecified.

### Decision

Phase 1 defines the economic model and mechanisms:

- token purpose and utility roles
- staking role and validator incentive structure
- slashing philosophy
- fee components and formula structure (already captured in ARCHITECTURE.md)
- fee classes per algorithm (structure, not final coefficients)
- issuance or non-issuance philosophy
- governance powers tied to token
- what is expressed in token vs what is policy-defined

Phase 2 defines concrete parameters, after prototype benchmark data exists:

- `sigverify_fee` coefficients per algorithm (from measured CPU cost on real hardware)
- `byte_fee` coefficient (from observed storage growth)
- staking minimum amounts
- slashing amounts and conditions
- anti-spam thresholds
- reward schedule

### Consequences

- avoids publishing arbitrary numbers before they can be grounded in measurement
- gives Phase 1 enough economic structure to write coherent specs
- aligns with the Phase 2 exit criterion: "fee and signature-cost assumptions measured, not just estimated"
- supports credibility: model is principled, parameters are evidence-based

## ADR-016 - Linux-First Direct Process Runtime; No Container Or Orchestration Layer In Scope

**Date**: 2026-04-10  
**Status**: Accepted

### Context

As the prototype moves toward an operable node, an infrastructure runtime model must be chosen. The options considered were: (a) Linux process managed by systemd, (b) Docker container, (c) Kubernetes workload. Consensus-critical software with validator key material, stateful disk, and deterministic replay has different failure-domain requirements from a stateless web service.

### Decision

The reference deployment model for PQ Chain is a native Linux process managed by `systemd`, running on a Linux VM or bare-metal host. Docker and Kubernetes are explicitly out of scope for the current phase. The path is: single-node Linux VM → local multi-node VM devnet → controlled VM devnet. Automation is shell scripts first, Ansible for repeatable multi-VM provisioning. Full details and topology diagrams are in [`deployment_architecture.md`](ARCHITECTURE.md).

### Consequences

- keeps failure domains simple and explicit during protocol iteration
- storage layout, process lifecycle, and key handling are visible to operators without abstraction layers
- validator key material does not cross container runtime boundaries
- debug and restart cycles are faster on a direct process
- adds friction for developers who prefer Docker-based local setups; this is an accepted trade-off
- Ansible automation applies to the direct process runtime and does not introduce a parallel runtime model

## ADR-017 - Relax vault_create valid_from_height Rejection Guard (Prototype Path)

**Date**: 2026-04-10  
**Status**: Accepted (prototype path; revisit before testnet)

### Context

`apply_vault_create` originally rejected a transaction if `valid_from_height < store.block_height()`. This was intended to prevent stale activation heights from silently producing Pending keys (which violate invariant I-1: at least one Active key must exist). In practice, the check created an unsolvable timing race: because `store.block_height()` equals H at the time `assemble_block` runs for height H+1, and because Phase 2 ML-DSA signing takes 100–500 ms in debug mode (with no lock held), a `vault_create` tx with `valid_from_height=H` is valid when injected but rejected when the producer has already advanced to H+1.

### Decision

Remove the `valid_from_height < store.block_height()` rejection. The remaining semantics are:
- if `valid_from_height ≤ store.block_height()` at apply time → key status is `Active` (I-1 satisfied)
- if `valid_from_height > store.block_height()` at apply time → key status is `Pending` → `check_invariants()` returns I-1 violation → `ApplyError::PayloadDecode` → tx rejected
- callers should use `valid_from_height = 0` for an immediately-active genesis key on any block

### Consequences

- eliminates the timing race in the producer loop; `valid_from_height=0` is always valid
- a past `valid_from_height` is treated as equivalent to height 0; there is no semantic difference between "activate at genesis" and "activate at some past height"
- the constraint that a vault key activates at a specific future block is weakened; this is acceptable for the prototype path where vault creation is the only key-creation path
- before testnet, evaluate whether the `valid_from_height` field provides enough value to keep, or whether the field should be dropped in favour of a simpler "activate immediately / activate at next boundary" model

## ADR-018 - Declare Phase 2 Exit: Prototype Node And Controlled Devnet Complete

**Date**: 2026-04-10  
**Status**: Accepted

### Context

Prototype Stabilization Review #2 (TASK-040) was conducted after TASK-038 (product-wedge tx tests on devnet) and TASK-039 (Criterion benchmarks for sig verify/sign, block throughput, and state_root scaling). The purpose of this review is to evaluate whether the Phase 2 exit criteria defined in ROADMAP.md are met and to formally record any known deferred scope before opening the Phase 3 backlog.

### Phase 2 Exit Criteria — Assessment

| Criterion | Status | Evidence |
|-----------|--------|---------|
| Deterministic transaction handling across independent runs | **MET** | scenario_runner.rs: state_root equality after restart, replay determinism across N nodes, tip_hash agreement after follower restart; product_workflows.rs: vault+attestation state_root determinism after follower restart and disk replay |
| Basic vault and attestation flows demonstrated | **MET** | product_workflows.rs: vault_create in mempool→block→follower; attestation_create with correct nonce sequencing; both payloads survive follower shutdown, restart, and disk replay; 3 tests, 0 failures |
| Fee and signature-cost assumptions measured, not just estimated | **PARTIALLY MET** | sig_verify bench: ML-DSA-44 (163 µs), ML-DSA-65 (233 µs), ML-DSA-87 (390 µs); V-B relative ratios confirmed; commit sign (1.37 ms); block throughput and state_root scaling measured; Ubuntu VM re-run required before fixing concrete token fee parameters |

### Known Deferred Scope (not bugs — recorded for Phase 3 opening backlog)

These items are explicitly not regressions. They were never in scope for Phase 2 and are documented here so the Phase 3 backlog is not written from scratch.

| Gap | Severity | Phase 3 priority |
|-----|----------|-----------------|
| StubVerifier in mempool admission (`pqcd::node`, `pqcd::devnet`, `pqcd::main`) — commit path uses real ML-DSA, but tx validation does not | High — required before testnet | First Phase 3 item |
| FeeParams::default() everywhere — all fee coefficients are 0; fee enforcement is structurally complete but economically inert | High — required before testnet | After Ubuntu VM benchmark numbers |
| Payload size cap (1 MB, SPEC-TX-001 §5.9) not enforced in code | Medium — DoS surface | Early Phase 3 |
| No `/v1/txs/submit` endpoint — tx submission happens only via internal `inject_tx` path; API.md specifies it as a target | High — required for testnet clients | Phase 3 |
| State root is O(accounts) — computed over full account set on every block; at 500 accounts: 555 µs/block | Medium — becomes bottleneck above ~10K accounts | Phase 3 before testnet |
| No fuzz targets — TESTING.md lists fuzzing but no fuzz harnesses exist | Medium | Phase 3 |
| P2P transport unauthenticated — static HTTP block polling, no ML-KEM session, no peer identity | High — required before public testnet | Phase 3 |
| Ubuntu VM re-run for concrete fee token parameters — V-B ratios confirmed; absolute token values blocked on Linux numbers | Low (structure is in place) | Phase 3 before testnet |

Status update after the Phase 3 opening slices:

- live runtime no longer hardcodes `FeeParams::default()` in bootstrap, replay, mempool admission, or devnet block assembly
- runnable configs now carry an interim non-zero fee baseline
- the remaining fee-model gap is the Ubuntu VM re-benchmark that will replace those provisional values before public-testnet use

### Additional Findings

- **134 tests, 0 failures** across all crates as of 2026-04-10.
- **ADR-017** records the `valid_from_height` relaxation in `apply_vault_create` — spec deviation accepted for the prototype path; revisit before testnet.
- `allowed_tx_types` policy is enforced in the validation pipeline step 8 (key_lookup with permission_bit). Tested in pipeline.rs.
- `chain_id` validation is wired end-to-end: `StateStore` carries the genesis chain_id; the validation pipeline checks it at step 2; production and devnet configs use real hex chain_ids from genesis config files.
- Out-of-gas semantics: fee settled, payload reverted — confirmed tested.

### Decision

**Phase 2 exit criteria are met.** The prototype node and controlled devnet deliver:

- a deterministic single-node and multi-node execution path
- real ML-DSA-65 commit signatures with BFT quorum validation
- vault + attestation + key-management + governance execution slices end to end
- disk persistence, checkpoint-aware bootstrap, and replay recovery
- the first measured PQ signature verification and block throughput baselines
- a running 3-node local devnet with product-wedge tx flows and follower restart coverage

The three deferred "High" items (StubVerifier in mempool, FeeParams zeroed, no tx submission API) are the Phase 3 critical path opening items and MUST be resolved before any public testnet exposure.

### Consequences

- Phase 3 opens with a prioritized backlog anchored on the three "High" deferred items above
- all Phase 2 milestones (single-node alpha, foundation closed, product-wedge coverage, benchmark baseline) are declared complete
- the Phase 2 codebase is the starting point for Phase 3 hardening, not a throwaway prototype

## ADR-019 - Phase 3 Fee Distribution: Proposer Priority Share + Static Validator Pool

**Date**: 2026-04-11 (original) / 2026-04-11 (revised by TASK-049)
**Status**: Accepted (revised — provisional 100%-to-proposer rule superseded)

### Context

TASK-011 introduced `distribute_block_fees` with a provisional 100%-to-proposer rule (no validator pool split). ADR-019 formally recorded this as a Phase 3 exception to SPEC-TOKEN-001. TASK-049 replaces that provisional rule with a minimal validator-set-aware distribution layer, closing the SPEC-TOKEN-001 tension.

### Decision (revised — TASK-049)

`distribute_block_fees(store, proposer, fees_collected, pool_validators, dist)` in `pqc-state::apply` now accepts:

- `pool_validators: &[Address]` — all active validator addresses (derived from `config.devnet.validators` at node startup in Phase 3)
- `dist: &FeeDistributionParams { proposer_share_bps: u16 }` — proposer's priority share in basis points (0–10 000); default Phase 3 value is 5 000 (50%)

Split rule:
- proposer receives `fees_collected × proposer_share_bps / 10_000` as the priority share
- remainder is split equally among all `pool_validators` (which may include the proposer as a validator)
- integer-division rounding goes to the proposer
- when `pool_validators` is empty, 100% goes to proposer (backward-compatible empty-set fallback)

The accounting invariant is strict:

- Every token debited from a sender (`fee_charged + fee_tip`) appears exactly once in `fees_collected`.
- `Σ proposer_credit + Σ validator_credit == fees_collected` exactly; no fee is created or destroyed.
- Empty blocks call `distribute_block_fees` with `fees_collected = 0`, which is a no-op.
- Out-of-gas transactions charge `fee_charged = tx.fee`; the full amount enters `fees_collected`.

Implementation: `FeeDistributionParams` and `distribute_block_fees` in `pqc-state::apply`. Called in both `pqc-consensus::engine::assemble_block` (production) and `pqc-consensus::recovery::replay_blocks_from_state` (recovery) after all `apply_tx` calls and before `advance_height()`. Validator pool derived from `config.devnet.validators` in `pqcd::devnet::start_from_config_path`; threaded through `AssemblyConfig.validator_pool`.

The Phase 3 exception recorded in `specs/token-utility.md` is updated to reflect the resolved SPEC-TOKEN-001 tension. The remaining deviation (static config pool, no on-chain staking) is resolved by the on-chain validator staking lifecycle (TASK-049 Phase 4, ADR-007).

### Consequences

- SPEC-TOKEN-001 tension resolved: proposer no longer receives 100% of fees; pool always receives a share when validators are configured
- Accounting invariant preserved: total credited == fees_collected in all cases
- Recovery and production paths remain symmetric: both call `distribute_block_fees` with the same params
- Remaining provisional behavior: pool is static config (no on-chain staking), deferred to Phase 4 ADR-007 validator lifecycle

## ADR-020 - Phase 3 `consensus_key_rotate` Implementation: Record-Only With Static Validator Config Gap

**Date**: 2026-04-11
**Status**: Accepted

### Context

SPEC-OPS-001 §7.4 specifies `consensus_key_rotate` as a validator-only operation that:
1. Verifies the sender is the operator of an active or candidate validator.
2. Validates the new consensus key (algorithm, size, rotation window).
3. Updates the validator's consensus key in state at `rotation_start_height`.

Phase 3 has no on-chain validator registry. Validators are identified by static `proposer_address_hex` in node configuration files read at startup. There is no `ValidatorSet` type in state, and no mechanism to distinguish validator accounts from regular accounts at the state layer.

Additionally, Phase 3 nodes read their consensus signing key from configuration. Even if an on-chain rotation record were present, nodes would not act on it without a restart and config update.

### Decision

Phase 3 `apply_consensus_key_rotate` implements the following subset of SPEC-OPS-001 §7.4:

**Enforced:**
- Payload structure validation (CBOR fields 1–3 all required).
- Algorithm restriction: SLH-DSA (`0x0020`) and ML-KEM (`0x0100`) are rejected with `AlgorithmNotAllowedForConsensus`.
- Public key size: `new_consensus_pk_bytes.len()` must match the registry `pk_size` for `new_consensus_alg_id`.
- Rotation window: `rotation_start_height ≥ store.block_height() + ROTATION_WINDOW` (Phase 3 baseline: 100 blocks). Violations return `InvalidRotationHeight`.
- State write: a `ConsensusKeyRotation { operator, new_alg_id, new_pk_bytes, rotation_start_height, recorded_at_height }` record is stored under the operator address. A second rotation by the same operator overwrites the first (only the most recent pending rotation is stored).
- Record included in incremental state root under domain `"PQC-CONSENSUS-ROTATE-LEAF-V1"` — deterministic and replay-safe.

**Deferred (Phase 4):**
- Validator-set membership check: `sender` MUST be a registered validator operator. Not enforced in Phase 3 because there is no on-chain validator registry. Any account can submit `consensus_key_rotate` in Phase 3.
- Key activation: the node's actual consensus signing key does NOT change as a result of this operation. The record is stored for audit and future Phase 4 activation.
- `CONSENSUS_KEY_CONFLICT` check (new key already in use by another validator): not enforceable without a validator registry.

### Consequences

- `consensus_key_rotate` transactions are accepted and recorded on-chain in Phase 3, providing an audit trail and a migration path to Phase 4.
- The validator-set membership gap is a known deviation from SPEC-OPS-001 §7.4, accepted for the prototype path (same category as the `valid_from_height` relaxation in ADR-017).
- Phase 4 resolution: implement `ValidatorSet` in `StateStore` (TASK-054-D Phase 4 follow-on, ADR-007 validator lifecycle); re-enable the membership check; add key activation logic to `advance_height`.
- `ROTATION_WINDOW = 100` blocks (≈10 minutes at 6 s/block) is defined in `crates/pqc-state/src/apply/consensus_rotate.rs` and is the Phase 3 baseline. A governance-tunable parameter is Phase 4 scope.

## ADR-021 - Declare Phase 3 Exit: Public Testnet Prototype Complete

**Date**: 2026-04-11  
**Status**: Accepted

### Context

Phase 3 objective was to expose the design to realistic operator and user workflows. The five exit criteria were:

1. Stable finality under expected validator churn
2. Key rotation and algorithm lifecycle flows exercised successfully
3. Storage growth and performance metrics collected on realistic workloads
4. ADR-019 provisional fee-distribution rule replaced by the full proposer/pool split
5. Fault injection scenarios demonstrated at validation layer

TASK-057 (load generator) and TASK-058 (cross-algorithm key-rotation drill) complete the final deliverable closures on criteria 2 and 3. All five criteria are now evaluated below.

### Criterion-by-Criterion Evaluation

**Criterion 1 — Stable finality under expected validator churn: NOT MET in prototype.**

The Phase 3 prototype uses a static validator set configured at startup. There is no on-chain validator registration, bonding, jailing, or unbonding mechanism. The BFT quorum and commit-signature logic assumes a fixed validator set throughout the node's lifetime. Dynamic churn requires the on-chain staking lifecycle deferred to Phase 4 (ADR-007, HotStuff track). This gap is accepted; it is a scope boundary, not a regression. No test infrastructure for validator churn exists and none is planned for Phase 3.

**Criterion 2 — Key rotation and algorithm lifecycle flows exercised successfully: MET.**

- TASK-055 (2026-04-11): algorithm lifecycle deprecation drill — full 4-step governance lifecycle (Active→Discouraged→Deprecated→Banned) for ML-DSA-44 on a live single-node devnet. All 4 lifecycle stages produce correct tx admission and rejection behavior.
- TASK-058 (2026-04-11): cross-algorithm key-rotation drill — `key_rotate_ml_dsa65_to_fn_dsa_padded512` and `key_rotate_ml_dsa65_to_slh_dsa128s` both pass. State lifecycle is verified end to end: old key revoked, new key active with correct alg_id and allowed_tx_types, signing with revoked key rejected at admission. Scope boundary: post-rotation signing with FN-DSA/SLH-DSA is deferred to Phase 4 (requires multi-algorithm verifier backend; MlDsaVerifier only in prototype). This is an implementation gap, not a protocol gap.

**Criterion 3 — Storage growth and performance metrics collected on realistic workloads: PARTIALLY MET.**

- TASK-057 (2026-04-11): load generator infrastructure (`load_test_smoke`) in place. Multi-sender design (N independent senders, nonce=0) correctly measures concurrent admission throughput. Calibrated FeeParams active. CI baseline on Windows debug: 38.6 effective TPS (100/100 txs admitted, 44.8 injection TPS, 11 blocks produced, 9.1 txs/block avg). SPEC-TEST-001 §3.3 target (≥100 TPS) and §4.5 target (≥200 TPS) require reference hardware in release build (`LOAD_TX_COUNT=10000 cargo test --release`).
- Storage growth analysis (block size growth vs. state size growth over N blocks at realistic tx rates) is not yet measured. This remains an open item for Phase 4.
- Accepted as partially met: the infrastructure exists and produces reproducible metrics; the reference-hardware measurement is the outstanding item.

**Criterion 4 — ADR-019 provisional fee-distribution rule replaced by the full proposer/pool split: MET.**

TASK-049 (2026-04-11): `distribute_block_fees` implements the proposer/pool split (`FeeDistributionParams.proposer_share_bps`), wired in both block assembly and replay. ADR-019 revised.

**Criterion 5 — Fault injection scenarios demonstrated at validation layer: MET.**

TASK-056 (2026-04-11): two integration tests: simulated partition recovery (late-joining follower syncs from genesis and converges to identical state_root) and Byzantine equivocation (commit signature over wrong block hash rejected with INVALID_COMMIT_SIGNATURE). Phase 3 gaps (Byzantine majority liveness, fork choice, dynamic churn, network-level chaos) documented in `specs/fault-injection-report.md` as Phase 4 requirements.

### Decision

Phase 3 is declared closed as of 2026-04-11.

Two criteria are fully met, two are fully met, and one (storage growth / realistic-workload TPS) is partially met with infrastructure in place. Criterion 1 (validator churn) is explicitly out of scope for the prototype and is the primary Phase 4 opening item. No prototype-blocking gaps remain.

The Phase 4 backlog opens with:
- On-chain validator staking lifecycle (ADR-007 HotStuff track)
- Reference-hardware load test run and storage growth analysis
- Multi-algorithm verifier backend (FN-DSA, SLH-DSA) for post-rotation signing
- Byzantine majority and fork-choice fault injection (documented in `specs/fault-injection-report.md`)
- Cryptographic audit scope definition

### Consequences

- Phase 3 exit is recorded with a clear deferred-gap inventory.
- Phase 4 opens immediately. No transition gate is required beyond this ADR.
- The 207-test suite (0 failures) is the baseline for the Phase 4 opening.
- ROADMAP.md Phase 3 exit criteria updated with MET/PARTIALLY MET/NOT MET status.

## ADR-022 - Phase 4 On-Chain Validator Staking Lifecycle: Partial Closure of GAP-04 and GAP-05

**Date**: 2026-04-12
**Status**: Accepted

### Context

ADR-020 and ADR-021 identified GAP-04 (static validator set, no height-indexed quorum membership) and GAP-05 (`consensus_key_rotate` record-only, no quorum effect) as the primary Phase 4 architectural items. SPEC-VAL-001 defines five lifecycle states (candidate, active, jailed, unbonding, exited) and requires three staking operations (register, exit, unjail).

Phase 4 objective: implement the on-chain validator registry and lifecycle transitions so that (1) validator registration, exit, and unjail are protocol-level transactions that modify on-chain state; (2) the commit quorum derives from on-chain active validators rather than static config; (3) genesis validators are seeded from node config into the on-chain registry at genesis.

### Decision

**Implemented in TASK-064:**

1. **On-chain registry**: `ValidatorRecord` + `ValidatorStatus` (Candidate/Active/Jailed/Unbonding/Exited) added to `pqc-types`. `StateStore` holds a validator registry (`HashMap<[u8;32], ValidatorRecord>`) with CRUD methods and incremental leaf-hash state root inclusion (domain `PQC-VALIDATOR-LEAF-V1`).

2. **Three new MsgTypes**: `ValidatorRegister (0x0400)`, `ValidatorExit (0x0401)`, `ValidatorUnjail (0x0402)`. All require `GOVERNANCE` bit in `allowed_tx_types`.

3. **Apply handlers** (`pqc-state/src/apply/validator.rs`):
   - `ValidatorRegister`: consensus key must be ML-DSA (44/65/87 only — SPEC-VAL-001 §4); uniqueness check across active+candidate set; self_bond > 0; locked from operator balance; immediately promoted to Active if active set has capacity (<24), else Candidate.
   - `ValidatorExit`: sender must be Active; guard: exit must not leave active set empty; transitions to `Unbonding { start_height }`.
   - `ValidatorUnjail`: sender must be Jailed; transitions to Candidate (or Active if capacity).

4. **Unbonding expiration**: `StateStore::process_validator_unbonding_expirations(height)` called per-block in engine after tx application; returns bond to operator balance when `current_height ≥ start_height + VALIDATOR_UNBONDING_PERIOD` (default 100 blocks).

5. **GAP-04 partial closure**: `CommitQuorumPolicy::from_state_store()` reads active validators from the on-chain registry. Genesis validators are seeded into the on-chain registry from node config in `build_genesis_state()`.

**Deferred to Phase 5:**

- **Height-indexed replay correctness**: `DiskChainStore` still uses the genesis-time quorum policy for replay validation. On-chain validator changes (register/exit) only affect blocks produced after the change. Full height-indexed quorum for replay requires per-block quorum snapshots (significant complexity; deferred per ADR-007 HotStuff track).
- **GAP-05 (consensus_key_rotate activation)**: `CommitQuorumPolicy::from_state_store()` uses the `consensus_pk` from `ValidatorRecord`, but `ValidatorRecord` is still bootstrapped from genesis config. Integration of `ConsensusKeyRotation` records into `ValidatorRecord` is Phase 5.
- **Slashing**: slashing conditions and amounts are TBD Phase 2 (SPEC-VAL-001 §7). Phase 4 supports jailing only via direct state insert (admin path); automatic slashing detection is Phase 5.
- **Delegation and min_stake**: Phase 2 per ADR-015. Self-bond > 0 is the Phase 4 floor; `min_stake` governance parameter is Phase 5.

### Consequences

- 10 new unit tests cover all five lifecycle-state transitions, error conditions (duplicate key, wrong algorithm, zero bond, empty-set guard), and state root change confirmation. 219 workspace tests pass.
- GAP-04 partially resolved; GAP-05 partially resolved. Both remain in audit scope for Phase 5 completion.
- SPEC-VAL-001 §4 (ML-DSA-only consensus key) is now enforced at the apply layer.
- State root now includes validators; replay tests updated to seed identical validator state for deterministic root matching.

## ADR-023 - Declare Phase 4 Exit: Hardening and Audit Readiness Complete

**Date**: 2026-04-12  
**Status**: Accepted

### Context

Phase 4 — Hardening and Audit Readiness — opened on 2026-04-12 following the Phase 3 exit declaration in ADR-021. The objective was to prepare the protocol for external review and production planning by addressing cryptographic audit scope, threat modeling, performance tuning, and security hardening.

Nine tasks were executed (TASK-060 through TASK-068). This ADR records the formal criterion-by-criterion exit evaluation.

### Exit Criteria Evaluation

| Criterion | Status | Notes |
|-----------|--------|-------|
| Critical findings addressed or accepted explicitly | **MET** | All HIGH and MEDIUM security findings fixed (TASK-067: `kem_encapsulate` panic on peer-supplied data → `Result`; session_id KDF derivation); 4 LOW/INFO findings deferred with documented rationale |
| Remaining risks documented with mitigation owners | **MET** | `specs/threat-model.md` (24 surfaces, 4 accepted risks); `specs/security-scan-001.md` (deferred items explicitly enumerated); `specs/audit-scope.md` (6 pre-audit gaps) |
| Launch decision can be made on evidence instead of narrative | **MET** | `specs/launch-readiness.md` provides criterion-by-criterion status; performance baseline measured and documented in TESTING.md; Phase 5 gaps are explicit |

### Phase 4 Work Summary

**TASK-060** (audit scope): `specs/audit-scope.md` produced. 7 primary-scope modules identified, 4 secondary-scope modules, 6 pre-audit gaps (GAP-01 through GAP-06), 7 audit questions for external auditor.

**TASK-061** (threat model): `specs/threat-model.md` produced. 24 threat surfaces evaluated across 7 attack categories. 13 confirmed mitigated, 4 partial, 5 gap, 4 accepted risk. Phase 4 closure checklist produced.

**TASK-062** (reference-hardware load test): 10,000 txs on Ubuntu Linux 6.8.0-107-generic (VM, release build). 81.6 effective TPS. §3.3 target NOT MET pre-optimization; bottleneck documented (state clone during mutex hold). Opened TASK-066.

**TASK-063** (multi-algorithm verifier): `PqVerifier` added to `pqc-crypto` dispatching ML-DSA-44/65/87 and SLH-DSA-SHA2-128s. FN-DSA deferred to FIPS 206 finalization (GAP-01 partially resolved).

**TASK-064** (on-chain validator staking): `ValidatorRecord` + `ValidatorStatus` in `pqc-types`; `ValidatorRegister/Exit/Unjail` MsgTypes; on-chain registry in `StateStore`; `CommitQuorumPolicy::from_state_store()` factory; genesis validators seeded from config; unbonding bond return per-block. GAP-04 partially resolved.

**TASK-065** (Byzantine majority + fork-choice fault injection): `byzantine_majority_liveness_halt` (>f withholding → INSUFFICIENT_COMMIT_QUORUM) and `split_brain_fork_chain_rejected` (phantom fork rejected via PARENT_HASH_MISMATCH; documents first-come-first-served fork choice). `specs/fault-injection-report.md` updated with 4 tested scenarios.

**TASK-066** (performance tuning): `KeyEntry.pk_bytes: Vec<u8>` → `Arc<[u8]>`. `StateStore::clone()` is now O(N × atomic refcount) instead of O(N × pk_size). Load test result: 81.6 → 129.4 effective TPS (+59%). §3.3 target (≥100 TPS) MET. §4.5 (≥200 TPS) NOT MET; next bottleneck documented.

**TASK-067** (security scan): `specs/security-scan-001.md` produced. HIGH finding fixed: `kem_encapsulate` panicked on peer-supplied mathematically-invalid KEM key; fixed to return `Result<..., CryptoError::KemInvalidKey>`. MEDIUM finding fixed: P2P `session_id` derived from raw shared-secret bytes; fixed to use `SHAKE-256(ss || "session-id")`. Constant-time status documented for `ml-dsa` and `ml-kem`.

**TASK-068** (launch readiness): `specs/launch-readiness.md` produced (this decision). Phase 4 declared complete.

### Deferred to Phase 5

The following items are accepted Phase 5 risks; they are explicitly acknowledged, not forgotten:

1. External cryptographic audit engagement (audit scope is ready; firm not yet contracted)
2. FN-DSA production support (blocked on FIPS 206 finalization)
3. `zeroize` feature for ml-kem/ml-dsa (secret material zeroing on drop)
4. Height-indexed quorum replay (per-block quorum snapshots for validator-churn replay determinism)
5. `consensus_key_rotate` activation into `ValidatorRecord` (GAP-05)
6. 200 TPS performance target — next bottleneck is HashMap structure clone per block tick (~6 ms/10K accounts)
7. ~~Tokenomics finalization~~ — resolved by ADR-024 (Phase 5)
8. ~~Genesis block specification~~ — resolved by ADR-025 (Phase 5)
9. 7-day staging testnet dress rehearsal (procedure documented; execution is Phase 6 prerequisite)

### Consequences

- Phase 4 declared complete as of 2026-04-12.
- Phase 5 — Mainnet Economics and Genesis Preparation — is now open.
- **221 tests, 0 failures** as of Phase 4 exit.
- `specs/launch-readiness.md` is the authoritative Phase 4 exit artifact.
- ROADMAP.md Phase 4 exit criteria updated; README.md current-status updated.

## ADR-024 - Viper Token Economics: Fixed Supply, Genesis Distribution, and Staking Parameters

**Date**: 2026-04-12
**Status**: Accepted

### Context

ADR-015 established the token model (4 roles: fee payment, validator self-bond, governance, slashing) and deferred all numeric parameters pending benchmark data. Phase 4 load tests (TASK-062, TASK-066) and the Ubuntu VM calibration (TASK-042) now provide the evidence base. Phase 5 requires a formal tokenomics document before the genesis block can be specified.

The project was rebranded to Viper PQ Chain (TASK-069). The native token is named Viper, ticker VPR, atomic unit venom (1 VPR = 10^18 venom).

### Decision

**Token identity:**
- Name: Viper; Ticker: VPR; Decimals: 18; Atomic unit: venom (1 VPR = 10^18 venom)
- Supply model: fixed — no inflation, no minting after genesis

**Total supply:** 1,000,000,000 VPR (1 billion)
- In venom: 10^27 venom; fits in `u128` (max ~3.4 × 10^38) with headroom

**Genesis distribution:**

| Allocation | Percentage | VPR amount | Vesting | Purpose |
|---|---|---|---|---|
| Founder | 20% | 200,000,000 | 4-year linear, 1-year cliff (off-chain custody) | Long-term alignment |
| Treasury | 30% | 300,000,000 | Governance-controlled, no lockup schedule | Ecosystem development, grants, partnerships |
| Genesis validators | 10% | 100,000,000 | No vesting; committed as stake at genesis | Bootstrap consensus |
| Reserved | 40% | 400,000,000 | Locked until governance vote | Future distribution: community, sales, partners |

Vesting note: Phase 1 has no on-chain vesting contract. Founder vesting is managed off-chain via custody arrangement. This ADR documents the commitment; enforcement deferred to a future governance-controlled vesting module.

**Staking parameters:**

| Parameter | Value | Rationale |
|---|---|---|
| `min_stake` | 1,000,000 VPR (0.1% of supply) | 24 validators × 1M = 24M staked minimum (2.4% of supply) |
| `unbonding_period` | 14 days in blocks (at target block time) | Standard PoS; long enough for slashing evidence to materialize |
| `evidence_validity_window` | 28 days | 2× unbonding period |
| `max_active_set_size` | 24 (VALIDATOR_MAX_ACTIVE_SET_SIZE, ADR-013) | Prototype cap; Phase 6 governance may raise |

**Slashing parameters:**

| Offense | Slash % of stake | Rationale |
|---|---|---|
| Equivocation (double sign) | 5% | Severe deterrent; not destructive to small operators |
| Liveness failure | 0.5% | Punishes downtime without destroying good-faith operators |
| Invalid vote (repeated) | 2% | Between liveness and equivocation |

Note: slashing execution code is not yet implemented (Phase 5 deliverable). These parameters are the governance target; enforcement requires the slashing module.

**Fee coefficients (production floor):**

The Phase 4 calibrated coefficients (TASK-042) are expressed in venom. They represent the technical cost floor, not the economic price floor. With 18 decimals, current values produce fees in the sub-femto-VPR range — economically negligible. During the dress rehearsal (Phase 5), a fee multiplier will be determined so that a typical `token_transfer` costs between 0.001 and 0.01 VPR. The final multiplier is a governance parameter, not a protocol constant.

| Coefficient | Current value | Unit |
|---|---|---|
| `base_fee` | 500 | venom/tx |
| `byte_fee` | 2 | venom/byte |
| `sigverify_fee_v_b` | 14,000 | venom (ML-DSA-65 baseline) |
| `exec_fee_per_gas` | 43 | venom/gas |

### Consequences

- Total supply is final and immutable; no code path may mint after genesis.
- Genesis distribution table is the input for ADR-025 (genesis block specification).
- Slashing percentages require implementation of the slashing module before mainnet.
- Fee recalibration is a Phase 5 dress-rehearsal deliverable; current values are the technical floor.
- `specs/tokenomics.md` (SPEC-TOKEN-002) is the normative document for these parameters.

## ADR-025 - Viper PQ Chain Genesis Block Specification

**Date**: 2026-04-12
**Status**: Accepted

### Context

A mainnet genesis block must be fully deterministic: any operator given the same genesis inputs must independently arrive at the same genesis hash. This ADR defines the structure, state composition, hash derivation formula, and ceremony procedure for the Viper PQ Chain genesis block.

### Decision

**Chain ID:** `viper-mainnet-1` (UTF-8 encoded, then hex for config files)

**Genesis block fields:**
- `height = 0` (genesis does not execute transactions)
- `prev_hash = [0x00; 32]` (null anchor — no predecessor)
- `timestamp`: set at ceremony time; not pre-determined
- `state_root`: computed deterministically from the initial state (accounts, Algorithm Registry, governance parameters, validator set)
- `genesis_hash`: derived after all fields are fixed (see formula below)

**Genesis state composition:**

1. **Account table** — from ADR-024 distribution:
   - Founder account: 200,000,000 × 10^18 venom, ML-DSA-65 key
   - Treasury account: 300,000,000 × 10^18 venom, ML-DSA-65 key (multi-sig deferred to Phase 6)
   - Genesis validator accounts: each holding `min_stake` balance (1,000,000 × 10^18 venom); one account per genesis validator
   - Reserved account: 400,000,000 × 10^18 venom, ML-DSA-65 key (governance-locked)

2. **Algorithm Registry** — initial state per SPEC-ACCOUNT-001 §6.3: ML-DSA-44, ML-DSA-65, ML-DSA-87, SLH-DSA-SHA2-128s all Active; FN-DSA-padded-512, FN-DSA-padded-1024 Active (signing deferred until FIPS 206); ML-KEM-768 Active

3. **Governance parameters** — initial values from `specs/governance.md` and SPEC-FEE-001; all fee coefficients from ADR-024

4. **Validator set** — genesis validators with operator addresses, consensus keys (ML-DSA-65), and `self_bond = min_stake`

**Genesis hash derivation:**

```
genesis_hash = SHAKE-256(
    "VIPER-GENESIS-V1" ||
    chain_id_bytes       ||
    state_root           ||
    timestamp_be64,
    output_len = 32
)
```

The domain string `"VIPER-GENESIS-V1"` provides uniqueness against any other SHAKE-256 usage in the protocol. This formula must be implemented in `pqcd genesis-verify` before mainnet.

**Genesis ceremony procedure:**
1. Each genesis validator generates an ML-DSA-65 keypair offline (air-gapped recommended)
2. Validator public keys and operator addresses are collected and published
3. The genesis config file (`configs/mainnet-genesis.json`) is constructed with all accounts, validators, and governance parameters
4. One operator runs `pqcd genesis-init configs/mainnet-genesis.json` to produce the genesis block
5. The resulting `genesis_hash` is published; every candidate validator independently runs `pqcd genesis-verify` against the same config and confirms the hash matches
6. Chain launch proceeds only when all genesis validators confirm the same hash

**Verification procedure:**
Any operator can verify their node has the correct genesis by running:
```
GET /v1/status → tip_hash at height 0 must equal the published genesis_hash
```

### Consequences

- `specs/genesis-spec.md` (normative) documents these fields and procedures in full.
- The `pqcd genesis-init` and `pqcd genesis-verify` CLI commands are Phase 5 implementation targets (not yet implemented).
- The genesis timestamp is not pre-determined — it is set at ceremony time and included in the published genesis config for independent verification.
- Any deviation from the published genesis config produces a different `state_root` and therefore a different `genesis_hash`; nodes with wrong genesis configs cannot join the network.

## ADR-026 - Declare Phase 5 Exit: Mainnet Economics and Genesis Preparation Complete

**Date**: 2026-04-12
**Status**: Accepted

### Context

Phase 5 — Mainnet Economics and Genesis Preparation — opened on 2026-04-12 following the Phase 4 exit declaration in ADR-023. The objective was to finalize the economic parameters and genesis block specification required before mainnet launch.

Five tasks were executed (TASK-069 through TASK-073). This ADR records the formal criterion-by-criterion exit evaluation.

### Exit Criteria Evaluation

| Criterion | Status | Evidence |
|---|---|---|
| Tokenomics parameters ratified in a formal document (ADR accepted) | **MET** | ADR-024 accepted; `specs/tokenomics.md` (SPEC-TOKEN-002) produced: 1B VPR fixed supply, 20/30/10/40 distribution, min_stake=1M VPR, slashing 5%/0.5%/2% |
| Genesis block specification reviewed, deterministic genesis hash formula agreed | **MET** | ADR-025 accepted; `specs/genesis-spec.md` (SPEC-GENESIS-001) produced: chain ID `viper-mainnet-1`, SHAKE-256 genesis hash formula, ceremony procedure, verification procedure |
| All candidate validators completed KYC/KYB and hardware attestation | **NOT MET** | Deferred to Phase 6 (no genesis validators yet contracted); format and channel TBD by ceremony coordinator |
| 7-day dress rehearsal completed | **PARTIALLY MET** | Procedure documented (`docs/dress-rehearsal-procedure.md`); execution requires live infrastructure — is a Phase 6 prerequisite, not a Phase 5 document deliverable |
| Validator production onboarding documented | **MET** | `docs/validator-onboarding.md` produced: hardware requirements, key generation, registration, operations, SLA expectations |

### Rationale for Partial Credit on Dress Rehearsal

The dress rehearsal procedure is fully documented and matches the ROADMAP.md Phase 5 deliverable ("dress rehearsal procedure documented"). Execution of the rehearsal requires live validator infrastructure and 7 days of calendar time — neither is possible in a documentation-only session. The ROADMAP.md Phase 5 exit criteria state "dress rehearsal completed"; this is accepted as partially met: the procedure is ready for execution, which becomes the first Phase 6 activity.

### Phase 5 Work Summary

**TASK-069** (rebranding): Project renamed to Viper PQ Chain; token is Viper (VPR, 18 decimals, venom atomic unit). Updated CONVENTIONS.md, AGENTS.md, README.md, WHITEPAPER.md, CONTEXT.md, pq_chain_foundation_v2.md. No code changes.

**TASK-070** (tokenomics): ADR-024 accepted. `specs/tokenomics.md` produced. 1B VPR fixed supply; 20% founder (4-year vesting off-chain), 30% treasury, 10% genesis validators, 40% reserved; min_stake = 1M VPR; slashing 5%/0.5%/2%; fee recalibration deferred to dress rehearsal.

**TASK-071** (genesis spec): ADR-025 accepted. `specs/genesis-spec.md` produced. Chain ID `viper-mainnet-1`; genesis hash = SHAKE-256("VIPER-GENESIS-V1" || chain_id || state_root || timestamp_be64); ceremony procedure in 6 steps.

**TASK-072** (validator onboarding): `docs/validator-onboarding.md` produced. Hardware requirements (Ryzen 7 7700, 32 GB, 1 TB NVMe), key generation (operator vs. consensus key, air-gap recommended), registration via msg_type 0x0400, operations guide, SLA expectations.

**TASK-073** (dress rehearsal procedure): `docs/dress-rehearsal-procedure.md` produced. 7-day checklist with specific per-day drills: bootstrap (D1), load test (D2), key rotation (D3), deprecation (D4), validator restart (D5), snapshot import (D6), autonomous operation (D7). Exit criteria, failure procedure, and post-rehearsal report format defined.

### Deferred to Phase 6

1. `pqcd genesis-init` and `pqcd genesis-verify` CLI command implementation
2. Genesis ceremony execution (key collection, genesis config construction, genesis hash agreement)
3. Validator KYC/KYB documentation and hardware attestation collection
4. 7-day dress rehearsal execution on live infrastructure
5. Fee coefficient economic recalibration (multiplier for 0.001–0.01 VPR/tx target)
6. On-chain vesting module (founder vesting currently off-chain)
7. Treasury multi-sig key management

## ADR-027 - Adopt Tendermint-like BFT Consensus with PQ Signatures

**Date**: 2026-04-13  
**Status**: Accepted

### Context

ADR-007 established the consensus direction: PoS BFT, Tendermint-like first, HotStuff-like later. Phases 1–5 used a static single-producer prototype to validate the cryptographic stack, fee model, and execution layer without the complexity of a real consensus protocol. Phase 5 is now closed (ADR-026), 221 tests pass, and the protocol is stable. The time is right to specify and implement round-based BFT consensus.

The static producer is a known structural gap: a single point of failure, no liveness guarantee under proposer failure, no evidence of Byzantine fault tolerance beyond the existing commit-signature quorum check. Phase 6 (mainnet launch) cannot proceed with a static producer.

### Decision

Adopt a Tendermint-like three-phase BFT consensus protocol (Prevote → Precommit → Commit) with the following characteristics:

1. **Proposer rotation**: round-robin weighted by bonded stake; deterministic and reproducible by all nodes from shared state.
2. **Three-phase voting**: NewRound → Prevote → Precommit → Decide, with independent local timers per step.
3. **Locking rules**: a validator that precommits a block is locked on it; cannot precommit a different block at the same height without an unlock polka.
4. **View change**: on timeout without commit, increment round and retry with the next proposer; no explicit view-change message required.
5. **PQ signatures**: all vote messages (Proposal, Prevote, Precommit) are signed with the validator's registered consensus key (ML-DSA-65 or FN-DSA-padded-512); SLH-DSA is prohibited for consensus keys.
6. **Commit material**: the quorum of Precommit signatures is stored in the block body; the block header contains only `commit_hash = SHAKE-256("VIPER-COMMIT-V1" || sorted_precommits, 32)`.

The normative specification is `specs/consensus.md` (SPEC-CONSENSUS-001).

### Consequences

**Positive**:
- The chain survives proposer failure (view change selects the next proposer automatically).
- Proposer rotation distributes block production across all active validators.
- Equivocation is detectable and produces on-chain slashing evidence.
- Safety and liveness properties are inherited from the Tendermint protocol with known Byzantine fault tolerance bounds (`f < n/3`).
- The existing `CommitQuorumPolicy` and `CommitSig` data model are reused without wire-format changes.

**Negative / trade-offs**:
- Three-phase voting adds prevote messages (ephemeral, not stored) to the consensus traffic. For 24 validators with ML-DSA-65, total in-flight traffic per height is ~3.7 MB — acceptable for Phase 1 datacenter validators.
- The prevote + precommit round adds latency compared to the static producer path. Minimum block time under the default timeouts is ~5s (round 0, good network). This is acceptable for Phase 1 vault and attestation workflows.
- A P2P messaging layer for real-time vote propagation is required (currently HTTP-polled; SPEC-P2P-001 defines the requirements).
- HotStuff-like linear communication complexity remains a later optimization; the Tendermint all-to-all vote broadcast is `O(n²)` and becomes a bottleneck above ~50 validators.

### Migration Path

The static `producer_loop` is retained for single-node testing (see SPEC-CONSENSUS-001 §13). The BFT consensus engine is implemented incrementally over TASK-083 through TASK-085.

### Supersedes

This ADR supersedes the "Proposed" status of ADR-007, which is now Accepted with this implementation decision. ADR-007's validator set targets and PQ overhead tables remain authoritative.

### Consequences

- Phase 5 declared complete as of 2026-04-12 (document deliverables MET; operational items deferred to Phase 6).
- Phase 6 — Mainnet Launch and Stabilization — prerequisites: dress rehearsal execution, genesis ceremony, KYC/KYB collection.
- **221 tests, 0 failures** as of Phase 5 exit (no code changes in Phase 5).
- `specs/tokenomics.md`, `specs/genesis-spec.md`, `docs/validator-onboarding.md`, `docs/dress-rehearsal-procedure.md` are the authoritative Phase 5 exit artifacts.

## ADR-028 - Bound ChainStore In-Memory Window Using Trusted Checkpoints

**Date**: 2026-04-14  
**Status**: Accepted

### Context

`DiskChainStore` loads every committed block from genesis into a `HashMap<BlockHash, StoredBlock>` at startup (`open_internal`). On the devnet producer at height ~90,000 (approximately 12 hours of 500 ms blocks with one ML-DSA-65 validator signature per block), this consumed ~7.5 GB RSS — the entire RAM of the 7.8 GB VPS — triggering continuous OOM restarts. The `ChainStore` design comment explicitly called it "for the single-node prototype," indicating this was a known future gap.

### Decision

1. **Periodic checkpoint writes**: both `producer_loop` and `consensus_loop` in `pqcd::devnet` write a trusted checkpoint (`DiskChainStore::write_trusted_checkpoint`) every `CHECKPOINT_INTERVAL` (10,000) blocks. The checkpoint serializes the full application `StateStore` to disk alongside chain metadata (height, tip hash, state root).

2. **Checkpoint-bounded open**: `DiskChainStore::open_internal` now reads the checkpoint file on startup (reusing `read_snapshot_base_if_present`). If a checkpoint exists at height H, only blocks H+1 through tip are loaded into the in-memory `ChainStore`. Pre-checkpoint blocks remain on disk and are still scanned for file presence and hash-index integrity, but are not retained in `by_hash`.

3. **Disk fallback for P2P block export**: `DiskChainStore::export_block_bytes` first checks the in-memory chain; if the requested block is below the checkpoint window it falls back to reading the CBOR block file directly from disk without retaining it in memory.

### Consequences

**Positive**:
- In-memory RSS is bounded to approximately `CHECKPOINT_INTERVAL × block_size` (~60 MB at 10,000 blocks × 6 KB/block) rather than growing without limit.
- Startup time is reduced: scanning pre-checkpoint blocks for file presence is I/O-light (no full deserialization into memory).
- Followers and API callers can still access historical blocks — they are served from disk on demand.
- The first checkpoint is written at block 10,000 (~1.4 hours at 500 ms/block); subsequent startups before that height still replay all blocks, but the OOM risk is low at that scale.

**Negative / trade-offs**:
- Startup still reads all pre-checkpoint block file headers to validate inventory; on very deep chains this is I/O-bound but not memory-bound.
- The checkpoint write is synchronous and holds the state lock for the duration. At CHECKPOINT_INTERVAL = 10,000, the write occurs roughly every 83 minutes (500 ms blocks); the lock hold time is bounded by `StateStore` serialization speed (measured under 100 ms for devnet scale).
- P2P block export for historical blocks now incurs a disk read per request; this is acceptable for devnet follower sync rates.

### Deviation from prior approach

The previous `open_internal` loaded all blocks unconditionally. The checkpoint-bounded path is only activated once at least one checkpoint has been written; before that, the full replay path remains active (unchanged behavior for fresh nodes or nodes with fewer than 10,000 blocks).

### Amendment (2026-04-14)

The initial implementation of ADR-028 had a critical omission: `StateSnapshotRecord` did not serialize validator state (`validator_leaf_hashes`), while `state_root()` includes it. This caused `load_valid_checkpoint` to always compute a mismatched state root and fall back to `recover_tip` — which failed with `HEIGHT_GAP` because only tail blocks were in memory.

**Fix**: `StateSnapshotRecord` now includes `#[serde(default)] validators: Vec<ValidatorSnapshotRecord>` (backward-compatible with old checkpoints via serde default). `state_into_record` serializes all validator records; `record_into_state` deserializes and calls `state.insert_validator()` for each. `load_valid_checkpoint` now emits structured `tracing::warn!` at every failure point. `recover_tip_with_checkpoint` now returns `StorageError::PartialChainCannotFullReplay` (with the data directory path) when the checkpoint is present but invalid and the chain is loaded in tail-only mode, rather than silently emitting a confusing `HEIGHT_GAP` from the full-replay path.

Old checkpoints (written before this fix) will still fail the state_root check and require a chain data wipe. The `deploy/ansible/playbooks/reset-chain.yml` playbook and `make reset-chain` target automate this recovery.

## ADR-029 - Multi-Step Governance (GovernanceVote + Quorum + Tally)

**Date**: 2026-04-15
**Status**: Accepted

**Updated**: 2026-04-15 — TASK-100 complete; original Deferred status superseded.

### Context

`GovernanceProposal` (`MsgType = 0x0300`) was previously implemented as a single-signer, immediate-execution model: any account with the `GOVERNANCE` permission bit submitted a proposal and it was applied atomically in the same block. There was no voting period, no quorum requirement, and no `GovernanceVote` handler.

This was an intentional Phase 3 shortcut to unblock the algorithm lifecycle deprecation drill (TASK-055).

### Decision

TASK-100 implemented the full multi-step governance flow:

1. **Propose** — `GovernanceProposal` creates a `PendingProposal` in `Voting` state with `voting_deadline = current_height + GOVERNANCE_VOTING_PERIOD (5 blocks, devnet)`. Proposal types: `RegistryUpdate (0x01)`, `BurnRateUpdate (0x02)`, `FeeParamUpdate (0x03)`.
2. **Vote** — `GovernanceVote` (`MsgType = 0x0301`) records an active validator's yes/no vote. One vote per validator per proposal; only `ValidatorStatus::Active` accounts may vote.
3. **Tally** — `process_governance_tallies` is called once per block after the tx loop. Proposals with `voting_deadline < current_height` are tallied. Quorum: `quorum_required(n) = (2n+2)/3` (ceiling of 2/3). If quorum met and yes > no: execute effect. If quorum met and no ≥ yes: `Rejected`. If quorum not met: `Expired`.
4. **Timelock** — `GOVERNANCE_TIMELOCK = 0` (immediate execution, Phase 4). Non-zero timelock deferred to a future upgrade.

### Resolved open questions

- Quorum threshold: absolute validator count, ceiling of 2/3 (`(2n+2)/3`).
- Voting period: height-based (deterministic), `GOVERNANCE_VOTING_PERIOD = 5` blocks for devnet.
- Emergency fast-path: not implemented; requires a future ADR.

### Consequences

- `GovernanceVote` transactions are now fully handled at the state layer.
- Parameter changes (burn rate activation, fee param tuning) are now possible via governance without a code deploy.
- The governance account seed no longer needs to be treated as a cold key in the same way; governance power is distributed across the active validator set.
- Audit scope: `pqc-state::apply::governance` and `pqc-types::governance`.

## ADR-030 - Versioned State Format with Fail-Fast Boot Check

**Date**: 2026-04-15
**Status**: Accepted — implemented in TASK-101 (2026-04-16)

### Context

During Phase 2–4 development, every change to the state layout (PQC-STATE-ROOT-V2, AIMD fee market leaf, proposal leaves, validator `tombstoned` field) has required a full chain wipe (`make reset-chain`) because old checkpoints and new binaries are silently incompatible: the binary deserializes old bytes, computes a different state root, and diverges at the first block. Today this fails as `StateRootMismatch { height: N }`, several blocks *after* the actual format break, making the root cause hard to find.

This is acceptable on devnet. On a public testnet — and certainly on mainnet — silent divergence is unacceptable: it looks like a consensus bug, wastes operator time, and erodes trust.

### Decision

Introduce a `STATE_FORMAT_VERSION: u16` constant compiled into the binary and persisted inside every `StateSnapshotRecord` and `ChainCheckpoint`. On boot, the node compares the on-disk version to the compiled version:

- `disk_version == compiled_version` → normal boot.
- `disk_version < compiled_version` → abort with `STATE_FORMAT_UPGRADE_REQUIRED` pointing to the migration procedure (ADR-031).
- `disk_version > compiled_version` → abort with `BINARY_TOO_OLD` instructing the operator to upgrade.

Bump the version on any change that affects: leaf hash domain strings, leaf sort order, checkpoint serde schema, account/validator/proposal struct layout. Do **not** bump for purely runtime changes (API, metrics, logs).

### Consequences

- Any format break fails instantly and deterministically with a clear error, instead of diverging 50 blocks later.
- Forces every PR that touches state layout to make the version bump an explicit, reviewable decision — the ADR-process equivalent of a consensus rule change.
- Pairs with ADR-031: version mismatch is detected here, migration is performed there.
- Audit scope: `pqc-consensus::storage`, `pqc-state::store`.

## ADR-031 - Coordinated State Migration via UpgradeHandler and Migration Height

**Date**: 2026-04-15
**Status**: Accepted — implemented in TASK-102 (2026-04-16)

### Context

ADR-030 provides fail-fast detection of format changes, but not the solution: operators still cannot upgrade without `make reset-chain`. The industry-standard pattern is a **hard fork coordinated at a pre-committed block height**:

- Ethereum: named hard forks (London, Shanghai, Dencun) activate at a specific block.
- Cosmos SDK: `UpgradeHandler` trait + on-chain `MsgSoftwareUpgrade` proposal sets the height.
- CometBFT: app-level upgrade at `height == upgrade_height`, all nodes run the new binary.

Viper now has the prerequisite: multi-step governance (ADR-029, TASK-100). A `SoftwareUpgrade` proposal type can vote an upgrade through, set `activate_at_height`, and the state layer runs the migration when that height is reached.

### Decision

1. Add an `UpgradeHandler` trait in `pqc-state`:
   ```rust
   trait UpgradeHandler {
       fn name(&self) -> &'static str;       // e.g. "v1-to-v2-aimd"
       fn from_version(&self) -> u16;        // STATE_FORMAT_VERSION before
       fn to_version(&self) -> u16;          // STATE_FORMAT_VERSION after
       fn migrate(&self, store: &mut StateStore) -> Result<(), ApplyError>;
   }
   ```
2. A registry `upgrade_handlers: Vec<Box<dyn UpgradeHandler>>` compiled into every binary. On boot, if `disk_version < compiled_version`, the node finds the chain of handlers connecting the two and runs them sequentially, atomically, before resuming block production.
3. Extend `GovernanceProposalType` with `SoftwareUpgrade { activate_at_height: u64, expected_version: u16 }`. When a proposal of this type passes tally, `pending_upgrades` records the (height, version) pair. At `activate_at_height`, the state layer verifies the compiled binary reports `expected_version` and refuses to proceed otherwise — preventing nodes that forgot to upgrade from contributing to consensus.
4. The `v1→v2→v3` migration chain is re-runnable and deterministic: any node replaying from genesis applies the migrations in order, so fresh syncs and in-place upgrades converge to the same state root.

### Consequences

- Upgrades no longer require `make reset-chain`. Operators run `make deploy` to install the new binary before `activate_at_height`; the chain migrates itself.
- Adds a non-trivial invariant: every format bump **must** ship with a handler. Enforce via a compile-time check that there is an unbroken handler chain from any historical version to the current one.
- Governance gains real teeth: it can coordinate a mainnet upgrade without out-of-band operator coordination.
- Audit scope: `pqc-state::upgrade`, governance tally logic.
- Not required before Phase 5 exit but is a blocker for public testnet (Phase 6) per ROADMAP exit criteria refinement.

## ADR-032 - Migrate DiskChainStore to RocksDB with Column Families

**Date**: 2026-04-15
**Status**: Accepted — implemented in TASK-103 + TASK-104 (2026-04-16)

### Context

The current `DiskChainStore` (ADR-028, TASK-089) is a custom checkpoint-bounded store: tail blocks in memory, older blocks on disk as length-prefixed CBOR files, a single snapshot file for state. It works for devnet and the prototype public testnet, but has structural limitations that will bite before mainnet:

- **No ordered range queries**: cannot efficiently answer "blocks N..M" without opening N files.
- **Single checkpoint file**: state snapshot is a whole-file rewrite; no incremental commit or column-level compaction.
- **No historical state access**: `get_account(addr, at_height=N)` is impossible without full replay; explorers, SDKs, and reorg-safe APIs need this.
- **No pruning primitive**: cannot drop column ranges atomically; pruning today means "delete files and hope".
- **No state sync primitive**: ADR-028 snapshot sync ships a monolithic file; modern chains stream chunks of a trie.

All of these are solved by the de facto standard: **RocksDB with column families**. Used by Ethereum (geth, reth), Solana, Cosmos SDK (iavl/memiavl), CometBFT, Polkadot.

### Decision

Replace `DiskChainStore` with a RocksDB-backed implementation using column families:

| Column family       | Key                     | Value                           |
|--------------------|-------------------------|---------------------------------|
| `blocks`           | `block_height: u64 BE`  | CBOR-encoded `Block`            |
| `block_metadata`   | `block_height: u64 BE`  | `StoredBlockMetadata` (hash, bytes_used, tx_count) |
| `block_by_hash`    | `block_hash: [u8; 32]`  | `block_height: u64 BE`          |
| `state_accounts`   | `address: [u8; 32]`     | CBOR-encoded `Account`          |
| `state_validators` | `address: [u8; 32]`     | CBOR-encoded `ValidatorRecord`  |
| `state_proposals`  | `proposal_id: TxHash`   | CBOR-encoded `PendingProposal`  |
| `state_registry`   | `alg_id: u16 BE`        | CBOR-encoded `AlgorithmEntry`   |
| `state_leaf_hashes`| domain + entity_key     | `[u8; 32]`                      |
| `tx_receipts`      | `tx_hash: [u8; 32]`     | CBOR-encoded `TxReceipt`        |
| `checkpoints`      | `checkpoint_height: u64 BE` | `ChainCheckpoint`           |

Adopt Merkle-Patricia trie for the state column families later (Phase 6+), gated behind its own ADR. Step 1 is just the RocksDB migration itself.

### Consequences

- Gains: atomic batched writes (WriteBatch), native range iterators, per-CF compaction, pruning via `delete_range`, and a much simpler state sync (copy CF range).
- Costs: adds a C++ dependency (`rust-rocksdb`); cross-compilation to Windows is more involved; binary size grows ~8 MB.
- Migration path: write a one-shot tool `pqcd migrate-store --from legacy --to rocksdb` that reads the old disk store and writes a RocksDB snapshot. Tied to a specific `STATE_FORMAT_VERSION` bump via ADR-030/031.
- Not blocking Phase 5 (economics) or a closed public testnet. **Is blocking mainnet**: a custom store is not what auditors want to see on a chain that holds real value.
- Audit scope (large): entire storage layer.

## ADR-033 - CLI Wallet with Pluggable Signing Backends

**Date**: 2026-04-16
**Status**: Accepted

**Updated**: 2026-04-17 — TASK-105 complete; `pqcd wallet` implemented with local-rust backend, Argon2id keystore, BIP39 mnemonic, SPEC-ADDRESS-001 domain-separated addresses, Bech32m encoding.

### Context

Viper PQ Chain has transaction builders in the Python and TypeScript SDKs and a full validation/apply pipeline in the node, but no key management, no keystore format, and no signing CLI. Users cannot create wallets, sign transactions, or interact with the chain without writing custom code against the `pqc-crypto` crate directly.

ML-DSA is now standardized (FIPS 204), with implementations in OpenSSL 3.5+, AWS KMS, Luna HSM, and several Rust crates (`ml-dsa`, `fips204`). The `pqc-crypto` crate already wraps `ml-dsa` for keygen and signing from a 32-byte seed. Existing post-quantum chain projects (QRL, IOTA) and classical chains (Cosmos SDK `keys`, Ethereum `geth account`) demonstrate viable CLI wallet patterns that can be adapted for non-ECDSA algorithms.

Additionally, the current address derivation in devnet uses `SHAKE-256(pk_bytes)` without algorithm domain separation, which is a latent collision risk when multiple signature algorithms are supported. A canonical address spec is needed before wallet tooling can be built on a stable foundation.

### Decision

1. **SPEC-ADDRESS-001** defines canonical address derivation with `sig_alg_id` domain separation (`SHAKE-256(sig_alg_id_be16 || pk_bytes, 32)`) and Bech32m display format (`vpr1...` mainnet, `vpt1...` testnet/devnet). This is a breaking change from the current devnet derivation and requires a chain reset.

2. **SPEC-WALLET-001** defines the wallet keystore format and key lifecycle:
   - Mnemonic derivation: BIP39 mnemonic → PBKDF2-HMAC-SHA512 → HKDF-SHAKE256 → 32-byte ML-DSA seed.
   - Keystore encryption: Argon2id (64 MiB, 3 iterations) + XChaCha20-Poly1305. Only the 32-byte seed is encrypted; the keypair is re-derived on unlock.
   - Direct seed import for programmatic use.
   - CLI interface via `pqcd wallet` subcommands: `create`, `import-mnemonic`, `import-seed`, `address`, `public-key`, `sign`, `send`, `export-seed`.

3. The signing backend is **pluggable** via a `WalletSigner` trait. The default backend (`local-rust`) uses existing `pqc_crypto::ml_dsa_sign_with_seed`. Future backends (OpenSSL 3.5+, AWS KMS, PKCS#11 HSM) can be added without changing the wallet CLI or keystore format.

4. Seed material is zeroized from memory after every use (`zeroize` crate). Passphrases are read interactively, never from command-line arguments.

5. Browser wallet, HD derivation paths (BIP-44 style), and multi-account management are out of scope for this ADR. Each will require its own ADR when pursued.

### Consequences

- Users can create wallets, send VPR, and interact with the chain from the CLI without writing custom code.
- SDKs gain a real signing path: build unsigned transaction → `pqcd wallet sign` → submit signed transaction to node.
- The address derivation change breaks backward compatibility with existing devnet state — a chain reset is required. This is acceptable at the current stage (pre-mainnet).
- Mnemonic recovery is possible: the same 12 or 24 words (plus optional passphrase) produce the same address on any machine.
- New external crate dependencies: `argon2` (password hashing), `bech32` (address encoding), `bip39` (mnemonic generation), `zeroize` (memory cleanup). All are well-audited, small, and widely used in the Rust ecosystem.
- Audit scope: `pqcd::wallet` module, `pqc-crypto` address derivation helpers, keystore encryption/decryption, signing flow.

## ADR-034 - P2P Layer: Static Peers Sufficient Through Phase 6, Gossip Required for Phase 8

**Date**: 2026-04-16
**Status**: Accepted

### Context

SPEC-P2P-001 defines the requirements for the P2P layer (broadcast, reliability, authentication, confidentiality, ordering). The current implementation uses static HTTP peer polling with ML-KEM-768 authenticated sessions (TASK-045). This works for a controlled 3-node devnet and a known-operator Phase 6 mainnet launch, but cannot scale to an open validator set.

### Decision

Accept the current static-peer HTTP model as sufficient for devnet and Phase 6 mainnet (known validator set, coordinated launch). Defer gossip protocol implementation (libp2p or custom) to Phase 8 (Public Testnet and Audit). The ML-KEM session infrastructure will be reused as the transport security layer under any gossip protocol. Tracked as TASK-112.

### Consequences

- Phase 6 mainnet is launchable with static peer configs and known validators.
- Phase 8 must implement real P2P before opening to external validators.
- SPEC-P2P-001 remains the requirements document; no spec changes needed.

## ADR-035 - Dynamic Validator Set Deferred to Phase 8

**Date**: 2026-04-16
**Status**: Accepted

### Context

On-chain validator staking lifecycle is implemented: `ValidatorRegister`, `ValidatorExit`, `ValidatorUnjail` (TASK-049, TASK-054). Equivocation slashing with tombstoning is implemented (TASK-097). However, the consensus engine reads the active validator set from `config.devnet.validators` at startup. Adding or removing a validator requires a config change and node restart. For a public testnet, validators must be able to join and leave via on-chain transactions without operator intervention.

### Decision

Accept the static validator set as sufficient for Phase 6 (known validator set, coordinated launch). Defer dynamic validator set changes (consensus engine reads from `StateStore::validators_in_order()` instead of config; epoch-boundary transitions) to Phase 8. The on-chain staking primitives are already in place; what remains is wiring the consensus engine to the state layer for set changes. Tracked as TASK-113.

### Consequences

- Phase 6 validators coordinate out-of-band for set changes.
- Phase 8 must wire `engine.rs` to read validators from state, not config.
- No protocol spec changes needed — SPEC-CONSENSUS-001 already assumes a state-derived validator set.

## ADR-036 - FN-DSA (FALCON) Signing Deferred to FIPS 206 Finalization

**Date**: 2026-04-16
**Status**: Deferred

### Context

FN-DSA (FALCON) is registered in the Algorithm Registry as Active (AlgId 0x0501 FN-DSA-padded-512, 0x0502 FN-DSA-padded-1024). The `PqVerifier` dispatches FN-DSA but returns `NotASigningAlgorithm` (GAP-01 in specs/audit-scope.md). Key rotation drills pass at the state level (`key_rotate_ml_dsa65_to_fn_dsa_padded512`), but FN-DSA signatures cannot be produced. FIPS 206 is not yet finalized by NIST as of 2026-04-16.

### Decision

Keep FN-DSA in the registry as Active (future-proofing). Do NOT implement FN-DSA signing until FIPS 206 is finalized. When published: add `fn_dsa_sign_with_seed` and `fn_dsa_verify` to `pqc-crypto`, wire into `PqVerifier`, run the full key-rotation + signing drill. Tracked as TASK-114.

### Consequences

- Users cannot sign transactions with FN-DSA keys until FIPS 206 ships.
- No security risk: FN-DSA keys can be registered/rotated at state level but cannot produce valid signatures.
- Mainnet (Phase 6) does not require FN-DSA; ML-DSA-65 is the mandatory consensus algorithm.

## ADR-037 - GitLab CI/CD Pipeline: Build Once on Runner, Deploy via Ansible

**Date**: 2026-04-16
**Status**: Accepted

### Context

The `make deploy` / `make deploy-binary` targets previously triggered `cargo build --release` on each target node (producer-1, follower-1, follower-2). This caused repeated failures when C build dependencies (`clang`, `libclang-dev`) were absent or stale on nodes, and wasted compile time rebuilding the same binary three times in parallel.

### Decision

Introduce a GitLab CI/CD pipeline on the existing self-hosted runner (`agws-runner`, #52492470). The pipeline:

1. Validates (fmt, clippy, secret detection) and tests on every push.
2. Builds `pqcd --release` once on the runner for `main` branch and tags; the binary is saved as a GitLab artifact.
3. Exposes manual deploy jobs that use Ansible to distribute the pre-built artifact to nodes (`pipeline-deploy.yml`) rather than building on each node.
4. Retains `make deploy` (full provision, build-on-node) for first-time infrastructure setup and major infra changes where Rust must be verified on the node.

The runner already has SSH access to all devnet nodes and the Ansible inventory; no new secrets or network paths are required.

### Consequences

- Nodes no longer require Rust toolchain or `clang`/`libclang-dev` for normal binary updates.
- Incremental builds use the runner's on-disk cargo cache; after the first run, re-builds compile only changed crates.
- `reset-chain`, `health`, `deploy:config` are available as one-click manual jobs in the GitLab UI.
- `deploy:full` (build-on-node via `site.yml`) is retained for first-time provisioning and infrastructure debugging.
- Binary provenance is the GitLab artifact SHA; no artifact signing yet (deferred to Phase 6 mainnet preparation).

---

## ADR-038 - ValidatorRegister `self_bond` Field Encoded as 16-Byte Big-Endian bstr

**Date**: 2026-04-17
**Status**: Accepted

### Context

`encode_register_payload` in `pqc-state::apply::validator` encoded `self_bond` (a `u128` field) as `Value::Integer((p.self_bond as i64).into())`. This cast silently truncates any bond value > `i64::MAX` (~9.2 × 10^18). Since 1 VPR = 10^18 venom, a validator bonding > 9.2 VPR would have their bond amount corrupted on-chain without any error.

This is a CBOR format change to the `ValidatorRegister (0x0400)` transaction payload (field 4), covered by the SPEC-TX-001 backwards-compatibility rule.

### Decision

Encode `self_bond` as `Value::Bytes(p.self_bond.to_be_bytes().to_vec())` — a 16-byte big-endian byte string, consistent with how `MultisigAccountState.balance` and similar `u128` fields are encoded. The decoder is updated to parse the 16-byte bstr form. Old integer-encoded payloads are no longer accepted.

This is a breaking change at the devnet stage only (no mainnet). A chain reset clears all existing `ValidatorRegister` payloads from history; future re-registrations will use the new encoding.

### Consequences

- Bonds up to `u128::MAX` (~3.4 × 10^38 venom) are representable without truncation.
- Existing devnet validator register payloads (integer-encoded) are incompatible; requires a chain reset before deploying this binary.
- Consistent with the `u128` bstr encoding pattern used for balance fields throughout the codebase.
- Audit finding F-023 resolved.

---

## ADR-039 - ProposalStatus::ExecutionFailed — New Governance Execution Failure State

**Date**: 2026-04-17
**Status**: Accepted

### Context

`tally_one` in `pqc-state::apply::governance` always set `ProposalStatus::Executed` after a proposal passed tally, even when `execute_registry_update` silently skipped the effect (e.g., unknown `alg_id`, invalid lifecycle transition). This meant on-chain state showed `Executed` for proposals whose effects were never applied, making it impossible for observers to detect the no-op.

### Decision

1. Add `ProposalStatus::ExecutionFailed` to the `ProposalStatus` enum in `pqc-types`. Serialized as integer `4` in all storage and leaf-hash contexts (extending the existing 0–3 range).
2. Change `execute_registry_update` to return `bool` (`true` = effect applied, `false` = skipped).
3. `tally_one` sets `Executed` if `true`, `ExecutionFailed` if `false`.
4. Update all three serialization sites: `pqc-state::store::compute_proposal_leaf_hash`, `pqc-consensus::storage` serializer, `pqc-consensus::storage` deserializer.

The `ExecutionFailed` state is terminal and observable via `GET /v1/governance/receipts/{proposal_id}` and the proposal leaf hash (which commits to the status byte).

### Consequences

- Governance observers can now detect and alert on proposals that passed voting but failed execution.
- State root reflects the true execution outcome for every proposal.
- Serialized as `4`; old binaries that encounter a checkpoint with a `4`-status proposal return `InvalidPersistedValue` and refuse to start — same upgrade path as any other state format change.
- This does not require a `STATE_FORMAT_VERSION` bump because the value only appears in checkpoints written after this binary is deployed; old checkpoints have no `ExecutionFailed` proposals. However, operators should be aware that a rollback to an older binary after this value appears on disk would fail the version check.
- Audit finding F-027 resolved.

---

## ADR-040 - Phase 6 Mainnet Launch, Stabilization Window, and Phase 7 SDK Publication

**Date**: 2026-04-20
**Status**: Accepted

### Context

Phase 6 (Mainnet Launch and Stabilization) requires a live genesis block, a minimum BFT-viable validator set, and a 30-day uninterrupted stabilization window. Phase 7 exit criteria include publishing the TypeScript and Python SDKs to public registries.

### Decisions

**Mainnet genesis (2026-04-20T16:32:47Z)**

Chain ID `viper-mainnet-1` launched with 3 validators (ML-DSA-65, FIPS 204). Genesis block hash `6c5462ad8072d233aa366921dbb6bdafcd49ba480c5493fa80cb8701fa93e4e6`; `prev_hash` all-zeros (anchor per ADR-025). Three validators provisioned via Ansible (`deploy/ansible/playbooks/site.yml`) on Contabo VPS infrastructure: producer-1, follower-a, follower-b. Real keypairs generated with `pqcd keygen`; seeds stored in Argon2id+XChaCha20-Poly1305 keystores (`~/.viper/keystore/`); never committed to the repository. Mainnet-specific secrets kept in gitignored `deploy/ansible/group_vars/all/mainnet_keys.yml`.

**30-day stabilization window**

Starts 2026-04-20, ends 2026-05-20. No protocol upgrades during this window without emergency governance (≥ ⅘ threshold, SPEC-GOV-001 §7.4). Prometheus metrics active at `/v1/metrics` on all nodes.

**Infrastructure note — Contabo hosted firewall**

A stale firewall rule on the producer VPS referenced the decommissioned follower-1 address instead of the replacement host. This asymmetrically blocked follower-1 from initiating P2P connections to the producer. Resolved by updating the hosted-firewall rule. An SSH reverse-tunnel workaround was deployed and subsequently removed once the root cause was fixed. The configure role now supports a `viper_producer_p2p_addr_override` per-host inventory variable (ADR-037 pattern) to allow future per-node transport overrides without template changes.

**Phase 7 SDK publication**

- `viper-pqchain==0.1.0` published to PyPI (2026-04-20): `pip install viper-pqchain`
- `@v1p3r4llbl4ck/sdk@0.1.0` published to npm (2026-04-20): `npm install @v1p3r4llbl4ck/sdk`

The npm scope `@viper-pqchain` requires an npm organisation; deferred to Phase 8 when the scope will be migrated. The `pyproject.toml` build backend was corrected from `setuptools.backends.legacy:build` (Python 3.9 incompatible) to `setuptools.build_meta`.

### Consequences

- Phase 6 stabilization window is formally open; exit requires 30 uninterrupted days, one IR drill, and fee-revenue data collection.
- Phase 7 is fully complete; all code deliverables done and both SDKs accessible via public registries.
- The npm package name `@v1p3r4llbl4ck/sdk` is a temporary name; a Phase 8 task will migrate it to `@viper-pqchain/sdk` and deprecate the old name.
- Validator keystores must be backed up off-site; loss of all three seeds would require a chain reset and new genesis ceremony.

---

## ADR-041 - P2P Layer Phase 8 — libp2p + QUIC + X25519MLKEM768

**Status**: Accepted
**Date**: 2026-04-21  
**Deciders**: Alberto Galassi
**Supersedes**: ADR-034

### Context

The SSH reverse tunnel currently in use (systemd service `pqchain-tunnel-follower1.service`) is a temporary workaround introduced in Phase 6. Phase 8 requires a real P2P layer: multi-client interoperability, a negotiable hybrid post-quantum handshake, and throughput sufficient for PQ signatures of 2–16 KB (10–600× larger than classical). SSH reverse tunnels do not scale to independent validators and do not support dynamic discovery.

### Decision

Adopt **rust-libp2p vendored** (internal fork pinned, imported at sub-crate level: `libp2p-core`, `libp2p-noise`, `libp2p-quic`, `libp2p-gossipsub`, `libp2p-kad`) — not the omnibus crate, to avoid 0.x semver churn. Transport: QUIC primary + TCP/TLS 1.3 fallback. Handshake: TLS 1.3 with X25519MLKEM768 as default (codepoint 0x11EC, draft-ietf-tls-ecdhe-mlkem-04 February 2026; already in production on Chrome, Firefox 132+, rustls, OpenSSL 3.5). GossipSub v1.2 for consensus messages (IDONTWANT is critical to suppress duplicates of large PQ payloads). Three separate networks: private validator (port 26656), trusted VFN (26666), public (26676). Sentry architecture for validators behind NAT/VPN. Layered discovery: signed bootstrap → ENR-over-DNS (DNSSEC) → discv5 + Kademlia DHT → on-chain validator registry. Anti-eclipse: bind node ID to validator pubkey on-chain, max N peers per ASN (/24 diversity), ≥3 persistent out-of-band connections (Cosmos sentry pattern).

### Consequences

- Removes SSH reverse tunnel and the `pqchain-tunnel-follower1.service` systemd unit.
- Introduces a dependency on rust-libp2p with a mandatory internal fork.
- ~1.2 KB overhead on the QUIC ClientHello (MTU must be tested).
- The 59k KEM session failure WARNs currently logged are resolved structurally.

### Addendum (2026-04-22) — hybrid KEM deferral to M1b

Phase 8 M1 (P2P cutover, `docs/phase-8-m1-plan.md`) ships libp2p 0.55 with **classical X25519** TLS 1.3 as the default named group. The X25519MLKEM768 hybrid PQ group (codepoint `0x11EC`) is **pre-wired behind the `hybrid-kem-tls` Cargo feature flag and the `P2pConfig::hybrid_kem_enabled` runtime flag, but off by default**. Activation is deferred to M1b, conditional on:

1. `rustls-post-quantum` reaching a stable release with production guidance for server-side 0x11EC support.
2. rust-libp2p 0.56+ exposing the required rustls hooks for custom named groups at the `libp2p-tls` layer.

Rationale: M1's exit criterion is "libp2p/QUIC live, HTTP peer endpoints removed, SSH tunnel gone" (devnet transport modernisation). Locking the timeline to an upstream hybrid-KEM stabilisation risks slipping a 2-week milestone by months. The feature flag preserves ADR-041's architectural commitment — the hybrid default is the destination, not optional — and the M1b task (separate from the M1 tracker) is the trigger.

Phase 8 **exit criterion** as stated in ROADMAP.md remains "libp2p/QUIC" transport; PQ-hybrid at TLS layer is necessary for mainnet cutover but is not on the M1 critical path.

---

## ADR-042 - Dynamic Validator Set On-Chain

**Status**: Accepted
**Date**: 2026-04-21  
**Deciders**: Alberto Galassi
**Supersedes**: ADR-035

### Context

The current validator set is static (3 nodes hardcoded in config). Phase 8 requires independent validators to be able to join and leave without node restarts. The design must handle weak-subjectivity security, slashing, and committee sizes compatible with non-aggregable PQ signatures.

### Decision

Epoch length: 1 hour, adjustable via governance with a floor of 15 minutes (≥4× finality time). Activation churn: `max(4, active/256)` per epoch; exit churn: `max(4, active/32)` per epoch; maximum 25% turnover per epoch. Unbonding: 21 days, extendable only upward via governance. Two-level slashing: (1) hardcoded core offences — equivocation 5%, double-sign 5%, persistent downtime 0.01% + jail; (2) pluggable verifier registry `evidence_type_id → verifier_contract` with a 30-day timelock and 66% supermajority for new verifier registration. Ethereum-style correlation penalty: multiplier 3, window 36 days, cap 100% at ≥33.4% simultaneously slashed. Proposer selection: RANDAO + hash-based VDF v1 (classical EC-based VRFs are PQ-broken by Shor). Committee: 64 validators at genesis → 256 in year 2 → 1024 in year 5 when STARK aggregation matures. Validator eligibility: whitelist in Phase 8 → hybrid Phase 9–10 → permissionless within 18 months post-mainnet, controlled by a single governed parameter `eligibility_mode`. Soft-cap on voting power: `min(effective_stake, 2× median_stake)`.

### Consequences

- The chain requires a new genesis (chain reset).
- Introduces the validator-set module with the `ValidatorTransaction::Reconfig` pattern.
- Prerequisite for the Phase 8 milestone: 5 external validators × 7 days.

---

## ADR-043 - SLH-DSA-SHAKE-192s as Second PQ Algorithm

**Status**: Accepted
**Date**: 2026-04-21  
**Deciders**: Alberto Galassi
**Supersedes**: ADR-036

### Context

ADR-036 indicated FN-DSA (Falcon) as the second algorithm, deferred to FIPS 206 finalization. As of April 2026: FIPS 206 is in draft (submitted for internal approval August 2025, IPD preview September 2025, final expected late 2026/early 2027). The more important concern is that FN-DSA is lattice-based (NTRU/FFT) — the same mathematical family as ML-DSA-65 (MLWE/MSIS). This provides no cryptographic diversity: a breakthrough on structured lattices would break both algorithms simultaneously.

### Decision

Adopt **SLH-DSA-SHAKE-192s** (FIPS 205, final August 2024) as the second algorithm. Parameters: signature 16,224 B, pk 48 B, Category 3 ~AES-192, "s" variant (slow-sign, small-sig) because validators verify far more often than they sign. Usage: consensus-layer fallback paired with primary ML-DSA-65. Via AA: SLH-DSA-SHAKE-128s (7,856 B) for low-value accounts. Archival/notary root overlay: SLH-DSA-SHAKE-256s (29,792 B, Cat 5). FN-DSA (once FIPS 206 is final and the fixed-point variant standardized) is re-evaluated Q4 2027 as an optional third bandwidth-optimized algorithm. SLH-DSA has 45+ years of study (Lamport 1979, Merkle 1989, XMSS 2011) with no algebraic structure exploitable by Shor-like algorithms. The history of SIKE (broken in one hour July 2022) and Rainbow (broken in a weekend 2022) justifies family diversity.

### Consequences

- Storage per validator signature increases (16 KB vs 3.3 KB for ML-DSA-65); acceptable because it is used as a fallback/secondary, not on the hot path for every transaction.
- SLH-DSA verification is CPU-heavy (~951 verify/s vs ~55k ML-DSA): restrict to infrequent events (checkpoints, key rotation, archival overlay).
- FN-DSA is not on the immediate implementation roadmap.

---

## ADR-044 - Crypto Agility — TLV Envelope and On-Chain Verifier Registry

**Status**: Accepted
**Date**: 2026-04-21  
**Deciders**: Alberto Galassi

### Context

Currently ML-DSA-65 is the only supported algorithm and there is no explicit `algo_id` in the wire format. This creates lock-in: adding a second algorithm would require changes to the transaction format, breaking backward compatibility. A chain targeting 20+ years must be able to add verifiers for algorithms not yet invented without a hard fork.

### Decision

Introduce a **multicodec-prefixed TLV envelope** for all signatures and public keys:

```
signature_envelope := <version:u8><algo_id:varint><sig_len:varint><signature_bytes>[<aux_len:varint><aux>]
public_key_envelope := <version:u8><algo_id:varint><pk_len:varint><pk_bytes>
```

`algo_id` is dual-registered: multicodec upstream (github.com/multiformats/multicodec) for off-chain tooling interop + on-chain registry for verifier dispatch. Register codepoints for ML-DSA-44/65/87, SLH-DSA-SHAKE-128s/192s/256s, FN-DSA-512/1024. The `aux` field carries algorithm-specific context. On-chain verifier registry: map `algo_id → verifier_address` with a `deprecated:bool` field; historical entries are never removable, deprecation only blocks new signatures. Stable precompiles at fixed addresses: `verify_ml_dsa`, `verify_slh_dsa`, `poseidon2_hash`, `stark_verify`. Parallel hybrid pattern (not IETF composite): wrapper codepoint `HYBRID_PARALLEL` with two nested envelopes — preferable to composite (single OID) which would require key re-issuance on every update.

### Consequences

- The transaction wire format changes — a chain reset (new genesis) is required.
- All signatures increase by ~3 bytes (TLV header).
- Prerequisite for ADR-043 (SLH-DSA), multi-algo accounts, and the archival strategy in ADR-045.

---

## ADR-045 - Archival Overlay — SLH-DSA-SHAKE-256s + RFC 3161 Timestamping

**Status**: Accepted
**Date**: 2026-04-21 (placeholder); fleshed out 2026-04-23
**Deciders**: Alberto Galassi
**Depends on**: ADR-043 (SLH-DSA-SHAKE-192s), ADR-044 (TLV envelope + verifier registry), ADR-042 (dynamic validator set), ADR-030 (versioned state-root folding)
**Implemented by**: SPEC-ARCHIVAL-001 (`specs/archival-overlay.md`), `docs/phase-8-m4-plan.md`, TASK-160..165

### Context

Viper PQ Chain commits to a **20-year verifiability horizon** for every notary receipt and attestation it issues (WHITEPAPER.md §2; `docs/phase-8-spec.md` §1). The horizon is longer than the current confidence interval on either (a) the asymptotic hardness of structured-lattice problems or (b) the operational lifetime of any single timestamp authority. A chain that signs block commits *only* with ML-DSA-65 does not meet the horizon: ML-DSA-65 is lattice-based (MLWE/MSIS), the same mathematical family as FN-DSA. A single cryptanalytic advance against structured lattices in year N+10 — e.g. an improved BKW variant, or a sub-exponential LLL refinement — would simultaneously invalidate every signature the chain has ever issued. ADR-006 and ADR-043 already commit the project to **cryptographic family diversity** (lattice primary, hash-based secondary), but that diversity has to reach the long-term archival layer, not just the live consensus layer.

The Phase 8 audit-readiness review (`docs/phase-8-audit-readiness.md` §6) explicitly flagged the missing archival layer as a gap against the stated 20-year horizon. Three design options were considered.

**(A) On-chain hash-based signature over each epoch + external RFC 3161 timestamping + RFC 4998 renewal.** Strongest long-term assurance: SLH-DSA is stateless hash-based (Lamport 1979 → Merkle 1989 → SPHINCS+ 2017 → FIPS 205 2024), 45+ years of cryptanalytic exposure, no algebraic structure exploitable by Shor-class algorithms. External TSAs add a temporal anchor outside the chain's own trust boundary, which is what ETSI TS 119 511 / 512 and BSI TR-03125 require for qualified preservation. RFC 4998 ERS renewal extends validity past the life of any individual TSA certificate.

**(B) Bitcoin OP_RETURN or Ethereum L1 as the sole external anchor.** Proof-of-publication with a 14-year track record on Bitcoin, cheap (~$0.50/tx). Weakness: provides temporal ordering only, no integrity attestation from the chain's own signing set; leans on a foreign L1's survival and that L1's hash-function strength; embeds a hard external-chain dependency at the protocol level, which the project did not want.

**(C) Status quo (no archival layer).** Rely on a future fork to add hash-based signatures once lattice confidence weakens. Weakness: leaves pre-fork history permanently vulnerable — a receipt issued in 2026 is not retroactively coverable by a 2035 upgrade, so year-N+20 auditability cannot be promised today.

### Decision

Adopt **Option A**, fully specified in SPEC-ARCHIVAL-001:

1. At each epoch boundary (ADR-042 `EpochInfo::is_epoch_boundary(h)`, ~1 h on mainnet), every honest node deterministically computes `epoch_root = SHAKE-256("VIPER-ARCHIVAL-V1" || epoch_number || first_height || last_height || concat(block_hashes))`. The computation is consensus-critical: byte-stable across nodes, folded into the state root under `VIPER-ARCHIVAL-*-V1` domain tags.

2. A governance-controlled subset of the Active validator set — `archival_signer_set` — co-signs `epoch_root` under **SLH-DSA-SHAKE-256s** (FIPS 205 Cat 5, pk 64 B, sig 29 792 B). Default signer set: all Active validators at epoch 0. Default threshold: `ceil(2n/3)`-of-n, mirroring the SPEC-CONSENSUS-001 §6 BFT commit quorum so the archival claim is never weaker than the consensus claim it backs. Both are governance-mutable under SPEC-GOV-001 §5 (66% supermajority, 30-day timelock).

3. The result is bundled as an `ArchivalRecord` transaction (new `MsgType::ArchivalRecordSubmit = 0x0700`) and applied to `StateStore.archival_records`. A companion `ArchivalRecordAddAnchor = 0x0701` attaches RFC 3161 `TimeStampToken` bytes from ≥ 2 EU-qualified timestamp authorities (eIDAS-qualified, ETSI TS 119 511 conformant; initial list Aruba QTSA, InfoCert TSA, Namirial TSA, TrustPro Cloud TSA — operationally independent per TS 119 511 §6.2). A third `ArchivalRecordRenew = 0x0702` extends the validity horizon per RFC 4998 ERS every ≤ 5 years (ETSI TS 119 512 §6 "preservation-with-TST-renewal", BSI TR-03125 Modul M.3 alignment).

4. The TSA interaction is **out-of-consensus**: the chain records the `TimeStampToken` bytes verbatim but does not verify them cryptographically on apply (X.509 chain-walking against the EU Trust List is deferred to the external auditor at proof time, per ETSI TS 119 512 §7.2 "preservation-with-external-verification"). A dedicated sidecar binary (`viper-archival-sidecar`, M4.5) runs alongside each signing node, subscribes to epoch-boundary events, POSTs `TimeStampReq` per RFC 3161 §2, and submits `ArchivalRecordAddAnchor` on grant.

5. External verification protocol (SPEC-ARCHIVAL-001 §7): a year-N+20 auditor reconstructs the integrity claim by (a) recomputing `epoch_root`; (b) verifying the SLH-DSA signature set against the snapshotted `archival_keys` — purely hash-based, stands even if every ML-DSA-65 signature in history is forgeable; (c) verifying the TSA counter-signs against a historic EU Trust List snapshot from `TSTInfo.genTime`; (d) following the RFC 4998 ERS chain forward to the current horizon.

Option B (Bitcoin-only) is retained as a deferred, governance-addable supplementary anchor (SPEC-ARCHIVAL-001 §6.4) but is not in the mandatory set. Option C is rejected: pre-archival receipts would never be retroactively coverable.

### Consequences

- Introduces a consensus-critical state column `archival_records: BTreeMap<u64, ArchivalRecord>` plus five supporting columns (`archival_signer_set`, `archival_threshold_m_of_n`, `archival_keys`, `archival_tsa_endpoints`, `archival_renewal_period_blocks`). All fold into the state root under distinct `VIPER-ARCHIVAL-*-V1` domain tags; snapshot-sync byte-stability (the `snapshot_full_replay_equivalence` pin) is preserved because the columns start empty and only grow.
- Each Active signer carries a **second long-lived private key** (archival SLH-DSA-SHAKE-256s pk/sk) alongside the consensus key. Cold-storage custody is recommended — the signer is out-of-consensus-hot-path, so the archival key can live on an air-gapped device and be brought online at the once-per-hour epoch cadence. Documented in `docs/validator-onboarding.md` (extended in TASK-163).
- Per-epoch storage cost: `|archival_signer_set| × 29 792 B` signatures + TSA token bytes (~1–5 KB per TST). At `|signer_set| = 24` and 2 TSAs, ~730 KB per epoch, ~6.4 GB/year of archive growth. Acceptable for an L1 with a 20-year horizon — full archive nodes carry it, pruned nodes keep only recent records plus the latest ERS.
- Operational cost: ≥ 2 TSA anchors × ~8 760 epochs/year × €0.10–0.50 per TST → **~€1 750–€8 760/year**. Budgeted at the conservative ~€5 256/year figure (4 TSAs × €0.15 avg × 8 760), documented in `docs/phase-8-m4-plan.md` §5.
- New workspace crate (`viper-archival-sidecar`), new Ansible role (`deploy/ansible/roles/viper-archival-sidecar/`), new dev dependency (`rasn`, pure-Rust ASN.1, for RFC 3161 DER encoding).
- Archival enablement is itself behind a governance parameter (`archival_enabled`, default `true` after M4 merges). Emergency disable via SPEC-GOV-001 §7.4 ⅘-supermajority is available for a TSA-compromise scenario — past records remain valid, new epochs simply do not archive. This is the clean rollback path.
- Phase 9 product-layer work: the SDKs (TS + Python) gain a reference verifier implementing SPEC-ARCHIVAL-001 §7; the block explorer gains an "archival proof" export button. Explicitly out of M4 scope.
- Audit surface: the crypto-audit engagement (TASK-115) scope is extended to include the archival overlay — SLH-DSA-SHAKE-256s backend, `archival_*` apply-path modules, ERS renewal tooling, and the §7 verification-protocol implementation.

### References

- FIPS 205 — Stateless Hash-Based Digital Signature Standard (August 2024)
- NIST SP 800-208 — Recommendation for Stateful Hash-Based Signature Schemes (context for the stateless choice)
- RFC 3161 — Internet X.509 PKI Time-Stamp Protocol
- RFC 4998 — Evidence Record Syntax (ERS)
- RFC 5816 — ESSCertIDv2 update for RFC 3161
- ETSI TS 119 511 — Preservation service policy/security requirements
- ETSI TS 119 512 — Preservation service protocols
- BSI TR-03125 (TR-ESOR) — Beweiswerterhaltung kryptographisch signierter Dokumente
- SPEC-ARCHIVAL-001 (`specs/archival-overlay.md`) — implementation spec
- `docs/phase-8-m4-plan.md` — M4 phased implementation plan (M4.1–M4.7, TASK-160..165)

---

## ADR-009 - Keep The Repository In Foundation Mode Until The Whitepaper Skeleton And Core Specs Exist

**Date**: 2026-04-09  
**Status**: Accepted

### Context

The repository currently contains research and placeholders, but no implementation. Starting code without a stable narrative and technical baseline would create churn.

### Decision

The immediate priority is to complete the whitepaper skeleton, core protocol specs, roadmap, and decision log before implementation begins.

### Consequences

- improves alignment before engineering work starts
- reduces the risk of building against an unstable thesis
- delays visible code output in exchange for clearer foundations

---

## ADR-046 - Restrict Consensus Keys To NIST Category ≥ 3 (Disallow ML-DSA-44)

**Status**: Accepted
**Date**: 2026-04-22  
**Deciders**: Alberto Galassi
**Refines**: ADR-006, ADR-043

### Context

The algorithm registry (`crates/pqc-crypto/src/alg.rs`, `registry.rs`) currently admits four signing algorithms for validator consensus keys via `AlgId::allowed_for_consensus()`: ML-DSA-44, ML-DSA-65, ML-DSA-87, and SLH-DSA-SHAKE-192s. ML-DSA-44 is NIST Category 2 (pk 1,312 B / sig ~2,420 B). The Phase 8 crypto-audit readiness review (`docs/phase-8-audit-readiness.md` §4, gap C7; `KNOWN-ISSUES.md` R-03) flagged this as marginal for an L1 with a 20+ year archival horizon. The Phase 8 audit plan (`docs/phase-8-audit-plan.md` §3.2 item 8) records the parameter-sets guidance: ML-DSA-65 (Cat 3) is the general-use recommendation of NCSC/BSI; ML-DSA-87 (Cat 5) is the archival high-assurance choice; ML-DSA-44 is reserved for low-security scenarios where space is critical. No validator on devnet-2 uses ML-DSA-44 today (R-03), so there is no deployed dependency to break.

Three options were considered. (A) Tighten `allowed_for_consensus()` to require ≥ Cat 3; keep ML-DSA-44 in the registry for non-consensus use. (B) Keep ML-DSA-44 permitted and document the justification; let operators self-select 65. (C) Expose the floor as an on-chain governance parameter `min_consensus_sig_category` defaulting to 3.

### Decision

Adopt **Option A**. `AlgId::allowed_for_consensus()` is restricted to `{MlDsa65, MlDsa87, SlhDsaShake192s}` — a one-line guard change. ML-DSA-44 **stays in the registry** and remains valid for non-consensus use (AA-style low-value attestations, client-side algorithmic options, future experimentation). The post-audit path to re-admit ML-DSA-44 — if a real use case emerges — is an on-chain governance parameter (Option C reduced to a future extension), not a code change.

Rationale, in one paragraph. A 20-year L1 archival horizon is longer than the current confidence interval on lattice hardness estimates; the bandwidth savings of Cat 2 (~33% on pk, ~27% on sig vs ML-DSA-65) are not material at validator-set sizes relevant to Phase 8 (≤64 active per ADR-042). Audits score the floor, not the ceiling: shipping with the tighter floor removes a standing finding and aligns with NCSC/BSI general-use guidance. Option B (documented allowance) would carry the finding through audit unchanged and is rejected on that basis alone. Option C (governance knob) is the right long-term shape but adds a state-machine parameter and a governance proposal before audit; deferring it keeps Phase 8 scope tight and preserves the option.

### Consequences

- Runtime change is a one-line edit to `allowed_for_consensus()` plus a test update.
- ML-DSA-44 remains registered, callable, and enumerable — only the consensus gate rejects it.
- `ValidatorRegister` transactions carrying `consensus_alg_id = 0x0001` are rejected at the CBOR-payload validation step with a clear error; no devnet-2 validator is affected.
- Mildly API-breaking for any future operator who had planned to use ML-DSA-44 as a validator key; no such operator exists today.
- Post-audit, if the constraint needs to be softened, it is a one-line change or a governance-parameter addition — not a cryptographic re-design.

### Supplement (2026-05-06) — TASK-223 closes the consensus-key rotation full path

ADR-020 explicitly framed `consensus_key_rotate` as **Phase 3 record-only**: the apply path (`apply_consensus_key_rotate`) admits the tx and stores a `ConsensusKeyRotation` record on chain, but the validator-record `consensus_alg_id + consensus_pk` is **not** mutated when `rotation_start_height` is reached. Phase 3 nodes continued to read their consensus signing key from static node configuration. This was the documented Phase 4+ gap (GAP-05 in ADR-020 §6).

TASK-223 closes the gap with no ADR-046 invariant change:

- New per-block hook `StateStore::activate_pending_consensus_key_rotations(current_height)` walks the pending rotation map and, for every record with `rotation_start_height <= current_height` matching a registered validator, atomically swaps the operator's `consensus_alg_id + consensus_pk` and removes the rotation record from state.
- Called once per block in BOTH `engine.rs::assemble_block` (live) and `recovery.rs::replay_blocks_from_state` (replay) — under P-COMPAT-001 §2(d) the two paths must mirror each other or replay diverges from live.
- `AlgId::allowed_for_consensus()` (this ADR's invariant) is enforced at the `apply_consensus_key_rotate` admission step (already in place since ADR-020) — the activation hook does not need to re-check because the invariant was checked when the rotation record was admitted.
- Slashing semantics during the rotation window: activation is atomic at `rotation_start_height`. A `CommitSig` for block N is verified against `ValidatorRecord.consensus_pk` AS IT STOOD at block N — old key for blocks `< rotation_start_height`, new key for blocks `>= rotation_start_height`. Equivocation evidence with the OLD key for a block before activation MUST be admitted before the activation height (otherwise the chain can no longer verify the old-key signature). The unbonding period (ADR-050) upper-bounds the evidence window; operators are expected to keep `rotation_start_height >= current + ROTATION_WINDOW (100)`, which is enforced at apply time.
- Cold-sync replay test invariant: TASK-223 is *additive* (no change to existing leaf encodings). The existing `cold_sync_replay.rs` pin (TASK-198) is unchanged. A separate replay-parity test `crates/pqc-consensus/tests/consensus_key_rotation_replay.rs` exercises the rotation+activation path and asserts byte-identical state-roots between the live and replay paths across 4 blocks (rotation pending → activation → post-activation).
- New CLI `pqcd wallet rotate-consensus-key <current-keystore> --new-keystore <path> --node <url> [--rotation-start-height <h>]` submits the rotation tx signed with the operator's current keystore. Default `rotation_start_height = current_tip + 200` so the operator has 1 epoch of buffer to align the keystore swap.

This unblocks ADR-065 §D2 Step 1 (3 → 64 validators) by closing the dynamic-keystore gap that ADR-020 / TASK-113 Step 6 explicitly flagged as Phase 4+.

---

## ADR-047 - Mainnet ValidatorPeerId Binding: On-Chain Field In ValidatorRegister

**Status**: Accepted
**Date**: 2026-04-22  
**Deciders**: Alberto Galassi
**Refines**: ADR-041, ADR-042

### Context

Phase 8 binds validators to libp2p PeerIds with a config-time allow-list: `libp2p.bootstrap_peers` in the node JSON plus `libp2p.validator_peer_ids` in `pqcd/src/node.rs`, enforced in `crates/pqcd/src/p2p.rs` (`is_tx_admitted`, `route_event`). `crates/pqc-p2p/src/peer.rs` already exposes a `ValidatorPeerId` struct for the logical binding. `KNOWN-ISSUES.md` D-03 tracks this as deferred-to-M2 with an on-chain registry as the mainnet target; `docs/phase-8-m2-plan.md` §6 ("Out-of-scope M2b (PeerId registry) — pre-work") confirms the same direction. The threat modelled (`specs/threat-model.md` §3.3.3) is eclipse/Sybil on the validator peer list: under a config-only binding, an attacker with write access to the node configuration can re-point a validator PeerId to their own peer and receive validator gossip, degrading into misrouted Transaction/Vote messages.

Three options were considered. (A) Add a `peer_id: [u8; 38]` field (libp2p PeerId encoded as multihash) to `ValidatorRegister`; make the binding immutable once registered; add a separate `ValidatorRotatePeerId` tx for controlled rotation. (B) Off-chain signed record ("ENR-over-DNS" style) with a Merkle-root checkpoint anchored on-chain — lighter on-chain footprint but more plumbing and an extra trust layer. (C) Keep the config allow-list for mainnet, harden config change control via multi-sig + on-chain policy — not actually better than A because it leaves the binding off the state root.

### Decision

Adopt **Option A**. The on-chain `ValidatorRegister` payload gains a single new field for the libp2p PeerId (multihash-encoded, 38 bytes for identity-hashed PeerIds, variable for others — stored as `bstr` rather than fixed-length to allow future hash upgrades). A companion `ValidatorRotatePeerId` transaction performs controlled rotation under the validator's own consensus key, with a short timelock (one epoch) to bound the re-routing window. The state store gains a `peer_id_bindings: HashMap<Address, PeerId>` column family (or equivalent under the RocksDB backend from ADR-032); the consensus state root commits to it.

Wire-format sketch — extending `ValidatorRegisterPayload` CBOR map (`crates/pqc-types/src/validator.rs`):

```
1: node_id           (tstr)
2: consensus_alg_id  (u16)
3: consensus_pk      (bstr — TLV envelope per ADR-044)
4: self_bond         (bstr, 16-byte big-endian u128 per ADR-038)
5: peer_id           (bstr — libp2p PeerId multihash)    ← NEW
```

Migration plan. Devnet-2 keeps the config allow-list (no migration cost). Testnet-public enables on-chain binding at an agreed epoch boundary: existing validators submit `ValidatorRotatePeerId` during a migration window, after which the config allow-list is removed from the enforcement path and the in-memory set is rebuilt from state at node boot. Mainnet never ships without on-chain binding: it is a hard prerequisite in the mainnet exit-criteria list, tracked against the existing M2b marker in `docs/phase-8-m2-plan.md`.

### Consequences

- `ValidatorRegister` CBOR layout changes — requires the TLV-envelope + registry reset already scheduled around ADR-044 (not an extra chain reset).
- New transaction type `ValidatorRotatePeerId` (opcode allocated in the `0x04xx` validator-lifecycle range, adjacent to `ValidatorRegister = 0x0400`).
- Slashing becomes possible for a validator whose gossip source PeerId disagrees with its on-chain binding (misbinding detection is stateless and cheap).
- The config fields `libp2p.bootstrap_peers` and `libp2p.validator_peer_ids` remain for bootstrap discovery and devnet-2 compatibility; they are no longer the source of truth once a node runs against a chain whose state carries the bindings.
- Compromise of a single node's configuration no longer enables peer impersonation; to re-point a validator PeerId an attacker must obtain the validator's consensus signing key or execute a governance-admitted rotation.

---

## ADR-048 - Correlation Penalty Multiplier (Ethereum ETH2-Style)

**Status**: Accepted
**Date**: 2026-04-23
**Deciders**: Alberto Galassi
**Refines**: ADR-024, ADR-042, SPEC-SLASH-001
**Closes**: KNOWN-ISSUES D-02 (TASK — not separately numbered)

### Context

SPEC-SLASH-001 §10 sets the base equivocation slash at 500 bps (5% of `self_bond`). That is adequate against a lone misconfigured validator but under-prices a coordinated Byzantine attack: at a 5% flat rate, slashing 1/3 of stake costs only `0.333 × 0.05 × total_active_stake ≈ 1.67%` of the attacker's aggregate bond — below the profit threshold for a successful safety violation against a 24-committee. Ethereum's ETH2 design addresses the same asymmetry with a *correlation penalty*: the slash fraction scales with the fraction of stake slashed in a sliding window, so simultaneous slashes are disproportionately expensive. SPEC-SLASH-001 §17 already formalises this direction; KNOWN-ISSUES D-02 tracked the code landing. `pqc-types::slashing::RecentSlashEntry` and `StateStore::recent_slashes: VecDeque<RecentSlashEntry>` (leaf domain `VIPER-RECENT-SLASHES-V1`, folded into `state_root()`) provide the consensus-critical substrate.

Three shape options were considered. (A) **Linear multiplier** `mult = min(1.0, fraction_slashed × K)` with a per-validator additive boost `effective = base × (1 + mult × B)` — Ethereum's actual shape (K=3 in ETH2; `B` a governance-tunable max boost). (B) **Quadratic** `mult = min(1.0, (fraction_slashed / threshold)²)` — steeper curve near the threshold but less predictable at mid-range; requires a square-root divide for bound analysis. (C) **Stepwise tiers** — simpler to audit but discontinuous at boundaries, creating sharp economic cliffs that a sophisticated attacker can dance around.

### Decision

Adopt **Option A**, matching Ethereum's general shape but with protocol-specific parameters tuned for a smaller committee (ADR-013 sets `VALIDATOR_MAX_ACTIVE_SET_SIZE = 24`). The concrete formula, all in u128 basis-point arithmetic:

```
ratio_bps     = min(10_000, window_slashed_stake × 10_000 / active_stake)
multiplier    = min(10_000, ratio_bps × CORRELATION_BASE_MULT)       // cap at 1.0
boost         = 10_000 + multiplier × MAX_MULT_BOOST                  // 10_000 = ×1.0
effective_bps = min(10_000, base_fraction_bps × boost / 10_000)
```

with `CORRELATION_BASE_MULT = 3` and `MAX_MULT_BOOST = 19`. `CORRELATION_WINDOW_BLOCKS = 6_220_800` (36 days at 500 ms/block, matching `EpochConfig::mainnet()`). Single-validator slashes see an empty window and keep the 500 bps base — SPEC-SLASH-001 §10 byte-stability preserved. At the 1/3 stake threshold `multiplier = 10_000` so `effective_bps = 500 × 200_000 / 10_000 = 10_000` (100% slash, capped at `self_bond`). The 20× boost cap (`MAX_MULT_BOOST = 19`, so `1 + 1.0 × 19 = 20`) is intentionally aggressive for a 24-validator committee — Ethereum runs with 300K+ validators where 1/3 is a much larger absolute stake; a smaller set needs a steeper penalty to preserve the same attacker-cost floor. This is the "calibrated-conservative" choice called out in the task brief.

Single-slash path is unchanged (the test `single_equivocation_applies_base_5pct_no_correlation` pins the byte-stable invariant). Multi-slash path is boosted starting from the second slash in the window: the first slash records its entry AFTER computing the multiplier, so two simultaneous slashes produce `(base 5%) + (5% × correlation_boost)` rather than double-boosting the first. This is the Ethereum semantics.

### Consequences

- Fresh consensus-critical state column on `StateStore` (`recent_slashes: VecDeque<RecentSlashEntry>`) with leaf domain `VIPER-RECENT-SLASHES-V1` folded into the state root. Snapshot sync byte-stability is preserved because the ledger starts empty and only grows on slashes.
- Lazy pruning (on each slash apply) keeps the ledger bounded to the window even without a per-block sweep. Two validators processing the same slash at the same height run an identical prune+insert sequence, so state roots converge.
- No changes to the base 500 bps SPEC-SLASH-001 §10 constant — `SLASH_FRACTION_BPS` stays hardcoded per ADR-042 (a governance-immutable safety invariant). Only the correlation multiplier is composition-on-top.
- If ≥ 1/3 of active stake is slashed in the 36-day window, subsequent slashes reach 100% of self_bond. This is the same upper bound as the pre-ADR-048 `self_bond` floor (§13 edge case).
- Overflow analysis: all intermediate `u128` products stay below `u128::MAX ≈ 3.4 × 10^38`. Largest realistic: `window_slashed_stake × 10_000` with `window_slashed_stake ≤ total_supply ≤ 10^27` → `10^31`, well inside u128. `saturating_mul` is defensive belt-and-braces.
- Future governance can tune `CORRELATION_WINDOW_BLOCKS`, `CORRELATION_BASE_MULT`, and `MAX_MULT_BOOST` via supermajority per SPEC-SLASH-001 §17.2, but the threshold (1/3) is hardcoded — same logic as ADR-042's base slash fraction.
- The pluggable verifier registry (ADR-042 §16, KNOWN-ISSUES D-01) can reuse this ledger unchanged; any future slashable offense just calls `record_recent_slash` on apply.

### References

- Vitalik Buterin, *"Accountable safety via correlation penalties"* (Ethereum research forum, 2019)
- Ethereum ETH2 slashing: see `consensus-specs/specs/phase0/beacon-chain.md` §`process_slashings`
- SPEC-SLASH-001 §17 (in-repo) for the protocol-level spec body
- ADR-013 (24-validator committee target)
- ADR-042 (hardcoded offense parameters + correlation penalty direction)

---

## ADR-049 - AddAlgorithm Governance Proposal (Runtime Registry Extension)

**Status**: Accepted
**Date**: 2026-04-22
**Deciders**: Alberto Galassi
**Refines**: ADR-044, SPEC-ACCOUNT-001 §7, SPEC-GOV-001
**Closes**: KNOWN-ISSUES D-05

### Context

ADR-044 landed the TLV envelope and on-chain Verifier Registry (`StateStore::alg_registry`) with governance-mutable lifecycle transitions (`Active → Discouraged → Deprecated → Banned`). What it did *not* ship was a way to *add* a new signature algorithm to the registry after genesis. That gap is KNOWN-ISSUES D-05: Phase 8's registry is static, populated at `StateStore::new()` from `phase1_registry()`, which means the chain has a hard-fork dependency on every future PQ algorithm. NIST is expected to finalize FIPS 206 (FN-DSA) in 2026 and other candidate families (HAWK, SQIsign, CROSS) may follow; the 20-year archival horizon of ADR-045 means at least 2–3 major algorithm generations will land during the chain's life. Requiring a chain reset for each one is operationally inadmissible.

Three shape options were considered. (A) **Governance proposal type** — a new `ProposalEffect::AddAlgorithm` that carries full `AlgEntry` metadata, validated at apply and inserted into the on-chain registry. (B) **Genesis-only + hard fork** — the status quo; rejected because every PQ algorithm becomes a coordinated chain upgrade. (C) **Allow the existing `RegistryUpdate` to cover AddAlgorithm** — rejected because `RegistryUpdate` operates on an `alg_id` that already exists in the registry, overloading the same variant for create-and-update is semantically fragile and audit-hostile (a single typo could silently mutate the wrong entry).

### Decision

Adopt **Option A**, a new `GovernanceProposalType::AddAlgorithm = 0x05` carrying `ProposalEffect::AddAlgorithm(AddAlgorithmProposal)`. The proposal body is:

```
AddAlgorithmProposal {
    alg_id: u16,                    // CBOR key 2
    spec_ref: String,               // CBOR key 11
    pk_size: u32,                   // CBOR key 12
    sig_size: u32,                  // CBOR key 13
    sig_class: Option<u8>,          // CBOR key 14   (0=None, 1=Reduced, 2=Standard, 3=Premium)
    initial_lifecycle: Lifecycle,   // CBOR key 15   (0=Active, 1=Discouraged)
    benchmark_verify_per_sec: u32,  // CBOR key 16
    min_fee: u64,                   // CBOR key 4    (reused from RegistryUpdate)
}
```

Validation at apply-time (tally path inside `apply/governance.rs::execute_add_algorithm`):

- `alg_id` not already registered → `AlgorithmAlreadyRegistered`
- `alg_id` not in reserved range `0x0000..=0x000F` → `ReservedAlgIdRange` (checked both at CBOR decode for fast rejection and at tally for defense in depth)
- `pk_size > 0`, `sig_size > 0`, both `< 256 KB` → `InvalidSize`
- `initial_lifecycle ∈ {Active, Discouraged}` → `InvalidInitialLifecycle` (registering a freshly-deprecated or banned algorithm is rejected as a nonsense transition)
- `alg_id` decodable via `AlgId::from_u16` (i.e. known to the compiled binary)

The `spec_ref` field type on `AlgEntry` is switched from `&'static str` to `std::borrow::Cow<'static, str>` so the same struct can carry either a genesis-baseline literal (zero alloc) or a governance-added owned `String`. `AlgEntry::new_governance(...)` is the public constructor for the owned path.

**Two-phase rollout**. `PqVerifier` dispatches by matching on a fixed list of `AlgId` variants — the compiled binary cannot *verify* signatures for an alg_id it has never heard of. A successful `AddAlgorithm` proposal therefore *reserves the slot and lands the metadata*; the algorithm becomes usable only after a coordinated `SoftwareUpgrade` (ADR-031) that bumps the binary to a version with the new match arm. Until then, a proposal for an alg_id outside `AlgId::from_u16`'s domain tallys to `ProposalStatus::ExecutionFailed` with the registry unchanged. This is intentional: it lets governance schedule algorithm adoption independently of the binary upgrade (e.g. vote to accept FN-DSA in month N, ship binary upgrade in month N+1).

### Consequences

- `ProposalEffect` gains a variant — non-exhaustive match in `pqc-consensus/src/storage.rs` extended additively; the legacy `PendingProposalRecord` snapshot schema does not carry the full payload (spec_ref is variable-length). Snapshot restore of an in-flight `AddAlgorithm` proposal is deferred to a follow-up that bumps `STATE_FORMAT_VERSION`. Today the proposal is only durable across a restart if it has already tallied (the `GovernanceReceipt` is byte-stable).
- `AlgEntry.spec_ref` is now `Cow<'static, str>`. Downstream `.to_string()` / `.to_owned()` calls on `spec_ref` continue to compile; `PartialEq` on string-like types is preserved. This is the minimum-surface change that satisfies both genesis and governance-added code paths.
- `state_root()` does NOT gain a new leaf column from D-05 alone: governance-added entries flow through the existing `alg_leaf_hashes` map (same leaf domain `PQC-ALG-LEAF-V1` as the genesis entries). That keeps D-05 orthogonal to D-01 / ADR-050 which adds a separate slashing-registry leaf column.
- `add_algorithm_proposal_rejects_duplicate_alg_id`, `add_algorithm_proposal_rejects_reserved_range`, `add_algorithm_proposal_rejects_oversized_sig`, and `add_algorithm_proposal_active_after_timelock` pin the four validation branches.

### References

- ADR-044 (TLV envelope + on-chain verifier registry)
- ADR-045 (20-year archival overlay — frames the "2-3 algorithm generations" horizon)
- SPEC-GOV-001 §5 (governance proposal lifecycle)
- SPEC-ACCOUNT-001 §7 (Algorithm Registry field definitions)
- KNOWN-ISSUES D-05 (closed by this ADR)

---

## ADR-050 - Pluggable Slashing-Verifier Registry (ADR-042 §16)

**Status**: Accepted
**Date**: 2026-04-22
**Deciders**: Alberto Galassi
**Refines**: ADR-024, ADR-042 §16, ADR-048, SPEC-SLASH-001
**Closes**: KNOWN-ISSUES D-01

### Context

ADR-042 §16 envisioned a pluggable slashing-verifier registry so future slashable offenses (data-withholding, DA bias, long-range attacks, downtime) could be added without a hard fork. What Phase 8 actually ships is a single hardcoded handler: `apply_submit_equivocation_evidence` with a `SLASH_FRACTION_BPS = 500` constant (SPEC-SLASH-001 §10, ADR-024). That matches ADR-042's "hardcoded offense parameters for Phase 8" clause, but it means the chain cannot evolve its slashing surface through governance — every new evidence type is a coordinated binary upgrade, and even tuning the equivocation fraction is source-level.

ADR-048 (correlation penalty, D-02) already proved the shape: a small consensus-critical column on `StateStore`, folded into `state_root()` under a stable leaf domain, updated atomically with the apply path. The pluggable registry generalizes that same pattern to a per-offense metadata table.

Three shape options were considered. (A) **On-chain registry keyed by `u8` evidence-type discriminant**, with core types `0x01..=0x0F` code-governed and governance-extensible in `0x10..=0xFF`. (B) **Registry keyed by arbitrary strings** — nicer DX but adds state-root length variability and makes on-chain dispatch slower for zero benefit. (C) **Pure code configuration** — the status quo; rejected because it denies governance any steering over the slashing surface.

### Decision

Adopt **Option A**. A new column on `StateStore`:

```
pub slashing_registry: HashMap<u8, SlashingVerifierEntry>

SlashingVerifierEntry {
    evidence_type: u8,
    spec_ref: String,
    slash_fraction_bps: u16,      // 500 = 5%
    jail_duration_blocks: u64,
    tombstone: bool,
    lifecycle: Lifecycle,
}
```

At genesis the registry is seeded with a single entry `0x01` (equivocation, 500 bps, `tombstone = true`, `lifecycle = Active`) whose spec_ref is `"SPEC-SLASH-001 §10 (equivocation, ADR-024)"`. Governance can add new evidence types via `ProposalEffect::AddSlashingVerifier(SlashingVerifierProposal)` carried by `GovernanceProposalType::AddSlashingVerifier = 0x06`. Reserved range: `0x00` (invalid sentinel) and `0x01..=0x0F` (core types, code-governed, cannot be overridden by governance). Governance-added types occupy `0x10..=0xFF`.

The registry is folded into `state_root()` under leaf domain `VIPER-SLASHING-REGISTRY-V1` — one 32-byte leaf per entry, sorted by `evidence_type` ascending. The per-entry serialization encodes `evidence_type || len-prefixed spec_ref || slash_fraction_bps || jail_duration_blocks || tombstone_byte || lifecycle_byte`. Any change to this encoding is a new ADR + `STATE_FORMAT_VERSION` bump.

Validation at apply-time for an `AddSlashingVerifier` proposal:

- `evidence_type != 0x00` and `evidence_type > 0x0F` → `ReservedSlashingEvidenceType`
- `evidence_type` not already registered → `DuplicateSlashingVerifier`
- `slash_fraction_bps ≤ 10_000` (100%) → `InvalidSlashingFraction`
- `lifecycle ∈ {Active, Discouraged}` → `InvalidInitialLifecycle`

**Two-phase rollout** (same shape as ADR-049). Governance can *register* a new evidence type and its metadata, but the actual evidence-handler *dispatch* lives in code (`apply_tx` matches on `MsgType::SubmitEquivocationEvidence` and calls the hardcoded handler). A new evidence type needs both a successful `AddSlashingVerifier` proposal (for metadata) and a coordinated `SoftwareUpgrade` (ADR-031) that adds the dispatch arm and the handler body.

**Governance-tunable equivocation fraction**. `StateStore::effective_slash_fraction_bps(evidence_type)` reads from the registry with `DEFAULT_EQUIVOCATION_SLASH_FRACTION_BPS = 500` as the fallback for pre-registry checkpoints. The hardcoded `SLASH_FRACTION_BPS` constant inside `apply/slashing.rs` is preserved verbatim for this commit so the D-02 byte-stable test `single_equivocation_applies_base_5pct_no_correlation` continues to produce the identical state root. Phase 2 wiring swaps the constant for `store.effective_slash_fraction_bps(SLASHING_EVIDENCE_TYPE_EQUIVOCATION)` — byte-stable on the genesis-seed path, governance-tunable thereafter.

### Consequences

- Fresh consensus-critical state column on `StateStore` (`slashing_registry: HashMap<u8, SlashingVerifierEntry>` + leaf-hash map) with leaf domain `VIPER-SLASHING-REGISTRY-V1` folded into `state_root()`. New chains seed `0x01` at genesis; cargo test -p pqcd --test snapshot_sync stays green because both sides of the roundtrip seed identically.
- `ProposalEffect` gains a variant. Same caveat as ADR-049: the legacy `PendingProposalRecord` snapshot schema cannot carry the full payload; snapshot durability of an in-flight `AddSlashingVerifier` proposal is deferred to a follow-up.
- The ledger from ADR-048 (`recent_slashes: VecDeque<RecentSlashEntry>`) is orthogonal: it tracks the *correlation* history across all slashable offenses, independent of the registry's per-type metadata. The two columns cooperate (the equivocation entry's `slash_fraction_bps` drives the base, the ledger drives the multiplier) without coupling.
- `add_slashing_verifier_proposal_rejects_duplicate_type`, `add_slashing_verifier_proposal_lands_after_timelock`, and `equivocation_applies_registry_driven_slash_fraction` pin the three validation / apply / read-side branches.
- Future governance can tune individual `slash_fraction_bps` values by landing a follow-up ADR that extends `ProposalEffect::RegistryUpdate` shape (or a dedicated `SlashingRegistryUpdate`) — deliberately deferred; ADR-050 covers insertion only.

### References

- ADR-042 §16 (pluggable registry vision)
- ADR-024 (equivocation slash constants — 500 bps baseline)
- ADR-048 (correlation penalty ledger — shape precedent)
- SPEC-SLASH-001 (protocol spec body)
- KNOWN-ISSUES D-01 (closed by this ADR)

---

## ADR-051 - M2b: CommitSig Unification per SPEC-CONSENSUS-001 §10.4 — Retire Legacy `PQC-COMMIT-V1` Preimage

**Status**: Accepted (2026-04-23, post-audit revision)
**Date**: 2026-04-23
**Deciders**: Alberto Galassi
**Refines**: ADR-007 (BFT consensus), SPEC-CONSENSUS-001 §8.4 / §10.3 / §10.4
**Closes**: KNOWN-ISSUES D-06 (production path); the M2b multi-node BFT code blocker that TASK-113 Step 6 currently flags as "Phase 9+"

### Context

The Phase 8 BFT-prototype `BlockRecord` carries `commit_signatures: Vec<CommitSig>`, each signed over the legacy preimage `"PQC-COMMIT-V1" || height_be64 || block_hash` (`crates/pqc-consensus/src/commit.rs:139`). Separately, TASK-136 landed a full `SignedVote` gossip path whose Precommit signatures are built over the `SPEC-CONSENSUS-001 §8.4` preimage `SHAKE-256("VIPER-VOTE-V1" || height_be64 || round_be32 || step_u8 || block_hash)` (`crates/pqc-consensus/src/round.rs:44`). **Note**: §8.4's `pol_round_i32_be` field is present only in the Proposal preimage, not in the Prevote/Precommit preimages — the vote preimage carries `step_u8` (1=Prevote, 2=Precommit) but no pol_round. An earlier revision of this ADR stated "round = 0, pol_round = -1 defaults" — the `pol_round = -1` default is vestigial and is dropped in the §Decision section below.

Both preimages are currently in production. The 3c4a5f4 commit's receiver-side buffer (`pending_precommits`) holds `SignedVote` objects, but the producer path still writes `Vec<CommitSig>` with the legacy preimage into each committed block. This means a multi-node BFT finalizer cannot simply drain the precommit gossip buffer into `block.commit_signatures` — the preimages are incompatible and SPEC-CONSENSUS-001 §8.4 explicitly forbids intermixing:

> "These preimages differ from the existing commit preimage in `pqc-consensus::commit`; the two formats MUST NOT be intermixed." (consensus.md:363)

The spec then commits to the target data model in §10.3 and §10.4:

> "The commit material for height `h` consists of the set of `Precommit` messages whose signatures establish the quorum. This material… is included verbatim in `block_body.commit_sigs`." (consensus.md:406)
> "This spec extends the same data model: `CommitSig` is a Precommit message with a valid signature. The `CommitQuorumPolicy::verify` call covers the commit condition in §10.1 without modification." (consensus.md:413)

So the target architecture is not "add a parallel gossip channel" or "extend SignedVote with a second signature" — it is "retire the legacy `PQC-COMMIT-V1` preimage, and make `CommitSig` structurally a `Precommit` `SignedVote`". Every precommit a validator emits on the `/viper/<chain>/consensus-vote/1.0.0` gossip topic is, modulo encoding wrapper, the signature that will land in the next committed block's `commit_sigs`.

Three shape options were considered for bringing the code in line with the spec:

- **(A) Unify to the Precommit preimage and reset devnet-2.** Retire `PQC-COMMIT-V1` entirely. Re-key `CommitSig` verification against the §8.4 preimage (with `round = 0` during the single-round prototype slice; `pol_round` is not present in the vote preimage). Reset devnet-2's chain from genesis — existing blocks become unverifiable by the new binary, and no migration is attempted. Spec-aligned, code-minimal (~200–300 lines of deltas across `pqc-consensus::commit`, `pqc-consensus::engine`, and the devnet producer/consensus loops).
- **(B) Activation-height hybrid decoder.** Keep `PQC-COMMIT-V1` verification for blocks at heights below a cut-over height `H*`, use the §8.4 preimage for blocks above. Implement a dual decoder in `CommitQuorumPolicy::verify` driven by the block's own height. No devnet-2 reset. ~1 000 lines + two verified code paths + test matrices (legacy blocks, new blocks, cut-over edges). The legacy preimage lives in the replay code path forever.
- **(C) Parallel third preimage — the `CommitSig` gossip topic proposed in today's scratchwork.** Add a fresh gossip topic that carries raw `CommitSig` payloads over `PQC-COMMIT-V1` for today, keep it in lockstep with `SignedVote` via double signing. Rejected: it introduces a third preimage where the spec forbids a second, doubles gossip bandwidth on the commit path, and still has to be torn down the day §10.4 actually ships.

Devnet-2 today runs **3 genesis validators only** with `chain_id = "viper-devnet-2"` (`deploy/ansible/group_vars/all/defaults.yml` — `viper_chain_id_hex = 76697065722d6465766e65742d32`, hex of `viper-devnet-2`). The prior `viper-mainnet-1` genesis referenced in TASKS.md TASK-107..110 was superseded by the ADR-042 cutover (new genesis with TLV envelope + epoch model, 2026-04-22); the current chain is NOT the one TASK-110's external notary validation ran against. External validator cohort recruitment (Phase 8 exit criterion, `ROADMAP.md` M4 row) has not started; there is no operator stake, no external onboarding, no third-party whose data is pinned to the current tail. The ADR-042 precedent (viper-devnet-1 → viper-devnet-2 genesis reset) establishes that this network is operated as an iterating devnet — another reset at ADR-051 cutover is precedent-consistent.

### Decision

Adopt **Option A**: retire `PQC-COMMIT-V1`, make `CommitSig` a thin wrapper around a Precommit `SignedVote`, reset devnet-2 from genesis on cut-over.

Concrete scope for the M2b implementation commit:

1. **Delete** `commit_preimage` (`pqc-consensus::commit:139`) and its call sites in the producer/consensus loops.
2. **Change** `CommitQuorumPolicy::verify` to rebuild the §8.4 Precommit preimage `SHAKE-256("VIPER-VOTE-V1" || height_be64 || round_be32 || step_u8 || block_hash)` with `step = VoteStep::Precommit (2)` and `round = 0` during the single-round prototype slice. **Add a `round: u32` parameter** to `CommitQuorumPolicy::verify` so the verifier is not coupled to a consensus-layer-owned struct field — the round context flows in explicitly. This is the honest reading of SPEC-CONSENSUS-001 §10.4's "`CommitQuorumPolicy::verify` call covers the commit condition in §10.1 without modification": the interface gains a `round` argument, but the SET-LEVEL semantics (accept a vector of Precommit sigs, verify each, enforce threshold) are unchanged. The spec also notes §10.1 allows "Precommits from different rounds MAY be combined if they all reference the same `block_hash(B)`", so at M2c the verifier will accept a heterogeneous `Vec<(round, SignedVote)>` instead of a single `round` argument.
3. **Repurpose** `CommitSig` as a `#[repr(transparent)]` newtype around `pqc_types::SignedVote` where `msg_type == MSG_TYPE_PRECOMMIT` is a type invariant (check on construction). The block's `commit_signatures: Vec<CommitSig>` field retains its name for wire-format continuity at the `BlockRecord` CBOR level — the CBOR keys and order are unchanged; only the bytes of each signature shift from `PQC-COMMIT-V1` to `VIPER-VOTE-V1` semantics. Producer and verifier build the SAME bytes (verifier rebuilds from the SignedVote fields, producer constructs from the ML-DSA signer's view — same formula, same output).
4. **Drain** `pending_precommits[(height, block_hash)]` directly into `block.commit_signatures` in the producer loop when `distributed_signing = true`, without any re-signing step.
5. **Producer signs own precommit only.** `snapshot_block_signers` already filters by keystore (audit confirmed, commit `3c4a5f4`); a node with only its own `commit_seed` emits exactly one `SignedVote` (its own) and relies on gossip for the rest of the quorum.
6. **Followers auto-sign on proposal.** Upon receiving a gossiped block below threshold, a validator node signs its own Precommit for the block's hash and broadcasts it on the vote topic. Blocks at threshold are imported normally.
7. **`phase-8-m2-pre` tag on the current `develop` tip** as the rollback anchor.
8. **Devnet-2 chain reset**: the Ansible `cutover-libp2p.yml` sibling playbook `cutover-commitsig.yml` wipes `/var/lib/pqchain/data`, rebuilds genesis with the same 3 validators + chain_id `viper-devnet-3` (new chain id — versioning the genesis reset explicitly so `viper-devnet-2` references continue to pin the prior genesis), and restarts all three nodes. Block heights restart at 0. The notary service account's existing vault persists in the genesis config (so the TASK-110 external-validation path is preserved — it will replay against the new height 0).
9. **No backward compatibility**. The new binary does not verify any block signed with `PQC-COMMIT-V1`. A node pointed at the old devnet-2 data directory will refuse to start past its first block verification.
10. **Feature-flag gate for N+1 deployment safety.** The M2b code lands BEHIND the existing `DevnetConfig::distributed_signing` flag (default `false`). When the flag is `false`, the producer keeps the legacy self-signing-for-all-keystore-seeds behaviour exactly as today — same preimage, same block bytes. When `true`, the producer signs with own seed only, emits Precommit gossip, drains `pending_precommits`, and builds the §8.4 preimage. **Between N+1 merge and N+2 devnet-2 reset, the flag stays `false` on the live deployment** — the new binary is safe to roll because nothing about the signed block bytes changes until the flag is flipped. At the N+2 cutover, new-genesis config ships with the flag `true`; the chain produces its first block in the new format and the binary rejects the old format (no replay concern, new chain starts at height 0).

### Consequences

- **200–300 lines** of code delta total (versus ~800 for the hybrid option and ~1 000 + permanent two-preimage support for Option B). The wire-format-breaking-change-but-same-wire-format nuance means no new CBOR keys, no `BlockRecord` version bump.
- **`CommitQuorumPolicy::verify` gains a `round: u32` parameter.** The single-round prototype slice pins it to `0`; the multi-round finalizer (L1/L2 of TASK-153's Quint model) extends the policy to accept `Vec<(round, SignedVote)>` on re-proposals (§10.1 "Precommits from different rounds MAY be combined"). Future-proofed against §9.3 locking rules.
- **Snapshot-sync semantics are preserved.** A node that bootstraps via snapshot trusts the snapshot state root, not individual historical block signatures. No snapshot format version bump is required. A node that replays FROM GENESIS across the cutover boundary is not supported (devnet-2 reset → new chain starts at height 0 → no replay across cutover exists).
- **External validators can now participate** without the LocalProposer keystore blocker of TASK-113 Step 6: each operator runs pqcd with their own `commit_seed` in their own keystore; the producer never needs external operators' seeds because each operator gossips their own precommits.
- **Block header `commit_hash` field** (spec §10.3: "`commit_hash = SHAKE-256(sorted_precommit_cbor)`") is deferred to a follow-up ADR. For M2b, the full commit_sigs vector rides in the block body and the block header remains as today. Lightweight-client verification via commit_hash is a separate spec-extension.
- **Historical block-explorer browsing** loses the current devnet-2 block tail. Devnet-2 externally serves notary receipts — the notary service's attestation_ids issued before the reset become unverifiable via `GET /api/verify/{id}`. Mitigation: before executing the cut-over, snapshot the notary account's attestations to a static JSON file at `reports/viper-devnet-2-pre-commitsig-reset/attestations.json` so external users who hold an old receipt have an offline verification path.
- **Chain-id versioning**: the new genesis carries `chain_id = "viper-devnet-3"` (distinct from prior `viper-devnet-2` which itself superseded `viper-devnet-1` at ADR-042). This makes the reset legible in logs + SDK config + explorer metadata without ambiguity.
- **TASK-113 Step 6 → `[x]`**. The LocalProposer harness keystore blocker is dissolved; the `#[ignore]`d `rapid_fire_multi_operator_validator_registrations_converge` test (`65d9db1`) is reactivated under the new architecture.
- **TASK-116 (dress rehearsal)** gains a dependency: the rehearsal must be re-executed against the reset devnet with the new commit protocol. Operator drill procedures in `docs/dress-rehearsal-procedure.md` are updated to include the external-validator onboarding path.

### Implementation Plan

Phased over two sessions:

**Session N+1** (next): implement items 1–6 + pins. Integration tests use in-process multi-node harness only — no devnet-2 change. Dry-run on a fresh 3-node `cargo test` devnet.

**Session N+2**: operator playbook (`cutover-commitsig.yml`), attestation-snapshot export, devnet-2 reset on a coordinated maintenance window, external validator onboarding doc (`docs/validator-onboarding.md`), open the cohort intake.

### Rollback

`phase-8-m2-pre` git tag + `pqcd` binary checksum of the current `develop` HEAD are pinned before session N+1 starts. If M2b implementation surfaces an unrecoverable issue, revert the merge on `develop`, re-deploy the tagged binary, restore data from the snapshot taken before cut-over. Devnet-2 rolls back cleanly because the data directory was snapshot-copied (not destroyed until the M2b binary has produced ≥1 000 blocks on the new history).

### Post-audit revisions (2026-04-23)

Initial draft (commit `261db85`) had six imprecisions flagged by a full-spec-read audit of `specs/consensus.md`. Corrected inline above:

1. **"Without modification" language** (§10.4 citation): clarified that `CommitQuorumPolicy::verify` gains a `round: u32` parameter — the SET-LEVEL semantics stay unchanged (verify a vector of precommit sigs), but the interface surface widens. The spec's "without modification" refers to the commit-condition semantics (§10.1), not to the function signature.
2. **`pol_round` in Precommit preimage**: initial draft specified `pol_round = -1` as a Decision-item-2 default. §8.4 does NOT include `pol_round` in Prevote/Precommit preimages — only in Proposal preimages. Default removed; Precommit preimage formula explicitly spelled out.
3. **Chain-identity**: initial draft incorrectly referenced `viper-mainnet-1` as the current chain. Actual current chain is `viper-devnet-2` (`deploy/ansible/group_vars/all/defaults.yml`). Prior `viper-mainnet-1` genesis was superseded by ADR-042 cutover on 2026-04-22; no production mainnet is affected by this reset. Precedent established by ADR-042 (viper-devnet-1 → viper-devnet-2) applies here (viper-devnet-2 → viper-devnet-3).
4. **Signer/verifier encoding symmetry**: clarified that producer and verifier build the SAME bytes from the §8.4 formula — "rebuild from height + round + step + block_hash" describes the reconstruction both sides do, no asymmetry.
5. **Snapshot-sync semantics**: explicitly noted that snapshot bootstrap trusts the state root, not per-block signatures, so no snapshot format bump is required. Genesis-replay across cutover is not supported (new chain = height 0, no prior blocks to replay).
6. **N+1/N+2 timeline**: clarified that M2b lands BEHIND the `distributed_signing` flag (default `false`). Between N+1 merge and N+2 cutover the flag stays `false` on the live chain — the new binary is safe to roll. N+2 cutover flips the flag to `true` in the new genesis config. No window of binary-vs-chain mismatch.

### References

- SPEC-CONSENSUS-001 §8.4 (vote preimage definition, §363 "MUST NOT be intermixed" clause)
- SPEC-CONSENSUS-001 §10.3 (commit material storage in `block_body.commit_sigs`)
- SPEC-CONSENSUS-001 §10.4 (CommitSig == Precommit message — target data model)
- ADR-007 (BFT consensus baseline)
- ADR-042 (prior genesis reset precedent: viper-devnet-1 → viper-devnet-2)
- TASK-113 Step 6 (blocker closed by this ADR)
- KNOWN-ISSUES D-06 (production-path closure)
- Commit `3c4a5f4` (M2b sig-gossip receiver + `pending_precommits` buffer — infrastructure baseline)

## ADR-052 - Forward-Compatible State Evolution (No Chain Resets Post-`viper-pq-1`)

**Status**: Accepted 2026-04-24
**Supersedes**: implicit "cutover = reset" posture of ADR-042 and ADR-051 going forward (for `chain_id` ≠ `viper-pq-1` the older posture remains factual history).

### Context

Viper's trust thesis is long-term post-quantum verifiability — attestations notarized on this chain are expected to remain cryptographically verifiable for 10–20 years. That promise is incompatible with a testnet-attitude operating model where each breaking change is handled by spinning up a new `chain_id` and discarding the previous one. ADR-042 (`viper-devnet-1` → `viper-devnet-2`, new genesis with TLV envelope + epoch model) and ADR-051 (`viper-devnet-2` → "devnet-3", new genesis with M2b CommitSig unification + `distributed_signing = true`) both took that path, legitimately, because the chain at each step had no third-party stake pinned to its tail. The precedent is fine as history but must not become a pattern.

The 2026-04-24 rolling-upgrade incident on `viper-devnet-2` surfaced the failure mode concretely. A binary built for the post-ADR-045 state_root topology (archival overlay subtree) was deployed via `ansible copy` + `systemctl restart` onto live `viper-devnet-2` hosts. The new binary read the old checkpoints, recomputed state_root under the new Merkle layout, detected the mismatch at heights 1000/2000/3000/4000, and fell through to `full_replay from genesis`. Producer halted block production during replay. Recovery required manual rollback on all three hosts within ~3 minutes. See KNOWN-ISSUES.md R-09 for the post-mortem and TASK-189 for the follow-up.

The incident is a designed consequence (archival state hashes into the root, so a binary aware of archival computes a different root than a binary unaware of it), not a regression. Under the testnet-attitude model the answer is "don't deploy that binary to the old chain — reset instead." Under the mainnet-discipline model that answer is unavailable: the chain must survive. The precedent being corrected by this ADR is therefore not the individual reset events but the *pattern* of treating reset as the primary tool for breaking-change evolution.

From `viper-pq-1` onwards the project treats the chain as a long-lived artefact that must survive every future breaking change.

### Decision

**Policy P-COMPAT-001 — Forward-Compatible State Evolution.** From the launch of `viper-pq-1` onwards:

1. **No chain reset is permitted.** A chain reset is the deletion of on-disk chain state + republication of genesis with the same or a different `chain_id`. Exceptions are restricted to safety-critical events (catastrophic cryptographic compromise, e.g. an irreparable practical attack on ML-DSA-65 or SHAKE-256, or a discovered consensus-safety flaw that cannot be patched in-place) and must be authorised by explicit on-chain governance (`GovernanceProposalType` with its own dedicated effect variant and a long voting window). The absence of such authorisation renders any reset action a policy violation.

2. **Every breaking change to consensus-relevant state carries a forward-compatible upgrade path.** "Consensus-relevant state" includes: the `BlockHeader` CBOR layout, the `state_root` Merkle topology, the canonical encoding of any state that contributes a leaf to `state_root`, the `CommitSig` / vote preimage format, and the transaction-envelope schema. A breaking change to any of these must land with: (a) a dedicated ADR documenting rationale, alternatives considered, and rollback strategy; (b) an activation height embedded in the binary or an on-chain activation-height registry entry; (c) dual-path decoder/hasher support — the binary must retain the pre-activation path in full fidelity and dispatch on the activation height during replay or block-import; (d) a cold-sync integration test that replays from genesis across the activation boundary and asserts byte-identical `state_root` continuity at every height; (e) a coordinated rollout playbook for operator binary swaps (followers first, producer last, signal checks between).

3. **Binary refuses to start on chain_id mismatch.** The node binary records at build time (or at first-successful-boot) the `chain_id_hex` it is targeting. On every subsequent start, before opening any chain store, it reads the persisted `chain_id` from the store's metadata and compares to the targeted value. On mismatch the binary exits with a non-zero code and a log line that cites this ADR, the expected `chain_id`, the observed `chain_id`, and the recovery guidance ("you are trying to run a binary for network X against a data directory for network Y — move the data directory aside or download the correct binary"). This removes the failure mode of the 2026-04-24 incident at the meta level without needing to first observe a state_root mismatch.

4. **State_root-level divergence detection is a second-line defence.** In addition to (3), on first block import after boot the binary also compares the stored `state_root` at a recent checkpoint against its own recomputation of that checkpoint. A divergence at that depth is fatal — it indicates a binary that believes itself targeting `chain_id X` but computes a different `state_root` than the rest of the network. The binary exits rather than silently falling through to `full_replay`. Exact implementation — which checkpoint, how often, treatment for fresh data directories — tracked as TASK-189 deliverable (d).

5. **Crypto-agility is handled on-chain, never by reset.** Rotation of the active signature algorithm, addition of a new algorithm to the registry, lifecycle transitions (Active → Discouraged → Deprecated → Banned), and eventual deprecation of legacy algorithms are governed by the `ProposalEffect::AddAlgorithm` path (ADR-049), the `alg_registry` lifecycle (ADR-044), and coordinated `SoftwareUpgrade` records (ADR-031). A reset as a response to a cryptographic evolution is a policy violation.

6. **Reserved evolution capacity in genesis.** The `viper-pq-1` genesis block is authored with explicit forward-compatibility slots: reserved CBOR keys in `BlockHeader`, an embedded `state_format_version: u32` (initial value 1), an empty activation-height registry that governance can populate, and an algorithm registry pre-populated with slots for algorithms not yet active but anticipated (e.g. ML-DSA-87 as a disaster-recovery fallback, a post-ML-DSA FN-DSA entry once FIPS 206 finalises). The cost of authoring these at genesis is trivial; the cost of adding them later under this policy is significant because every such addition triggers the dual-path + cold-sync test apparatus.

7. **Dual-path code budget — every dual-path decoder ships with a scheduled deprecation epoch.** Rule 2(c) mandates dual-path decoder/hasher support for breaking changes to consensus-relevant state. Without an accompanying deprecation schedule the codebase accumulates legacy decode paths indefinitely — Ethereum's `body-is-legacy-RLP-or-typed-transaction` dispatch currently carries eight branches because no branch was ever retired. Every ADR that introduces a dual-path decoder MUST specify: (a) an explicit `legacy_path_deprecation_epoch` (or activation height) at which the legacy branch is removed from the binary, (b) a deprecation window of at minimum the network's unbonding period so that any producer carrying legacy state has time to migrate, and (c) a follow-up TASK filed against the deprecation epoch that physically deletes the legacy branch from the codebase. The deprecation epoch MAY be extended via governance but MAY NOT be indefinite (the absence of a scheduled removal is itself a policy violation). On binary deprecation-epoch rollover the dual-path code is deleted and the binary retains only the post-activation path. This clause is tracked under ADR-053 §T2.5 and enforced in AGENTS.md §Compliance.

### Consequences

**For the `viper-pq-1` launch work**:
- The launch playbook produces the last operator-executed reset of Viper's history. The playbook remains substantively the same as the one drafted for TASK-168 (wipe chain data, publish new genesis, restart from height 0 with `distributed_signing = true`), but its framing changes: it is the launch of a chain meant to last, not another iteration of the testnet pattern.
- The launch binary (currently `phase-8-devnet-3-rc1` tag) is re-tagged as the first `viper-pq-1` release (suggested naming: `viper-pq-1-v0.1.0`), and the RUNBOOK §22 release registry is updated accordingly. The rc1 tag remains in git history as historical reference; the new tag points to the same commit plus whatever genesis adjustments are required to land rule (6) above.
- The `viper-pq-1` genesis block must be authored after this ADR is drafted and must include every forward-compatibility slot listed in (6). Once the genesis block is published the contents of that block are immutable.
- The chain_id hard-fail check (rule 3) is wired in before the `viper-pq-1` launch. Tracked as part of the launch work (replaces some scope of TASK-189).
- The cold-sync test harness required by rule 2(d) becomes a standing CI invariant from `viper-pq-1` onwards — every PR that touches consensus-relevant state must land a cold-sync test proving replay equivalence across any activation boundary it introduces, and the green-across-genesis invariant is an always-on CI guard.

**For operator experience**:
- Releases from `viper-pq-1` onwards are tagged `<chain_id>-<semver>` (e.g. `viper-pq-1-v0.2.0`). Each new release either lands no consensus-relevant change (patch/minor per semver semantics) or lands a breaking change bundled with activation height + dual-path decoder + cold-sync test. No binary is ever "just a swap" without passing this checklist.
- The rollout pattern becomes: operators download the new binary, verify its SHA-256 per RUNBOOK §22, restart pqcd on their node. If the new binary includes an activation height the pre-activation behaviour remains identical and the switch is transparent at that height. If the operator is behind (binary older than current activation) the binary refuses to start with a clear upgrade directive rather than silently diverging.
- The `viper-pq-1` chain is the permanent development chain even after a public-facing mainnet launches on a later `chain_id`. Rehearsal of breaking changes happens here first, under the same discipline.

**Historical records preserved**: ADR-042 and ADR-051, and TASK-168's "devnet-3 cutover" framing, remain valid as history of the period during which the chain was still a testnet-attitude artefact. This ADR supersedes only the *pattern*, not the specific prior events.

**Tracked follow-ups**:
- **P-COMPAT-001 §(3)** chain_id pre-flight: landed by the `viper-pq-1` launch work. Simple first version (string compare against stored metadata) lands now; richer variants (refuse-to-start on activation-height staleness, warn on state_format_version mismatch) follow as those infrastructures land.
- **P-COMPAT-001 §(4)** state_root pre-flight: TASK-189 deliverable (d).
- **P-COMPAT-001 §(6)** forward-compatibility slots in `viper-pq-1` genesis: tracked as part of the launch work.
- **Standing CI cold-sync invariant** for rule 2(d): TASK-190 (to be filed as part of the launch work).
- **Renaming the cutover playbook** from `cutover-devnet-3.yml` to something like `launch-viper-pq-1.yml` to reflect the semantics change: part of launch work.

### Related

- KNOWN-ISSUES.md R-09 (the rc1 state_root mismatch incident that forced this ADR)
- TASK-189 (state_root incompat post-mortem and the §(4) infrastructure)
- ADR-031 (SoftwareUpgrade — mechanism for coordinated version rollout on-chain)
- ADR-042 (past cutover — superseded pattern, retained as history)
- ADR-044 (TLV envelope + verifier registry — the upgrade-path primitive already in use for algorithm additions)
- ADR-049 (AddAlgorithm governance — on-chain crypto-agility, the forbidden-by-reset alternative)
- ADR-051 (past cutover for distributed signing — superseded pattern)
- AGENTS.md §Repository Status (operational summary of this policy for agents and contributors)
- `reports/audits/internal-audit-2026-04-23.md` (internal audit that preceded the rc1 incident)

## ADR-053 - `viper-pq-1` Genesis Architecture

**Status**: Accepted 2026-04-24
**Depends on**: ADR-052 (P-COMPAT-001 — forward-compatible state evolution forbids post-launch resets); external L1 design-mistakes research of 2026-04-24 (20 recommendations across 8 dimensions).
**Governs**: the genesis block, initial spec surface, and breaking-change budget of `chain_id = viper-pq-1`.

### Context

ADR-052 committed the project to mainnet discipline from `viper-pq-1` onwards: no post-launch resets, every breaking change travels with an activation path. That policy forces every breaking design decision into genesis authorship — anything not in the genesis block is either evolvable under P-COMPAT-001 or impossible to add without a safety-critical reset. The 2026-04-24 research ("Audit dei design mistakes nei principali L1") surveyed ten years of Ethereum / Bitcoin / Solana / Cosmos / Polkadot / Aptos / Sui post-mortems and produced twenty recommendations ranked by cost-of-late-correction. The most expensive mistakes in those chains are ones that could have been avoided by a handful of decisions at genesis: type-prefixed envelopes (EIP-2718), binary Merkle state trees (EIP-6800 → EIP-7864), forward-compatible block header slots (EIP-3675 orphan fields, BIP431 v3-retrofit), tagged hashing (CVE-2012-2459), crypto-agility as a first-class protocol feature (Polkadot MultiSignature vs the Ethereum secp256k1 lock-in), and smart-account-by-default (the nine-year EIP-86 → EIP-7702 saga).

Viper's thesis ("post-quantum trust infrastructure with long-term verifiability") gives most of those recommendations a particularly strong fit — an attestation notarized in 2026 must remain cryptographically verifiable in 2046, which imposes requirements (crypto-agility, light clients, tagged domain separation, stateless-verifier readiness) that more general-purpose L1s can defer but Viper cannot. A smaller subset of recommendations is actively misaligned with the thesis (state expiry, which would make 2046 verification of 2026 attestations unsafe) and is explicitly rejected here.

This ADR records the decisions that become immutable at genesis, the decisions that become costly post-launch under P-COMPAT-001, and the decisions that are deferred with their forward-compatibility accommodation. It is not the launch plan — implementation work is tracked as TASK-190..199 below. It is the north star the launch plan aims at.

### Decision

The genesis block of `viper-pq-1` ships with the following architectural commitments. Items are grouped by tier based on cost-of-late-correction (P-COMPAT-001 lens): Tier 1 is impossible to change post-launch under any reasonable upgrade path, Tier 2 requires an upgrade ADR + dual-path decoder + cold-sync test, Tier 3 is architectural and decidable now without reset.

#### Tier 1 — immutable at genesis

**T1.1 `BlockHeader` with explicit version slot and extension root.**
The header carries, as its first field, `header_version: u16` (initial value `1`). It carries an `extension_root: [u8; 32]` that commits to a key→value map of extension fields; initial value is the Merkle root of the empty map, reserving the slot for future commitment addition (execution payload root analogs, beacon payload roots, MEV builder bids) without layout change. Timestamps are `uint64` nanoseconds (no Bitcoin 2106 problem, no Ethereum uint32 budget). CBOR keys are allocated with gaps (e.g. reserved keys in the 0x20..=0x2f range) so future mandatory fields do not require re-numbering. The principle: **add fields via the extension_root map, renumber keys never**.

**T1.2 `ForkDigest`-scoped signing domains.**
Every signing-domain string in the protocol (currently `"VIPER-VOTE-V1"`, `"VIPER-PROPOSAL-V1"`, `"PQC-TX-V1"`, `"ARCHIVAL_SIG_DOMAIN"`, etc.) is replaced with a `ForkDigest = SHAKE-256("VIPER-FORK-V1" || fork_version_u32_be || genesis_validators_root, 4)[..4]` prefix. Signing preimages become `ForkDigest || legacy_domain_tag || body`. This is the Ethereum beacon-chain lesson: without genesis-scoped domain separation a signed vote on `viper-pq-1` can be replayed on any future or parallel chain that shares the legacy domain tags. Cost at genesis: a 4-byte prefix and a tiny helper. Cost of adding later: every signature in the chain's lifetime becomes ambiguous until the activation height.

**T1.3 Tagged-hash address derivation with `chain_id` domain.**
The current derivation is `SHAKE-256(alg_id_be16 || pk_bytes, 32)` (TASK-177). The `viper-pq-1` derivation is `SHAKE-256("VIPER-ADDR-V1" || chain_id_bytes || alg_id_be16 || pk_bytes, 32)`. Adding `chain_id` to the preimage means a public key that generates address `A` on `viper-pq-1` generates a different address on any future chain — cross-chain replay of signed messages becomes impossible at the address layer, not just at the signing-domain layer. Lesson: Bitcoin's CVE-2012-2459 and the keccak-vs-SHA3 ambiguity are both consequences of missing domain separation. Cost at genesis: 8 extra bytes in the preimage. Cost post-launch: every existing address is retroactively non-portable across hosts of the domain.

**T1.4 Hash-function registry (even with one entry).**
An on-chain `hash_registry: HashMap<u8, HashEntry>` is seeded at genesis with entry `0x01 = SHAKE-256` (NIST FIPS 202). The protocol dispatches on the hash id stored in each header/signing-domain rather than hard-coding `SHAKE-256` in the call sites. Governance can add (not replace) future hash functions via `ProposalEffect::AddHash` (new governance proposal type, symmetric to `AddAlgorithm` in ADR-049). This is the Ethereum keccak-vs-SHA3 lesson: a single unnamed hash function pins the chain forever. Cost at genesis: ~50 LOC of dispatch + one spec entry. Cost post-launch: every hash-using site in the codebase needs a coordinated version bump that the current codebase is not structured to accommodate.

**T1.5 Stake-weighted validator churn limit.**
The current churn limit is `max(4, active/256)` (TASK-113 count-based). `viper-pq-1` uses a stake-weighted limit: per epoch, the total stake entering or exiting cannot exceed `max(active_stake_frac_min_bps, active_stake_frac_target_bps × active_stake) / DENOM` bips of total active stake. Bips are registry-defined so governance can tune. Lesson: Ethereum EIP-7514 (count-cap) had to be rewritten as EIP-7251 stake-weighted; doing the rewrite retroactively required reshaping the slashing formula from `1/32` to `1/4096`. Cost at genesis: a single formula change + test. Cost post-launch: two EIPs + slashing re-derivation.

#### Tier 2 — landable pre-launch, evolvable under P-COMPAT-001

**T2.1 Fee market — multi-dimensional, exponential base-fee update, reserve floor.**
SPEC-FEE-002 is revised to price four dimensions separately: compute gas, storage growth (bytes × epoch lifetime), witness size (forward-compat for stateless clients), and per-account contention. Each dimension has its own base fee updated per block via the EIP-4844 formula `base_fee_{n+1} = MIN * e^((used − target) / UPDATE_FRACTION)`, with a reserve-price floor that cannot be set to zero by governance. Lesson: EIP-1559's additive update rule is provably suboptimal; EIP-4844 replaced it; EIP-7918 added the floor after the 2024 $78M revenue-miss. Tracked as TASK-201.

**T2.2 Storage fund — upfront, perpetual, refundable on deletion.**
State growth is priced via an upfront storage fund contribution sized to `bytes × perpetual_cost_per_byte`; the fund is stake-delegated to the active validator set, whose storage rewards come from its yield. Deletion of a state entry returns a fraction of the contribution to the originator (storage rebate). Lesson: Sui storage fund aligns long-term storage with validator economics without rent's complexity and without Ethereum's "state lives forever, someone pays for the free-rider externality" problem. Strongly aligned with Viper's notary thesis (user pays once per attestation, chain carries it forever). Tracked as TASK-202.

**T2.3 Timestamp-based activation for upgrades.**
ADR-031 `SoftwareUpgrade` activation switches from `height` to `timestamp` (uint64 ns). Block times are variable under network load; timestamp is unambiguous. Lesson: Ethereum's post-Merge switch from height to timestamp was motivated by exactly this. Small ADR + one-line change in `apply_upgrade`. Tracked as TASK-203.

**T2.4 BIP340-style double-tagged hashing.**
Every tagged hash uses the BIP340 pattern `H(H(tag) || H(tag) || data)` rather than the simpler `H(tag || data)`. Cost is one additional hash block per tagged operation; benefit is immunity to the CVE-2012-2459 class of attacks (leaf-vs-internal collision in Merkle trees, domain-tag collision in signatures). Lesson: Bitcoin tagged-hash after CVE-2012-2459 is the canonical defense. Tracked as TASK-204.

**T2.5 Dual-path code budget clause in P-COMPAT-001.**
Policy amendment: every breaking change that lands a dual-path decoder must specify (in its ADR) a scheduled deprecation epoch after which the legacy path is removed. Without this clause the codebase accumulates decoder paths indefinitely (Ethereum's current `body-is-legacy-RLP-or-typed-transaction` dispatch has eight branches). Tracked as TASK-205.

#### Tier 3 — architectural decisions (accept/defer/reject)

**T3.1 ✅ Stateless-client-ready state tree.**
State is committed under a **binary Merkle tree** (branching factor 2), not the hex/nibble 16-ary tree of Ethereum. Leaves are keyed canonically and hashed with tagged `"VIPER-STATE-LEAF-V1"`. Witness generation and the `extension_root` slot are designed together so that future witness-in-block commitment does not require header layout change. Full stateless-client protocol is deferred (witness generation at every block is a significant implementation cost and Viper's MVP notary use case does not force it today), but the **state tree topology** is chosen at genesis and is Tier-1-immutable in practice — it cannot be changed without state-migration effort on the order of Ethereum's Verkle → Binary Tree abandonment. Tracked under T3.6 launch implementation work.

**T3.2 ❌ State expiry REJECTED.**
Viper's thesis ("a 2026 attestation verifies in 2046") is incompatible with state entries that expire. No resurrection-via-proof mechanism removes the trust-degradation problem that the attestation's witness chain now depends on a third party providing the resurrection proof. The pre-mainnet-scale alternative is TASK-188 (cold-storage rotation for chain-data history, not state). State entries for accounts / validators / fee_market / alg_registry / hash_registry / attestations / proof_anchors / archival records remain alive indefinitely. The economic pressure that Ethereum's state-expiry research tries to solve is handled in `viper-pq-1` by Tier-2 T2.2 (storage fund) — users pay upfront for perpetual storage.

**T3.3 ✅ Storage fund (Sui-style).**
See Tier-2 T2.2. Listed here as a Tier-3 decision because its rationale is architectural (reject state expiry, align economics with thesis), not fee-model engineering.

**T3.4 🟡 ePBS-ready header fields, implementation DEFERRED.**
Enshrined proposer-builder separation (EIP-7732 analog) is not implemented at launch. Block header reserves one extension_root entry key `"exec_payload_root"` and one key `"builder_bid_commitment"` as optional; both are absent from v1 blocks. When a future proposal lands ePBS under P-COMPAT-001, the activation height switches them to mandatory and dispatches the block-validity rule through a dual-path decoder. Cost at genesis: two reserved keys and one paragraph in SPEC-CONSENSUS-001. Cost of adding later without reservation: a block-header layout-breaking change on the magnitude of Ethereum post-Merge.

**T3.5 ✅ Unified smart-account model with default EOA-equivalent template.**
Every account at genesis is a "smart account" in the protocol sense — storage for `verifier_template_id: u16` plus `auth_data: Vec<u8>`. The default template (id `0x01`) is `"sig.verify(msg, embedded_pk)"` — semantically identical to an Ethereum EOA. Governance can add new templates via `ProposalEffect::AddAuthTemplate` (new governance proposal type). Users can migrate their own account in-place to another template via a signed tx (no address change, no resource migration). This collapses the nine-year Ethereum EIP-86 → EIP-7702 saga into a genesis decision. Cost: a small auth-template dispatch in the tx-validation path and in the wallet keystore format. Tracked as TASK-206.

**T3.6 ✅ Light-client protocol as first-class feature — SPEC-LIGHT-CLIENT-001.**
A 2046 verifier of a 2026 attestation MUST be able to verify without full-sync of 20 years of chain. The light client protocol: the signed validator set of each epoch is a **sync committee** (conservative initial size 16), which signs a compact header attestation; header attestations are collected off-chain and distributed via a dedicated p2p topic; a light verifier downloads headers + sync-committee attestations and can verify inclusion proofs of any attestation via the binary Merkle tree state_root. Sync committee members are slashable for signing invalid headers (unlike Ethereum Altair, which has no slashing for sync committee — a documented Altair flaw). Implementation at launch is the spec + the sync-committee consensus rule; the light verifier SDK is post-launch. Current PQ signature sizes (ML-DSA-65, 3.3 KB per signature × 16 committee = ~53 KB per header attestation) are acceptable for periodic verification but too heavy for per-block attestation — this is an accepted consequence of PQ signing and is not a reason to defer the protocol. Tracked as TASK-207.

#### Tier 4 — deferred with documented rationale (not at genesis)

**T4.1 PQ signature aggregation.** ML-DSA and SLH-DSA do not aggregate. Future aggregate schemes (LaBRADOR, variants of SQISign) are 2-3 years from standardization. Light-client committee size is capped conservatively to keep per-attestation bandwidth acceptable until aggregation matures. When a suitable scheme is standardized, it is added to the algorithm registry via ADR-049 and the light-client protocol is upgraded via P-COMPAT-001.

**T4.2 2D transaction nonces.** A `(channel_id, seq)` nonce enables parallel transaction submission from a single account. Monotonic nonce is kept for launch simplicity; 2D is a minor future evolution covered by P-COMPAT-001.

**T4.3 Pull-based withdrawals.** Not applicable at launch — `viper-pq-1` does not yet have protocol-level staking rewards / withdrawals (MVP notary use case). When staking economics land they land with pull-based withdrawals by default.

### Consequences

**For the launch plan.** ADR-053 reshapes what "launch viper-pq-1" means from "rename chain_id and publish genesis" into "ship a genesis block with 5 Tier-1 breaking design decisions + 5 Tier-2 infrastructure revisions + 5 Tier-3 architectural commitments". Estimated additional engineering budget: 2-4 weeks of focused work before launch is reasonable. Tasks are filed as TASK-190..207 with explicit dependency ordering.

**For the first launch release.** The tag `phase-8-devnet-3-rc1` (commit `3718960`, binary SHA `bbb4a820…`) is superseded — it lacked every Tier-1 and Tier-2 item in this ADR. The new first release is tagged `viper-pq-1-v0.1.0` on the launch commit (TBD). The rc1 tag stays in git history as a reference point for the 2026-04-24 incident post-mortem.

**For existing code.** Several existing modules become first-version under the registry pattern rather than hard-coded constants: `AlgId` / `HashId` registries grow parallel governance proposal types; signing-domain strings become `ForkDigest`-prefixed; address derivation changes one line; `BlockHeader` gains two fields. Most of this is bounded, bench-testable, and has backward-compatibility escape hatches via P-COMPAT-001 for any followup. None of it is speculative — every single change is motivated by a published post-mortem of a live L1.

**For the notary use case (Viper's MVP).** Transparent — users and the notary service interact via the HTTP API which changes only at the JSON schema level (address format stays 32 bytes hex). Validators see a slightly larger block header (under 1 KB larger) and must upgrade to the new launch binary before `viper-pq-1` first block.

**Superseded / obsoleted.**
- `phase-8-devnet-3-rc1` release intent (the binary does not implement Tier 1/2 items; it is not the launch binary).
- The implicit "cutover is reset" framing of TASK-168 (replaced by TASK-208 launch playbook).

### Related

- ADR-049 (AddAlgorithm governance proposal — the upgrade-path primitive that T1.4 mirrors for hashes and T3.5 mirrors for auth templates)
- ADR-031 (SoftwareUpgrade — the activation primitive that T2.3 switches to timestamp)
- ADR-041 (libp2p transport — no change, unaffected by this ADR)
- ADR-045 (archival overlay — unchanged, complements T3.6 light client with long-term TSA-anchored evidence)
- ADR-052 (P-COMPAT-001 — enforcement mechanism for the Tier 2 commitments in this ADR)
- External L1 design-mistakes research (2026-04-24) — source of the 20 recommendations this ADR disposes of
- `reports/audits/internal-audit-2026-04-23.md` (internal audit preceding the rc1 incident)

---

## ADR-054 - BFT-Correct Block Reception Pipeline (post-2026-04-25 follower divergence incident)

**Status**: Accepted 2026-04-25
**Depends on**: SPEC-CONSENSUS-001 §7 (Tendermint-like state machine), §10 (commit signatures), §10.4 (CommitPreimageMode); ADR-007 (BFT direction); ADR-027 (Tendermint adoption); ADR-051 (distributed precommit signing); ADR-024 / SPEC-SLASH-001 (equivocation evidence + slashing).
**Governs**: every code path that ingests a block from a peer (gossip Next, block-fetch response, snapshot-tail import) and the storage primitives that persist canonical chain state.

### Context

On 2026-04-25 follower-1 (`viper-pq-1` mainnet) entered an infinite replay-fail loop after fast-syncing from genesis. Forensics showed F1 had persisted a non-canonical variant of block 7321 (timestamp `1777136734`, hash `a88e51a7…`) whose body was byte-identical to the canonical variant produced by the rest of the network (timestamp `1777136736`, hash `4372d2c4…`) — same `prev_hash`, same `state_root`, same `tx_root`, same proposer, only the timestamp differed. When block 7322 arrived with `prev_hash = 4372d2c4…` (the canonical 7321), F1 rejected it with `ParentHashMismatch` and aborted every block-fetch batch — recovery required a snapshot import from F2.

The class of bug is two distinct gaps in `crates/pqcd/src/devnet.rs::import_remote_block`:

1. **Soft persistence of unfinalized blocks.** The fast-sync path persisted a block whose `commit_signatures` did not (or did not provably) meet the 2f+1 BFT quorum threshold of SPEC-CONSENSUS-001 §10. The legacy gossip Next path has the PROPOSAL/FINAL discrimination from ADR-051 (`handle_non_proposer_proposal_if_applicable`) but the `block-fetch/1.0.0` response handler (TASK-135 step 13) and the snapshot-tail importer call straight into `import_remote_block` with no equivalent guard.
2. **No recovery on parent-hash mismatch.** When a child block H+1 arrives whose `prev_hash` does not match the local tip(H), the importer returns the error and breaks the import loop. There is no second-chance flow to detect divergence, fetch the canonical variant of H, swap, and retry.

This ADR is the minimal-surface, BFT-correct fix. It is **not** a fork-choice rule in the GHOST/longest-chain sense — Tendermint-style BFT has finality by construction (a committed block is irreversible, §4 "Commit"). It is a strict-finality enforcement layer plus a sibling-resolution flow for the specific race the incident exposed (proposer re-emits the same block body with a new timestamp because the first emission did not collect quorum in time, and a follower's local copy ends up state-equivalent but not canonical).

### Decision

The block reception pipeline is refactored into four explicit stages with strict invariants. The same pipeline serves every ingest source — gossip Next, block-fetch response, snapshot-tail import.

#### Stage 1 — structural validation
Identical to today: decode the block envelope, verify metadata internal consistency (heights match, body counts match, block_hash recomputes), verify tx-root and state-root commitments at the leaf level. This stage is byte-deterministic and side-effect-free.

#### Stage 2 — strict finality gate
**Invariant**: no block is ever persisted unless it carries a verifiable 2f+1 commit-signature quorum against the active validator set as observed at the parent block's state. The gate is `validate_block_commit_quorum` against the policy reconstructed from `StateStore::active_validators()` *before* the block's apply (mirroring the live producer path, ADR-051 / TASK-113). Failure modes are explicit:
- `MissingCommitSignatures` / `InsufficientQuorum` → reject as `BlockReceptionError::Unfinalized`. Emit a `peer_served_unfinalized_block_total` metric tagged with the source peer ID.
- `InvalidSignature` / `UnauthorizedSigner` / `DuplicateSigner` → reject as `BlockReceptionError::MalformedQuorum`. Same metric, separate label.

The gate runs **before** the store touches RocksDB. It is impossible for a block without quorum to enter the canonical chain through any wired ingest path. The genesis block is the single explicit exception (no parent, no quorum required) and is constructed locally, never received.

#### Stage 3 — tip-linkage classifier
Given a finalized block B at height H and the local tip at height L with hash T:

| Class                     | Condition                                                  | Resolution                                         |
|---------------------------|------------------------------------------------------------|----------------------------------------------------|
| `LinkAtTip`               | `H == L+1 && B.prev_hash == T`                             | Append (Stage 4 normal path).                      |
| `Duplicate`               | A block with `B.block_hash` already exists locally          | Idempotent ok — return success without re-applying.|
| `SiblingAtTip { local }`  | `H == L && B.block_hash != T`                              | Sibling resolution (below).                        |
| `OrphanFutureChild`       | `H > L+1`, OR `H == L+1 && B.prev_hash != T`               | Buffer in `BlockTreeCache`, fetch missing parent.  |
| `BelowFinalized`          | `H ≤ L` and not duplicate                                  | Reject (no reorg below tip permitted).             |

The classifier is a pure function over `(B, ChainStore::tip())`; no I/O. Its output drives Stage 4 dispatch.

#### Stage 4 — resolution dispatch

**`LinkAtTip`** → existing `append_stored_block` flow, unchanged.

**`SiblingAtTip { local }`** → BFT-aware swap:
- (a) Both `B` and `local` carry valid 2f+1 quorum (Stage 2 already verified `B`; the local block's quorum was verified at its own ingest time, asserted as a stored invariant).
- (b) If `B.prev_hash == local.prev_hash && B.state_root == local.state_root && B.tx_root == local.tx_root`: the variants are *state-equivalent* (timestamp / signature-mix variation only). Atomic swap via `RocksDbChainStore::replace_canonical_at_height(B, prev=local)`: WriteBatch removes the old `(hash_index, blocks)` entries, writes the new ones, archives `local` to a new `siblings` CF, updates the in-memory `ChainStore` tip. State is unchanged — no rollback needed. Counter `canonical_sibling_swap_total` incremented, structured log emitted.
- (c) If `B.state_root != local.state_root` (or `tx_root`, or `prev_hash`): two quorum-signed blocks at the same height have *different state-effects*. By Tendermint safety this is a 2f+1 double-sign — slashable. Build `EquivocationEvidence` pairs from the overlap of signers in `B.commit_signatures` and `local.commit_signatures`, submit via `apply_submit_equivocation_evidence` to the slashing-evidence pool, halt block reception on this height pending operator review (`fail_loud` mode), counter `equivocation_evidence_submitted_total` incremented.

**`OrphanFutureChild`** → buffer + fetch:
- Insert `B` into `BlockTreeCache` keyed by `B.block_hash`, indexed by `prev_hash` for parent lookup. Cache is bounded by TTL (default 60s) and total entries (default 1024); LRU eviction.
- Dispatch a `BlockFetchByHashRequest { hash: B.prev_hash }` (new request-response protocol, see below) to the source peer — and on no-response after 2s, broadcast to one other peer per attempt up to 3 attempts. Counter `orphan_parent_fetch_dispatched_total` per attempt.
- On parent arrival (any ingest source — the parent comes back through Stage 1–4 like any other block): walk the cache for descendants whose `prev_hash` matches the new parent's hash; re-classify each (now `LinkAtTip` or `SiblingAtTip`) and dispatch. Bounded recursion since each step extends the chain by one and the cache is finite.
- The **original 7321/7322 incident** is this branch: F1's local 7321 is a state-equivalent sibling, the canonical 7321 lives on F2; when 7322 arrives with `prev_hash = canonical_7321`, it classifies as `OrphanFutureChild`, F1 fetches `canonical_7321` by hash, the response classifies as `SiblingAtTip` (state-equivalent), atomic swap, then 7322 re-classifies as `LinkAtTip` and applies normally.

**`Duplicate`** → return success without re-applying. Idempotency is required because gossip + block-fetch overlap during catch-up is not pathological.

**`BelowFinalized`** → reject with `BlockReceptionError::BelowTip { local: L, got: H }`. Stage 3 ensures no path here mutates state.

#### Storage layer extensions

- New CF `siblings` (key: hash `[u8; 32]` || height `u64 BE`, value: full `StoredBlockRecord`). Holds replaced variants for forensic audit. Pruned alongside `compact_to_checkpoint` (anything below the latest checkpoint is dropped — finalization makes siblings unreachable).
- New API `RocksDbChainStore::replace_canonical_at_height(canonical, prev_local)` — single atomic `WriteBatch`:
  1. Remove `hash_index[prev_local.block_hash]`.
  2. Move `prev_local` → `siblings` CF.
  3. Write `canonical` to `blocks[height]`, `hash_index[canonical.block_hash]`, `tx_index[*]`.
  4. Update `meta.tip_height` (unchanged value, but the batch atomicity makes the swap visible).
  5. Update in-memory `ChainStore` via `replace_tip_block`.
  Pre-condition guards (`prev_hash + state_root + tx_root` equality) are checked before the batch — divergence returns `StorageError::SiblingStateDivergence` to the caller, which is the trigger for the equivocation-evidence path.
- New API `ChainStore::replace_tip_block(stored)` — pure-memory companion with the same pre-condition guards.

#### P2P wire extension

New libp2p request-response protocol `/viper/<chain>/block-fetch-by-hash/1.0.0`:

```
BlockFetchByHashRequest { hash: [u8; 32] }
BlockFetchByHashResponse { block: Option<StoredBlockBytes> }
```

Responder reads `hash_index` CF; if absent, falls back to `siblings` CF; returns `None` if neither has it. This is needed because the existing `block-fetch/1.0.0` is height-ranged — under sibling-divergence two peers can return different blocks for the same height. By-hash fetch lets the receiver request a *specific* variant by its hash.

#### On-startup integrity audit

`RocksDbChainStore::open` invokes `verify_chain_quorum_invariants` on the post-checkpoint tail. For each block above the trusted checkpoint, the audit reconstructs the validator set as it was at the parent block, builds the `CommitQuorumPolicy`, and asserts `validate_block_commit_quorum` succeeds. Failure refuses startup with a structured error suggesting `pqcd snapshot-import` recovery from a healthy peer. Pre-checkpoint blocks are not audited (the checkpoint is itself a trusted root, written under the same finality discipline).

This audit closes the bug class where a non-quorum block was silently persisted on disk by a buggy older binary or a corrupted ingest path: even if Stage 2 were bypassed by some future regression, an operator could not start the node again without surfacing the corruption.

### Consequences

**Behavior change for operators.** Followers that catch up via fast-sync now have a real recovery story for the 7321/7322 class of incidents — manual `snapshot-import` is the disaster-recovery escape hatch, no longer the primary path. The startup integrity audit makes "node started, but DB is corrupted" impossible to miss.

**Behavior change for slashing.** Validators that double-sign in a way that produces state-divergent blocks at the same height now have their evidence emitted automatically by any follower that observes both blocks. SPEC-SLASH-001 §10 already defines the 500-bps slashing fraction; this ADR closes the detection gap.

**Behavior change for proposers.** No change. The proposer-side state machine of SPEC-CONSENSUS-001 §7 is unaffected.

**Test surface.** Every new code path lands with unit tests in its own module + at least one integration test in `pqcd/tests/`. The flagship test reproduces the 7321/7322 incident: a 3-node simulated devnet where the proposer is forced to re-emit a block with a different timestamp; one follower captures variant A, the other captures variant B; the divergent follower receives variant B + child via fast-sync and recovers via `OrphanFutureChild` → `SiblingAtTip` → swap.

**P-COMPAT-001 lens.** This ADR is non-breaking on chain state and signing rules — no signing preimage changes, no state-root format changes, no on-chain governance proposal changes. It is breaking on the binary's behavior at ingest, on the wire (new optional request-response protocol), and on the storage layout (new CF + new meta keys for the audit cursor). Per P-COMPAT-001 §2, the changes are additive in shape; the new CF is created on first open of an existing DB, and the new wire protocol is opt-in (peers that don't speak it fall back to height-ranged block-fetch, which is the existing path). No activation-height coordination is required.

**Out of scope (future ADRs).** This ADR explicitly does *not* introduce:
- a fork-choice rule for chains with state-divergent quorums (Tendermint safety means this should never happen; if it does, the chain is halted by design pending operator intervention — full reorg/state-rollback is a Phase 5 question if BFT safety is ever provably broken);
- byzantine recovery beyond 2f+1 (the chain's safety properties depend on at most f Byzantine validators by SPEC-CONSENSUS-001 §16; outside that bound, automated recovery is impossible by FLP-style impossibility);
- light-client-side reception (the SPEC-LIGHT-CLIENT-001 sync-committee verifier has its own ingest discipline, see ADR-053 §T3.6).

### Tasks

Implementation is staged across nine tasks (TASK-207..215), targeted under the new "Tier 4 — BFT block reception hardening (post-launch incident response)" section in TASKS.md. Order: storage primitives (TASK-207, TASK-208) → in-memory orphan cache (TASK-209) → P2P by-hash protocol (TASK-210) → reception pipeline refactor (TASK-211) → orphan resolution loop (TASK-212) → equivocation emission (TASK-213) → startup audit (TASK-214) → integration tests (TASK-215).

### Related

- SPEC-CONSENSUS-001 §7 (round state machine), §10 (commit signatures), §10.4 (`CommitPreimageMode`)
- SPEC-SLASH-001 §10 (equivocation slashing fraction, ADR-024 / ADR-048 correlation penalty)
- ADR-051 (distributed precommit signing — defines the FINAL/PROPOSAL discrimination this ADR generalizes to all ingest paths)
- ADR-052 (P-COMPAT-001 — non-breaking-change envelope this ADR fits inside)
- ADR-053 (`viper-pq-1` genesis architecture — this ADR is post-launch hardening, not genesis)
- 2026-04-25 follower-1 incident root-cause analysis (preserved in operator session log)


---

## ADR-055 - Three Attestation-Derived Public Services on Top of `viper-pq-1`

**Status**: Accepted 2026-04-27
**Depends on**: ADR-002 (notary as first wedge); ADR-052 (P-COMPAT-001 non-breaking envelope); existing `attestation_create` primitive (`pqc-state` apply path) and `viper-notary` HTTP backend (the notary service (private)).
**Governs**: the public product surface exposed over HTTP by the producer-side notary service. Does **not** add new chain primitives, new opcodes, new state types, or new consensus rules.

### Context

`viper-pq-1` ships with a single concrete public service today (`POST /api/notarize`, document proof of existence). The marketing surface (`agwswebconsulting.it/it/viper-pq-chain/`) still describes the project as "vault + attestations + notarization + identity proofs" — broad, vague, hard to convert. After the 2026-04-27 stealth-mode positioning review, three concrete additional services were identified that:

1. solve a clearly named problem with a regulated buyer in EU (NIS2 / DORA / eIDAS 2),
2. can be built **entirely on top of the existing `attestation_create` primitive** without touching consensus, state schema, or fee model,
3. give three distinct LinkedIn / sales narratives instead of one generic "blockchain" pitch.

The three services are:

- **PQ Timestamping Authority** (RFC 3161-style API, post-quantum token format) — buyer: legal tech, GED, archives, CI/CD, eIDAS-qualified TSA candidates.
- **Evidence Chain** (immutable append-only audit log of process events) — buyer: NIS2 / DORA compliance, internal-audit teams, regulated SaaS.
- **Code Release Attestation** (signed build/release attestation anchored on chain, sigstore-PQ pattern) — buyer: dev/security teams in supply-chain-aware orgs.

This ADR records the architectural decision to ship them as **thin HTTP wrappers in the existing `viper-notary` backend** rather than as new chain modules or as separate microservices.

### Decision

#### D1. No new chain primitives

The three services share `attestation_create` as their on-chain primitive. They differ only in:

- the shape of the off-chain receipt they return,
- the `metadata` field they pack inside the attestation payload,
- the verification semantics on the read side.

There is no new transaction kind, no new state entry, no new opcode, no governance proposal needed. P-COMPAT-001 §1 (chain reset prohibition) is not engaged because nothing on-chain changes.

#### D2. Single backend, three endpoint groups

The services are added to the existing `viper-notary` backend (the notary service (private)) as three new endpoint groups, mounted on the same Axum `Router` as `/api/notarize`. The service account (consensus seed in `notary.env` → `service_signer_seed_hex`) submits all attestations.

**Timestamping**:
- `POST /api/timestamp` — body: `{ digest: hex32, hash_alg: "sha-256" | "sha3-256" | "shake-256", policy?: string }`. Submits an `attestation_create` whose payload metadata records `kind=timestamp`, `policy`, `client_nonce`. Returns a `TimeStampToken`-shaped JSON receipt with `serialNumber`, `genTime`, `messageImprint`, `accuracy`, `tsa_signature` (over the receipt itself, PQ).
- `GET /api/timestamp/{token_id}` — returns the receipt + chain anchor proof.

**Evidence Chain**:
- `POST /api/evidence` — body: `{ stream_id: string (≤64 chars), event_type: string, payload_digest: hex32, prev_event_id?: string, occurred_at: rfc3339 }`. Submits an `attestation_create` whose payload metadata carries `kind=evidence`, `stream_id`, `seq` (server-assigned monotonic, persisted in a small RocksDB sidecar), `event_type`, `prev_event_id`. Hash-chains within a stream so a missing event is detectable client-side.
- `GET /api/evidence/{stream_id}/events?since=<seq>&limit=<n>` — paginated read.
- `GET /api/evidence/{stream_id}/head` — current head (seq + event_id + chain anchor).

**Release Attestation**:
- `POST /api/release/sign` — body: `{ artifact_hash: hex32, repo: string, ref: string (tag or commit), builder_id: string, build_log_hash?: hex32, sbom_hash?: hex32 }`. Submits an `attestation_create` whose payload metadata carries `kind=release`, `repo`, `ref`, `builder_id`, optional `build_log_hash`, optional `sbom_hash`. Returns a release-attestation receipt JSON.
- `GET /api/release/{attestation_id}/verify` — returns the attestation + verification verdict (matches expected hashes? signature valid? finalized?).

All three groups share the **same chain submission infrastructure** as `/api/notarize` (`tx_builder::build_attestation_create_tx`, `chain::NodeClient::submit_tx_and_wait`, `NOTARY_FINALIZATION_TIMEOUT_MS`).

#### D3. Per-service service-account is OUT OF SCOPE at launch

All three services share the single service signer of `viper-notary`. Per-service signing identity (so a customer can pin a `release-tsa` issuer key separately from the `notary` issuer key) is a future follow-up. The decision: **don't fragment keys before there is concrete operator demand**. ADR-049 `AddAlgorithm` is not engaged.

#### D4. No new state schema; per-service local sidecar OK

Evidence Chain needs a server-side `(stream_id, seq) → event_id` index to assign monotonic seq and to serve `GET /events`. This is **off-chain**, in a small RocksDB column family inside the notary process (`evidence_streams` CF). The on-chain attestation remains the source of truth; the local index is a cache that can be rebuilt from chain state by replaying attestations whose metadata `kind=evidence` matches the stream id.

Same for Release Attestation if a `repo → latest_release` view is needed.

#### D5. No frontend coupling

The notary frontend (the notary SPA) keeps its current Dashboard / Explorer / Notarize tabs. The three new services are **API-first**. The three customer-facing landing pages live on the AGWS Web Consulting site (`/it/strumenti/{timestamp,evidence,release}`) as preview / "request access" pages. UI behind authentication and the actual API consoles ship after the company is incorporated and a billing plan is in place. This is consistent with the stealth-mode strategy.

#### D6. Same systemd unit, same ansible role

Deployment uses the existing `notary` ansible role on producer nodes. The endpoint groups are added to the same `viper-notary` binary. No new systemd units, no new firewall rules, no new ports.

### Consequences

**For the chain.** Zero impact. No consensus change, no state-schema change, no fee-table change, no governance event. P-COMPAT-001 §1 is not engaged.

**For the notary backend.** The single-binary surface grows from 4 routes (`/api/notarize`, `/api/verify/{id}`, `/health`, plus `/v1/*` proxies) to roughly 12 routes. Backend code grows by an estimated 800–1200 LOC across three new modules + a small sidecar storage layer for Evidence Chain. Build time delta is negligible.

**For the marketing site.** The `viper-pq-chain` page now references four concrete services (notarization + the three new ones) instead of vague "use cases". Three new tool pages on `/strumenti/` give individual deep-link targets for LinkedIn posts and conversations, each with its own narrative angle.

**For the product positioning.** Three distinct buyer narratives instead of one generic "blockchain" pitch: legal/eIDAS, NIS2/DORA compliance, dev/security supply chain. Each is independently defensible and independently sellable.

**For service-key fragmentation.** Postponed. If a customer eventually requires a separately-pinned issuer for one of the services, the migration is "spawn a second service-account key, migrate that endpoint group" — not a chain change.

**For operator burden.** Slight. The notary systemd unit gets a few more env vars (one per service-group feature flag) and the RocksDB working set grows by the Evidence Chain CF. Backups (`/var/lib/pqchain/notary.db`) cover it transparently.

### Out of scope

- Per-service signer keys (D3).
- Authenticated, billed API consoles (D5).
- Customer self-service signup (deferred until company incorporation).
- New on-chain primitives, new opcodes, new state, new fee dimensions.
- Aggregating multiple events into a single `attestation_create` — each evidence event is its own attestation. Batch optimization is a fee-model question, not a launch question.
- A separate "release-attestation" verifier UI on the notary frontend. The verify endpoint returns JSON; a UI can be added later without touching the backend.

### Tracking tasks

- TASK-229 — `/api/timestamp` + `/api/timestamp/{id}` (PQ Timestamping)
- TASK-230 — `/api/evidence/*` + RocksDB sidecar (Evidence Chain)
- TASK-231 — `/api/release/sign` + `/api/release/{id}/verify` (Release Attestation)
- TASK-232 — three AGWS landing pages (`/strumenti/timestamp`, `/strumenti/evidence`, `/strumenti/release`)

### Related

- ADR-002 (notary as first wedge — this ADR is "second / third / fourth wedge")
- ADR-049 (AddAlgorithm — not engaged: no new algorithm; same signer alg as `viper-notary`)
- ADR-052 (P-COMPAT-001 — not engaged: no chain change)
- ADR-053 (genesis architecture — orthogonal; this ADR sits entirely above the chain)
- the notary service (private) (existing service that becomes the carrier of the three new endpoint groups)
- 2026-04-27 LinkedIn stealth-mode positioning review (operator session log)


---

## ADR-056 - Chart Deploy Ceremony Tooling (`pqcd ceremony` Subcommand)

**Status**: Accepted 2026-05-05
**Depends on**: ADR-053 §T1.3 (chain-id binding via `derive_address(chain_id, alg_id, pk_bytes)`); ADR-053 §T2.4 (canonical address derivation); existing `pqc_crypto::ml_dsa_public_key_from_seed` + `pqc_crypto::address::derive_address` runtime crypto path; existing Helm chart skeleton under `charts/pqchain/`.
**Governs**: the operator workflow that produces the per-cluster Helm `values.yaml` JSON and the per-role Kubernetes Secret manifests required to start a fresh `viper-pq-1`-style cluster.

### Context

The Helm chart shipped with ADR-053 was structurally complete (templates, role splits, init-containers, services, NetworkPolicies) but every fresh deploy still required manual ceremony work: generate N validator seeds, derive each ML-DSA public key, derive each canonical address against the target chain-id, hand-write the resulting `node.json` per role, hand-write a Secret manifest per node embedding the seed, and assemble a Helm values JSON. This is exactly the kind of toil the chart was supposed to eliminate, and worse — every step uses primitives that already live inside `pqcd` (`pqc_crypto::ml_dsa_public_key_from_seed`, `pqc_crypto::address::derive_address`), so re-implementing them in shell or in a side script risks subtle divergence from the binary's runtime crypto path (in particular, the chain-id-bound address derivation in ADR-053 §T1.3).

The decision to be made: where does the ceremony logic live, and what does it emit?

### Decision

#### D1. Ceremony lives inside `pqcd` as a subcommand

The chart deploy ceremony is a new `pqcd` subcommand: `pqcd ceremony [--chain-id S] [--validators N] [--block-time-ms M] [--output FILE] [--deploy-token user:pass@registry]`. It is wired through `crates/pqcd/src/main.rs` (entry: `cmd_ceremony`) and implemented in `crates/pqcd/src/ceremony.rs` (`generate_ceremony_values` at line 428, `derive_validator_entry` at line 152, `build_secrets_manifest` at line 369).

The single binary that runs the chain at runtime is also the binary that performs the ceremony. There is no second Python / shell / Go tool to keep in sync.

#### D2. Reuse runtime crypto, not a re-implementation

`derive_validator_entry` calls `pqc_crypto::ml_dsa_public_key_from_seed(alg_id, seed)` (ceremony.rs line 158) and `pqc_crypto::address::derive_address(chain_id_bytes, alg_id, &pk_bytes)` (line 160) — the same two functions the runtime calls when it loads `node.json` at boot. Any ADR-053 §T1.3 chain-id binding change automatically propagates to the ceremony output without a second code edit.

#### D3. Single emit: Helm values JSON + Kubernetes Secret manifests

`generate_ceremony_values` returns a single JSON document with two top-level keys:

- `values` — the full `values.yaml`-shaped JSON that `helm install -f` accepts directly (chain-id, block-time, per-role node.json blocks, image refs, deploy-token, NetworkPolicy toggles).
- `secrets` — an array of Kubernetes Secret manifests, one per node, each embedding that node's seed under a stable key name. The operator pipes the array through `kubectl apply -f -` (or splits per-secret if a separate kubeseal pass is required).

One subcommand invocation, one file, no manual gluing.

#### D4. Defaults that produce a working cluster

`--validators` defaults to a value that aligns with the chart's default validator-set size; `--block-time-ms` defaults to the production-grade value already documented under ADR-053; `--chain-id` is required (no implicit default — a typo here cannot be silently masked because addresses bind to it). `--deploy-token` is optional and only injected when the chart's image registry requires authentication.

### Alternatives considered

- **Standalone shell / Python script in `scripts/`.** Rejected: would re-implement `ml_dsa_public_key_from_seed` and `derive_address`, creating two crypto paths to keep aligned with ADR-053 §T1.3. Every future address-derivation change would need two edits.
- **Embed the ceremony directly in a Helm post-install hook.** Rejected: post-install hooks run inside the cluster, but the ceremony needs to *produce* the values that drive the install — it must run on the operator's workstation before `helm install`. A Helm hook is too late.
- **A separate `pqc-ceremony` binary in the workspace.** Rejected: would duplicate the dependency tree of `pqcd` (pqc-crypto, address derivation, config schema). Subcommand is strictly cheaper.
- **Emit two files (`values.yaml` + a directory of Secret manifests) instead of one combined JSON.** Rejected: increases coordination cost on the operator side (two paths to track, two `kubectl`/`helm` invocations, easy to drift). Single JSON keeps the artefact atomic.

### Consequences

**For operators.** A fresh-cluster deploy collapses from "run the ceremony notebook, copy-paste outputs into `values.yaml`, hand-craft Secrets" to `pqcd ceremony --chain-id <id> --validators N > deploy.json && jq '.values' deploy.json > values.yaml && jq '.secrets[]' deploy.json | kubectl apply -f - && helm install pqchain charts/pqchain -f values.yaml`. The chart goes from "structurally complete but operationally incomplete" to "deploy-ready in one command".

**For chain-id binding.** ADR-053 §T1.3 is now enforced end-to-end: the same `derive_address` function feeds both the genesis ceremony and the runtime startup path. A test in `ceremony.rs` (`ceremony_values_have_expected_top_level_keys` at line 696) locks the emitted shape.

**For future work.** Any new Secret material the chart starts to consume (TLS certs, per-service signer seeds, ADR-055 service-account seeds) lands as additional fields in `generate_ceremony_values`; there is now a single canonical place to extend.

**For ADR-053 P-COMPAT-001 lens.** Non-engaged: no chain change, no consensus change, no on-disk format change. Pure tooling.

### Tracking task

- TASK-233 — `pqcd ceremony` subcommand emitting Helm values JSON + Kubernetes Secret manifests (commits `9d810a6`, `451dd53`, `213c34c`).

### Related

- ADR-053 §T1.3 / §T2.4 (chain-id-bound address derivation — same crypto path the ceremony reuses)
- `crates/pqcd/src/ceremony.rs` (implementation)
- `crates/pqcd/src/main.rs:121` (`cmd_ceremony` dispatch)
- `charts/pqchain/` (chart consumed by the emitted `values` JSON)


---

## ADR-057 - Follower Disk Reclamation Via On-Disk Prune (`pqcd snapshot-prune`)

**Status**: Accepted 2026-05-05
**Depends on**: ADR-054 (BFT block reception pipeline — defines the `siblings` CF that this ADR's prune path also reclaims); ADR-053 §T3 (checkpoint discipline — the prune cutoff is constrained to remain *above* a retained checkpoint so node restart still works); KNOWN-ISSUES R-10 (empty-block consensus chatter at 500 ms block-time accumulating ~4 GB/day).
**Governs**: the on-disk retention policy of follower nodes (full nodes that are not validators and not archive nodes) and the operator-facing tooling that enforces it.

### Context

`viper-pq-1` runs at a 500 ms block-time. Even when the chain is empty (no transactions), the consensus envelope of a block — header, commit signatures from the active validator set, the per-validator BLS-style signature blob, the encoded validator-set fingerprint — is on the order of a few KB. KNOWN-ISSUES R-10 quantifies the steady-state accumulation at roughly 4 GB/day (~1.5 TB/year). On a 200 GB NVMe a follower runs out of disk in roughly 50 days — well below the operational lifetime an operator expects from a node host.

Validators must keep full history (no information loss for slashing windows); archive nodes by definition keep full history (that is their product contract); but **followers** — full nodes that serve RPC and gossip but make no commits — have no consensus-correctness reason to retain blocks below a comfortably-old cutoff. The chain's safety properties depend on the validator set; followers are caches.

The decision to be made: how does a follower discard old blocks safely without breaking startup, fast-sync, RPC consistency, or the BFT-correctness invariants from ADR-054.

### Decision

#### D1. Per-role retention policy

- **Validators**: keep full history. No prune. (Slashing-evidence windows can reach back arbitrarily; never throw the receipts away on a node that signs commits.)
- **Archive nodes**: keep full history. (Product contract.)
- **Followers**: prune below `tip - keep_tail_blocks` on a weekly cadence. Default `keep_tail_blocks` is sized to comfortably cover the longest expected slashing-evidence lookback plus operator headroom; tunable per-deploy.

#### D2. The prune is RocksDB `delete_range` over five CFs

`RocksDbChainStore::prune_blocks_below(cutoff_height)` (`crates/pqc-consensus/src/storage_rocksdb.rs` line 715) issues `delete_range` against:

- `CF_BLOCKS` (line 752) — height-keyed, BE-ordered, so a single range delete covers everything below the cutoff.
- `CF_HASH_INDEX` (line 765) — keyed by block hash; iterated and per-key deleted because there is no height ordering on the keys.
- `CF_TX_INDEX` (line 776) — same shape as `CF_HASH_INDEX`, same per-key iteration.
- `CF_SIBLINGS` (line 789) — the ADR-054 sibling-archive CF; composite key `block_hash[32] || height_be[8]` so the height suffix is iterated.
- `CF_CHECKPOINTS` (line 804) — retains the **most recent** entry only, so the node can still bootstrap from disk on next start. Older trusted-checkpoint records are dropped.

State-store column families (account, validator-set, fee, governance, ADR-055 evidence-stream sidecar) are **not** touched. State is the latest-frontier projection of the chain; reclaiming state would re-introduce a sync requirement.

#### D3. Pre-flight refusals

Before any range delete is issued, `prune_blocks_below` refuses three classes of unsafe input:

- `cutoff_height == 0` — would be a no-op and likely an operator typo. Refused.
- `cutoff_height > tip` — would be requesting a prune past the chain tip; refused as a guard against off-by-one in operator scripts.
- No checkpoint at or after the cutoff — refused, because pruning out the bootstrap checkpoint would leave the node unable to restart from disk. The pre-flight iterates `CF_CHECKPOINTS` from the end (line 731) and confirms a survivor exists at `height >= cutoff` before proceeding.

These guards make the subcommand safe to run from a systemd timer (`pqcd-prune.timer`) without an interactive operator.

#### D4. Operator-facing surface: subcommand + Ansible timer

- `pqcd snapshot-prune <node-config.json> [--keep-tail-blocks N] [--force]` — subcommand (entry `cmd_snapshot_prune` in `crates/pqcd/src/main.rs:353`, library wrapper `snapshot_prune` re-exported from the runtime crate).
- Ansible role ships a `pqcd-prune.timer` + `pqcd-prune.service` pair on follower hosts only. Validator and archive roles do not get the timer.
- Default cadence: weekly. Empirically, weekly is the largest cadence that keeps a 200 GB follower comfortably under the disk-fill threshold for the chosen `keep_tail_blocks` default.

### Alternatives considered

- **TTL on RocksDB CFs.** Rejected: TTL is wall-clock-driven, not block-height-driven. A follower that pauses for a week then resumes would TTL-delete everything older than a week regardless of how many blocks that actually corresponds to, and the slashing-evidence lookback is defined in *blocks*, not seconds.
- **Discard at write time (write-side compaction with a height filter).** Rejected: every write path would need to know the prune policy, and worst of all the WAL would still hold the data until the next compaction. The CF-level `delete_range` on a periodic schedule is operationally simpler and explicit.
- **A standalone `pqc-prune` binary.** Rejected for the same reason as ADR-056's standalone binary: re-implements the storage-layer's CF schema and column-family handles. Putting the prune entry in `pqc-consensus`'s storage module keeps it co-located with the schema.
- **Prune validators too, with a deeper `keep_tail_blocks`.** Rejected for now: validators carry slashing liability and their disk is already provisioned for full history. Reducing that on the off-chance of disk pressure would trade a non-issue against a real correctness risk.
- **Empty-block suppression at consensus.** Considered but out of scope for this ADR; that is a chain-rule change with P-COMPAT-001 implications. Disk-side reclamation is the pragmatic, non-breaking lever and is what this ADR exercises.

### Consequences

**For operators.** Followers now have a maintenance story that runs unattended: weekly `pqcd-prune.timer` keeps disk usage flat at roughly the size of `keep_tail_blocks` × per-block overhead, indefinitely. A 200 GB NVMe goes from "fills up in 50 days" to "stable forever".

**For RPC consumers.** RPC against a follower returns 404 for blocks below the prune cutoff. Clients that need full history must hit an archive node (the role exists for exactly this reason). The role split is now operationally meaningful, not just a label.

**For ADR-054 compatibility.** The `CF_SIBLINGS` reclamation in step D2 is what keeps the ADR-054 swap path's archive cost bounded — without it, sibling-archive grows monotonically. ADR-054's startup integrity audit is unaffected because it only validates the post-checkpoint tail, and the most recent checkpoint is always retained (D2 / D3).

**For fast-sync semantics.** Fast-sync from a pruned follower will refuse to serve blocks below the prune cutoff. The block-fetch protocol surfaces this as a missing-block response; the requester falls back to another peer. Same operational shape as a peer that is simply slower; no new error class.

**For P-COMPAT-001 lens.** Non-engaged. No chain rules, no signing preimages, no state-root format change, no on-disk format change beyond *fewer entries* in the same CF schema.

### Tracking tasks

- TASK-187 — design + storage primitive (`prune_blocks_below`).
- TASK-187a — operator wiring (`pqcd snapshot-prune` subcommand + Ansible `pqcd-prune.timer` + role gating to followers only). Commits `25f4bf1`, `7720700`.

### Related

- ADR-053 §T3 (checkpoint discipline — the survival-of-most-recent-checkpoint guard)
- ADR-054 (`CF_SIBLINGS` introduced; this ADR keeps it bounded)
- KNOWN-ISSUES R-10 (the empty-block accumulation problem this ADR addresses)
- `crates/pqc-consensus/src/storage_rocksdb.rs:715` (`prune_blocks_below`)
- `crates/pqcd/src/main.rs:353` (`cmd_snapshot_prune` dispatch)


---

## ADR-058 - Cold-Storage Rotation: Export-Only Path With Stub Manifest Schema (`pqcd cold-storage-export`)

**Status**: Accepted 2026-05-05
**Depends on**: ADR-045 (archival overlay — defines the durability tier this ADR feeds); SPEC-ARCHIVAL-001 §6 (batch convention of 10k blocks); ADR-057 (follower prune — orthogonal; followers don't run export, archive nodes do).
**Governs**: the export half of the cold-storage rotation pipeline — how an archive node packages historical blocks for upload to S3 / cold-storage backends. **Restore, signing, S3 push, TSA anchoring, and ADR-045 RFC-3161 binding are explicitly deferred** (see §Out of scope).

### Context

`viper-pq-1` is positioned for multi-year operation. Even with ADR-057 follower prune, the network as a whole must retain full history somewhere — the archive-node role's product contract and ADR-045's archival overlay both depend on it. A live archive node holds full history on a hot RocksDB; that storage is expensive (NVMe-class) and grows monotonically. The rotation strategy is: archive nodes export blocks older than a cutoff to an off-host cold-storage backend (S3 / Glacier / equivalent) and the operator can prune the on-host copy once the cold copy is verified.

This ADR records the **export half** of that pipeline — the half that produces the cold-storage artefacts. The complementary halves (signing the manifest, restoring from cold, pushing to S3, anchoring batches with an RFC-3161 TSA per ADR-045) are deferred to TASK-188b.

The decision to be made: artefact format, batch granularity, compression level, and manifest schema — chosen now even though the consumer-side (restore/verify) lands later, because the export shape is what locks in compatibility.

### Decision

#### D1. One subcommand, one export run, one manifest

`pqcd cold-storage-export <node-config.json> --cutoff-height N --output-dir DIR [--batch-size 10000]` (entry `cmd_cold_storage_export` in `crates/pqcd/src/main.rs:421`, implementation `export_cold_storage` in `crates/pqcd/src/cold_storage.rs:162`). One invocation produces one manifest plus N batch files in `DIR`.

#### D2. Batch size: 10 000 blocks per file

Matches SPEC-ARCHIVAL-001 §6's batch convention. Empirically chosen because:

- Smaller batches inflate per-batch metadata overhead (filename, manifest entry, S3 object header, TSA anchor cost when ADR-045 binding lands).
- Larger batches make partial-restore more painful and increase the blast radius of a single corrupted batch.

10k is the SPEC value; this ADR adopts it without divergence.

#### D3. Compression: zstd level 19

`zstd::encode_all(raw.as_slice(), 19)` (`crates/pqcd/src/cold_storage.rs:134`). Level 19 is zstd's "high compression" tier — slow on the encode side (acceptable: this is offline, batch work) and very fast on the decode side. Empirically achieves a 50-60% reduction on Viper block CBOR — measured in the test path of `cold_storage.rs` which round-trips a deterministic batch through encode/decode.

#### D4. Manifest schema: `viper-cold-storage-v1`

`MANIFEST_SCHEMA_VERSION = "viper-cold-storage-v1"` (`crates/pqcd/src/cold_storage.rs:92`). The manifest is a JSON document at the root of the output dir listing every batch by `file_name` (`blocks-<low_height_hex>-<high_height_hex>.zst`), `low_height`, `high_height`, the SHA-256 of the *uncompressed* CBOR concatenation, and the SHA-256 of the *compressed* artefact. Future versions append to this schema; the version field is checked by the consumer.

The manifest is **unsigned at this stage** — the signing pass (TASK-188b) will wrap this same JSON with a PQ signature envelope without changing its structure.

#### D5. No S3 push from the binary

`pqcd cold-storage-export` writes to a local directory only. Upload to the cold-storage backend is delegated to the operator via `aws s3 sync <output-dir> s3://<bucket>/<prefix>/` (or the backend-specific equivalent). This keeps the binary narrow, removes a dependency on the AWS SDK from `pqcd`, and lets the operator pick *any* cold-storage backend (S3, Backblaze B2, GCS, MinIO, plain WebDAV) without recompiling.

### Alternatives considered

- **Direct S3 push from `pqcd`.** Rejected: would pull the AWS SDK into the binary, would tie us to S3 specifically, and would intermix the chain logic with cloud-vendor credentials. The "emit then `aws s3 sync`" split keeps each tool to its strength.
- **Larger batches (100k blocks).** Rejected: at 10k, batch files are sized in the small-MB-to-tens-of-MB range after zstd-19, comfortable for partial restore and for individual TSA anchoring later. 100k inflates the unit blast radius without proportional metadata savings.
- **Smaller batches (1k blocks).** Rejected: 10× the manifest entries and 10× the eventual TSA anchors per unit of chain history.
- **gzip / xz instead of zstd.** Rejected: zstd-19 dominates both on decode speed (cold-storage *will* be read back occasionally and quickly matters) and is roughly comparable to xz on archival-tier ratios. gzip is simply worse on ratio.
- **Sign + push + anchor in one subcommand.** Considered, rejected: each stage has a different operational profile (export is CPU-bound and fast; sign is HSM-gated; push is network-bound and credential-gated; TSA anchor is external-API-bound). Forcing them into one command makes failure modes harder to reason about and forces all three sets of credentials into the same execution context. They are explicitly split into their own tasks.

### Consequences

**For operators.** A working export pipeline today: rotate weekly, `pqcd cold-storage-export ... --cutoff-height N --output-dir /var/lib/pqchain/cold-export`, then `aws s3 sync /var/lib/pqchain/cold-export s3://...`. The on-host store can be pruned (or compacted) past the exported cutoff with the existing storage tools.

**For the v1 manifest schema.** Locks in *now*. The TASK-188b signing pass adds an outer envelope; restore tooling parses `viper-cold-storage-v1` payloads and treats unsigned-vs-signed as a schema-version check. There is no upgrade pain for batches exported under this ADR — the signed schema is a strict superset.

**For ADR-045 binding.** Deferred to TASK-188b. The export artefacts are anchor-ready (the manifest carries the per-batch SHA-256) but the TSA call is not made by this ADR's code path. When TASK-188b lands, it consumes the same manifest and adds an `rfc3161_token` field per batch.

**For recovery semantics.** Restore is **out of scope for this ADR**. An operator who needs to restore today does so manually: `aws s3 cp` the batch, `zstd -d` it, and feed the CBOR back into a node via existing snapshot-import primitives. TASK-188b ships the wired-up restore path.

**For P-COMPAT-001 lens.** Non-engaged. Off-chain artefacts; no consensus or signing-preimage involvement.

### Out of scope (deferred to TASK-188b)

- Signing the manifest with a PQ signature envelope.
- S3 / cold-storage backend push from the binary.
- RFC-3161 TSA anchoring per ADR-045.
- Automated restore subcommand.
- Verification subcommand that round-trips a manifest end-to-end against an on-host RocksDB.

### Tracking task

- TASK-188 — export half (this ADR). Commit `b6d6e80`.
- TASK-188b — signing + S3 push + TSA anchor + restore (deferred).

### Related

- ADR-045 (archival overlay + RFC-3161 — the durability tier this pipeline feeds; binding deferred to TASK-188b)
- SPEC-ARCHIVAL-001 §6 (batch convention of 10k blocks)
- ADR-057 (orthogonal — follower prune is the on-disk reclamation; this ADR is the off-host rotation)
- `crates/pqcd/src/cold_storage.rs:162` (`export_cold_storage`)
- `crates/pqcd/src/cold_storage.rs:92` (`MANIFEST_SCHEMA_VERSION = "viper-cold-storage-v1"`)
- `crates/pqcd/src/main.rs:421` (`cmd_cold_storage_export` dispatch)
- ADR-060 (the v2 schema bump that closes the deferred half)


---

## ADR-060 - Cold-Storage Rotation v2: SLH-DSA Manifest Signing, RFC-3161 Anchoring, Restore, S3 Push, Monthly Timer

**Status**: Accepted 2026-05-06
**Depends on**: ADR-058 (export-only path — defines the batch + manifest shape this ADR signs); ADR-045 (archival overlay + RFC-3161 — the TSA anchoring pattern this ADR re-uses for off-chain manifests); ADR-052 (P-COMPAT-001 §7 — schema-bump rule for `schema_version` discriminator).
**Governs**: the closure of the four deferred halves in ADR-058 §"Out of scope" — manifest signing, TSA anchoring, restore subcommand, and S3 push — plus the Ansible monthly timer that ties them into a scheduled rotation.

### Context

ADR-058 landed the export-only path and explicitly listed four deferred items. After 30 days of operating that path the gaps that motivated the deferral are now actionable:

- Manifests written today are unsigned. An operator who downloads a `viper-cold-storage-v1` archive from S3 can verify file integrity against `sha256` in the manifest, but the manifest itself is only as trustworthy as the bucket policy. There is no operator-level attestation that the bundle came from a specific validator at a specific time.
- Restore is manual (`aws s3 cp` + `zstd -d` + per-block `pqcd snapshot-import`). A fresh follower bootstrapping from cold storage walks 30 days of blocks one HTTP `GET` at a time. The operator workflow is unergonomic and error-prone.
- The Ansible side has no scheduled hook for the rotation — operators run the export by hand on a calendar tick they maintain themselves.
- AWS SDK is intentionally absent from pqcd, so even when the operator is on EKS with IRSA they cannot hit S3 from within the binary.

This ADR closes all four gaps in one schema bump (`viper-cold-storage-v1` → `viper-cold-storage-v2`) and one feature-gated dependency addition.

### Decision

#### D1. Schema bump v1 → v2 with two new optional fields

Two `Option`-typed fields land on `ColdStorageManifest`:

- `signature: Option<ManifestSignature>` — SLH-DSA-SHAKE-256s sig over canonical manifest bytes.
- `tsa_token: Option<String>` — base64-encoded RFC 3161 `TimeStampResp` DER.

Both use `skip_serializing_if = "Option::is_none"` so a v2 manifest with neither field set serialises to bytes that differ from v1 only in the `schema_version` string. Restore code accepts both versions; the importer refuses to replay an unsigned v1 archive without explicit `--insecure-no-verify`.

#### D2. Canonical signing preimage = "stripped manifest" + domain prefix

The signing preimage is `MANIFEST_SIGNING_DOMAIN || serde_json::to_vec_pretty(stripped_manifest)`, where `stripped_manifest` has both `signature` and `tsa_token` set to `None`. `MANIFEST_SIGNING_DOMAIN = b"VIPER-COLD-STORAGE-MANIFEST-V1"`. The struct field order is fixed by the Rust declaration so the bytes are byte-deterministic across runs of the same crate version. Pin tests assert this invariant in CI.

The same canonical bytes also feed the TSA imprint: `sha256(MANIFEST_TSA_DOMAIN || canonical_bytes)`. `MANIFEST_TSA_DOMAIN = b"VIPER-COLD-STORAGE-TSA-V1"` (distinct from `MANIFEST_SIGNING_DOMAIN` so a manifest signature can never be replayed as a TSA imprint or vice-versa).

#### D3. SLH-DSA-SHAKE-256s, key reuse, public-key recovery

Signing reuses `pqc_crypto::slh_dsa_shake_256s_sign` and the operator's `archival_sk` slot in the keystore — the same key the validator already operates for the in-band archival overlay. The 64-byte public key is recovered from `sk[64..128]` (FIPS 205 §10.3 layout — pk is contiguous in the secret-key encoding) and embedded in the manifest's `signer_pk_hex` for verification convenience; restore code re-derives + checks this against the embedded sig.

Why SLH-DSA over ML-DSA at this layer: cold-storage manifests are off-chain artefacts that may be validated decades after writing. SLH-DSA's hash-based foundation is more conservative for that horizon than the lattice-based ML-DSA which the on-chain consensus layer uses for throughput reasons.

#### D4. Restore via `cold-storage-import` with three orthogonal gates

`pqcd cold-storage-import <node-config.json> <input-dir> [--insecure-no-verify] [--require-tsa]`. Three orthogonal verifications:

1. **Manifest signature** — verified by default; bail without `--insecure-no-verify` on an unsigned manifest.
2. **TSA token presence** — only checked when `--require-tsa` is set; the chain does NOT verify the TST DER cryptographically (matches SPEC-ARCHIVAL-001 §6.1's "TST verification is the auditor's job"). The token is forwarded opaquely.
3. **Per-batch integrity** — SHA-256 of each `.zst` file matches the manifest entry; height ladder is contiguous and starts at `batch.low_height`; last block's hash matches `batch.anchor_block_hash`.

Replay uses `RocksDbChainStore::append_stored_block(stored, None)` — the manifest signature attests authenticity at bundle level so per-block quorum policy is intentionally `None` (matches the P2P-sync semantics for trusted-source incoming blocks).

Pre-flight: live tip < manifest.low_height. Restore is a fresh-follower workflow; importing into a populated store would corrupt the canonical chain and so refuses.

#### D5. S3 push as Cargo feature `s3-upload`

The new `--upload-to s3://<bucket>/<prefix>/` flag is gated behind `cargo build -p pqcd --features s3-upload`. Default-off so the standard build still drops the AWS SDK (~30 transitive crates, ~30 s extra compile). Builds without the feature error out with a message pointing the operator at `aws s3 sync` as the externally-driven alternative.

The SDK reads `AWS_ROLE_ARN` + `AWS_WEB_IDENTITY_TOKEN_FILE` env vars via IRSA on EKS, so chart-side ServiceAccount wiring needs no in-process credential plumbing. `aws-config = { features = ["behavior-version-latest"] }` pins the SDK behaviour version so a future SDK release does not silently change auth or retry semantics.

#### D6. Monthly Ansible timer gated by `viper_cold_rotate_enabled`

Three new Ansible templates under `deploy/ansible/roles/configure/templates/`: `pqcd-cold-rotate.{sh,service,timer}.j2`. The timer fires `OnCalendar=*-*-01 02:00:00 UTC` (1st of month, `RandomizedDelaySec=30min`, `Persistent=true`). The wrapper script resolves the live tip via `pqcd status` to compute `cutoff = tip - viper_cold_rotate_keep_tail_blocks` (default 1209600 ≈ 7 days at 500 ms), then dispatches `pqcd cold-storage-export` with the configured `--sign-with-operator`, `--anchor-tsa`, `--upload-to` flags.

Default `viper_cold_rotate_enabled = false` — opt-in per host, mirroring the prune-role pattern from ADR-057.

#### D7. The TSA DER encoder lives in a shared `pqc-tsa` crate

**Original decision (2026-05-06 morning, pre-extraction):** The minimal RFC 3161 `TimeStampReq` DER builder was copied from `viper-archival-sidecar/src/rfc3161.rs` into `crates/pqcd/src/cold_storage.rs::rfc3161` (~80 LOC). The sidecar crate already depended on pqcd, so importing back would create a cycle. A future cleanup was deferred — extract to a shared `pqc-tsa` crate when a third consumer appears — to avoid inflating TASK-188b's scope.

**Cleanup landed (same-day, 2026-05-06):** Once TASK-188b shipped, the third use site was already the cold-storage manifest anchoring. The cycle-avoidance argument no longer applied (a leaf crate with no internal deps is the right home for the encoder). New workspace member `crates/pqc-tsa/` houses the encoder; both consumers (`pqcd::cold_storage` and `viper-archival-sidecar::rfc3161`) import from there. No on-chain or wire-format implication — byte-identical DER output, refactor-only. See the CHANGELOG entry "TASK-188b follow-up — pqc-tsa shared crate extraction" for the move.

### Alternatives considered

- **Sign with ML-DSA-65** instead of SLH-DSA-SHAKE-256s. Rejected: lattice schemes are less conservative for multi-decade off-chain artefacts. SLH-DSA-SHAKE-256s key reuse for cold-storage matches the validator's existing archival-overlay key, so there is no new key-management cost.
- **Inline RocksDB-internal zstd / blake3 / SHA3-256** instead of SHA-256 for batch integrity. Rejected: SHA-256 is the digest baked into the RFC 3161 imprint we send to the TSA, so reusing it for batch integrity costs nothing and avoids a second hash function in the audit trail.
- **Sidecar-style bundle: `manifest.json` + `manifest.sig`** in two files. Rejected: violates ADR-058 D4's "one manifest" rule. Carrying the signature inline keeps the operator-visible artefact count constant across schema bumps.
- **Add aws-sdk-s3 as default dep**. Rejected: ~30 transitive crates and ~30 s extra compile per CI run. The feature gate is the right cost/benefit tradeoff; production deployments that want in-band upload re-build with the feature.
- **Restore via `pqcd snapshot-import --from-cold <manifest>`** (sub-flag on the existing snapshot-import). Considered, rejected: cold-storage import is operationally distinct (multi-file → many appends; takes minutes-to-hours; refuses on a populated store), so a separate subcommand surface keeps the failure modes obvious.
- **TSA DER parsing on the import path**. Rejected: SPEC-ARCHIVAL-001 §6.1 says TST verification is an auditor's job, not the chain's. The token is forwarded opaquely and the manifest signature alone gates the import.
- **Hourly / daily Ansible timer**. Rejected: the rotation requires stopping pqcd briefly, and 30 days at 500 ms (~5.2M blocks at ~3.3 KB ≈ 17 GB raw → ~8.5 GB zstd-19) is the natural cadence to amortise the stop-and-restart cost.

### Consequences

**For operators.** Three new things they can do that they could not do at ADR-058's landing: produce a signed + anchored manifest with one CLI invocation; restore a fresh follower from cold storage with one CLI invocation; schedule the whole rotation as a monthly systemd timer with three Ansible variables. The pre-existing v1 manifests still parse and replay (with `--insecure-no-verify`) so existing cold archives are not stranded.

**For the schema.** v2 is a strict additive superset of v1. A v1 reader sees a v2 manifest and parses successfully (the unknown-field tolerance of `serde_json` covers `signature` + `tsa_token`); a v2 reader sees both formats. No P-COMPAT-001 §7 dual-path window is needed — there is no consensus involvement.

**For the keystore.** No change. The `archival_sk` slot is the same one the in-band archival overlay uses; an operator who runs an archival validator already has the key. An operator who wants to rotate without signing simply omits `--sign-with-operator`.

**For the build matrix.** One new feature flag (`s3-upload`). The default CI build does not pull AWS SDK; the chart's release-image build adds `--features s3-upload` if the operator wants in-band S3 push. Both build paths are exercised in CI by separate jobs.

**For the audit trail.** Manifest signing + TSA anchoring give an external auditor a 2-of-2 path: the validator key proves origin, the TSA token proves not-after-time. Either failure (key compromise OR TSA collusion) leaves the other half of the attestation intact.

**For P-COMPAT-001 lens.** Non-engaged. Off-chain artefacts; no consensus or signing-preimage involvement; no STATE_FORMAT_VERSION bump.

### Tracking task

- TASK-188b — this ADR. Commit will be appended on land.

### Related

- ADR-045 (archival overlay + RFC-3161 — the in-band TSA pattern this ADR mirrors out-of-band)
- ADR-052 (`schema_version` bump rule)
- ADR-057 (Ansible role pattern for the monthly timer)
- ADR-058 (the export half this ADR completes)
- SPEC-COLD-STORAGE-001 v2 (manifest schema spec)
- `crates/pqcd/src/cold_storage.rs::sign_manifest_in_place`
- `crates/pqcd/src/cold_storage.rs::verify_manifest_signature`
- `crates/pqcd/src/cold_storage.rs::anchor_manifest_with_tsa`
- `crates/pqcd/src/cold_storage.rs::import_cold_storage`
- `crates/pqcd/src/cold_storage.rs::upload_to_s3`
- `crates/pqc-consensus/src/storage_rocksdb.rs::decode_block_bytes_from_reader`
- `deploy/ansible/roles/configure/templates/pqcd-cold-rotate.sh.j2`


---

## ADR-059 - libp2p Cold-Start Retry With Bounded Backoff

**Status**: Accepted 2026-05-06
**Depends on**: TASK-148 (periodic redial loop, 15 s cadence); ADR-053 §T4 (libp2p snapshot-fetch / genesis-replay fallback); the libp2p Swarm + TLS handshake timing characteristics observed in the 2026-05-05 kind smoke.
**Governs**: the cold-start sequence of a sentry / full node when it joins an existing `viper-pq-1` cluster and needs to fetch a snapshot from a bootstrap peer over libp2p before falling back to genesis replay.

### Context

In the 2026-05-05 kind smoke, sentries and follower full nodes joined the cluster and stayed at height 0 indefinitely. Forensics showed the cold-start path issued exactly one libp2p snapshot-fetch request, fired roughly 1 s after the local Swarm started — and that request raced the bootstrap peer's libp2p TLS handshake. The handshake had not yet completed; the request errored or timed out; the cold-start fallback then dropped to genesis replay, which on a non-empty chain means "stay at height 0 because there is nothing to replay locally beyond genesis". The node never made a second attempt.

The bug is structural, not a network glitch: the single-shot fire-and-fallback path had no allowance for the variability of libp2p TLS handshake completion, even though a parallel periodic-redial loop (TASK-148, 15 s cadence) was already racing to bring the connection up.

The decision to be made: how does the cold-start path reliably wait for the connection to come up without ever stalling indefinitely, and how does it stay BFT-safe (never silently desync, always preserve the genesis-replay fallback as a last resort).

### Decision

#### D1. Retry up to 6 attempts with bounded backoff

`cold_start_from_libp2p_snapshot` (`crates/pqcd/src/devnet.rs:3270`) is rewritten to retry the libp2p snapshot-fetch request up to 6 times. The three timing constants are:

- `INITIAL_HANDSHAKE_GRACE: Duration = Duration::from_secs(5)` (`devnet.rs:3323`) — sleep before *any* attempt, to let the bootstrap peer's TLS handshake complete on a healthy network.
- `RETRY_BACKOFF: Duration = Duration::from_secs(8)` (`devnet.rs:3324`) — wait between attempts (after the initial grace), constant rather than exponential to bound the worst-case time-to-fallback.
- `PER_ATTEMPT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(8)` (`devnet.rs:3325`) — per-attempt deadline for the response stream, so a stuck attempt cannot block the loop.

Worst-case time before the genesis-replay fallback fires: `5 s (initial grace) + 6 × 8 s (per-attempt timeout) + 5 × 8 s (inter-attempt backoff) = 5 + 48 + 40 + ε ≈ 101 s`. Best-case (first attempt succeeds): ~5-10 s.

#### D2. Behaviour on each terminal path is preserved

- **Success** (any attempt returns a snapshot): apply the snapshot, exit cold-start with the resulting tip height. Same downstream wiring as before.
- **Empty response** (peer answers definitively "I have no snapshot newer than genesis"): treat as success of the *fetch*, with an empty payload — drop to genesis replay immediately, no further retries (retrying would not produce a different answer).
- **Final timeout** (all 6 attempts exhausted): emit a structured warning, fall back to genesis replay. The node is now in the same state it would have been in before this ADR — the fallback is preserved.

#### D3. Coexists with the TASK-148 redial loop, doesn't replace it

TASK-148's periodic redial loop runs in parallel at 15 s cadence and is responsible for *establishing* the connection. This ADR's retries-with-backoff loop is responsible for *using* the connection once it exists. By attempt 2 (~13 s of wall time) the redial loop has typically had one redial pass and the connection is up; the per-attempt timeout (8 s) is sized to allow one full redial cycle to land if the first attempt happened to race.

This ADR does **not** add a second redial mechanism — there is exactly one (TASK-148). The cold-start retries reuse it.

### Alternatives considered

- **Single-shot with a longer initial grace (e.g. 30 s).** Rejected: hard-coded grace makes the cold-start unconditionally slow on healthy networks (typical handshake is 2-5 s) and still fails on unhealthy ones (one bad redial cycle and the request is gone). Retry with a short grace + bounded backoff is strictly better on both axes.
- **Exponential backoff (1, 2, 4, 8, 16, 32 s).** Rejected: worst-case is dominated by the *last* sleep, not the sum, so exponential makes the tail much longer (~63 s of inter-attempt sleep alone, vs. 40 s constant) for no reliability gain on this workload — the bottleneck is the libp2p TLS handshake, which has bounded latency.
- **Block forever on the connection.** Rejected: removes the genesis-replay fallback, which is the safety net for the case where the bootstrap peer is genuinely unreachable. A node that cannot snapshot-fetch *and* cannot replay genesis is operationally worse than a node that replays genesis and ends up at height 0 with a clear log line.
- **Tie attempts to libp2p connection events.** Considered, rejected for now: would couple the cold-start path to libp2p event-stream plumbing it does not currently consume. Time-based backoff is strictly simpler, has no library-version surface, and the redial loop already does the connection-management work. If future telemetry shows a sub-100 s tail still costs us in real deployments, an event-driven variant is a follow-up.
- **Increase TASK-148 redial cadence below 15 s.** Rejected: redial cadence affects the entire cluster's connection-discipline, not just cold-start. Tuning a cluster-wide knob to fix a one-shot path is the wrong shape.

### Consequences

**For cold-start reliability.** The 2026-05-05 smoke failure mode is closed: a sentry / full node joining a healthy cluster will reliably catch up on the first or second attempt (~5-15 s wall time). On a degraded cluster it tries for ~100 s before falling back to genesis replay — still bounded, still safe.

**For operator UX.** A new node joins, logs a structured "libp2p cold-start attempt N/6" line per attempt, and either reaches sync or surfaces a clear failure log with the timing breakdown. No more silent height-0 stalls.

**For BFT safety.** No change. Cold-start was never on the consensus path; this ADR only changes how a *fresh* node decides where to start replay from. ADR-054's reception pipeline still gates everything that gets persisted.

**For test surface.** The retry loop is unit-testable by mocking the libp2p snapshot-fetch trait (success-on-attempt-N, always-timeout, empty-response). Integration coverage in the kind smoke is the canary that surfaced the original bug.

**For P-COMPAT-001 lens.** Non-engaged. Local startup behaviour, no chain change.

### Tracking task

- TASK-234 — cold-start retry-with-backoff. Commit `1504d10`.

### Related

- TASK-148 (periodic redial loop, 15 s cadence — the parallel mechanism this ADR cooperates with)
- ADR-053 §T4 (libp2p snapshot-fetch / genesis-replay fallback path this ADR strengthens)
- ADR-054 (BFT block reception — orthogonal; reception correctness is untouched)
- `crates/pqcd/src/devnet.rs:3270` (`cold_start_from_libp2p_snapshot` rewrite)
- 2026-05-05 kind smoke failure log (operator session log)


---

## ADR-061 - STARK Signature Aggregation for ML-DSA / SLH-DSA *(reserved)*

**Status**: Reserved 2026-05-06; trigger conditions not yet met.
**Authority:** `docs/long-horizon-roadmap.md` §1.
**Y-band:** Y4-Y6 (2030-2032), gated on Ethereum Lean STARK aggregator maturity + production-ready Rust binding handling at least one of ML-DSA-65 / SLH-DSA-SHAKE-192s / SLH-DSA-SHAKE-256s.

### Reservation rationale

Lattice + hash-based PQ signatures dominate Viper's per-block bandwidth at scale (3.3 KB ML-DSA-65 × 3 sigs × 172 800 blocks/day ≈ 1.7 GB/day at zero traffic; 64-validator scale = 36 GB/day). STARK aggregation collapses N independent verifications into one O(log N)-sized proof. Reserving this slot now so the closure ADR has a stable identifier when the trigger fires; closure target for KNOWN-ISSUES R-10.

When the trigger fires, this ADR is promoted to `accepted` status with full context / decision / alternatives / consequences sections, and the Y-band table in `docs/long-horizon-roadmap.md` §1 is updated to "**closed** (commit `<hash>`, YYYY-MM-DD)".

### Related

- `docs/long-horizon-roadmap.md` §1 — full direction + trigger conditions + selection criteria
- TASK-228 — scale-up plan that gates on this ADR's closure for the Phase 11+ band


---

## ADR-062 - PQ-VRF Migration *(reserved)*

**Status**: Reserved 2026-05-06; trigger conditions not yet met.
**Authority:** `docs/long-horizon-roadmap.md` §2.
**Y-band:** Y3-Y5 (2029-2031), gated on IETF/NIST PQ-VRF standardisation + ≥1 audited Rust impl + ≤2 KB pk size + ≤5 % round-budget verify cost.

### Reservation rationale

ADR-053 §T1.4 fixes genesis randomness as `RANDAO + ML-DSA-65 signature commit-reveal`. A real PQ-VRF (single-round, publicly verifiable, no commit-reveal latency) is the right primitive but no audited PQ-VRF is standardised as of 2026-05. Reserving the closure ADR ID for stable cross-reference; the new spec slot SPEC-VRF-001 is reserved alongside.

### Related

- ADR-053 §T1.4 (current RANDAO+sig placeholder)
- `docs/long-horizon-roadmap.md` §2 — full direction
- SPEC-VRF-001 (reserved)


---

## ADR-063 - NIST On-Ramp 3rd Algorithm *(reserved)*

**Status**: Reserved 2026-05-06; trigger conditions not yet met.
**Authority:** `docs/long-horizon-roadmap.md` §3.
**Y-band:** Y3-Y4 (2029-2030), gated on NIST on-ramp Round-2 finalised standard + production-ready Rust binding + benchmarks within per-tx budget.

### Reservation rationale

Adds a 3rd algorithm (foundational diversity beyond ML-DSA + SLH-DSA — preferred non-lattice / non-hash). Watch-list: MAYO (multivariate), CROSS (code-based), FAEST (symmetric), SQIsign (isogeny — not pre-final per Castryck-Decru lessons). AlgId range `0x0011..0x0017` is reserved at the registry level alongside this ADR slot.

### Related

- ADR-043 / ADR-044 (existing 2-algorithm Algorithm Registry + TLV envelope)
- `docs/long-horizon-roadmap.md` §3 — selection criteria table
- TASK-226 / ADR-067 — separate FN-DSA slot (FIPS track, not on-ramp)


---

## ADR-064 - Fee-Primacy Crossover Taper Schedule *(reserved)*

**Status**: Reserved 2026-05-06; trigger conditions not yet met.
**Authority:** `docs/long-horizon-roadmap.md` §4.
**Y-band:** Y8-Y12 (2034-2038), gated on 90-consecutive-day fee revenue > inflation aggregated network-wide at 256+ active set.

### Reservation rationale

When sustained fee revenue overtakes inflation, governance opens the inflation taper schedule. Reserving the closure ADR ID for the schedule decision; default proposal (linear taper to ~0.5%/year security floor over 8-12 years) is a starting point — actual schedule is governance-decided when the trigger fires.

### Related

- ADR-022 (genesis tokenomics + fee model)
- `docs/long-horizon-roadmap.md` §4 — full crossover definition
- TASK-118 (recurring 30-day fee-revenue measurement vehicle)


---

## ADR-065 - Scale-Up Plan: Committee 3 → 64 → 256 → 1024 Validators

**Status**: Accepted 2026-05-06.
**Depends on:** ADR-013 (closed-cohort baseline that this scale-up evolves from), ADR-041 (libp2p + GossipSub v1.2 transport), ADR-042 (validator identity + ValidatorPeerId binding), ADR-046 (consensus-key rotation framework, Phase-3 partial), ADR-051/052 (BFT signing + P-COMPAT-001 state-evolution policy), ADR-053 (`viper-pq-1` genesis architecture), TASK-222 (GossipSub peer-score calibration — already calibrated for the 64-256 band).
**Governs:** the staged growth ladder from the current 3-validator launch through 64 / 256 / 1024 active validators, with the explicit gate conditions each step must clear.

### Context

`viper-pq-1` launched 2026-04-25 with 3 validators on a single operator's infrastructure (devnet-2 hardware re-purposed for mainnet-discipline operation). The ADR-053 genesis architecture was sized for this baseline — `EpochConfig::viper_pq_1()` defaults `churn` to 39 / 313 bps which approximates the legacy `/256` and `/32` per-epoch limits at uniform stake (TASK-194 commit `341aee9`).

The chain is engineered for multi-decade operation; staying at 3 validators indefinitely defeats every decentralisation property the project commits to. But brute-force scaling to N validators surfaces a layered set of constraints that each need their own closure work. This ADR sequences the four growth steps with explicit gate conditions, owner-tasks, and exit criteria, so the operator running the cohort onboarding (TASK-185) and the protocol team driving the technical gates (TASK-222 / 223 / 186) work from the same forecast.

The framing the project rejects: "open to permissionless tomorrow". The framing the project accepts: phased growth, each step gated on observable closure of the previous step's constraints, with a multi-year arc that takes the chain from operator-controlled launch to fully-permissionless-with-diversity-targets at the Y10 horizon (per `docs/long-horizon-roadmap.md` §5).

### Decision

#### D1. Four-step ladder

| Step | Active size | Phase | Gate(s) closed before opening | Hardware target per validator |
|------|-------------|-------|-------------------------------|-------------------------------|
| 0 | 3 | 8.5 (current) | n/a — launch baseline | 4-core / 16 GB / 500 GB NVMe |
| 1 | 4 → 64 | 9 | TASK-185 onboarding closed; TASK-223 dynamic keystore landed; TASK-186 block-time decision pinned | 8-core / 32 GB / 1 TB NVMe |
| 2 | 64 → 256 | 10 | TASK-222 peer-score telemetry shows steady-state under cohort load (DONE-pending-soak); fee-revenue trajectory stable per TASK-118 | 16-core / 64 GB / 2 TB NVMe |
| 3 | 256 → 1024+ | 11+ | STARK aggregation matured (ADR-061 closure); committee size economically rational (TASK-118 fee data); hardware re-baseline | re-baselined post-aggregation |

Each step is opened by a governance vote against on-chain `max_active_validators` (currently a `viper-pq-1` mainnet constant; promoted to a governance-mutable parameter in Step 1). The vote MUST cite this ADR and the specific gate-closure evidence.

#### D2. Step 1 (3 → 64): the cohort step

**Owner-tasks:**
- TASK-185 — external operator onboarding (≥5 operators × 7-day soak by 2026-05-20)
- TASK-223 — online consensus-key rotation + dynamic keystore (unblocks TASK-113 Step 6)
- TASK-186 — final block-time decision (the per-block budget at 64 × 3 sigs / block needs the right envelope)
- TASK-222 — GossipSub peer-score calibration (DONE 2026-05-06) — already sized for this step

**Constraints unblocked:**
- The `LocalProposer` test harness keystore caps at 3 keys (TASK-113 Step 6 `#[ignore]`d at 4-validator scale because `INSUFFICIENT_COMMIT_QUORUM` fires when the producer can't sign for the 4th validator). The unblock is *not* a code change to LocalProposer — it is a real keystore-layer that loads dynamically-registered validators' signing material per ADR-046's full path. TASK-223 is exactly that work.
- BFT quorum threshold `ceil((2N+1)/3)` grows with N; without dynamic keystore the producer becomes the bottleneck. With dynamic keystore + distributed signing (ADR-051 M2b N+2 — already live), each validator signs for itself and gossips its precommit; the producer waits for ≥ threshold gossip-collected sigs.

**Hardware target rationale:** at 64 validators × 3 sigs / block × 1 s block-time (post-TASK-186 likely landing) ≈ 192 sigs/s × 3.3 KB ≈ 4 MB/s pure consensus traffic. 1 TB NVMe at ~4 GB/day chain-data growth (KNOWN-ISSUES R-10) supports ~250 days before TASK-187a prune fires; weekly prune brings steady-state to ~30 GB. 8-core / 32 GB sized for the GossipSub peer-score sampler + RocksDB compaction headroom under the larger mesh (mesh_n=8 across 64 peers).

**Exit criterion:** 64 validators × 7-day soak with zero unplanned halts; `pqchain_p2p_gossip_peers_graylisted` stays at 0 across the 64-node cohort; chain growth tracks the TASK-186 forecast within 10 %.

#### D3. Step 2 (64 → 256): the Phase 10 step

**Owner-tasks:**
- TASK-222 peer-score calibration tuned from Step 1 soak data (the calibration was *intended* for this band but the actual numbers may shift ±2× per the documented "tune from soak data" workflow)
- TASK-118 fee-revenue trajectory stable (the chain economics need real signal at the 64-band before the 256-band opens)
- Hardware spec re-baseline if Step 1 soak surfaces unexpected I/O or memory pressure

**Constraints unblocked:**
- GossipSub IDONTWANT (already wired) becomes essential: at 256 × 3 sigs × 16 KB SLH-DSA-256s archival sig × 0.1 archival-cadence-fraction ≈ 1.2 MB/s archival overlay traffic alone. Without IDONTWANT the duplicate-message bandwidth would be O(N) larger per gossip round.
- TASK-186 block-time decision becomes load-bearing: at 500 ms / 256 / 3 sigs the chain produces ~17 GB/h pure consensus chatter — sustainable only if the 7-day soak supports it. If Step 1 soak shows the 500 ms cadence is too aggressive, governance shifts to 1000 ms before opening Step 2.
- Validator-set divergence risk grows quadratically with N (more pairs of equivocation-evidence to track). The slashing-evidence-registry's per-validator memory footprint is `O(N × evidence_count)`; ADR-050 caps it but at 256 the cap matters.

**Hardware target rationale:** 16-core / 64 GB sized for the 256-peer GossipSub mesh + the higher chain-data growth rate. 2 TB NVMe at the steady-state growth (post-prune ~120 GB) plus 6× headroom for incident-response (snapshot import, RocksDB compaction blowup).

**Exit criterion:** 256 validators × 7-day soak; fee-revenue trajectory monotonically positive (TASK-118 reports); peer-score telemetry stable; `pqchain_p2p_block_gap_total` stays bounded under cohort load.

#### D4. Step 3 (256 → 1024+): the post-aggregation step

**Owner-tasks:**
- ADR-061 closure (STARK aggregation matured) — gating dependency
- Hardware re-baseline post-aggregation (proof verify cost shifts the per-validator CPU envelope)
- Long-horizon governance review: at 1024 validators the chain is genuinely permissionless; ADR-066 (TASK-224 permissionless transition) likely closed by this point

**Constraints unblocked:**
- Without STARK aggregation, commit-sig footprint at 1024 × 3 × 3.3 KB × 86 400 blocks/day ≈ 33 GB/day per validator of pure commit signatures. Two orders of magnitude beyond the 64-validator regime; not sustainable on commodity NVMe at any reasonable block-time. STARK aggregation collapses the per-block commit footprint to O(log N) — that is the unlock.
- GossipSub mesh sizing at 1024 peers exceeds the libp2p default `mesh_n=8`; this step needs `mesh_n=12-16` calibrated for the new band. TASK-222's calibration framework (peer_score module) supports this; the per-topic params will be re-tuned at Step 3 opening.
- Slashing-evidence registry at 1024 needs an explicit memory cap revision; ADR-050 currently caps at the per-validator level but the global aggregate matters.

**Hardware target:** re-baselined when ADR-061 closes. Speculative starting point: 32-core / 128 GB / 4 TB NVMe per validator, but the actual envelope depends on STARK proof verify cost.

**Exit criterion:** 1024 validators × 7-day soak post-aggregation; STARK proof verify within block-budget envelope; cross-region geographic diversity per `docs/long-horizon-roadmap.md` §5 Y10 targets.

#### D5. Open `max_active_validators` to governance at Step 1 opening

The current `viper-pq-1` mainnet has `max_active_validators` as a compile-time constant in `EpochConfig::viper_pq_1()`. Step 1 opens it to a governance-mutable parameter with the existing `ProposalEffect::ParameterUpdate` path (ADR-022 fee-model precedent). Each step opening is a governance vote with explicit gate-closure evidence in the proposal body.

#### D6. Hardware spec ladder is *guidance*, not protocol

The hardware target columns are operator runbook material — they do not appear in any ADR-052 P-COMPAT-001 §2 invariant and do not gate consensus. An operator running an under-spec node experiences degraded performance (slower commit signing → peer-score penalty → mesh demotion) but does not corrupt the chain. The ladder is published to set expectations for the cohort, not to enforce.

### Alternatives considered

- **Open to permissionless after Phase 8.5 launch.** Rejected. Permissionless without the diversity targets framework (TASK-227) and without the dynamic-keystore work (TASK-223) is operationally fragile; the 2026-04-25 ADR-054 BFT-correctness incident showed that even a 3-validator chain can hit divergence if the reception pipeline has a single bug, and a permissionless network with hundreds of unknown-quality operators amplifies that risk class.
- **Skip the 64-validator step; jump 3 → 256.** Rejected. The cohort-onboarding workflow (TASK-185) needs an intermediate step where operators can practise the runbook + onboarding flow at a scale where individual operator behaviour is observable; 256 is too many to track per-operator. The 64-step is the smallest size where the diversity-targets framework starts producing meaningful Nakamoto-coefficient numbers.
- **Allow Phase 10 (256) to open before TASK-186 block-time decision.** Rejected. Block-time is load-bearing at 256 × 3 × 3.3 KB. If the wrong cadence ships, governance has to halt the chain to migrate, which contradicts ADR-052 P-COMPAT-001's "no chain resets" commitment.
- **Make hardware spec a protocol-enforced minimum.** Rejected. Operator-side enforcement (peer-score sigverify-latency penalty) is sufficient and avoids the on-chain attestation complexity. ADR-066 (permissionless transition) revisits this if the post-cohort soak surfaces under-spec operator pathology.
- **Define committee size independently from active set size.** Considered, deferred. ADR-053 §T1.6 currently treats `committee_size = active_size` for the BFT signing path. A separate committee size (e.g. random-sampled subset of active set per round) is a more advanced design that pairs with TASK-228 §3 (Phase 11+) — track as an ADR-068 reservation if needed.

### Consequences

**For operators.** Clear forecast of the hardware envelope per step, with per-step gate evidence in the governance proposal that opens it. The cohort-recruitment process (TASK-185) targets Step 1 (3 → 64) explicitly and reuses `docs/validator-onboarding.md`. New operator onboarding for Step 2 + Step 3 is governed by `docs/permissionless-transition.md` (ADR-066) once that lands.

**For the protocol.** The `max_active_validators` constant becomes governance-mutable at Step 1 opening — that is itself a P-COMPAT-001 §2 schema change (the validator-record activation path is unchanged but the upper bound moves). Track as a follow-up ADR slot if the change requires a dual-path decoder window.

**For the BFT signing path.** Distributed signing (ADR-051 M2b N+2) is essential at every step ≥ 1; the producer-only-signs-everyone path is retired permanently after Step 1 opens.

**For peer-score calibration.** TASK-222's params are sized for the 64-256 band. Step 3 (1024+) opening triggers a re-calibration TASK; the calibration framework supports the bump natively.

**For state-root format invariants.** Each step opens via governance proposal which is a state-root touch (parameter update). P-COMPAT-001 §2 covers this path — no new infrastructure needed.

**For P-COMPAT-001 lens.** Engaged — `max_active_validators` becoming governance-mutable rides §2(c) (parameter-update path, no schema change). ADR-066 (permissionless transition) will engage §2(b) (schema change for validator-record extension).

### Tracking task

- TASK-228 — this ADR. Commit will be appended on land.
- TASK-185 — Step 1 cohort onboarding (the operator-side gate)
- TASK-223 — Step 1 dynamic keystore (the protocol-side gate)
- TASK-186 — Step 1 / Step 2 block-time decision
- TASK-222 — Step 2 peer-score re-tuning (DONE 2026-05-06; re-validation pending soak)

### Related

- ADR-013 (closed-cohort baseline this scale-up evolves from)
- ADR-041 / ADR-042 (libp2p + ValidatorPeerId)
- ADR-046 (consensus-key rotation framework — TASK-223 closes the full path)
- ADR-051 (M2b distributed BFT signing)
- ADR-052 (P-COMPAT-001 state-evolution policy)
- ADR-053 (`viper-pq-1` genesis — Tier 1/2/3 commitments this ADR builds on)
- ADR-061 (STARK aggregation — gates Step 3)
- ADR-066 (permissionless transition — pairs with Step 2/3)
- `docs/long-horizon-roadmap.md` §1 + §5 (long-horizon STARK + diversity context)
- `docs/phase-9-followup-plan.md` (TASK-228 detail)
- `crates/pqc-state/src/store.rs` `EpochConfig::viper_pq_1()` (current constants)
- `crates/pqc-p2p/src/peer_score.rs` (TASK-222 calibration ready for the 64-256 band)


---


---

## ADR-066 - Permissionless Eligibility Transition Within 18 Months Post-Mainnet

**Status**: Accepted 2026-05-06.
**Depends on:** ADR-013 (current closed-cohort gates this ADR evolves from), ADR-022 (tokenomics / fee model — sets the economic context for the stake floor), ADR-042 (validator identity + ASN diversity — the anti-Sybil substrate), ADR-050 (slashing-evidence registry — the window-extension this ADR mandates), ADR-053 (`viper-pq-1` genesis — `permissionless_enabled` flag is a governance-mutable extension), ADR-065 (scale-up plan — this ADR is the operator-side counterpart of the protocol-side ladder).
**Governs:** the design + governance pathway from the current closed-cohort model (24/32/50 size targets per ADR-013) to permissionless validator entry within 18 months post-mainnet, with explicit anti-Sybil mechanics, stake floor justification, and phased opening discipline.

### Context

ADR-013 sized the validator cohort to 24 (Phase 9 cap) / 32 (Phase 10 target) / 50 (long-term cap) — those numbers were chosen for the closed-cohort era where every operator goes through manual onboarding via TASK-185. The Phase 8.5 launch is operating at 3 validators, all on a single operator's infrastructure; the cohort onboarding RFP under TASK-185 grows that to ≥5 distinct operators × 7-day soak by 2026-05-20.

But the project's stated direction (`docs/long-horizon-roadmap.md` §5 + ADR-053 §T1 framing) is permissionless within 18 months post-mainnet. ADR-013's hard caps are *not* the long-term commitment — they are the bootstrap regime. This ADR:

1. Documents what gates currently constrain validator entry, and why each gate exists,
2. Designs the on-chain mechanics that enable permissionless entry without each new validator becoming a denial-of-service vector,
3. Sequences the phased opening so governance retains the ability to pause the transition if Sybil pathology surfaces.

The framing the project rejects:
- "Open permissionless on launch + 1 day" — the operator runbook + anti-Sybil mechanics are not ready, and the slashing-evidence registry windows assume a knowable validator set.
- "Stay closed forever" — defeats every decentralisation property the project commits to (long-horizon §5 diversity targets are unreachable with a 50-validator cap).

The framing the project accepts:
- Phased opening with on-chain `permissionless_enabled` flag, governance-mutable, default false at genesis.
- Hard prerequisites: dynamic keystore (TASK-223 / ADR-066 dependency on ADR-046), slashing-evidence window extension (this ADR's §3 below), diversity-targets dashboard (TASK-227).
- Explicit pause-button: governance can flip `permissionless_enabled` to false at any quarterly vote if cohort metrics degrade.

### Decision

#### D1. Three-tier eligibility model

Validators fall into one of three eligibility tiers, gated by the on-chain `permissionless_enabled` flag and per-validator stake:

| Tier | Entry path | Stake requirement | When opened |
|------|-----------|-------------------|-------------|
| **Cohort** (current) | Manual TASK-185 onboarding RFP | ADR-013 minimums (genesis: 1 venom; cohort cap 50) | now |
| **Open-application** | On-chain `ValidatorRegister` tx + governance ratification within 1 epoch | medium tier — see D3 | when `permissionless_enabled` flag flipped (Step 1 of D5) |
| **Permissionless** | On-chain `ValidatorRegister` tx, no governance ratification | medium tier — see D3 | when D5 Step 3 triggers |

The cohort tier never closes — even at full permissionless, governance retains the ability to cohort-onboard a strategic operator (e.g. a sovereign-grade validator joining for compliance reasons). The cohort tier is a privilege of governance, not a default operator path.

#### D2. The `permissionless_enabled` flag

A new on-chain governance parameter `permissionless_enabled: bool`, default `false` at genesis. Governance proposals can set it via the existing `ProposalEffect::ParameterUpdate` path (ADR-022 fee-model precedent). When `true`:

- `ValidatorRegister` tx admitted at mempool entry without governance ratification;
- Activation still subject to ADR-042 stake-weighted churn limits (one new validator per epoch under default churn config) — permissionless entry does NOT bypass the churn brake;
- `ValidatorExit` tx behaviour unchanged.

When `false` (default):
- `ValidatorRegister` tx admitted but enters `Pending` state until a governance proposal explicitly promotes the entry;
- This is the cohort tier — operator runs the runbook, governance ratifies.

The flag is governance-mutable in both directions. If permissionless surfaces Sybil pathology, governance can flip back to false at any quarterly vote; existing permissionless validators stay active (no retroactive slashing) but new entries gate on cohort path until governance re-opens.

#### D3. Stake floor — three scenarios scored

The minimum self-bond for non-cohort entry is the dominant anti-Sybil knob. Three candidate floors, scored against the economic-security model:

| Tier | Self-bond floor | Cost-to-attack at 50% stake | Validator yield at floor | Sybil resistance |
|------|----------------|------------------------------|--------------------------|------------------|
| Low | 1k venom | weak (matches genesis 1-venom min) | high APR (subsidy weighted to small stakes) | weak |
| **Medium** | 10k venom | moderate | balanced APR | moderate-strong |
| High | 100k venom | strong | low APR (effectively excludes small operators) | strong but exclusive |

**Selected:** medium (10k venom). Rationale:
- Genesis 1-venom minimum (ADR-013) is below the operational cost of running a validator over a year (estimated 4-6k venom in opportunity cost vs the inflation curve), so 1k offers no meaningful Sybil resistance.
- 100k venom excludes solo operators and tilts the cohort toward whales — defeats the diversity-target framework (`docs/long-horizon-roadmap.md` §5).
- 10k sits in the band where the bond is meaningful (≥ 1 year of running cost) without excluding the solo-operator class the project explicitly recruits via TASK-185.

Stake floor is a governance parameter, not a hard constant. Initial proposal at 10k venom; reviewable per quarter against TASK-118 fee-revenue trajectory + cohort-recruitment volume.

#### D4. Anti-Sybil mechanics

Three orthogonal layers, each catching a different Sybil class:

1. **Stake-floor** (D3) — economic gate. Catches "spin up 1000 validators at 1 venom each" attacks. Already governed.

2. **Proof-of-uniqueness via attestation hash** — operational gate. Each validator at registration includes an `attestation_hash: [u8; 32]` field bound to a tax-ID-bound off-chain attestation (an entity registration hash from a recognised jurisdiction; the chain stores ONLY the hash, never the underlying KYC data). The hash is per-entity, not per-validator: an entity running 3 validators publishes 3 different validator records all with the same `attestation_hash`. The slashing-evidence-registry treats co-attestation-hash validators as one entity for diversity-target accounting and for the per-entity stake cap (D5 below).

   **Critically not full KYC.** The chain never holds, processes, or routes KYC data. The `attestation_hash` is a binding to an off-chain attestation that the operator, *if subpoenaed*, can produce; absent subpoena the attestation is irrelevant. ADR-066 codifies this as the chain's anti-Sybil signal of last resort, not as a compliance regime.

   The attestation-hash registry is opt-in for cohort tier (genesis validators have it absent — `attestation_hash: None`) and required for permissionless tier (registration without `attestation_hash` is rejected when `permissionless_enabled = true`).

3. **ASN + /24 diversity** — network gate. ADR-041 already pins `max_peers_per_asn = 3` at the libp2p layer. ADR-066 extends this to the validator-record layer: the active set MUST NOT have > N validators from any single ASN (initial N=10, governance-mutable). Validators violating this cap during epoch transition are denied promotion to Active; the queue keeps them Pending until either a slot opens or governance reviews.

#### D5. Phased opening

Three governance-controlled steps:

**Step 1 — Open-application (cohort + governance review).** Year 1 post-launch. `permissionless_enabled = false`; new validators register on-chain but governance reviews the registration within 1 epoch. The review checks (a) attestation_hash uniqueness, (b) stake floor, (c) ASN diversity, (d) slashing history (any prior Banned status from another network is grounds for rejection). 25% of new active-set slots filled this way; 75% remain cohort-onboarded.

**Step 2 — Open-application majority.** Year 1 → Year 1.5. Same gates as Step 1, but 50% of slots filled via open-application.

**Step 3 — Permissionless.** Year 1.5 → Year 2. `permissionless_enabled = true` flipped via governance. Open-application becomes the default path; cohort tier remains as a governance privilege.

Each step opens via a governance proposal that cites this ADR + the cohort-metrics evidence (TASK-227 quarterly diversity reports + TASK-118 fee-revenue trajectory + zero unplanned halts during prior step's window). Governance can pause / reverse at any step.

Total timeline: launch (2026-04-25) → Step 1 (≤2027-04-25) → Step 2 (≤2027-10-25) → Step 3 (≤2028-04-25). The 18-month commitment is from launch to Step 3; the per-step gating is what enforces the discipline.

#### D6. Slashing-evidence-registry window extension

Closed-cohort assumes a knowable validator set; permissionless requires extending the slashing-evidence window because:

1. A validator that exits, gets re-registered (possibly under a different operator), and equivocates against its old self while still in the unbonding period creates an evidence-tracking gap if the registry only tracks Active validators.
2. Cross-operator equivocation (one operator running two validators with different `consensus_pk` but same `attestation_hash`) needs slashing-evidence at the entity level, not just per-validator.

ADR-066 extends ADR-050's evidence registry:
- Slashing-evidence retention extended from "1 unbonding period after Active" to "2 unbonding periods after Active OR until governance vote terminates the entity attestation_hash binding".
- Per-entity stake cap: an `attestation_hash` cannot have aggregate self-bond > N% of total stake (initial N=20, governance-mutable). Catches "one entity running 30% of validators under different addresses".

Both extensions ride P-COMPAT-001 §2 — schema bump on validator-record (additive `attestation_hash: Option<[u8;32]>` field) + slashing-evidence registry retention parameter, with dual-path decoder for the v1 → v2 transition.

### Alternatives considered

- **Open permissionless on launch.** Rejected. Anti-Sybil mechanics need real cohort data to calibrate; opening before D6 slashing-evidence extension is unsafe.
- **Stay closed forever (extend ADR-013 caps to 100/200/500).** Rejected. Defeats `docs/long-horizon-roadmap.md` §5 diversity-target arc; permissionless is the long-horizon commitment.
- **No stake floor — operator runbook compliance is the gate.** Rejected. Operator-side enforcement is bypassable by an attacker who runs a non-runbook-compliant validator. Stake floor is the only economically-binding gate.
- **Full KYC at registration.** Rejected. Compliance scope creep + privacy regression; the `attestation_hash` model is the minimum viable Sybil signal that does not require the chain to hold KYC data.
- **Per-validator slashing only, no per-entity cap.** Rejected. An entity running 30% of stake under different validators captures 30% of consensus weight while only risking a single validator's slashing — economically asymmetric, defeats stake-as-deterrent.
- **Open + close via emergency governance.** Considered, kept as the safety net. The on-chain `permissionless_enabled` flag is the formal pause-button; emergency governance is the runbook fallback if the flag's transition takes too long.
- **Make the 18-month timeline a hard chain-level commitment.** Rejected. The 18-month *target* is in this ADR; the actual transition is governance-paced. Hard-coding the schedule on-chain creates pressure to open even if metrics are bad.

### Consequences

**For operators.** Three-tier model gives a clear forecast: cohort-onboarded operators are first-class today; open-application opens within Year 1; permissionless within Year 1.5. The medium 10k venom self-bond floor is reachable for solo operators (≈ 1 year of pre-launch tokenomics yield).

**For governance.** New on-chain parameter `permissionless_enabled` + `stake_floor_venom` + `max_validators_per_asn` + `max_stake_per_attestation_hash`. Each is governance-mutable via existing parameter-update path; this ADR pre-allocates them so the schema bump rides P-COMPAT-001 §2 cleanly.

**For the slashing-evidence registry.** Retention window extension + per-entity stake cap. The on-disk size of the registry grows by ~2× under the extended window; KNOWN-ISSUES update tracks this.

**For the attestation_hash model.** The chain holds 32-byte hashes per validator (40 KB at 1024 validators — negligible). The off-chain attestation is the operator's responsibility; we publish guidance under `docs/permissionless-transition.md` (forthcoming) on what attestations satisfy the discipline.

**For ADR-013.** This ADR supersedes ADR-013's hard caps. ADR-013 stays as the historical record; this ADR governs from Step 1 opening forward.

**For TASK-227 diversity reporting.** The `attestation_hash` model gives the diversity-targets framework a per-entity grouping it currently lacks. TASK-227's Y1+ reports use it; the Y0 baseline pre-dates the model.

**For P-COMPAT-001 lens.** Engaged on §2(b) — schema change to validator-record (additive `attestation_hash` + new slashing parameters). Activation height + dual-path decoder + cold-sync replay test required at Step 1 opening.

### Tracking task

- TASK-224 — this ADR. Commit will be appended on land.
- TASK-223 — dynamic keystore (operationally essential for permissionless tier — open-application validators need the keystore layer to work)
- TASK-227 — diversity reporting (the Y1+ reports use this ADR's `attestation_hash` model)
- ADR-065 / TASK-228 — pairs with the scale-up plan (Step 1 opening of this ADR pairs with Step 1 of ADR-065)

### Related

- ADR-013 (current closed-cohort gates this ADR supersedes from Step 1 forward)
- ADR-022 (tokenomics — stake floor sits inside this ADR's economic envelope)
- ADR-042 (ASN diversity substrate this ADR extends to validator-record level)
- ADR-046 (consensus-key rotation framework — operationally needed for permissionless)
- ADR-050 (slashing-evidence registry this ADR extends)
- ADR-053 (`viper-pq-1` genesis — schema bumps ride this lineage)
- ADR-065 (scale-up plan — paired Step 1/2/3 sequencing)
- `docs/long-horizon-roadmap.md` §5 (diversity-targets context)
- `docs/phase-9-followup-plan.md` (TASK-224 detail)
- TASK-185 (cohort-onboarding workflow — the cohort tier this ADR formalises)


---


---

## ADR-067 - FN-DSA Evaluation Post-FIPS-206-Final + AlgId 0x0010 Reservation

**Status**: Accepted 2026-05-06 (reservation + criteria); spike + benchmark deferred to Q4 2027 (FIPS 206 finalisation gate).
**Depends on:** ADR-043 (second PQ algorithm landing — SLH-DSA-SHAKE-192s), ADR-044 (TLV envelope + Algorithm Registry — the wiring FN-DSA rides), ADR-053 §T1.5 (genesis algorithm registry), ADR-063 (NIST on-ramp 3rd algorithm — separate track; this ADR is the FIPS-track parallel).
**Governs:** the reservation of AlgId `0x0010` for FN-DSA-padded-512 ahead of FIPS 206 finalisation, the inclusion criteria for promoting `0x0010` to `Active` lifecycle once the spike + benchmark complete in Q4 2027, and the explicit pre-final adoption exclusion driven by the deterministic-FP cross-CPU portability risk.

### Context

Viper Chain currently carries two PQ signature algorithms in the on-chain Algorithm Registry: ML-DSA-65 (genesis default, AlgId `0x0001`) per ADR-043 and SLH-DSA-SHAKE-192s (Phase 8 M3 closure, AlgId `0x0021`) per ADR-043 + commit `c4e3c73`. Both are large by traditional-cryptography standards: ML-DSA-65 sigs are ~3.3 KB, SLH-DSA-SHAKE-192s sigs are ~16 KB. The signature footprint is a load-bearing constraint at scale (KNOWN-ISSUES R-10) and TASK-228 §3 (committee 1024+) gates on STARK aggregation maturity precisely because the per-block sig footprint is otherwise unsustainable.

FN-DSA-padded-512 (the FIPS 206 candidate, derived from Falcon) is bandwidth-optimised relative to ML-DSA: signatures are ~666 B and public keys are ~897 B at the FIPS L1 security level. Roughly 5× smaller than ML-DSA-65 sigs, 3-5× smaller than ML-DSA-65 public keys. For high-frequency transaction classes (token transfers, retail-class ops) this is a meaningful per-tx storage win.

But FN-DSA carries a Falcon-inherited risk class: Falcon signing relies on FFT operations that depend on exact floating-point arithmetic (specifically, Tonelli-Shanks-style operations in the signing inner loop). Cross-CPU-architecture FP determinism is *not* portable — x86, ARM, and RISC-V differ in subnormal handling, rounding mode default, and FMA fusion. A signature produced on one architecture and verified on another can fail to verify even when the implementations are textbook-correct, because the signing trajectory diverges at the FP level.

For a chain with heterogeneous validator hardware (the cohort under TASK-185 already mixes x86 and ARM operators), this means pre-FIPS adoption could ship signatures that some validators reject as malformed — a chain-halt class bug. FIPS 206 finalisation is expected to pin the determinism contract (likely mandating IEEE-754 strict mode + specific FP intrinsic sequences); pre-final, the contract is not stable.

### Decision

#### D1. Reserve AlgId 0x0010 *now* via governance proposal

The Algorithm Registry's `0x0010..0x001F` range is reserved for FN-DSA family additions per ADR-053 §T1.5 (genesis algorithm-registry seed). This ADR commits to a specific governance proposal:

```text
ProposalEffect::ReserveAlgId {
  alg_id: 0x0010,
  alg_name: "FN-DSA-padded-512",
  initial_lifecycle: Reserved,
  spec_ref: "FIPS 206 (draft)",
  output_size_bytes: 666,
  pk_size_bytes: 897,
}
```

Reserving in `Reserved` lifecycle (not `Active`, not `Discouraged`) means:
- Validators cannot register a `consensus_alg_id = 0x0010` key (mempool admission rejects).
- Transactions cannot include `sig_alg_id = 0x0010` envelopes (the TLV envelope decoder rejects unknown lifecycles per ADR-044).
- The slot is owned by the chain's governance — any future un-reserved use of `0x0010` would conflict and is rejected at registry-merge time.

Reserving now is low-cost: one governance proposal, no code change, no schema bump (ADR-053 §T1.5 already pre-allocated the range). The benefit is locking the slot identifier so all forward references (SDK, CLI, audit reports) use the same number when FN-DSA promotes to `Active` in Q4 2027.

#### D2. Pre-final adoption is excluded by policy

This ADR commits Viper Chain to *not* promote `0x0010` from `Reserved` to any active lifecycle until FIPS 206 finalisation. Specifically:

- `Reserved` → `Active` only after a NIST-final FIPS 206 publication;
- `Reserved` → `Discouraged` is permitted (e.g. if NIST withdraws FN-DSA from the standard track);
- `Reserved` → `Banned` is permitted (e.g. if a pre-final cryptanalytic break makes the algorithm unsafe);
- `Reserved` → `Active` skipping the post-FIPS-final gate is **explicitly forbidden** by this ADR.

The exclusion is a chain-level policy commitment, not a cryptographic invariant. Governance can in principle override an ADR; this ADR is the formal record that doing so before FIPS 206 finalisation contradicts the project's audit-readiness discipline.

#### D3. Inclusion criteria for the post-FIPS-final spike + benchmark

When FIPS 206 finalises (current NIST timeline projects Q4 2026 → Q4 2027 — the spike fires when the standard publishes, not on a fixed date), the spike must demonstrate the following before `0x0010` promotes to `Active`:

| Criterion | Threshold | Rationale |
|-----------|-----------|-----------|
| FIPS 206 final standard published | hard gate | the deterministic-FP contract must be pinned upstream |
| ≥ 1 audited Rust implementation | hard gate | matches ADR-043 / ADR-044 expectation for any Active-lifecycle algorithm |
| Sigverify cost ≤ 2× ML-DSA-65 verify on reference HW | soft gate | exceeding this means the per-tx fee class would need a separate `sigverify_fee_v_X` parameter, which is a P-COMPAT-001 §2(c) parameter-update — feasible but adds scope |
| Cross-CPU-arch interop verified | hard gate | sign on x86, verify on ARM, sign on ARM, verify on x86 — both directions must succeed on a 1k-vector test corpus. If any vector fails, the determinism contract is not strict enough and FN-DSA stays Reserved |
| Public key size ≤ 1.5 KB | soft gate | validator-record budget — current ML-DSA-65 pk at 1.95 KB sets the precedent ceiling; FN-DSA at 0.9 KB is well inside |
| Signature size ≤ 1 KB | soft gate | bandwidth-optimisation commitment — exceeding 1 KB defeats the purpose of selecting FN-DSA over ML-DSA |

Soft gates can be missed with documented justification + governance vote; hard gates are non-negotiable.

#### D4. The deterministic-FP risk in detail

Falcon (and by inheritance FN-DSA-padded-512 at the inner-loop level) signs by sampling discrete-Gaussian-distributed lattice vectors, which involves exact-arithmetic FFT-style computations over `F_q` for `q = 12289`. The reference implementation uses 64-bit floating-point as the high-precision arithmetic vehicle, with explicit rounding mode + subnormal handling.

The portability risk surfaces in three places:

1. **Subnormal handling.** x86 and ARM differ on flush-to-zero for subnormals. A signing operation that produces a subnormal intermediate may take a different rounding path between architectures, yielding a different signature for the same key + message.
2. **FMA fusion.** `a * b + c` may compile to a fused `vfmadd` on x86-AVX2 / ARM NEON or to discrete `mul + add` on RISC-V. The two paths differ in the last-bit precision, which cascades through the FFT.
3. **Default rounding mode.** Some embedded ARM cores default to round-to-nearest-even but have alternate modes that switch the cascade behaviour — a chain-halt vector if a validator misconfigures its CPU.

The **mitigation** baked into FIPS 206 (per current draft) is mandating IEEE-754 strict mode + specific FP intrinsic sequences. The spike under D3 must verify the mitigation is sufficient on x86 + ARM + RISC-V (the three architectures the cohort plausibly mixes); failure to verify across all three is grounds for keeping FN-DSA in `Reserved` indefinitely.

The **alternative cryptographic mitigation** (post-FIPS-final) is the recently-explored "exact-integer" Falcon variants that replace FFT with NTT — these eliminate the FP path entirely. If the FIPS 206 standard mandates the integer variant, the cross-arch risk evaporates; if it leaves the FP path as the reference, the spike's cross-arch test is the gate.

#### D5. The Q4 2027 spike is operator-paced, not calendar-paced

The "Q4 2027" target is a NIST-timeline placeholder, not a Viper commitment. The spike fires when:
- FIPS 206 publishes (standard available + reviewed by ≥ 1 external auditor outside NIST), AND
- An audited Rust implementation exists (the project monitors `pq-rust` ecosystem + the `fn-dsa-rs` crate-name reservation).

If NIST slips the FIPS 206 publication to Q1 2028, the spike slips with it. ADR-067's reservation under D1 is the Y1 commitment; the Y4-Y6 promotion is upstream-paced. `docs/phase-9-followup-plan.md` (TASK-226 detail) tracks the trigger conditions.

### Alternatives considered

- **Reserve AlgId 0x0010 only when FN-DSA finalises.** Rejected. Reserving now costs one governance proposal; reserving later means every forward reference (SDK, CLI, RUNBOOK) uses a placeholder name until the slot lands, creating doc drift.
- **Pre-final adoption with operator-side opt-in flag.** Rejected. The FP determinism risk is not opt-in-able; one validator on an under-spec'd CPU can fork the chain regardless of every other operator's flag.
- **Skip FN-DSA entirely; rely on ADR-063 NIST on-ramp 3rd algorithm.** Considered. The on-ramp candidates (MAYO / CROSS / FAEST / SQIsign) are tracked separately under ADR-063 — they are *foundational diversity* (non-lattice / non-hash), where FN-DSA is *bandwidth-optimisation* (lattice family). The two slots cover orthogonal needs; both are kept.
- **Adopt the Falcon-1024 variant directly (not FN-DSA-padded-512).** Rejected. Falcon-1024 has the same FP determinism risk + is unstandardised. FN-DSA-padded-512 is the FIPS-tracked descendant; adoption gates on the FIPS publication.
- **Use exact-integer Falcon (NTT-based) directly.** Considered, premature. The integer variant is research-stage as of 2026-05; FIPS 206 may or may not standardise it. Wait for the standard to pin the choice.

### Consequences

**For the Algorithm Registry.** AlgId `0x0010` becomes non-assignable until FIPS 206 finalises. The genesis algorithm-registry seed (ADR-053 §T1.5) is unchanged; this ADR is the operational commitment that the slot stays Reserved through Q4 2027 minimum.

**For SDK + CLI doc references.** All forward references to FN-DSA in user-facing material can use the canonical AlgId number `0x0010` from this ADR forward. Audit reports that mention FN-DSA cite this ADR.

**For the spike workstream.** TASK-226 detail in `docs/phase-9-followup-plan.md` is the operator-side artifact; the spike fires when triggers met and produces `reports/fn-dsa-spike-<UTC>.md` plus the governance promotion proposal.

**For cross-CPU-arch operators.** Cohort guidance under `docs/validator-onboarding.md` will (post-spike) include the cross-arch test vectors — every operator runs them at deployment time before joining the active set. Failure to pass = stay on ML-DSA-65 / SLH-DSA-SHAKE-192s, do not register an FN-DSA key.

**For ADR-063 (NIST on-ramp).** Orthogonal — that slot covers foundational diversity (non-lattice). FN-DSA addition does not satisfy ADR-063's selection criteria (still lattice family); the two ADRs live in parallel.

**For P-COMPAT-001 lens.** Non-engaged at reservation time (governance-mutable parameter, no schema bump). Engaged at promotion time — adding FN-DSA verify dispatch is a schema-touching change to `pqc-crypto::verify`; activation height + dual-path decoder + cold-sync replay test required at promotion.

### Tracking task

- TASK-226 — this ADR + the deferred Q4 2027 spike. Commit will be appended on land.
- ADR-063 — parallel NIST on-ramp track (separate workstream, foundational diversity)
- ADR-053 §T1.5 — genesis algorithm-registry seed (the schema this ADR rides on)

### Related

- ADR-043 (second PQ algorithm — the wiring precedent FN-DSA inherits)
- ADR-044 (TLV envelope + Algorithm Registry — the on-chain governance vehicle)
- ADR-053 §T1.5 (genesis algorithm-registry seed including the `0x0010..0x001F` reservation range)
- ADR-063 (NIST on-ramp 3rd algorithm — orthogonal track)
- KNOWN-ISSUES R-10 (PQ signature footprint cost — FN-DSA's bandwidth-optimisation contributes to mitigation)
- `docs/long-horizon-roadmap.md` §3 (NIST on-ramp context — this ADR is the FIPS-track sibling)
- `docs/phase-9-followup-plan.md` (TASK-226 detail + trigger conditions for the deferred spike)
- `crates/pqc-crypto/src/alg.rs` (`AlgId` enum where `0x0010` is reserved)


---


## ADR-068 - The Verification Path Must Not Link The Node Core (pqc-light-client, pqc-keystore)

**Status**: Accepted 2026-08-24.
**Depends on:** ADR-053 (`SPEC-LIGHT-CLIENT-001` sync-committee scaffolding), SPEC-WALLET-001 (keystore format).
**Governs:** which crates an external verifier or an operator-side tool may depend on, and the rule that keeps that set free of consensus/state/p2p/node code.

### Context

The public-release preparation (2026-08-24) classifies the workspace into a permissively licensed *verification path* (`pqc-crypto`, `pqc-types`, `pqc-tx`, `pqc-tsa`, specs, SDKs) and a source-available *node core* (`pqc-consensus`, `pqc-state`, `pqc-mempool`, `pqc-p2p`, `pqc-hsm`, `pqcd`). The promise behind the verification path is the one the project sells: a 2046 verifier of a 2026 attestation must be buildable without the node. Two facts in the tree contradicted it:

1. The light client (`SPEC-LIGHT-CLIENT-001`: sync-committee selection, compact headers, attestation encode/decode) was a module *inside* `pqc-consensus`. Anyone wanting the verifier had to depend on the whole BFT engine — and inherit its licence.
2. `viper-archival-sidecar` needed exactly one type from the node, `pqcd::wallet::Keystore` (3 call sites), and paid for it by linking `pqcd` in full, including the `token_economics` feature forward.

`cargo metadata` confirmed the rest of the path was already clean: `pqc-crypto` has no internal dependency, `pqc-types` depends on `pqc-crypto`, `pqc-tx` on both.

### Decision

- **D1.** The light client becomes its own crate, `crates/pqc-light-client`, depending on `pqc-crypto` only. `pqc-consensus` re-exports it (`pub use pqc_light_client as light_client;`) so every existing `pqc_consensus::light_client::…` path keeps resolving; `pqcd` and `pqc-p2p` are unchanged.
- **D2.** The wallet keystore becomes `crates/pqc-keystore`, depending on `pqc-crypto`, `pqc-types`, `pqc-tx`. `pqcd` re-exports it as `pqcd::wallet`; `viper-archival-sidecar` depends on `pqc-keystore` directly and no longer on `pqcd`. The sidecar's `token_economics` feature no longer forwards to `pqcd`.
- **D3. Boundary rule.** No crate in the set {`pqc-crypto`, `pqc-types`, `pqc-tx`, `pqc-tsa`, `pqc-light-client`, `pqc-keystore`} may depend, directly or transitively, on {`pqc-consensus`, `pqc-state`, `pqc-mempool`, `pqc-p2p`, `pqc-hsm`, `pqcd`, `viper-archival-sidecar`, `viper-notary`}. A licence-boundary check over `cargo metadata` enforces this in CI (public-release Phase 7); until then the rule is this ADR.

### Consequences

- Verified 2026-08-24: `cargo check --workspace --all-targets` clean; `cargo test -p pqc-light-client` 11/11, `cargo test -p pqc-keystore` 7/7; internal dependency sets exactly as stated in D1/D2.
- Operator-facing behaviour: none. No `NodeConfig` field, endpoint, env var or systemd unit changed → no Ansible/chart update needed.
- Wire/state: none. Encodings and hashing domains are untouched (module moved, code unchanged).
- Alternatives rejected: (a) relaxing the licence of `pqc-consensus` to cover the verifier — wrong direction, it would give away the consensus engine to fix a packaging defect; (b) duplicating `Keystore` inside the sidecar — two copies of an audited crypto path.

## ADR-069 - Node Roles Live In The Binary (validator / sentry / full / rpc / archive / bootnode)
**Status**: Accepted 2026-08-24.
**Depends on:** ADR-041 (libp2p network roles), TASK-233 (`pqcd ceremony`), ADR-068 (public-release crate boundary).
**Governs:** the `devnet.role` vocabulary of `node.json`, what each role is allowed and required to do, and how the Helm chart and the ceremony map onto it.

### Context
The Helm chart has modelled six roles since 0.2.0 (`validator`, `sentry`, `full`, `rpc`, `archive`, `bootnode`): one StatefulSet each, with its own network policy, storage and service profile. The binary knew three (`single_node`, `producer`, `follower`), so the ceremony translated by hand — `validator → producer`, `sentry → follower`, `full → follower` — and the chart's `VIPER_ROLE` environment variable was never read. The binary could not tell a sentry from an archive node: the snapshot-prune guard protected only validators, an archive node was "a follower with a sidecar", the API exposure defaults were the same for a validator and an RPC node, and `configs/` still described a devnet vocabulary the chart does not use. On the `viper-lab-1` deployment this showed up as three followers stuck at height 0: their bootstrap multiaddr was baked into `node.json` by a ceremony run under another release name, and nothing in the binary or the chart could notice.

### Decision
1. `devnet.role` becomes `NodeRole` with the chart's vocabulary plus `single_node`: `validator`, `sentry`, `full`, `rpc`, `archive`, `bootnode`, `single_node`. `producer` and `follower` remain accepted as serde aliases of `validator` and `full` so every existing `node.json` still loads; the ceremony, the examples and the docs emit only the new names.
2. Behaviour is derived from predicates on the enum, not from `matches!` at call sites:
   - `is_validator()` — `validator`, `single_node`: runs the consensus loop, needs signing material and a static validator set (unless `single_node`).
   - `keeps_full_history()` — `validator`, `single_node`, `archive`: `snapshot-prune` refuses without `--force`. Archive nodes are now protected by the binary, not only by an Ansible variable.
   - `p2p_role()` — `validator`/`single_node` → libp2p `Validator` (listens on `validator_listen`); `sentry` → `ValidatorFullnode` (`vfn_listen`); `full`, `rpc`, `archive`, `bootnode` → `PublicFullnode` (`public_listen`).
   - `serves_public_tx_submission()` default — false for `validator`, `bootnode`, `single_node`; true otherwise. A validator configured with `api.public_tx_submission = true`, or a bootnode with a wildcard API bind, is reported by the startup config lint.
3. `VIPER_NODE_ID` overrides `node_id` when `devnet-serve` loads its config. The chart sets it from the pod name (downward API), so two replicas of the same role no longer share one libp2p/KEM identity. `node_id` is not a consensus identity (validators are identified by address); it only seeds the transport identities and the logs.
4. The ceremony emits one `node.json` per chart role (six), with the role-correct libp2p listen field and bootstrap topology: sentries dial the validator; full, rpc, archive and bootnode dial the sentries. It records `_release_name` and `_namespace` in the values file, and the chart refuses to render when they differ from `.Release.Name` / `.Release.Namespace` — the exact mistake behind the `viper-lab-1` cold-start.
5. `configs/roles/<role>.json` are the reference examples for each role; `configs/single-node.json` stays the local quick-start.

### Consequences
- One vocabulary end to end: `node.json`, `pqcd ceremony`, the chart, the docs. The chart's `VIPER_ROLE` becomes informational.
- Old configs keep working (aliases); the alias names are deprecated and will be removed at the first public minor release after `viper-testnet-2` genesis.
- Rendering `node.json` inside the chart from structured values (so the release name is never baked in) is the natural next step and is tracked as TASK-242; this ADR only makes the mismatch impossible to miss.
- The validator on `viper-lab-1` is OOM-killed periodically (1 GiB limit, RSS growing with height): unrelated to roles, tracked as TASK-241.
- The Ansible path (`viper_role` in inventories, `when: viper_role == 'producer'` in playbooks) still speaks the old vocabulary; its `node.json` keeps loading through the aliases. Moving it to the new names is TASK-243, together with the scripts and docs that describe the local devnet as producer/followers (Phase 6 rewrite).

## ADR-070 - Three Licences, Chosen By What A File Is For
**Status**: Accepted 2026-08-24.
**Depends on:** ADR-068 (verification path does not link the node core), the private release plan (the approved PP / PB / PRIV classification).
**Governs:** which licence applies to which path, the Business Source License parameters, and how the mapping is kept true.

### Context
The repository had no LICENSE file; `[workspace.package].license = "Apache-2.0"` was the only statement, and it covered the node, the notary product and the vendored libp2p patches alike. The public release splits the tree by purpose: what an external party needs to *verify* the chain must be usable without asking (Apache-2.0); the node that *produces* the chain is the part with commercial value and gets a source-available licence that converts to open source on a schedule (BUSL-1.1); the specifications are prose meant to be quoted and reused (CC BY 4.0); the notary product stays private. Vendored code keeps the licence it came with.

### Decision
1. **Apache-2.0**: `pqc-crypto`, `pqc-types`, `pqc-tx`, `pqc-tsa`, `pqc-light-client`, `pqc-keystore`, `sdk/*`, `tests/acvp`. The boundary is ADR-068's: nothing here may depend on a BUSL crate.
2. **BUSL-1.1**: `pqc-consensus`, `pqc-state`, `pqc-mempool`, `pqc-p2p`, `pqc-hsm`, `pqcd`, `viper-archival-sidecar`, `fuzz/`, `charts/`, `deploy/`, `docker/`, `scripts/`, build files. Parameters: Licensor Alberto Galassi; Additional Use Grant = production use to operate nodes of a Viper PQ Chain network whose genesis the Licensor publishes, and to build interoperating software — not to offer the work as a hosted/managed service, not to run another network; Change Date = four years from each version's first public release (2030-09-30 for the first); Change License = Apache-2.0.
3. **CC BY 4.0**: `specs/`, `docs/`, `WHITEPAPER.md` and the root documents.
4. **Proprietary** (`LicenseRef-Proprietary`): `notary/`, private repository only.
5. **Vendored** (`vendor/`): upstream licences reproduced next to the code (MIT for the libp2p patches, Apache-2.0 OR MIT for slh-dsa), attributed in `NOTICE`; the sources are not touched.
6. Mechanics: every Rust source outside `vendor/` starts with `// SPDX-License-Identifier: <id>`; every crate declares `license` in `Cargo.toml`; `REUSE.toml` covers files without a header; `LICENSES/` holds the verbatim texts (BUSL with its parameters filled in); `LICENSE.md` is the human map. `scripts/check-licenses.sh` fails when any of these drift and joins the CI gate in Phase 7.

### Consequences
- The verification path is unencumbered: wallets, explorers and auditors can depend on it under Apache-2.0 without touching BUSL code.
- BUSL-1.1 is not an OSI licence; the repository must not describe the node as "open source" until the Change Date. The Additional Use Grant is what lets anyone run a validator, sentry or full node in production today.
- The BUSL parameters are a business decision recorded here; changing them for a later version is a new ADR, and cannot retroactively change versions already released.
- Contributions follow the licence of the file they touch (CONTRIBUTING.md, Phase 6).

## ADR-071 - One Private Repository, One Exported Public Repository, CI On GitHub
**Status**: Accepted 2026-08-24.
**Depends on:** ADR-068, ADR-069, ADR-070; the private release plan for the classification.
**Governs:** how the public repository is produced from the private one, what must never cross, and where the continuous integration and the release artefacts live.

### Context
The private repository holds everything: the chain, the notary product, the deployment topology with its hosts, the reports, the business material and four months of history whose commit trailers and vendored `node_modules` are not fit for publication. The public repository must be clean on day one, must never leak a host or a credential, and must run its own CI without depending on the private infrastructure.

### Decision
1. **The private repository stays canonical.** The public repository `v1p3r4llbl4ck-86/viper-pq-chain` is an *export*, not a fork: `release/export-public.sh` takes `HEAD`, removes every path in `release/EXCLUDE.txt` (notary, internal docs and plans, reports, host-specific playbooks and scripts, the release tooling itself, the GitLab CI), drops the notary from the workspace, writes a public CHANGELOG (first public release plus the release-preparation section) and a public TASKS (open items), regenerates the lockfile, and creates a fresh repository with a single commit authored by Alberto Galassi.
2. **The export refuses to produce a tree that carries** a real IP address, one of the author's host names, the private repository's URLs or names, a private path, or any attribution to development tooling (`release/verify-public.py`), and it re-runs the licence and link guards, `cargo metadata`, `helm lint` and gitleaks on the exported tree. A failure is fixed at the source, never in the export.
3. **CI on GitHub Actions**, on GitHub-hosted runners by default (free for a public repository): fmt, clippy `-D warnings`, licence and link guards, `cargo deny`, the full test suite with all features and one test thread, `pqc-hsm` against SoftHSM, chart lint plus the render guard. A self-hosted runner on the author's host is an opt-in through the `CI_RUNS_ON` repository variable, installed with `CARGO_BUILD_JOBS=3` and one job at a time (the host went down under an 8-job build).
4. **Releases are tags.** `vX.Y.Z` builds the public-chain binaries (`--no-default-features --features hybrid-kem-tls`: no token economics, hybrid post-quantum TLS on) for Linux x86_64, pushes `pqcd` and `viper-archival-sidecar` images to `ghcr.io` signed with cosign (keyless), attaches a CycloneDX SBOM and checksums, and opens the GitHub Release.
5. The chart ships with the notary **off**; the genesis artefact of `viper-testnet-2` is published under `genesis/` at the ceremony.

### Consequences
- Public history is linear and starts at the first public release; later changes are exported on top of the public `main`, never force-pushed.
- Anything the verifier flags is a real leak candidate; the exclusion list grows, the source is corrected, the export is re-run.
- The GitLab pipeline keeps serving the private repository; the two CIs run the same gates (`make ci`).
