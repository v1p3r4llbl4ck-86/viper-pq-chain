# AGENTS.md

Project conventions and rules for Viper PQ Chain development.

## Authorship and Attribution

**Sole author**: Galassi Alberto.

All code, documentation, specifications, and design decisions in this repository are authored by Galassi Alberto. Future contributions, commits, and documentation entries must attribute the work exclusively to Galassi Alberto. No third-party co-authorship (AI tooling, contractors, or collaborators) is to be recorded in commit messages, file headers, documentation, or any artifact of this repository.

Commit messages carry the author's name only; no `Co-Authored-By:` trailers.

## Repository Status

**No live public network.** The public chain `viper-testnet-1` is created at a genesis ceremony
after the first public release of this repository; until then every claim in the documents is
about the design and the code, not about a running network. Three private chains preceded it —
`viper-pq-1` (2026-04-25 → 2026-05-12, archived at height 33,976), `viper-research-1`
(2026-05-12 → 2026-08, tokenless) and an internal single-validator lab — all retired. Their
records stay in the private repository; what they taught is in `KNOWN-ISSUES.md` and `ROADMAP.md`.
Never target a retired chain operationally.

The architecture is ADR-053 Tier 1+2+3 (BlockHeader v1, ForkDigest signing-domain prefix,
chain-id-bound address derivation, hash registry, multi-dimensional fee market, binary Merkle
state tree, sync-committee light client) with the node roles of ADR-069 and the licence map of
ADR-070. Token economics are a reserve behind the dormant `token_economics` feature; the public
chain is built without it.

**Compatibility discipline — Policy P-COMPAT-001 (ADR-052).** From `viper-testnet-1` genesis on,
committed state is a promise to the operators and users who hold it:

- **No chain reset.** Fixing an "invalid" state is done by an explicit, versioned migration with
  an activation height and an ADR — never by wiping and re-launching.
- **Every breaking change** to `state_root`, `BlockHeader` CBOR or consensus material carries an
  ADR, an embedded activation height, dual-path decoder support and a cold-sync replay test.
- **The binary released for chain_id X refuses to start** on on-disk state with chain_id ≠ X.
- **Crypto-agility** (algorithm, hash and auth-template upgrades) rides the on-chain registries
  and `SoftwareUpgrade`, never a reset.

Before genesis these rules are a discipline, not a binding promise: the author may still
re-create the private test deployments. The binding window opens at the first of: the network
is publicly announced and external operators are invited; an external validator produces a
block; anyone outside the author commits or references real state on the chain.

The specs in `specs/` are the protocol contract — code must conform to them. If code reveals an incompatibility with a spec, record it as an ADR or spec amendment; do not silently resolve it in code.

## Mandatory Updates After Every Change

After any code or doc change, before marking a task done — without asking for confirmation:

| What you touched | What to update |
|-----------------|----------------|
| Any change | `CHANGELOG.md` — add an entry under `[Unreleased]` with prefix `Added` / `Changed` / `Fixed` |
| A new or changed crate | `ARCHITECTURE.md` if the crate changes the system layer model |
| An API endpoint | `API.md` |
| A protocol decision or tradeoff | new ADR in `DECISIONS.md` |
| An infrastructure or deployment decision | new ADR in `DECISIONS.md`; update `ARCHITECTURE.md` and `charts/viper-pq-chain/README.md` if the runtime, topology, or automation model changes |
| A new `NodeConfig` field, new API endpoint, new env var, new service, or new systemd unit | check `deploy/ansible/` — update the relevant role template (`node-config.json.j2`, `pqcd.service.j2`, or role `main.yml`) if the change is operator-configurable or affects runtime behaviour; if the Ansible template is already compatible (e.g. serde default handles it), record that no update was needed |
| A completed task | move to `Completed` in `TASKS.md` with date |
| A new spec or spec amendment | reference it in `WHITEPAPER.md` if it affects a section there |

Do not ask "should I update the docs?" — always update them as part of the same task.

## Document Map

| File | Purpose |
|------|---------|
| [README.md](README.md) | Top-level entry point: status, repository map, source-code map |
| [WHITEPAPER.md](WHITEPAPER.md) | Vision, threat model, cryptographic baseline, consensus, fee model, governance (v0.3 framing) |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How changes are made and accepted; licences per path |
| [LICENSE.md](LICENSE.md) | The licence map and the BUSL-1.1 parameters (ADR-070) |
| [ARCHITECTURE.md](ARCHITECTURE.md) | As-built system layers, node roles, data objects, transaction path |
| [DECISIONS.md](DECISIONS.md) | ADR log — accepted, proposed, deferred, rejected decisions |
| [CONVENTIONS.md](CONVENTIONS.md) | Naming rules, documentation rules, commit format, locked implementation stack |
| [API.md](API.md) | External HTTP interfaces (`/v1/...`, `/api/...`) |
| [ROADMAP.md](ROADMAP.md) | Delivery phases and exit criteria |
| [TASKS.md](TASKS.md) | Active backlog and recently-closed tasks |
| [TESTING.md](TESTING.md) | Correctness strategy and load-test baseline |
| [CHANGELOG.md](CHANGELOG.md) | Meaningful repository-level changes |
| [docs/operators/RUNBOOK.md](docs/operators/RUNBOOK.md) | Operator playbook (build, configure, run, join, troubleshoot) |
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure policy, SLA, scope, safe harbour |
| [KNOWN-ISSUES.md](KNOWN-ISSUES.md) | Accepted risks, known gaps before genesis, deferred items |

Frozen historical inputs (audit trail only — superseded by `specs/` and `WHITEPAPER.md`): [`docs/historical/pq_chain_foundation_v2.md`](docs/historical/pq_chain_foundation_v2.md), [`docs/historical/deep-research-report.md`](docs/historical/deep-research-report.md). Index: [`docs/historical/README.md`](docs/historical/README.md).

## Core Thesis (Do Not Change Without Explicit Alignment)

Viper PQ Chain is **post-quantum trust infrastructure** — not a generic L1. Phase 1 wedge: digital vault accounts, attestation anchoring, identity-linked proofs, and policy-driven key management. These anchor decisions are in ADR-001 and ADR-002.

## Naming and Terminology

- Project name: `Viper PQ Chain` (short form: `Viper`; `PQ Chain` acceptable in technical contexts)
- Token: **none**. The reserve design (`token_economics` feature) is compiled out; do not describe it as live and never as an offer
- Node binary stays `pqcd`; Prometheus metrics stay `pqchain_*` (Phase 6 rename)
- Use NIST names: `ML-DSA`, `ML-KEM`, `SLH-DSA`, future `FN-DSA`
- Use `post-quantum-native`, not "quantum-ready" or "quantum-proof"
- Protocol terms: `alg_id`, `key_version`, `KeySet`, `Algorithm Registry`, `validator set`
- Distinguish `Accepted` / `Proposed` / `Deferred` / `Rejected` / `Superseded` / `Reserved` when writing about decisions; specs use `Draft` / `Proposed` / `Accepted` / `Normative` / `Reserved` / `Historical`
- Deployment roles: `validator`, `sentry`, `full`, `rpc`, `archive`, `bootnode`, `single_node` (ADR-069); `proposer` is the consensus role

## Documentation Rules

- Record every material architecture choice in [DECISIONS.md](DECISIONS.md) as a new ADR
- Mark unresolved items as `TBD`, `working assumption`, or `proposed` — never collapse them silently into accepted facts
- Dates must use `YYYY-MM-DD` format
- Roadmap items are phase-based, not version-based
- Update [TASKS.md](TASKS.md) when a foundation item is completed or opened
- Update [CHANGELOG.md](CHANGELOG.md) for meaningful repository-level changes

## Commit Format

Use conventional commit prefixes: `docs:`, `feat:`, `fix:`, `refactor:`, `chore:`

## Phase 4 Rules (Hardening and Audit Readiness)

These rules apply from Phase 4 onward and override any Phase 1–3 leniency where they conflict.

### Security review — mandatory before closing any task that touches a cryptographic path

Before marking a task done, verify:
- no secret material (private keys, KEM seeds, signing seeds) appears in any log output, tracing event, error message, or debug format (`{:?}`)
- error paths in signature verification, key management, and mempool admission do not leak timing information or internal key state beyond what the protocol spec requires
- no `unwrap()` or `expect()` in security-critical paths (`pqc-crypto`, `pqc-state::apply`, `pqcd::devnet` admission pipeline) — use typed errors
- if a new public API endpoint is added, confirm it does not expose validator consensus keys or raw signing material (ADR-014)

### Performance — mandatory for tasks that touch hot paths

Hot paths: mempool admission pipeline, block assembly (`build_next_block`), signature verification (`MlDsaVerifier`), state root computation (`state_root()`).

If a task modifies any hot path:
- run `cargo bench` for the relevant Criterion benchmark before and after the change
- record the before/after numbers in the task completion entry in `TASKS.md`
- if throughput regresses by more than 5%, investigate before closing the task

### Backwards compatibility — mandatory from Phase 4 onward

- **CBOR transaction format** (`SPEC-TX-001`): no field additions, removals, or type changes without a new ADR and an explicit migration path. The format is now treated as externally committed.
- **Account structure** (`SPEC-ACCOUNT-001`): same rule — any change to `Account`, `KeyEntry`, or `AttestationRecord` serialization requires an ADR.
- **State root derivation** (PQC-STATE-ROOT-V2): any change to the leaf hash domain string, sort order, or hash algorithm breaks replay determinism across nodes and requires an ADR and a coordinated upgrade path.
- **API response shapes** (`API.md`): existing field names and types in `/v1/` responses are now treated as stable. New fields may be added additively; existing fields must not be renamed, removed, or retyped without a versioning decision.

### Audit scope awareness

Phase 4 will produce a cryptographic audit scope document. When implementing any task, note in the task summary whether the changed code is in scope for external audit (anything in `pqc-crypto`, `pqc-tx` validation pipeline, `pqc-state::apply`, consensus commit verification). Audit-scope code requires extra scrutiny: prefer explicit over clever, small functions over large ones, and inline the invariant reasoning as comments where the logic is not self-evident.

### Cold-sync replay invariant (P-COMPAT-001 §2(d))

- **Cold-sync replay (P-COMPAT-001 §2(d))** — `crates/pqc-consensus/tests/cold_sync_replay.rs` MUST stay green. Every PR touching consensus-relevant state must update its expected-state-root vector in the same commit; a divergence between code and committed roots is a launch-blocker.

### P-COMPAT-001 §7 compliance — dual-path code budget (ADR-053 §T2.5)

From the `viper-pq-1` launch onwards every ADR that introduces a **dual-path decoder / hasher / codec** (as mandated by P-COMPAT-001 rule 2(c) for breaking changes to consensus-relevant state) MUST also specify, in the same ADR:

- a concrete **`legacy_path_deprecation_epoch`** (or activation height) at which the legacy branch is removed from the binary;
- a deprecation window at minimum equal to the network's unbonding period, so producers carrying legacy state have time to migrate;
- a follow-up TASK filed against the deprecation epoch that physically deletes the legacy branch from the codebase.

Indefinite deprecation windows are a policy violation — the absence of a scheduled removal is itself a violation, not a safe default. An extension of the deprecation epoch is admissible only through on-chain governance (`SoftwareUpgrade` with its own ADR); "we'll schedule it later" is not.

When reviewing any PR that adds a new dual-path branch, agents MUST check that the accompanying ADR satisfies these three conditions and reject (or request amendment) if any is missing. Exceptions are limited to safety-critical rollbacks (a freshly-shipped format turned out to be broken) and must themselves travel with a new ADR justifying the exception.

## Code Direction

- Rust-first core unless a future ADR changes this
- Deterministic CBOR for all signed protocol objects (ADR-004)
- Fee model must price bytes, signature verification, and execution as separate line items (ADR-005)
- ML-DSA as the default signature baseline; SLH-DSA reserved for recovery/emergency flows (ADR-006)
- PoS BFT consensus, Tendermint/CometBFT-like first, HotStuff-like later (ADR-007)
- No generic smart-contract VM in Phase 1 (ADR-008)
- Security-critical code paths must be small, explicit, and independently testable
