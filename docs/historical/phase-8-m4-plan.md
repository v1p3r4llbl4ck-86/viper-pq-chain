# Phase 8 — Milestone M4: Archival Overlay + External Cohort

**Doc ID**: phase-8-m4-plan
**Status**: **workstream (a) CLOSED 2026-04-23**. All 6 sub-tasks (TASK-160..TASK-165) landed on `develop`; sidecar + renewal cron + explorer production-ready (some operator-side follow-ups remain `[~]` per TASKS.md — real-TSA spike, Ansible role, T11 reconstruct). **Workstream (b) external cohort recruitment** is OPEN and now framed against the live `viper-pq-1` chain (TASK-185 — onboard ≥2 external operators on `https://pqchain.agwswebconsulting.it/v1/...` per `docs/validator-onboarding.md`). The original Phase-8-exit "≥5 × 7 days by 2026-05-20" gate folds into the broader Phase 8.5 post-launch soak window (see ROADMAP.md §"Phase 8.5"). This document stays as design rationale for workstream (a); workstream (b) progress is tracked in TASKS.md.
**Owner**: alberto (solo on archival overlay; external cohort is a parallel human-ops workstream)
**Date**: 2026-04-23
**Depends on**: ADR-045 (accepted), SPEC-ARCHIVAL-001 v0.1, ADR-043 (SLH-DSA-SHAKE-192s) and TASK-114 closure, ADR-044 (TLV envelope) live on `develop`
**Supersedes**: n/a (first M4 plan)

## 0. TL;DR

M4 turns the archival overlay from a design artefact (ADR-045, SPEC-ARCHIVAL-001) into running code on `develop`, and recruits the external-operator cohort that lets the chain hit the Phase 8 exit criterion of "≥ 5 independent validators for 7 consecutive days".

Two decoupled workstreams:

- **(a) Archival overlay implementation** — this plan's primary scope. Breaks into **M4.1 → M4.7** (§3), sequenced over ~5 calendar weeks solo. Produces: `pqc-types::archival` module, `MsgType::ArchivalRecordSubmit` / `ArchivalRecordAddAnchor` / `ArchivalRecordRenew` tx paths, SLH-DSA-SHAKE-256s signing helpers, epoch-boundary hook, RFC 3161 sidecar, RFC 4998 renewal cron, and integration tests.
- **(b) External cohort recruitment** — out of scope for this agent. Tracked at `docs/historical/phase-8-spec.md` §6 and executed by human ops: 8–12 operators, BYO hardware per `specs/launch-readiness.md` §3 (min spec: 8-core Zen4+/ARM, 32 GB ECC, 2 TB NVMe, 200 Mbps, US-participant carve-out). Incentives: 12-month lockup, no cash grant. Timeline: parallel to (a), target first ≥ 5 live by end of M4.6.

**Effort for (a)**: ~5 calendar weeks solo. **Budget**: €0 dev, ~€3–9k/year TSA costs once live (budget in `reports/m4/budget.md`, drafted in TASK-164). **Rollback**: the overlay is additive-only — setting `archival_enabled = false` via emergency governance (§12 of SPEC-ARCHIVAL-001) stops new records without invalidating past ones.

**Exit criterion (a)**: on devnet-2, one full epoch boundary produces an `ArchivalRecord` with ≥ 2 EU-qualified TSA anchors, the external verification protocol (SPEC-ARCHIVAL-001 §7) reconstructs from the `GET /v1/archival/proof` endpoint alone, and `pqchain_archival_records_pending_anchor` stays at 0 across a 24-hour soak.

**Exit criterion (b)**: ≥ 5 independent validators from ≥ 4 jurisdictions + ≥ 3 hosting classes online for 7 consecutive days without unplanned halt. This is the Phase 8 exit criterion.

---

## 1. Context and Motivation

### Where M3 landed us

TASK-114 closed SLH-DSA-SHAKE-192s end-to-end (2026-04-22). TLV envelope (ADR-044) is live on every transaction codec. On-chain algorithm registry is governance-mutable via `ProposalEffect::RegistryUpdate`. The chain has **everything needed to add SLH-DSA-SHAKE-256s as a registry entry** — the backend already wires the `slh-dsa` vendored crate for the Cat 3 variant; bumping to Cat 5 is a parameter-set change, not a new dependency.

### Why the archival overlay

ADR-045 states the why in one paragraph: ML-DSA-65 is lattice-based, SLH-DSA is hash-based. Against a 20-year archival horizon the chain cannot rely on a single cryptographic family. External TSAs and RFC 4998 renewal close the temporal-ordering gap that pure on-chain signatures can't. SPEC-ARCHIVAL-001 §3 carries the full threat-model rationale.

### Why the external cohort is coupled into the same milestone

The Phase 8 exit criterion in `ROADMAP.md` bundles them: "≥ 5 independent validators for 7 consecutive days" + archival overlay live. From a scheduling perspective these are independent — cohort recruitment happens in parallel with M4.1–M4.5 — but the milestone only closes when both converge. We accept that M4 has a hard-dependency on out-of-my-control operational work.

### What ADR-045 + SPEC-ARCHIVAL-001 gave us

- SPEC-ARCHIVAL-001 §4: full wire format (`ArchivalRecord`, `TimestampAnchor`, SLH-DSA signature preimage with domain separation)
- §5: on-chain state shape and state-root folding under `VIPER-ARCHIVAL-*-V1` domains
- §6: RFC 3161 sidecar protocol
- §7: external-auditor verification protocol (year N+20)
- §8: RFC 4998 ERS renewal cadence and procedure
- §10: Prometheus metrics surface
- §11: governance parameter table
- §13: test matrix T1–T11

### What's left to actually ship M4

The spec is done. M4 fills in *how* at the Rust/codebase layer across six sequenced phases (§3), each landing on `develop` independently, plus a final integration and spec-validation phase (M4.7).

---

## 2. Objectives and Out-of-Scope

### In scope (M4 primary workstream (a))

1. On-chain `ArchivalRecord` types + deterministic CBOR codec (`pqc-types::archival`).
2. Three new `MsgType` variants and their apply paths (`MsgType::ArchivalRecordSubmit = 0x0700`, `0x0701 AddAnchor`, `0x0702 Renew`).
3. SLH-DSA-SHAKE-256s signing helpers (parameter-set bump on the existing `slh-dsa` vendored crate from TASK-114).
4. Epoch-boundary hook in `pqc-consensus::engine` emitting the `epoch_root` for the sidecar.
5. Out-of-consensus RFC 3161 TSA sidecar (separate binary `viper-archival-sidecar`, deploy-time optional).
6. RFC 4998 ERS renewal cron tooling (script, not a binary — runs once per 6 months).
7. Integration and spec-validation tests (SPEC-ARCHIVAL-001 §13 T1–T11).

### Out of scope (explicitly deferred)

| Item | Deferred to |
|------|-------------|
| External-cohort recruitment | parallel human-ops workstream (TASK-167+, not in this plan) |
| Merkle-tree variant of `epoch_root` for large epochs | Phase 9 (O1 in SPEC-ARCHIVAL-001 §14) |
| Bitcoin OP_RETURN as second anchor | post-audit (O2) |
| On-chain verification of TSA X.509 chain | never (§6.1 of the spec defers this to the auditor, not the chain) |
| Formal (Quint/TLA+) proof of verification-protocol soundness | post-M4 audit (O4) |
| SDK-level proof helpers (TS/Python `verify_archival_proof`) | Phase 9 product track |

### Non-goals

- **Consensus involvement**. The archival overlay MUST NOT block block finality. §4.7 of the spec formalises this.
- **ERS retroactive coverage**. The first renewal lands at horizon + 5 years; epochs from before the overlay is enabled are not archived retroactively (see §4.4 below).
- **Zero-downtime rollout**. Archival enablement is a governance proposal; the chain is live before and after, no maintenance window needed.

---

## 3. Implementation sequence

Six sub-phases over ~5 calendar weeks, each producing a landable commit on `develop`. Integration (M4.7) follows.

### M4.1 — `ArchivalRecord` type + CBOR codec (Week 1)

- **TASK**: TASK-160.
- **Scope**: new module `crates/pqc-types/src/archival.rs` with `ArchivalRecord`, `TimestampAnchor`, `TsaRef`, `ValidatorArchivalKey` per SPEC-ARCHIVAL-001 §4.4 / §4.5. Deterministic CBOR encode/decode via existing `pqc-types` serde+ciborium pattern (mirrors `pqc-types/src/validator.rs`).
- **Tests**: T3 (CBOR roundtrip), T10 (deterministic-CBOR vs. reference fixture). Unit tests only, no consensus wiring yet.
- **Effort**: 2–3 days.
- **Acceptance**: `cargo test -p pqc-types` green; `cargo doc` has no dangling links on the new module.

### M4.2 — `MsgType::ArchivalRecord*` tx paths (Week 1–2)

- **TASK**: TASK-161.
- **Scope**: three new message-type variants in `pqc-types::tx::MsgType` (opcodes `0x0700/0x0701/0x0702`); corresponding apply functions in `crates/pqc-state/src/apply/archival_submit.rs`, `archival_add_anchor.rs`, `archival_renew.rs`. Admissibility checks per SPEC-ARCHIVAL-001 §4.6. State-store mutations for `archival_records`, `archival_keys`, etc.
- **Tests**: T4 (tampered epoch root rejected), T5 (unauthorised signer), T6 (threshold met / short).
- **Effort**: 3–4 days.
- **Acceptance**: apply-path unit tests green; replay-equivalence test (`snapshot_full_replay_equivalence`) still passes — state-root byte stability preserved by §5 domain-tag folding.

### M4.3 — SLH-DSA-SHAKE-256s signing helpers (Week 2)

- **TASK**: TASK-162.
- **Scope**: parameter-set bump on the vendored `slh-dsa` crate from TASK-114. Add `AlgId::SlhDsaShake256s = 0x0023` to the enum; add the registry entry in `crates/pqc-crypto/src/registry.rs` (sig_size=29_792 B, pk_size=64 B per FIPS 205 §10.3); add the `PqVerifier` dispatch match arm. Helpers in `crates/pqc-crypto/src/sign.rs`: `slh_dsa_shake_256s_{generate,sign}`. These mirror the TASK-114 192s trio line-for-line (same vendored crate, different params).
- **Tests**: sign/verify roundtrip + tampered-preimage reject + wrong-key reject, per the TASK-114 template. ACVP vectors for SLH-DSA-SHAKE-256s added to `tests/acvp/` (3 cases per NIST ACVP-Server `@15c0f3de`, extending TASK-154 harness).
- **Effort**: 2–3 days (parameter-set change is mechanical; per-test runtime ~5 min).
- **Acceptance**: `cargo test --features pq-verifier --test acvp_conformance -- --ignored` includes the 3 new cases, all pass.

### M4.4 — Epoch-boundary archival hook (Week 2–3)

- **TASK**: TASK-163.
- **Scope**: in `crates/pqc-consensus/src/engine.rs`, at each `is_epoch_boundary(h)` apply-block path, compute `epoch_root` (SPEC §4.1) and emit an `ArchivalEpochRoot` event on a new tokio broadcast channel. The `consensus_loop` subscribes; designated archival signers (membership check against `state.archival_signer_set`) sign the §4.5 preimage via their local `archival_sk` and submit an `ArchivalRecordSubmit` via `LiveNode::inject_tx`. Non-signers do nothing.
- Archival key storage alongside consensus key, same keystore layout (SPEC-TEST-001 §6). Includes a new `pqcd wallet archival-keygen` CLI command to initialise the archival key on an operator's node.
- New tx variant: `ValidatorRegisterArchivalKey` (opcode `0x0403`, validator-lifecycle range). Needed because archival pk is separate from consensus pk per ADR-043.
- **Tests**: T7 (3-node devnet hits an epoch boundary, all 3 produce the same `epoch_root`, 3 sigs submitted, one `ArchivalRecord` applies). Uses the shortened epoch length pattern from the `docs/historical/phase-8-m2-plan.md` test harness (`epoch_duration: 5 blocks`).
- **Effort**: 5 days (the archival-key tx, wallet plumbing, and test harness are the expensive bits).
- **Acceptance**: `pqcd/tests/product_workflows.rs::archival_record_applies_at_epoch_boundary` passes; devnet-2 dry run after merge on a small throwaway test chain (not production devnet-2 — no config change to prod yet).

### M4.5 — RFC 3161 TSA sidecar (Week 3–4)

- **TASK**: TASK-164.
- **Scope**: new `crates/viper-archival-sidecar/` binary crate (not part of `pqcd`, deployed alongside it). Responsibilities:
  1. Subscribe to `pqcd` WebSocket notification feed for `ArchivalRecordSubmitted{epoch, epoch_root}` events (new endpoint at `/v1/archival/feed`).
  2. POST `TimeStampReq` to each configured TSA URL per SPEC §6.1 flow (HTTP client: `reqwest` blocking, existing workspace dep).
  3. On a granted TST, submit `ArchivalRecordAddAnchor(epoch, TimestampAnchor)` via the normal tx-submit API (`POST /v1/txs`) using a dedicated sidecar account funded per §6.5 budget.
  4. Retry logic: per-TSA exponential backoff up to 24 h; metric `pqchain_archival_tsa_requests_total` exported over `/metrics` on port 9635.
- Config file `sidecar.toml`: TSA URLs, sidecar-account keystore path, node WebSocket URL, retry policy.
- Ansible role `deploy/ansible/roles/viper-archival-sidecar/` (matches the TASK-150 `time-sync` role shape).
- **Tests**: T8 (fake-TSA HTTP server returns an RFC 3161 response; sidecar submits the `AddAnchor` tx; chain accepts it; metric decrements).
- **Effort**: 5–6 days (HTTP plumbing + RFC 3161 DER parsing; use `rasn` or the existing `rfc3161-client` vendored crate if available — research in the first hour).
- **Acceptance**: sidecar unit tests green; `fake_tsa_integration_test` (single-node + sidecar against a mock TSA HTTP server) passes; manual run against a real staging TSA (e.g. InfoCert sandbox) produces a valid TST on devnet-2-staging.

### M4.6 — RFC 4998 ERS renewal tooling (Week 4)

- **TASK**: TASK-165.
- **Scope**: `scripts/archival-renewal.sh` + companion helper in the sidecar binary (`viper-archival-sidecar renew --since=…`). Walks `GET /v1/archival/records` to find records whose `evidence_record_version` is stale (per the renewal_period_blocks gov param), bundles them per RFC 4998 `ArchiveTimeStampChain` syntax, obtains ≥ 2 TSTs per bundle, submits one `ArchivalRecordRenew` tx per batch.
- Cron schedule: `0 3 1 */6 *` (3 AM on the 1st of every 6th month, UTC). For early operation, 6-month cadence is conservative; moves to quarterly once stable.
- **Tests**: T9 (5-year time warp: a fake clock in the sidecar test harness moves `now` past the renewal horizon, renewal bundle applies, `evidence_record_version` increments).
- **Effort**: 3–4 days (RFC 4998 `ArchiveTimeStampChain` ASN.1 encoding — use `rasn`).
- **Acceptance**: renewal integration test green; RUNBOOK §22 (new) documents the cron setup and the `renewal_overdue` alert response.

### M4.7 — Integration + spec validation (Week 5)

- **TASK**: included in TASK-165 closure.
- **Scope**:
  - T11 (SPEC-ARCHIVAL-001 §7 full-roundtrip): from a pinned chain snapshot + an `epoch_number`, the verification protocol reconstructs the `ArchivalProof` bundle without access to the live chain. This is a *pure* test (no network) that forces us to write the first reference verifier — the same code paths will ship in the SDKs post-audit (Phase 9).
  - RUNBOOK §22 section written: archival ops (sidecar restart, TSA outage response, renewal-overdue alert, governance proposal to disable archival in emergency).
  - CHANGELOG.md entry under `[Unreleased]` Added.
  - ROADMAP.md M4 status flipped from "queued" → "design landed … implementation tracked in TASK-160..165" and eventually "implementation complete".
  - TASKS.md TASK-160..165 flipped to `[x]`.
  - `reports/m4/2026-MM-DD.md` soak evidence (24-hour devnet run with archival enabled, all metrics healthy).

- **Effort**: 2–3 days.
- **Acceptance**: every SPEC §13 test (T1–T11) green in CI; 24-hour soak report green.

Total sequencing: **~25 engineering days + 2 ops days ≈ 5 calendar weeks solo**.

---

## 4. Known blockers (from the 2026-04-23 scope audit)

### 4.1 No existing WebSocket/event-stream surface on pqcd

The RFC 3161 sidecar (M4.5) wants to subscribe to archival-record-submitted events from pqcd. The node's current public API is HTTP-only (`/v1/…`). Two options:

1. **New WebSocket endpoint** `/v1/archival/feed`. ~1 day of plumbing (axum supports WS). More future-proof: event bus is reusable by block-explorer WebSocket UI.
2. **Polling** `GET /v1/archival/records?since={epoch}`. Zero new infra. Loses ~1 epoch of latency on anchor submission (acceptable; §6.3 allows 24 hours).

Recommendation: go with (2) for M4.5; revisit (1) in Phase 9 if product layer wants streaming.

### 4.2 RFC 3161 DER decoding

No ASN.1/DER parser is currently in the workspace (CBOR only). Options:

1. `rasn` crate (pure-Rust ASN.1) — adds one dep, ~2 MB binary. Recommended.
2. `rfc3161-client` (if it exists on crates.io, check first) — higher-level but might pull openssl. Avoid.
3. Hand-roll a minimal RFC 3161 parser for just `TimeStampToken`. ~2 days; fragile. Reject.

Recommendation: `rasn`.

### 4.3 Archival key custody inherits all consensus-key concerns

Storing a second long-lived private key on every designated signer doubles the key-custody attack surface. Mitigation: archival sigs are slow enough (~3 000 verify/s) that the signer is NOT in the consensus hot path, so the archival key can live on **cold storage** and be moved to an air-gapped signer at epoch boundaries (once per hour). Documented as a deployment option in `docs/validator-onboarding.md` (to be extended in TASK-163).

### 4.4 No retroactive archival for pre-enablement epochs

The chain has 200k+ blocks of history as of 2026-04-23. M4 doesn't retroactively archive epochs 0..N-1. The first `ArchivalRecord` lands at the next epoch boundary after the feature-flag governance proposal passes. This matches ADR-045's forward-looking scope (the threat model is year N+20 verifiability of forward-issued receipts). Customers relying on pre-M4 receipts get the current ML-DSA-65 integrity guarantee, not the hash-family fallback. Document explicitly in `docs/validator-onboarding.md` + WHITEPAPER.md §7.

### 4.5 Sidecar account funding

The sidecar submits `ArchivalRecordAddAnchor` transactions that cost gas. At a 1-hour epoch cadence that's 8 760 tx/year per TSA × (1 tx per anchor); at current fee levels (~0.0001 VPR/tx per ADR-022 calibration) this is ~1 VPR/year per TSA. Genesis-allocate **10 VPR** to the sidecar account to cover multi-year operation. Tracked as a one-liner in the genesis patch for the next chain reset (M3→M4 cutover naturally reuses the M3 reset opportunity).

---

## 5. TSA provider selection (SPEC-ARCHIVAL-001 §6.5)

M4.5 requires concrete TSA endpoints. Proposed initial list (confirmation deferred to operator-run spike during TASK-164 week 1):

| # | Provider | Jurisdiction | Cost est. | EU Trust List | Notes |
|---|----------|--------------|-----------|---------------|-------|
| 1 | Aruba QTSA | IT | ~€0.20/TST | ✅ qualified | Existing EIDAS provider, reliable SLA |
| 2 | InfoCert TSA | IT | ~€0.15/TST | ✅ qualified | Sandbox available for dev |
| 3 | Namirial TSA | IT | ~€0.10/TST | ✅ qualified | Cheapest qualified |
| 4 | TrustPro Cloud TSA | EU | ~€0.15/TST | ✅ accredited | Redundancy, non-IT jurisdiction |

Total estimated cost: 4 TSAs × 8 760 TSTs/year × €0.15 avg = **€5 256/year**. Budget entry in `reports/m4/budget.md` (TASK-164).

Negotiation note: at anchor volumes (~8k/year × 4 = 32k TSTs/year total) most qualified TSAs offer bulk contracts. A 30% discount on list price is realistic — budget estimate stays conservative at the non-discounted figure.

---

## 6. Dependency DAG

```
M4.1 (types) ─► M4.2 (tx apply) ─► M4.4 (epoch hook) ─► M4.7 (integration)
                  │                                       ▲
                  ▼                                       │
                M4.3 (SLH-DSA-256s) ───────────────┐      │
                                                   ▼      │
M4.5 (TSA sidecar) ───────────────────────────────────────┤
                                                          │
M4.6 (ERS renewal) ───────────────────────────────────────┘
```

Critical path: M4.1 → M4.2 → M4.4 → M4.7.
Parallelisable: M4.3 (SLH-DSA-256s) runs alongside M4.1/M4.2; M4.5 and M4.6 are independent of each other and of M4.4 once the tx schema is frozen.

Cohort-recruitment workstream (b) runs in parallel start-to-finish and does not block (a). Convergence is at M4.7: the 7-day soak (Phase 8 exit criterion) requires both (a) live in governance-enabled state AND (b) ≥ 5 independent operators.

---

## 7. Effort Estimate

Summed engineering effort: **~20 days**. Solo cadence with review and integration friction:

- happy path: **4 weeks** (M4.1–M4.6 tight sequencing + M4.7 integration)
- realistic: **5 weeks** — inclusive of ASN.1/RFC 3161 tooling friction, first TSA spike (possibly one provider turns out to have idiosyncratic auth requirements), and at least one iteration of the sidecar after first devnet dry-run.

Suggested sprint layout:
- Week 1: M4.1 + start M4.2 + start M4.3 (parallel)
- Week 2: finish M4.2, finish M4.3, start M4.4
- Week 3: finish M4.4, start M4.5
- Week 4: finish M4.5, M4.6
- Week 5: M4.7 integration + soak + docs + ROADMAP/TASKS updates

---

## 8. Rollback Strategy

The archival overlay is additive and behind a governance parameter (`archival_enabled`, default `true` at M4 enablement). Rollback options, in order of increasing severity:

1. **TSA outage** — no chain action. Records sit in `pending_anchor` state; SLH-DSA + epoch-root commitment stays intact. Sidecar retries indefinitely.
2. **Sidecar bug** — operator disables sidecar on their node; other signers' anchors still go through. No chain-level impact.
3. **SLH-DSA backend CVE** — emergency governance proposal (⅘ supermajority per SPEC-GOV-001 §7.4) executes `DisableArchival`. Past records remain valid; new epochs do not archive. Recovery: pin a patched `slh-dsa` vendored version, re-enable via governance.
4. **Catastrophic wire-format bug in `ArchivalRecord`** — same as (3), but requires a chain reset to re-enable (records stored in wrong format are stuck on state root). Covered in (3)'s recovery path with an added migration step.

No rollback is required for the cohort (b) workstream: if an external operator drops offline, the chain continues with `n - 1` validators as long as `n - 1 ≥ 5` (exit criterion) and `≥ ⅔` BFT quorum holds.

---

## 9. Acceptance Criteria (M4 Done)

All must be true for M4 (workstream a) to close:

- [ ] `specs/archival-overlay.md` merged (SPEC-ARCHIVAL-001)
- [ ] `DECISIONS.md` ADR-045 fleshed out to full form (no placeholder)
- [ ] TASK-160..165 all `[x]` on `develop`
- [ ] `cargo test --workspace --lib` green including all SPEC §13 T1–T11 tests
- [ ] `cargo test -p pqcd --tests product_workflows::archival_record_applies_at_epoch_boundary` green
- [ ] ACVP vectors for SLH-DSA-SHAKE-256s in `tests/acvp/`, `cargo test --features pq-verifier --test acvp_conformance -- --ignored` passes
- [ ] `crates/viper-archival-sidecar/` binary crate on `develop`, documented
- [ ] Ansible role `deploy/ansible/roles/viper-archival-sidecar/` present
- [ ] `scripts/archival-renewal.sh` + cron template present
- [ ] RUNBOOK §22 (archival ops) drafted
- [ ] `reports/m4/2026-MM-DD.md` 24-hour devnet soak report landed
- [ ] `ROADMAP.md` M4 row advanced to "implementation complete" once (a) is done; full M4 close requires (b)

For the full Phase 8 exit (both workstreams):

- [ ] ≥ 5 independent validators online from ≥ 4 jurisdictions + ≥ 3 hosting classes
- [ ] 7 consecutive days without unplanned halt
- [ ] `pqchain_archival_records_pending_anchor = 0` throughout the 7-day window
- [ ] ≥ 2 TSAs producing timely TSTs throughout the window
- [ ] Cryptographic audit report received (TASK-115) with no critical findings unresolved

---

## 10. Risks and Mitigations

| # | Risk | Likelihood | Impact | Mitigation |
|---|------|------------|--------|------------|
| R1 | RFC 3161 wire-format quirks vary per TSA (e.g. InfoCert requires a specific policyOID) | High | Med | Start M4.5 with a 1-day spike against 2 real TSAs before committing the sidecar shape |
| R2 | SLH-DSA-SHAKE-256s sign latency too high on commodity hardware (archival runs on validators' own nodes, not dedicated signers) | Med | Med | Benchmark during M4.3 (~1 s sign latency expected). Acceptable: archival is out-of-consensus (§4.7), once-per-hour, not on hot path |
| R3 | TSA contract complexity drags the cohort schedule (legal review, invoicing, VAT for a chain entity) | High | Med | Start legal/contracts work in parallel with M4.3 (Week 2), not at M4.5 |
| R4 | External cohort recruitment undershoots 5 operators | Med | High | Stretch target 8, accept exit at 5; carry two warm-spare providers who can bring a VPS online within 48 h |
| R5 | ERS renewal (M4.6) is hard to test meaningfully without a 5-year time warp — bugs surface only in year 5 | Med | Low-until-year-5 | Fake-clock test harness (T9) + formal test against RFC 4998 example vector Appendix A |
| R6 | ETSI TS 119 512 alignment is interpretive and a future audit might flag gaps | Med | Low | §9.2 mapping is explicit; gaps are documented, not hidden; auditor engagement in TASK-115 has scope for archival overlay review |
| R7 | Archival-key storage is a new attack surface (second long-lived PK per validator) | Low | Med | §4.3 blocker: recommend cold-storage signer for the archival key; document in validator-onboarding.md |
| R8 | TSA budget (~€5k/year) blows out if epoch cadence increases | Low | Low | Governance-mutable TSA list; can drop to 2 providers if budget pressure appears |

---

## 11. Deferred / Open Questions

| # | Question | Target resolution |
|---|----------|-------------------|
| Q1 | Exact `tsa_cert_ref` format (URI? SKI? cert-hash?) | Decide during M4.5 TASK-164 Week 1 spike |
| Q2 | Do we need an on-chain TSA-down grace counter, or is the 24-hour `pending_anchor` state sufficient? | Decide after first TSA outage on devnet-2 (operational data) |
| Q3 | Should `archival_signer_set` default to a strict subset of Active (e.g. top 8 by stake) rather than all Active? | Default all-Active; revisit at > 24 Active validators |
| Q4 | ERS renewal hash algorithm lock-in — if SHAKE-256 weakens between now and year 5, what's the migration path? | §12.3 of spec documents: new ERS version number chooses a new hash; chain verifier code retains both |
| Q5 | Does M4 need a dedicated `pqcd archival-key-rotate` CLI or is a `ValidatorRegisterArchivalKey` re-registration sufficient? | Sufficient; O3 in SPEC §14 tracks a dedicated rotation tx as a cleanup item |

---

## 12. References

- `DECISIONS.md` ADR-045 — Archival Overlay — SLH-DSA-SHAKE-256s + RFC 3161 Timestamping
- `DECISIONS.md` ADR-043, ADR-044, ADR-047, ADR-048 — dependency spine
- `specs/archival-overlay.md` — SPEC-ARCHIVAL-001 (companion to this plan)
- `specs/audit-scope.md` — crypto-audit scope will include the new `archival_*` modules
- `docs/historical/phase-8-spec.md` — Phase 8 top-level plan
- `docs/historical/phase-8-m1-plan.md`, `docs/historical/phase-8-m2-plan.md` — sibling plans, reuse their patterns
- `docs/validator-onboarding.md` — extended in TASK-163 for archival-key custody
- `ROADMAP.md` — Phase 8 objective, exit criteria, and the milestone progress table
- FIPS 205 — Stateless Hash-Based Digital Signature Standard
- RFC 3161 / RFC 4998 / RFC 5816
- ETSI TS 119 511 / 512
- BSI TR-03125 (TR-ESOR)
