# Launch Readiness Checklist

**Status**: Historical  
**Date:** 2026-04-12 (initial) · 2026-04-25 (post-`viper-pq-1`-launch banner)  
**Phase:** Phase 4 Exit — Hardening and Audit Readiness  
**ADR reference:** ADR-023 (Phase 4 Exit Review); ADR-053 (`viper-pq-1` launch architecture); ADR-052 (Policy P-COMPAT-001)  
**Outcome:** Phase 4 complete — the Phase 5 / 6 / 8 / 8.5 launches were all executed (see ROADMAP); the §6 list was largely closed by the Phase 8 + 8.5 deliverables

> **Historical.** This checklist gated the launch of `viper-pq-1` (2026-04-25), a chain that has since been retired together with its successors `viper-research-1` and `viper-lab-1`. It is kept unchanged for the audit trail; it does not describe the public chain `viper-testnet-1`, which is created at genesis after the public release. Runbook references below point to `docs/operators/RUNBOOK.md` (at the time the runbook was a single `RUNBOOK.txt` with numbered sections); the `producer` / `follower` config names are the pre-ADR-069 spellings of the `validator` / `full` roles.

> **Revision banner (2026-04-25)**: this checklist was authored at Phase 4 exit and gated Phase 5. Its concrete content is largely overtaken by the actual viper-pq-1 launch ceremony (TASK-205 `40712f0`, 2026-04-25) and by Policy P-COMPAT-001 (ADR-052) which formalised the post-launch upgrade discipline. The §6 deferred-items list below contains many entries that have since closed (libfuzzer corpus run via TASK-156, reproducible build + SBOM via TASK-157, archival overlay via M4 / TASK-160..165, distributed BFT signing via M2b N+2 / TASK-167..172, post-audit fixes via TASK-173..177, ADR-053 launch arc via TASK-190..206). Operators should treat this as a Phase-4 historical artefact; the `viper-pq-1` launch artefacts are `deploy/ansible/playbooks/launch-viper-pq-1.yml` + `deploy/ansible/files/genesis-viper-pq-1.json` (historical). A future `launch-readiness-002.md` may be drafted ahead of a public mainnet launch; until then this file stays for historical reference.

---

## §1 Protocol Completeness

| Item | Status | Evidence |
|------|--------|----------|
| Transaction envelope canonically specified (SPEC-TX-001) | COMPLETE | `specs/transaction-envelope.md`; CBOR encoding enforced in `pqc-tx`; all 6 proptest fuzz harnesses pass |
| Account and keyset model specified (SPEC-ACCOUNT-001) | COMPLETE | `specs/account-keyset-registry.md`; `KeyEntry`, `KeySet`, `Account` structs wired through all apply paths |
| Algorithm Registry + lifecycle (Active/Discouraged/Deprecated/Banned) | COMPLETE | `pqc-types::alg`; `governance_proposal(registry_update)` apply path; TASK-055 deprecation drill |
| Fee model: byte fee, sigverify fee, per-op gas (SPEC-FEE-001) | COMPLETE | `specs/fee-model.md §6.4`; Linux calibrated: `sigverify_fee_v_b=14000`, `exec_fee_per_gas=43`; all four runnable configs updated (TASK-042) |
| 10 built-in operation types | COMPLETE | `token_transfer`, `vault_create`, `vault_policy_update`, `attestation_create`, `attestation_revoke`, `proof_anchor`, `key_add`, `key_rotate`, `key_revoke`, `governance_proposal` + `consensus_key_rotate` + validator ops |
| Validator staking lifecycle (register, exit, unjail) | COMPLETE (Phase 4) | TASK-064; on-chain `ValidatorRecord`; `CommitQuorumPolicy::from_state_store()` |
| Consensus commit quorum (BFT 2/3+1) | COMPLETE | `validate_block_commit_quorum` in `pqc-consensus/src/commit.rs`; 7 multi-node quorum tests |
| Snapshot state sync (cold-start without full replay) | COMPLETE | `cold_start_from_snapshot`; 6 integration tests (TASK-050) |
| ML-KEM-768 authenticated P2P transport | COMPLETE | `GET /internal/p2p/kem-pubkey`, `POST /internal/p2p/session`; session token = `SHAKE-256(ss \|\| "block-fetch" \|\| height)` |
| Multi-algorithm verifier (ML-DSA-44/65/87 + SLH-DSA-SHA2-128s) | COMPLETE | `PqVerifier` in `pqc-crypto` (TASK-063); FN-DSA deferred to FIPS 206 finalization |
| FN-DSA (FIPS 206) support | DEFERRED | GAP-01; FIPS 206 not yet finalized; SLH-DSA-SHA2-128s used as fallback |

**Phase 4 completion:** all protocol operations implemented; FN-DSA production support gated on FIPS 206 finalization.

---

## §2 Security

| Item | Status | Evidence |
|------|--------|----------|
| Cryptographic audit scope defined | COMPLETE | `specs/audit-scope.md` (TASK-060); 7 primary-scope modules; 6 pre-audit gaps catalogued |
| Threat model reviewed | COMPLETE | `specs/threat-model.md` (TASK-061); 24 threat surfaces; 13 confirmed, 4 partial, 5 gap, 4 accepted risk |
| Security scan: secret leakage in logs | COMPLETE — no findings | No private key material in log output; `specs/security-scan-001.md` |
| Security scan: unwrap/expect in security-critical paths | COMPLETE — 2 fixed | U-001 HIGH fixed (`kem_encapsulate` returns Result); remaining expects are invariant assertions on typed-size arrays |
| Security scan: session ID derived from raw shared secret | COMPLETE — 1 fixed | S-001 MEDIUM fixed; session ID now `SHAKE-256(ss \|\| "session-id")` |
| Constant-time status documented | COMPLETE | `ml-dsa 0.1.0-rc.8` and `ml-kem 0.3.0-rc.2` use `subtle` crate ops (`ct_eq`, `ct_select`, `ConstantTimeDiv`); neither independently audited |
| Fuzz coverage | COMPLETE | 6 proptest targets (decode_tx, validate_tx, AlgId parsing); 3 cargo-fuzz libFuzzer targets; no crashes |
| Independent external audit | NOT DONE | Phase 4 produces audit scope; external engagement is a Phase 5 gate |
| Key material zeroization (`zeroize` feature) | PARTIAL | `ml-kem` and `ml-dsa` support `zeroize` feature; not yet enabled in `pqc-crypto` Cargo.toml; Phase 5 gap |

**Phase 4 security posture:** all identified CRITICAL/HIGH/MEDIUM findings fixed; no secret material in log paths; external audit deferred to Phase 5 (scope document ready).

---

## §3 Performance

| Metric | Target | Measured | Status |
|--------|--------|----------|--------|
| Effective TPS (SPEC-TEST-001 §3.3) | ≥100 TPS | **129.4 TPS** (TASK-066 post-optimization) | **MET** |
| Effective TPS (SPEC-TEST-001 §4.5 Phase 3-alpha) | ≥200 TPS | 129.4 TPS | NOT MET |
| Storage growth at 100 TPS (SPEC §3.3 advisory) | ≤33 GB/day | ~31 GB/day (10K ML-DSA-65 txs extrapolated) | MET |
| Benchmark: ML-DSA-65 verify | — | 323 µs (Ubuntu VM, release build) | Measured |
| Benchmark: `state_clone_realistic_pk/10000` | — | 6.07 ms after Arc optimization | Measured |
| Key bottleneck identified | — | HashMap structure clone ~6 ms/block for 10K accounts | Documented |

**Phase 4 performance posture:** §3.3 target MET; §4.5 target NOT MET; next bottleneck (HashMap structure clone) identified and documented for Phase 5. See TESTING.md for full baseline table.

---

## §4 Operability

| Item | Status | Evidence |
|------|--------|----------|
| Runnable single-node config | COMPLETE | `configs/single-node.json`; `scripts/run_single_node_api.sh` |
| 3-node local devnet config | COMPLETE | `configs/producer.json`, `configs/follower-a.json`, `configs/follower-b.json`; `scripts/run_local_devnet.sh` |
| External operator bootstrap guide | COMPLETE | `docs/operators/RUNBOOK.md` |
| Config reference | COMPLETE | `docs/operators/RUNBOOK.md` |
| Observability (Prometheus metrics) | COMPLETE | `GET /v1/metrics`; `GET /internal/metrics`; 9 stable metric names; `docs/operators/RUNBOOK.md` |
| Incident response playbooks (IR-01 through IR-06) | COMPLETE | `docs/operators/RUNBOOK.md` |
| Load test procedure | COMPLETE | `docs/operators/RUNBOOK.md` |
| Snapshot export/import CLI | COMPLETE | `pqcd snapshot-export`, `pqcd snapshot-import` |
| Key ceremony / genesis hash derivation | NOT DONE | Phase 5 (ADR-023 required) |
| Multi-validator production topology | NOT DONE | Phase 5 — 24-validator target per ADR-007; current prototype tested up to 3 nodes |

---

## §5 Documentation

| Item | Status | Evidence |
|------|--------|----------|
| Protocol specs (SPEC-TX-001, SPEC-ACCOUNT-001, SPEC-FEE-001, SPEC-GOV-001, SPEC-VAL-001) | COMPLETE | `specs/` directory |
| Architecture (ARCHITECTURE.md) | COMPLETE | Updated through Phase 4 |
| API reference (API.md) | COMPLETE | All `/v1/` endpoints documented |
| Decision log (DECISIONS.md) | COMPLETE | ADR-001 through ADR-023 |
| Audit scope document | COMPLETE | `specs/audit-scope.md` |
| Threat model | COMPLETE | `specs/threat-model.md` |
| Security scan report | COMPLETE | `specs/security-scan-001.md` |
| Fault injection report | COMPLETE | `specs/fault-injection-report.md` |
| Fee model with Linux calibration | COMPLETE | `specs/fee-model.md §6.4` |
| WHITEPAPER.md | COMPLETE (skeleton) | Sections marked TBD are pre-implementation placeholders |
| SDK and block explorer | NOT DONE | Phase 7 deliverable |

---

## §6 Open Phase 5 Items

Items deferred from Phase 4 that gate Phase 5 entry or are critical path for mainnet:

| Item | Priority | Owner | Notes |
|------|----------|-------|-------|
| External cryptographic audit engagement | CRITICAL | — | Audit scope ready (`specs/audit-scope.md`); external firm not yet contracted |
| FN-DSA (FIPS 206) production support | HIGH | — | GAP-01; blocked on FIPS 206 finalization |
| `zeroize` feature enabled for ml-kem/ml-dsa | HIGH | — | Secret material zeroing on drop; `zeroize` feature exists in both crates |
| Height-indexed quorum replay correctness | HIGH | — | GAP-04 partial: `CommitQuorumPolicy::from_state_store()` reads live state; per-block quorum snapshots needed for validator-churn replay determinism |
| `consensus_key_rotate` activation (GAP-05) | MEDIUM | — | Record-only today; needs integration with `ValidatorRecord` consensus_pk |
| Tokenomics finalization (ADR-022) | CRITICAL | — | Required before genesis |
| Genesis block specification (ADR-023) | CRITICAL | — | Required before launch |
| 200 TPS performance target (SPEC-TEST-001 §4.5) | HIGH | — | Current: 129.4 TPS; next bottleneck is HashMap structure clone per block tick |
| 7-day staging testnet dress rehearsal | CRITICAL | — | Phase 5 exit criterion |
| Validator KYC/KYB and SLA documentation | CRITICAL | — | Required before external validator onboarding |
| Slashing and automatic jailing detection | MEDIUM | — | Phase 5 per SPEC-VAL-001 §7 |
| SDK (TypeScript, Python) | MEDIUM | — | Phase 7 deliverable |
| Block explorer | MEDIUM | — | Phase 7 deliverable |

---

## Phase 4 Task Completion

| Task | Status | Summary |
|------|--------|---------|
| TASK-060 | COMPLETE | Cryptographic audit scope — `specs/audit-scope.md` |
| TASK-061 | COMPLETE | Threat model review — `specs/threat-model.md` |
| TASK-062 | COMPLETE | Reference-hardware load test (10K txs, 81.6 TPS baseline) |
| TASK-063 | COMPLETE | Multi-algorithm verifier backend (`PqVerifier`) |
| TASK-064 | COMPLETE | On-chain validator staking lifecycle |
| TASK-065 | COMPLETE | Byzantine majority + fork-choice fault injection |
| TASK-066 | COMPLETE | Performance tuning (`Arc<[u8]>` optimization, +59% TPS) |
| TASK-067 | COMPLETE | Security scan (`specs/security-scan-001.md`; 2 findings fixed) |
| TASK-068 | COMPLETE | Launch readiness checklist + Phase 4 Exit Review (this document + ADR-023) |

**Phase 4 declared complete: 2026-04-12. See ADR-023 in `DECISIONS.md` for the formal exit review.**

**221 tests, 0 failures as of Phase 4 exit.**
