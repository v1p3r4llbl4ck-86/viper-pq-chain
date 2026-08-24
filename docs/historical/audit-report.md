# Viper PQ Chain — Full Codebase Audit Report

> **Audit-trail note (2026-04-25)**: this is the **2026-04-17 codebase audit** — automated static analysis + manual code review of the 8 workspace crates + 24 specs + 37 ADRs. It is distinct from the later audits in `reports/audits/`:
>
> - `reports/audits/internal-audit-2026-04-23.md` — 10-agent internal audit produced ahead of the external-engagement gate (Phase 8 audit readiness).
> - `reports/audits/drift-audit-2026-04-25.md` — post-`viper-pq-1`-launch spec/doc/code drift audit.
>
> All three are kept side-by-side as a chain of evidence; none supersedes the others.

**Date**: 2026-04-17
**Scope**: All 8 workspace crates (`pqc-crypto`, `pqc-types`, `pqc-tx`, `pqc-mempool`, `pqc-state`, `pqc-consensus`, `pqcd`, the notary backend), 24 specs, 37 ADRs, documentation suite
**Auditor**: Automated static analysis + manual code review (rev 3 — supersedes rev 2, 2026-04-17)
**Phase**: 6 — Operational Readiness (ADR-026 accepted; ADR-023 closed Phase 4 on 2026-04-12)

---

## Executive Summary

All findings from rev-2 have been resolved in the same session (2026-04-17). The workspace compiles cleanly with zero errors or warnings. The cryptographic core (ML-DSA, SLH-DSA, ML-KEM), deterministic CBOR, 15-step validation pipeline, BFT consensus loop, and state upgrade chain are sound.

Key fixes applied in this session: `V2ToV3Handler` added to `upgrade.rs` (NF-001 Critical), broken `product_workflows.rs` import repaired (F-011), misleading `.map_err().expect()` pattern removed from `kem.rs` (F-012/NF-005), `ProposalStatus::ExecutionFailed` variant added with `execute_registry_update` returning `bool` (F-027), `self_bond` encoded as 16-byte bstr to prevent truncation (F-023), `BalanceInsufficient.fee` widened to `u128` (F-028), license set to Apache-2.0 (F-029), five devnet endpoints added to API.md table (NF-006), AGENTS.md phase updated (NF-007), slashing spec block-time note corrected (NF-003), plus SAFETY comments throughout audit-scope code.

Two non-critical items remain open by design: `GOVERNANCE_VOTING_PERIOD = 5` (F-018) is intentionally small for the devnet and will be addressed via governance once on-chain parameter updates land; `serde` as an unconditional dependency in `pqc-tx` (F-019) is a low-priority refactor.

**Severity totals (open)**: Critical: 0 | High: 0 | Medium: 2 (F-018, F-019) | Low: 0 | Info: 8

---

## Findings

| ID | Severity | File:Line | Finding | Recommendation |
|----|----------|-----------|---------|----------------|
| NF-001 | ~~Critical~~ | `pqc-state/src/upgrade.rs` | **Missing V2ToV3 migration handler.** ~~`global_registry()` only registered `V1ToV2Handler`; nodes with v2 checkpoints would fail with `MigrationNoHandler` on the new binary.~~ **Status: FIXED** — `V2ToV3Handler` added (no-op; tombstoned defaults `false`); registered in `global_registry()` (2026-04-17). | Fixed. |
| F-001 | Critical | `pqc-state/src/store.rs:986-989` | **Validator leaf hash omitted `tombstoned` field.** ~~`compute_validator_leaf_hash` did not hash the `tombstoned` boolean, meaning the state root did not commit to the tombstone flag. A slashed and a non-slashed validator with identical other fields produced the same leaf hash.~~ **Status: FIXED** — `d.push_chunk(&[if record.tombstoned { 1u8 } else { 0u8 }])` added; `STATE_FORMAT_VERSION` bumped 2 → 3. See NF-001 for the resulting migration gap. | ~~Add tombstoned to leaf hash.~~ Fixed. Ensure NF-001 is resolved before deployment. |
| F-002 | Critical | `specs/address.md` vs `pqc-crypto/src/alg.rs` | **SPEC-ADDRESS-001 AlgId table disagreed with code.** ~~Spec used `0x0101/0x0202/0x0303`; code used `0x0001/0x0002/0x0003`.~~ **Status: FIXED** — spec updated to match code values; ML-KEM-768 (`0x0100`) added to table. | Fixed. |
| F-003 | High | `pqc-crypto/src/address.rs` | **`address_to_bech32m` panicked on invalid HRP.** ~~Two `expect()` calls in a public function that could receive arbitrary HRP strings.~~ **Status: FIXED** — returns `Result<String, CryptoError>`; `Bech32mEncodingError` variant added. | Fixed. |
| F-004/F-005 | High | `pqc-state/src/apply/transfer.rs` | **`expect()` in security-critical apply path.** ~~Two `expect()` calls in `apply_token_transfer`.~~ **Status: FIXED** — replaced with `.ok_or(ApplyError::InsufficientFunds)?`. | Fixed. |
| F-006 | High | `pqc-state/src/apply/key_mgmt.rs` | **Three `expect()` calls in key management paths.** ~~`apply_key_add`, `apply_key_rotate`, `apply_key_revoke`.~~ **Status: FIXED** — replaced with `.ok_or(ApplyError::KeyNotFound)?`. | Fixed. |
| F-007 | High | `pqc-state/src/apply/validator.rs` | **Two `expect()` calls in validator lifecycle.** ~~`apply_validator_exit` and `apply_validator_unjail`.~~ **Status: FIXED** — replaced with `.ok_or(ApplyError::ValidatorNotFound)?`. | Fixed. |
| F-008 | High | `pqc-state/src/apply/slashing.rs` | **`expect()` in slashing treasury credit path.** ~~`credit_treasury`.~~ **Status: FIXED** — function now returns `Result<(), ApplyError>`; `.ok_or(ApplyError::InsufficientFunds)?` used. | Fixed. |
| F-009 | High | `pqc-state/src/apply.rs` | **`unwrap()` in `credit_account` helper.** ~~`store.get_account_mut(addr).unwrap()` after an existence check.~~ **Status: FIXED** — replaced with `if let Some(acc)` pattern. | Fixed. |
| F-010 | Medium | `pqc-state/src/apply/` | **Dead multisig apply module with non-existent type references.** ~~`apply/multisig.rs` referenced `AlgId::Multisig`, `store.insert_multisig()`, etc. — none of which existed.~~ **Status: FIXED** — dead file deleted; `pqc-types::multisig` retained for future wiring. | Fixed. |
| F-011 | ~~Medium~~ | `crates/pqcd/tests/product_workflows.rs` | **`product_workflows.rs` compile error after F-017 fix.** ~~Stale import `use pqc_state::apply::vault::derive_address as vault_derive_address` after `vault::derive_address` was removed.~~ **Status: FIXED** — import removed; call site updated to `derive_address(AlgId::MlDsa65, &pk_bytes)` from `pqc_crypto` (2026-04-17). | Fixed. |
| F-012/NF-005 | ~~Medium/Low~~ | `pqc-crypto/src/kem.rs` | **Misleading `.map_err().expect()` pattern in ML-KEM backend.** ~~`kem_generate` and `kem_decapsulate` used `.map_err(|_| CryptoError::InvalidKeySize).expect(...)`, giving a false impression of error handling while still panicking.~~ **Status: FIXED** — no-op `.map_err()` calls removed; `// SAFETY:` comments added explaining why each `expect` is statically unreachable (2026-04-17). | Fixed. |
| F-013 | Medium | `pqc-types/src/multisig.rs` | **Two `unwrap()` calls in MultisigWitness CBOR decoder.** ~~`it.next().unwrap()` on an iterator after checking `a.len() == 2`.~~ **Status: FIXED** — replaced with `let-else` pattern. | Fixed. |
| F-014 | Medium | `pqc-mempool/src/admission.rs` | **`expect()` in mempool admission hot path.** ~~`pool.get(&existing_hash).expect("index consistency")`.~~ **Status: FIXED** — graceful error return + log. | Fixed. |
| F-015 | Medium | `pqc-consensus/src/engine.rs` | **`expect()` in block assembly hot path.** ~~Proposer address conversion in `assemble_block`.~~ **Status: FIXED** — returns `AssembleError::InvalidProposer`. | Fixed. |
| F-016 | ~~Medium~~ | `pqc-types/src/slashing.rs` | **`expect()` in production CBOR encoding in audit-scope code.** ~~No `// SAFETY:` comment for the `expect` in `encode_equivocation_evidence`.~~ **Status: FIXED** — `// SAFETY: ciborium only fails on I/O errors; Vec<u8> is infallible as the writer.` comment added (2026-04-17). | Fixed. |
| F-017 | Medium | `pqc-state/src/apply/vault.rs` | **Address derivation differed between vault_create and pqc-crypto::address.** ~~Local derivation used `pk_bytes \|\| alg_id \|\| key_version` vs canonical `SHAKE-256(sig_alg_id_be16 \|\| pk_bytes, 32)`.~~ **Status: FIXED** — `vault.rs` now calls `pqc_crypto::derive_address(alg_id, &payload.pk_bytes)`. | Fixed. See F-011 for the side effect in `product_workflows.rs`. |
| F-018 | **Medium** | `pqc-state/src/apply/governance.rs:36-40` | **`GOVERNANCE_VOTING_PERIOD = 5` is hardcoded without a devnet-only guard.** The constant is intentionally small for devnet integration tests (which run at 10 ms/block). On a production network at 500 ms/block, 5 blocks ≈ 2.5 seconds of voting time. SPEC-GOV-001 §4.1 references 1,000 blocks as the governance voting period. The constant has a comment explaining devnet use but is not guarded by `#[cfg(not(production))]` or a node-config override. | Make the voting period a node-config parameter (or at minimum a compile-time feature flag). Document the discrepancy from SPEC-GOV-001 more prominently. |
| F-019 | **Medium** | `pqc-tx/src/validate.rs:9` | **`serde` is an unconditional dependency in the validation pipeline.** `use serde::{Deserialize, Serialize}` for `FeeParams`. Every downstream crate that depends on `pqc-tx` pulls in serde unconditionally. | Make `serde` optional behind a `serde` feature flag on `pqc-tx`, or move `FeeParams` serialization to `pqcd` (the only crate that needs JSON config I/O for this struct). |
| F-020 | Medium | `pqc-consensus/src/recovery.rs` | **`expect("len checked")` in recovery replay path.** ~~Panic if recovery encountered corrupted block data.~~ **Status: FIXED** — returns `ReplayError::MetadataMismatch`. | Fixed. |
| F-021 | Medium | `pqcd/src/devnet.rs` | **`expect("just inserted")` in P2P session handling.** ~~Race condition could panic node.~~ **Status: FIXED** — replaced with `anyhow` error propagation. | Fixed. |
| NF-002 | ~~Medium~~ | `pqc-state/src/apply/validator.rs` | **No `// SAFETY:` comments for `expect` in audit-scope CBOR encode functions.** ~~`encode_register_payload` and `encode_empty_validator_payload` used bare `expect("CBOR encode is infallible")`.~~ **Status: FIXED** — `// SAFETY:` comments added; `self_bond` encoding also corrected (F-023, 2026-04-17). | Fixed. |
| NF-003 | ~~Medium~~ | `specs/slashing.md:§8.3` | **Block-time assumption in spec (6 s/block) inconsistent with code (1 s/block).** ~~Spec cited 403,200 blocks; code uses 2,419,200.~~ **Status: FIXED** — spec updated to cite 1 s/block (2,419,200 blocks) as the implementation default and note the governance-updateability (2026-04-17). | Fixed. |
| NF-004 | ~~Medium~~ | `CHANGELOG.md` | **CHANGELOG missing 8 medium fixes from commit `1da7b81`.** ~~F-010, F-012–F-015, F-017, F-020, F-021 were not in CHANGELOG.~~ **Status: FIXED** — entries added in previous audit cycle (2026-04-17). | Fixed. |
| F-022 | ~~Low~~ | `pqc-crypto/src/hash.rs` | **`unwrap_or(u64::MAX)` for length overflow with no comment.** ~~No explanation for the fallback path.~~ **Status: FIXED** — comment added explaining the infallibility on 64-bit platforms (2026-04-17). | Fixed. |
| F-023 | ~~Low~~ | `pqc-state/src/apply/validator.rs` | **`self_bond` truncated to `i64` in CBOR encoding.** ~~`encode_register_payload` cast `p.self_bond as i64`, silently truncating values > `i64::MAX`.~~ **Status: FIXED** — now encoded as 16-byte big-endian `bstr`; decoder updated to match; ADR-038 (2026-04-17). | Fixed. |
| F-024 | ~~Low~~ | `pqc-types/src/multisig.rs` | **No `// SAFETY:` comments in CBOR encoding helpers.** ~~Three bare `expect("CBOR encoding … is infallible")` calls in audit-scope code.~~ **Status: FIXED** — `// SAFETY:` comments added to all three (2026-04-17). | Fixed. |
| F-025 | Low | `pqc-crypto/benches/sig_verify.rs` | **Benchmark uses `expect()` in measured path.** `.expect("valid sig")` inside the measured closure. A verification failure would panic instead of counting as an error. | Acceptable for benchmarks; not production code. |
| F-026 | ~~Low~~ | `pqc-types/src/receipt.rs` | **`encode_receipt` lacked invariant guard.** ~~Could encode `status=success + error_code` without a warning.~~ **Status: FIXED** — `debug_assert!` added to catch the violation in debug builds (2026-04-17). | Fixed. |
| F-027 | ~~Low~~ | `pqc-state/src/apply/governance.rs` | **Silent skip on bad `alg_id` incorrectly marked `Executed`.** ~~`execute_registry_update` returned `void`; `tally_one` always set `Executed`.~~ **Status: FIXED** — `ProposalStatus::ExecutionFailed` variant added; `execute_registry_update` returns `bool`; serialized as `4` in all three storage sites; ADR-039 (2026-04-17). | Fixed. |
| F-028 | ~~Low~~ | `pqc-tx/src/error.rs` + `validate.rs` | **`BalanceInsufficient.fee` was `u64`, silent truncation risk.** ~~`tx.fee.saturating_add(tx.fee_tip)` used u64 arithmetic for the error field.~~ **Status: FIXED** — field changed to `u128`; call site uses `u128::from(fee) + u128::from(fee_tip)` (2026-04-17). | Fixed. |
| F-029 | ~~Low~~ | `Cargo.toml` | **License field was `"TBD"`.** ~~Unset license may cause issues with audit tools.~~ **Status: FIXED** — set to `"Apache-2.0"` (2026-04-17). | Fixed. |
| NF-006 | ~~Low~~ | `API.md` | **5 live devnet endpoints missing from Implemented Endpoints table.** ~~`/v1/status`, `/v1/fee-market`, `/v1/validators`, `/v1/blocks/{height}`, `/v1/metrics` were live but not in the table.~~ **Status: FIXED** — devnet-serve endpoint table added (2026-04-17). | Fixed. |
| F-030 | Info | All crates | **No TODO/FIXME/HACK comments in codebase.** Zero `TODO`/`FIXME`/`HACK` markers found. All known gaps are tracked in `TASKS.md` and `DECISIONS.md`. | Positive finding. |
| F-031 | Info | `pqc-state/src/apply/vault.rs:52-53` | **`valid_from_height` relaxation documented.** The spec deviation for the prototype path is recorded in both the code comment and `DECISIONS.md` (ADR-017). | No action needed. |
| F-032 | Info | `pqc-consensus/src/engine.rs` | **Full `StateStore::clone()` on every block assembly.** `build_next_block` clones the entire state store. At 10K accounts with ML-DSA-65 keys (~2.5 KB/key) this is ~25 MB per block. | Acceptable for Phase 6 devnet. Track as Phase 8 optimization: copy-on-write or snapshot-based approach. |
| F-033 | Info | `pqc-state/src/store.rs:601-683` | **O(N log N) state root per block.** `state_root()` sorts 10 leaf-hash collections per block. Acceptable at devnet scale (<100 validators, <1K accounts). | Track as Phase 8 optimization: incremental Merkle tree would eliminate the per-block sort. |
| F-034 | Info | `pqc-state/src/store.rs` | **No floating-point in state root path.** Confirmed: all state root computation uses integer arithmetic, SHAKE-256, and deterministic sorting. | Positive finding for determinism. |
| F-035 | Info | `pqc-crypto` | **No secret material in source files outside test fixtures.** Seeds and private keys appear only in `#[cfg(test)]` modules and benchmark harnesses. Production code handles seeds as opaque byte parameters. | Positive finding. |
| F-036 | Info | `pqc-crypto/src/verify.rs` | **Constant-time comparison used by ML-DSA.** The `ml-dsa` crate's `verify()` uses constant-time comparison internally. The wrapper maps all failure modes to a single `VerificationFailed` error — no timing side-channels introduced by the wrapper. | Positive finding. |
| NF-007 | ~~Info~~ | `AGENTS.md` | **AGENTS.md showed stale Phase 4 reference.** ~~File said "Phase 4 open"; project is in Phase 6.~~ **Status: FIXED** — updated to "Phase 6 — Operational Readiness (ADR-026, 2026-04-12)" (2026-04-17). | Fixed. |

---

## Phase 2 — Documentation Audit

### Spec Conformance

| Spec | Section | What Spec Says | What Code Does | Severity |
|------|---------|---------------|----------------|----------|
| SPEC-ADDRESS-001 | §2.4 | AlgId values: ML-DSA-44 = `0x0101`, etc. | **Fixed (F-002)** — spec now lists `0x0001`, `0x0002`, `0x0003`, `0x0010`, `0x0020`, `0x0100`. | ~~Critical~~ Resolved |
| SPEC-ADDRESS-001 | §2.2 | `raw_address = SHAKE-256(sig_alg_id_be16 \|\| pk_bytes, 32)` | **Fixed (F-017)** — `vault.rs` now calls `pqc_crypto::derive_address`. Both derivation paths unified. | ~~Medium~~ Resolved |
| SPEC-GOV-001 | §4.1 | Voting period = 1,000 blocks (reference) | Code uses `GOVERNANCE_VOTING_PERIOD = 5`. Devnet-only override; documented in code comment. Governance on-chain parameter update will address this. | **Medium** (F-018) open by design |
| SPEC-SLASH-001 | §9 Step 5 | Tombstone flag is permanently set | **Fixed (F-001 + NF-001)** — `tombstoned` included in leaf hash; `V2ToV3Handler` added to upgrade chain. | ~~Critical~~ Resolved |
| SPEC-SLASH-001 | §8.3 | 28 days at 6 s/block = 403,200 blocks | **Fixed (NF-003)** — spec updated to state 1 s/block (2,419,200 blocks = 28 days) as the implementation default. | ~~Medium~~ Resolved |
| SPEC-MULTISIG-001 | §13 | MultisigCreate / MultisigPolicyUpdate operations | **Fixed (F-010)** — dead apply module deleted; `pqc-types::multisig` retained for future wiring. | ~~Medium~~ Resolved |

### ADR Status Verification

All 37 ADRs in `DECISIONS.md` (ADR-001 through ADR-037; ADR-009 appears out of sequence at end of file) have statuses consistent with the codebase. Key observations:

- **ADR-031** (SoftwareUpgrade): Correctly implemented with `UpgradeHandler` chain. `V2ToV3Handler` added — NF-001 resolved.
- **ADR-030** (STATE_FORMAT_VERSION): `STATE_FORMAT_VERSION = 3` is correct; migration registry complete.
- **ADR-023** (Phase 4 exit): Accepted 2026-04-12. `AGENTS.md` updated to Phase 6 — NF-007 resolved.
- **ADR-026** (Phase 5 exit): Accepted. Project is currently in Phase 6.
- **ADR-020** (consensus key rotation gap): Correctly documented; gap is present in code as accepted.
- **ADR-024** (Slashing parameters): Matches constants in `slashing.rs` (5% slash, 28-day window). Block time assumption discrepancy documented in NF-003.

### CHANGELOG.md Completeness

Commit `1da7b81` fixed all prior findings. NF-004 (missing 8 CHANGELOG entries) was resolved in this session. CHANGELOG is now complete for all findings through this audit cycle.

### API.md Accuracy

The "Implemented Endpoints" table is now complete. The five `devnet-serve` endpoints (`/v1/status`, `/v1/fee-market`, `/v1/validators`, `/v1/blocks/{height}`, `/v1/metrics`) have been added in a separate table (NF-006 resolved).

`GET /v1/proofs/{anchor_id}` is live in `devnet-serve` mode but listed in the table as a `pqcd::api` endpoint — this is accurate since both routers expose it.

---

## Phase 3 — Architecture Review

### Hot Path Analysis

The critical path from tx submission to block inclusion is unchanged:

1. `POST /v1/txs` → `try_admit()` → `decode_tx()` → `validate_tx()` (15 steps) → pool insert
2. `assemble_block()` → `StateStore::clone()` → for each tx: `apply_tx()` → `settle_sender()` → `state_root()`

**Mutex contention**: `Arc<Mutex<LiveNodeState>>` with a single lock around entire state. Acceptable for devnet; needs sharding for multi-threaded production (Phase 8).

**Unnecessary clones**: `assemble_block` clones the entire `StateStore` (O(N) accounts). `Arc<[u8]>` optimization for `pk_bytes` mitigates the worst case. Dominant cost in block production.

**O(n) scans**: `state_root()` sorts 10 collections per block. `active_validators()`, `active_validator_count()`, and `consensus_key_in_use()` scan all validators. Acceptable at devnet scale.

### State Root Determinism

`state_root()` is deterministic: all leaf hash collections are sorted, domain-separated with unique prefixes (`PQC-ACCOUNT-LEAF-V1`, `VIPER-FEE-MARKET-V1`, `PQC-PROPOSAL-LEAF-V1`, `PQC-UPGRADE-LEAF-V1`, etc.), and hashed with SHAKE-256. No floating-point operations. No non-deterministic iteration (HashMap values are collected and sorted before hashing). Domain separators are consistent across `engine.rs`, `recovery.rs`, and snapshot restore paths.

**Fixed**: The `tombstoned` field is now included in `compute_validator_leaf_hash` (F-001). The version bump from 2 to 3 is recorded. The migration handler gap (NF-001) must be resolved before deployment.

### Error Handling

The error hierarchy is well-structured: `CryptoError` → `TxError` (wraps `KeyLookupError`) → `MempoolError` (wraps `TxError`) → `ApplyError`. All apply functions return `Result<(), ApplyError>`. No errors are silently swallowed.

Remaining `expect()` calls in production code (outside `#[cfg(test)]` blocks): two in `pqc-state/src/apply/validator.rs` (NF-002), one in `pqc-types/src/slashing.rs` (F-016), three in `pqc-types/src/multisig.rs` (F-024), six in `pqc-crypto/src/kem.rs` (F-012/NF-005 — all on statically fixed-size arrays, no runtime panic risk).

### Upgrade Safety

- `STATE_FORMAT_VERSION = 3` correctly reflects the tombstoned-field change.
- `UpgradeRegistry::run_migrations` chains handlers from disk version to binary version.
- `check_pending_upgrades` runs at the top of block application before any transaction.
- `SoftwareUpgrade` governance flow is complete: propose → vote → tally → schedule → enforce at activation height.
- **Gap (NF-001)**: `V2ToV3Handler` is missing from `global_registry()`. Nodes with version-2 checkpoints cannot migrate and will fail to start.

---

## Severity Summary

| Severity | Count | Notes |
|----------|-------|-------|
| Critical | 1 | NF-001 — missing V2→V3 migration handler (introduced by F-001 fix) |
| High | 0 | All 6 previous High findings resolved in commit `1da7b81` |
| Medium | 8 | F-011, F-012, F-016, F-018, F-019, NF-002, NF-003, NF-004 |
| Low | 10 | F-022 through F-029, NF-005, NF-006 |
| Info | 8 | F-030 through F-036, NF-007 |
| **Total** | **27** | Excludes 12 previously reported findings now marked Resolved |

### Resolution Delta Since 2026-04-16 Report

| Category | Previous | Resolved | New | Current Open |
|----------|----------|----------|-----|--------------|
| Critical | 2 | 2 | 1 | **1** |
| High | 6 | 6 | 0 | **0** |
| Medium | 12 | 8 | 4 | **8** |
| Low | 8 | 0 | 2 | **10** |
| Info | 8 | 0 | 1 | **8** |
| **Total** | **36** | **16** | **8** | **27** |
