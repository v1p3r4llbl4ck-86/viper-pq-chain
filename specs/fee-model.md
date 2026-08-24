# Fee Model Specification

**Spec ID**: SPEC-FEE-001  
**Version**: 0.2  
**Status**: Draft  
**History**: v0.1 2026-04-09; v0.2 banner 2026-04-25 for ADR-053 §T2.1 + §T2.2.  
**Date**: 2026-04-25  
**Depends on**: ADR-005 (fee model), ADR-011 (deprecation), ADR-015 (parameters deferred), ADR-053 §T2.1 (multi-dim fee market), ADR-053 §T2.2 (storage fund), SPEC-TX-001, SPEC-ACCOUNT-001, SPEC-FEE-002 (multi-dim revision)

> **Revision banner (2026-04-25)**: this spec covers the four price components per transaction (`base_fee`, `byte_fee`, `sigverify_fee`, `exec_fee`) and remains valid as the per-tx fee algebra. Two newer mechanisms layer on top:
> - **Multi-dimensional fee market** (ADR-053 §T2.1, TASK-201): the per-block `base_fee` is no longer a single scalar — it is a vector across `compute / storage / witness / contention` dimensions, each with its own EIP-4844 exponential update + reserve floor. See **SPEC-FEE-002 v0.2** for the dimension-level formulas. The per-tx `base_fee` of this spec is paid out of the `compute` dimension at apply-time.
> - **Storage fund** (ADR-053 §T2.2, TASK-199): on every state-creating tx (vault create, attestation submit, governance proposal, archival anchor), an upfront `bytes × perpetual_cost_per_byte` is contributed to the storage fund (state-delegated, refunded fractionally on deletion). This is **on top of** the per-tx fee in this spec, not in lieu of it. Code: `crates/pqc-state/src/storage_fund.rs`.
> 
> A v0.3 deeper revision will fold these two mechanisms into the body and re-derive the worked examples; until then read this spec alongside SPEC-FEE-002 v0.2.

> **Reserved — `token_economics` (parts of this spec).** The public chain `viper-testnet-1` has no native token. The fee algebra (§4–§11) stays in force as the admission and anti-DoS accounting of the node; `venom` is the unit of account of the reserved token design. The token-dependent parts — §12 fee distribution (proposer share, validator pool, burn) and the storage fund contribution described in the banner above — are implemented behind the `token_economics` Cargo feature, compiled out of the public chain build, and kept as a design reserve. Nothing in this document is an offer, a sale or a promise of any token or other asset.

---

## 1. Scope

This document specifies the PQ Chain fee model: the formula that determines the minimum fee a transaction must declare to be admitted to the mempool, how that fee is computed from its components, how algorithm lifecycle status affects pricing, and how nodes enforce fee rules as an anti-DoS control surface.

This specification defines fee structure and enforcement. It does not define:

- final numeric values for fee coefficients (`byte_fee`, `exec_fee_per_gas`, benchmark class fees) — deferred to Phase 2 after prototype measurements (ADR-015)
- per-operation gas costs — deferred to SPEC-OPS (TASK-007)
- staking rewards and fee distribution to validators — deferred to TASK-011
- the governance process for updating fee parameters — deferred to TASK-010

---

## 2. Normative Language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as described in RFC 2119.

---

## 3. Normative References

| Reference | Document |
|-----------|----------|
| ADR-005 | Price bytes and signature verification explicitly |
| ADR-011 | Four-step algorithm deprecation process |
| ADR-015 | Token economics model Phase 1, parameters Phase 2 |
| SPEC-TX-001 | Transaction Envelope Specification |
| SPEC-ACCOUNT-001 | Algorithm Registry — lifecycle status and `min_fee` field |

---

## 4. Fee Formula

The minimum fee a transaction MUST declare is:

```
min_fee = base_fee
        + byte_fee × tx_bytes
        + effective_sigverify_fee(sig_alg_id)
        + exec_fee_per_gas × gas_limit
```

A transaction MUST be rejected at mempool admission if `tx.fee < min_fee`.

### 4.1 Components

| Component | Prices | Governance-controlled |
|-----------|--------|-----------------------|
| `base_fee` | fixed per-transaction network overhead | yes |
| `byte_fee × tx_bytes` | bandwidth and storage cost of raw transaction bytes | yes (rate) |
| `effective_sigverify_fee(sig_alg_id)` | CPU cost of signature verification, adjusted for algorithm lifecycle | yes (via Registry `min_fee`) |
| `exec_fee_per_gas × gas_limit` | execution budget declared by the sender | yes (rate) |

### 4.2 tx_bytes Definition

`tx_bytes` is the byte length of the canonical CBOR encoding of the full transaction envelope, including the `signature` field. It is measured after encoding, not estimated from field declarations.

Nodes MUST compute `tx_bytes` from the received canonical bytes, not from a field in the envelope. A transaction where the declared or implied size is inconsistent with the actual encoding MUST be rejected as `ENCODING_ERROR` before fee evaluation.

### 4.3 Gas Model

`gas_limit` declares the maximum execution budget the sender authorizes. The fee formula prices the worst case: `exec_fee_per_gas × gas_limit`.

If execution consumes fewer gas units than `gas_limit`, the overpaid portion of `exec_fee_per_gas × (gas_limit - gas_used)` is refunded to the sender at finalization. The refund is credited to the sender's balance in the same block.

If execution reaches `gas_limit`, execution halts, state changes from that transaction are discarded, and the full `fee` is charged — no refund. This is the standard behavior: fee payment and execution are separate; running out of gas does not cancel the fee.

Per-operation gas costs are defined in §4.4 below. `exec_fee_per_gas` converts gas units to fee token units at the same 43.3 units/µs calibration rate used for signature verification fees (see §6.4).

### 4.4 Per-Operation Gas Schedule (TASK-007, resolved 2026-04-11)

Gas unit definition: **1 gas ≈ 1 µs of state-machine execution** on the Linux reference node (see SPEC-FEE-001 §6.4). Gas costs are derived from the block-production benchmarks: the empty-block baseline is ~7 µs; each additional state operation adds proportional cost for CBOR decode, balance/key/attestation write, and leaf-hash recompute.

`exec_fee_per_gas = 43` (floor of 43.3 units/µs, matching the sigverify calibration rate). Execution fees are intentionally small relative to signature verification.

| Operation | Gas units | Exec fee (at 43) | % of sigverify_fee_v_b (14 000) |
|-----------|-----------|------------------|---------------------------------|
| `token_transfer` | 5 | 215 | 1.5 % |
| `vault_create` | 10 | 430 | 3.1 % |
| `attestation_create` | 8 | 344 | 2.5 % |
| `key_add` | 12 | 516 | 3.7 % |
| `key_rotate` | 15 | 645 | 4.6 % |
| `key_revoke` | 10 | 430 | 3.1 % |
| `governance_proposal` | 18 | 774 | 5.5 % |

**Rationale**: gas costs are proportional to state complexity — `key_rotate` costs more than `key_add` because it performs a revoke plus an add; `governance_proposal` is highest because it updates both the registry entry and writes a receipt, triggering two leaf-hash recomputes. All values are implementation-stable constants in `pqc-state::gas_schedule`; governance can adjust `exec_fee_per_gas` but not per-op gas costs (those require a protocol upgrade).

**Sender gas_limit contract**: the sender declares `gas_limit ≥ op_gas` in the transaction. If `gas_limit < op_gas`, execution is reverted (state changes discarded) but the full `tx.fee` is charged. `exec_fee_per_gas × gas_limit` is priced at mempool admission; any overpayment (`gas_limit > gas_used`) is refunded at finalization.

---

## 5. Effective Signature Verification Fee

### 5.1 Derivation Rule

The effective signature verification fee for an algorithm is:

```
effective_sigverify_fee(alg_id) = max(benchmark_class_fee[sig_class(alg_id)], registry[alg_id].min_fee)
```

Where:

- `benchmark_class_fee[sig_class]` is the base verification fee for the algorithm's class, calibrated against benchmark measurements on reference hardware (see §6)
- `registry[alg_id].min_fee` is the floor set in the Algorithm Registry for this algorithm, updatable by governance
- the `max()` ensures that governance-imposed minimums always dominate; a raised `min_fee` cannot be undercut by the benchmark baseline

### 5.2 Purpose of the Two-Level Structure

**`benchmark_class_fee`** reflects the real resource cost of verifying a signature of this type. It is calibrated once per class during Phase 2, updated periodically as hardware evolves, and applies uniformly to all algorithms in the class.

**`registry.min_fee`** is a governance lever. For active algorithms it is set at or below the benchmark class fee and has no practical effect. When governance moves an algorithm to `discouraged`, it raises `min_fee` above the benchmark value to create economic pressure on users to migrate. The `max()` ensures this penalty is always visible in the required fee even if the base class fee would be lower.

### 5.3 Lifecycle State and Fee Admission

The algorithm lifecycle state determines whether a transaction is admitted at all, independent of fee:

| `lifecycle_status` | Mempool admission | Fee behavior |
|--------------------|------------------|--------------|
| `active` | allowed | `effective_sigverify_fee = max(benchmark_class_fee, registry.min_fee)` |
| `discouraged` | allowed | `effective_sigverify_fee = max(benchmark_class_fee, registry.min_fee)` where `registry.min_fee` has been raised above benchmark |
| `deprecated` | MUST be rejected (`UNSUPPORTED_ALGORITHM`) | no fee computed; rejection is pre-fee |
| `banned` | MUST be rejected (`UNSUPPORTED_ALGORITHM`) | no fee computed; rejection is pre-fee |

A `deprecated` or `banned` transaction MUST be rejected before any fee computation occurs. The node MUST NOT charge a partial fee and MUST NOT consume signature verification resources for rejected algorithms.

---

## 6. Signature Verification Fee Classes

Algorithms are grouped into verification fee classes based on their measured verification throughput and signature size. Class assignment is fixed at Algorithm Registry registration and is immutable.

### 6.1 Class Definitions

| Class | Name | Criteria | Phase 1 algorithms |
|-------|------|----------|--------------------|
| V-A | reduced | smaller signature than V-B standard; comparable or faster verification speed | FN-DSA-padded-512, FN-DSA-padded-1024 |
| V-B | standard | primary use class; calibrated for ML-DSA performance profile | ML-DSA-44, ML-DSA-65, ML-DSA-87 |
| V-C | premium | significantly slower verification or much larger signature than V-B; restricted-use algorithms | SLH-DSA-SHA2-128s, SLH-DSA-SHA2-192s |

### 6.2 Benchmark Reference (eBATS, Zen 4)

These are the external measurements that inform class calibration. They are not the fee values; they are the performance data from which fee values are derived.

| Algorithm | Class | Sig size | Verify throughput (single core) | Relative cost vs ML-DSA-65 |
|-----------|-------|----------|---------------------------------|---------------------------|
| ML-DSA-44 | V-B | 2,420 B | ~89,000 verify/s | 0.62× |
| ML-DSA-65 | V-B | 3,309 B | ~55,000 verify/s | 1.00× (reference) |
| ML-DSA-87 | V-B | 4,627 B | ~40,000 verify/s | 1.38× |
| FN-DSA-padded-512 | V-A | 666 B | ~62,000 verify/s | 0.89× |
| FN-DSA-padded-1024 | V-A | 1,280 B | ~45,000 verify/s | 1.22× |
| SLH-DSA-SHA2-128s | V-C | 7,856 B | ~951 verify/s | 57.8× |
| SLH-DSA-SHA2-192s | V-C | 16,224 B | ~520 verify/s | 105.8× |

The fee class calibration MUST be derived from real measurements on actual node hardware, not extrapolated from these figures alone. These numbers establish the order-of-magnitude relationship between classes and justify the V-A / V-B / V-C distinction.

### 6.3 Measured Performance — Prototype Node (TASK-039, 2026-04-10)

**Machine**: Windows 11 development workstation (release build, `--opt-level 3 --lto`). **Not** the reference Ubuntu VM; these are interim numbers pending Ubuntu VM re-run. Relative cost ratios are reliable; absolute verify/s figures will be higher on tuned Linux hardware.

**Crypto backend**: `ml-dsa` crate v0.1.0-rc.8 (pure-Rust FIPS 204). eBATS figures use assembly-backed implementations, so the absolute difference is expected.

#### Signature verification latency (Criterion, 100 samples each)

| Operation | Median latency | Throughput (1 core) | Relative cost vs ML-DSA-65 |
|-----------|---------------|---------------------|---------------------------|
| ML-DSA-44 verify | 163 µs | ~6,130 /s | 0.70× |
| ML-DSA-65 verify | 233 µs | ~4,290 /s | **1.00× (reference)** |
| ML-DSA-87 verify | 390 µs | ~2,564 /s | 1.67× |
| ML-DSA-65 key decode | 156 µs | — | hot-path overhead included in verify |
| ML-DSA-44 sign | 683 µs | ~1,464 /s | signing cost (validator commit path) |
| ML-DSA-65 sign | 582 µs | ~1,718 /s | signing cost (validator commit path) |
| ML-DSA-87 sign | 448 µs | ~2,232 /s | signing cost (validator commit path) |

#### Commit material (ML-DSA-65 over 45-byte preimage)

| Operation | Median latency | Notes |
|-----------|---------------|-------|
| Commit sign | 1.37 ms | one sign per validator per block; validators sign in parallel |
| Commit verify | 259 µs | one verify per commit sig per validator during full-node import |

#### SHAKE-256/32 hashing (tx_hash + state_root hot path)

| Input size | Median latency | Notes |
|------------|---------------|-------|
| 64 B | 0.997 µs | short tx body (no sig) |
| 256 B | 1.72 µs | representative tx preimage |
| 1,024 B | 4.04 µs | medium payload |
| 4,096 B | 17.1 µs | full ML-DSA-65 tx with sig (~3.3 KB) |

#### Block production throughput (state machine only, StubVerifier)

| Scenario | Median latency | Notes |
|----------|---------------|-------|
| Empty block (assembly + state_root + commit) | 11.6 µs | theoretical ceiling with no txs |
| 1 transfer tx per block | 20.7 µs | includes CBOR decode, balance apply, state_root |
| 10 sequential blocks (1 tx each) | 587 µs | ~58.7 µs/block at growing state |
| 50 sequential blocks (1 tx each) | 2.10 ms | ~42 µs/block |
| 100 sequential blocks (1 tx each) | 5.84 ms | ~58 µs/block |

#### State root scaling with account count

| Accounts | Median state_root cost | Notes |
|----------|----------------------|-------|
| 1 | 10.2 µs | per-block hash includes all accounts |
| 10 | 18.9 µs | |
| 100 | 112 µs | |
| 500 | 555 µs | |

**Key findings from prototype measurement:**

1. **V-B verify relative ratios are confirmed**: ML-DSA-44 at 0.70× and ML-DSA-87 at 1.67× match the eBATS ordering; the V-B class grouping is justified.
2. **Commit signing dominates the producer loop**: ~1.37 ms per block for commit signing (ML-DSA-65) on this machine, vs ~11.6 µs for the pure state machine. Real node latency will be dominated by ML-DSA signing, not block assembly.
3. **State root is O(n) in account count**: 10× accounts adds ~8.7 µs; this is linear in the number of accounts × average key count. At 500 accounts: ~555 µs per block just for state_root computation.
4. **SHAKE-256 is fast**: A full tx hash over 4 KB (ML-DSA-65 tx with sig) costs ~17 µs; this is not the bottleneck.

**Windows results are superseded by §6.4 Linux measurements** — the same pure-Rust ml-dsa crate produces different absolute throughput under different OS schedulers and CPU configurations. Relative ratios were confirmed stable; absolute token fee values were calibrated from the Linux numbers in §6.4.

### 6.4 Measured Performance — Reference Linux Node (TASK-042, 2026-04-11)

**Machine**: Linux 6.8.0-107-generic (Ubuntu VM, release build, `--opt-level 3 --lto`). This is the reference hardware for fee calibration. **Crypto backend**: `ml-dsa` crate v0.1.0-rc.8 (pure-Rust FIPS 204), same as §6.3.

#### Signature verification latency (Criterion, 100 samples each)

| Operation | Median latency | Throughput (1 core) | Relative cost vs ML-DSA-65 |
|-----------|---------------|---------------------|---------------------------|
| ML-DSA-44 verify | 202 µs | ~4,950 /s | 0.63× |
| ML-DSA-65 verify | 323 µs | ~3,096 /s | **1.00× (reference)** |
| ML-DSA-87 verify | 520 µs | ~1,923 /s | 1.61× |
| ML-DSA-65 key decode | 217 µs | — | hot-path overhead included in verify |
| ML-DSA-44 sign | 574 µs | ~1,742 /s | signing cost (validator commit path) |
| ML-DSA-65 sign | 629 µs | ~1,590 /s | signing cost (validator commit path) |
| ML-DSA-87 sign | 909 µs | ~1,100 /s | signing cost (validator commit path) |

#### Commit material (ML-DSA-65 over 45-byte preimage)

| Operation | Median latency | Notes |
|-----------|---------------|-------|
| Commit sign | ~1.4 ms | one sign per validator per block; validators sign in parallel |
| Commit verify | ~328 µs | one verify per commit sig per validator during full-node import |

Sign latency on the reference VM showed moderate variability under sustained load (thermal throttling); the median across a fresh 100-sample run is the authoritative value. Commit signing consistently dominates the block production loop.

#### SHAKE-256/32 hashing (tx_hash + state_root hot path)

| Input size | Median latency | Notes |
|------------|---------------|-------|
| 64 B | 1.26 µs | short tx body (no sig) |
| 256 B | 1.84 µs | representative tx preimage |
| 1,024 B | 5.06 µs | medium payload |
| 4,096 B | 17.3 µs | full ML-DSA-65 tx with sig (~3.3 KB) |

#### Block production throughput (state machine only, StubVerifier)

| Scenario | Median latency | Notes |
|----------|---------------|-------|
| Empty block (assembly + state_root + commit) | 7.0 µs | theoretical ceiling with no txs |
| 1 transfer tx per block | 18.2 µs | includes CBOR decode, balance apply, state_root |
| 10 sequential blocks (1 tx each) | 423 µs | ~42.3 µs/block at growing state |
| 50 sequential blocks (1 tx each) | 2.26 ms | ~45.2 µs/block |
| 100 sequential blocks (1 tx each) | 4.32 ms | ~43.2 µs/block |
| build_next_block (1 tx, no commit) | 20.6 µs | proposer hot path |

#### State root scaling with account count

| Accounts | Median state_root cost | Notes |
|----------|----------------------|-------|
| 1 | 8.1 µs | incremental leaf-hash cache (TASK-047) |
| 10 | 11.7 µs | |
| 100 | 59.8 µs | |
| 500 | 272 µs | |

**Key findings from Linux reference measurement:**

1. **V-B verify relative ratios confirmed on Linux**: ML-DSA-44 at 0.63× and ML-DSA-87 at 1.61× closely match the Windows provisional ratios (0.70× / 1.67×) and the eBATS ordering. V-A / V-B / V-C class distinction is justified.
2. **Calibration rate**: ~43.3 fee_units/µs on Linux (323 µs → `sigverify_fee_v_b = 14 000`), consistent with the 42.9 units/µs Windows provisional baseline.
3. **Linux verify is ~1.4× slower than Windows** on this pure-Rust backend (323 µs vs 233 µs for ML-DSA-65), likely due to VM CPU configuration vs a bare-metal development workstation. The fee values are calibrated to this hardware and therefore provide conservative anti-DoS headroom on faster hardware.
4. **Commit signing dominates the producer loop**: ~1.4 ms per block on this machine vs ~7 µs for pure block assembly. Real node block time at 500 ms is not bottlenecked by signing.
5. **State root is O(n) with leaf-hash cache**: the incremental TASK-047 redesign reduces state_root cost vs the old O(N×entity_size) path; 500 accounts now costs ~272 µs vs the earlier 555 µs.
6. **SHAKE-256 is not a bottleneck**: 4 KB tx hash costs ~17 µs.

**Concrete `FeeParams` derived from this run** (TBD-FEE-01 through TBD-FEE-06 resolved for Phase 3 testnet):

| Parameter | Value | Derivation |
|-----------|-------|-----------|
| `base_fee` | 500 | flat per-tx network overhead |
| `byte_fee` | 2 | bandwidth/storage pricing per byte |
| `sigverify_fee_v_a` | 8 800 | 14 000 × 0.625 (ML-DSA-44 proxy for FN-DSA) |
| `sigverify_fee_v_b` | 14 000 | 323 µs × 43.3 units/µs |
| `sigverify_fee_v_c` | 810 000 | 14 000 × 57.8 (eBATS SLH-DSA/ML-DSA-65 ratio) |
| `exec_fee_per_gas` | 43 | floor(43.3 units/µs), same calibration rate as `sigverify_fee_v_b`; per-op gas costs in §4.4 |

These values are deployed in `configs/single-node.json`, `configs/producer.json` (role `validator`), `configs/follower-a.json`, and `configs/follower-b.json` (role `full`). They are governance-mutable after testnet launch; initial values represent conservative anti-DoS baselines, not economic equilibrium prices.

### 6.5 Class Assignment Rules

- Class assignment is set when an algorithm is added to the Algorithm Registry
- Class assignment is immutable; it cannot be changed by governance
- If a new algorithm is added whose performance profile falls outside existing class criteria, a new class may be defined via a governance vote that also updates this specification

---

## 7. Byte Fee

### 7.1 Linear Rate

Byte cost is linear:

```
byte_cost = byte_fee × tx_bytes
```

A single `byte_fee` rate applies to all transactions regardless of operation type. Operation-specific storage costs (e.g. attestation record writes that persist beyond the transaction) are accounted for in execution gas, not in byte fee.

Rationale: a flat byte rate is the simplest model that correctly prices the marginal bandwidth and ephemeral storage cost of any transaction, without requiring operation awareness at the mempool layer.

### 7.2 Interaction with Signature Size

Because `tx_bytes` includes the signature bytes, algorithms with larger signatures pay proportionally more in byte fee. At `byte_fee = B`:

| Algorithm | Sig size | Byte cost contribution (sig only) |
|-----------|----------|----------------------------------|
| FN-DSA-padded-512 | 666 B | 666 × B |
| ML-DSA-44 | 2,420 B | 2,420 × B |
| ML-DSA-65 | 3,309 B | 3,309 × B |
| SLH-DSA-SHA2-128s | 7,856 B | 7,856 × B |

This creates a natural incentive to prefer algorithms with smaller signatures even before the verification fee class is considered.

### 7.3 Payload Size Contribution

The `payload` field contributes to `tx_bytes`. There is no separate payload fee; the byte rate is uniform. Operations with large payloads (e.g. anchoring a large metadata blob) pay more in byte fee. The `payload` size cap of 1 MB (SPEC-TX-001 §5.9) bounds the maximum byte cost contribution from payload.

---

## 8. Execution Fee

### 8.1 Gas Metering

Execution gas measures the computational and state-access cost of applying a transaction's operation. Gas is dimensionless within this spec; the fee comes from multiplying gas by `exec_fee_per_gas`.

```
exec_cost = exec_fee_per_gas × gas_used
```

where `gas_used ≤ gas_limit` at completion.

### 8.2 Per-Operation Gas Costs

Per-operation gas schedules (vault operations, attestation anchoring, key rotation, etc.) are defined in SPEC-OPS (TASK-007). This document specifies only that:

- gas consumption is metered per operation type
- if `gas_used` reaches `gas_limit` mid-execution, execution halts and state changes are discarded
- the declared `gas_limit` is the maximum the sender is willing to pay; underuse is refunded, overuse halts execution

### 8.3 Minimum Gas Limit

A minimum `gas_limit` floor MAY be enforced at mempool admission to prevent zero-gas transactions that could be used to probe mempool state cheaply. This floor is a governance parameter (TBD, Phase 2).

---

## 9. Fee Admission Pipeline

Fee checks MUST be performed in this order within the broader validation pipeline defined in SPEC-TX-001 §10. Steps 9–13 of that pipeline (structural and cryptographic checks) MUST complete before fee evaluation begins.

### 9.1 Step 1 — Lifecycle Pre-Check

Before computing any fee, check `registry[tx.sig_alg_id].lifecycle_status`:

- `active` or `discouraged` → proceed to fee computation
- `deprecated` or `banned` → reject immediately with `UNSUPPORTED_ALGORITHM`; do not compute or charge fee

This step MUST precede signature verification to avoid spending CPU on algorithms that will be rejected regardless.

### 9.2 Step 2 — Compute min_fee

```
tx_bytes = len(canonical_cbor_bytes)
sig_class = registry[tx.sig_alg_id].sig_class
benchmark_fee = benchmark_class_fee[sig_class]
effective_sigverify = max(benchmark_fee, registry[tx.sig_alg_id].min_fee)
min_fee = base_fee + byte_fee × tx_bytes + effective_sigverify + exec_fee_per_gas × tx.gas_limit
```

### 9.3 Step 3 — Fee Sufficiency Check

```
tx.fee >= min_fee
```

If this condition fails, reject with `INSUFFICIENT_FEE`. The rejection MUST include sufficient diagnostic information for the sender to compute the correct fee (recommended: return `min_fee` in the rejection response).

### 9.4 Step 4 — Balance Check

```
sender.balance >= tx.fee + tx.fee_tip
```

If the sender does not have sufficient liquid balance, reject with `INSUFFICIENT_BALANCE`. Locked stake does not count toward liquid balance.

### 9.5 Ordering of Rejection vs Resource Use

The fee admission pipeline is designed to minimize wasted node resources:

1. Structural CBOR checks (cheap) — before any crypto or state work
2. Lifecycle pre-check (one registry lookup) — before signature verification
3. Signature verification (expensive crypto) — before state reads
4. Fee and balance checks (state reads) — after signature is confirmed valid

This ordering ensures that the most expensive operations (crypto verification, state reads) are only reached for transactions that pass all cheaper checks. Underpriced transactions are rejected before consuming signature verification CPU where possible — but signature verification MUST precede the final fee and balance check to prevent an attacker from submitting valid-looking headers with garbage signatures and forcing repeated state reads.

---

## 10. Mempool Rate Limiting

In addition to per-transaction fee sufficiency, nodes MAY enforce the following mempool-level rate limits as anti-DoS measures. These are node policy, not consensus rules; different nodes may apply different limits.

### 10.1 Per-Sender Verify Budget

A node MAY track cumulative `effective_sigverify_fee` consumed by a single sender in a rolling time window (e.g. 60 seconds). If a sender's cumulative verify budget is exceeded, subsequent transactions from that sender MAY be rejected with `RATE_LIMITED` until the window resets.

This limit protects against a single sender spamming expensive-to-verify transactions (particularly V-C class algorithms) that consume CPU even though each transaction individually meets the fee floor.

### 10.2 Per-Algorithm Admission Throttle

A node MAY cap the number of transactions using V-C class algorithms (SLH-DSA) admitted to the mempool per block interval. Given that SLH-DSA verification throughput is ~951 verify/s per core, a burst of SLH-DSA transactions can saturate verification capacity even at "correct" fee levels if the overall rate is unconstrained.

The recommended per-block SLH-DSA cap: `⌊(verify_budget_per_block × fraction_for_V-C) / SLH-DSA_verify_time⌋`. The `verify_budget_per_block` and `fraction_for_V-C` are node configuration parameters (TBD, Phase 2 calibration).

### 10.3 Global Mempool Pressure Signal

When the mempool is under pressure (size near capacity), a node SHOULD apply a higher effective `base_fee` floor for admission decisions. This is a dynamic mechanism that creates fee market pressure without requiring a protocol-level base fee auction. The mechanics of this dynamic fee floor are node implementation choices and are not consensus-normative.

---

## 11. Transaction Replacement Policy

A transaction in the mempool with `(sender, nonce)` MAY be replaced by a new transaction with the same `(sender, nonce)` if:

- `new_tx.fee ≥ old_tx.fee × 1.10` (at least 10% higher fee)
- `new_tx.fee_tip ≥ old_tx.fee_tip` (tip MUST NOT decrease)
- the new transaction passes all validation steps from SPEC-TX-001 §10 and §11

A replacement that meets these conditions MUST evict the old transaction and admit the new one. A replacement that does not meet these conditions MUST be rejected with `REPLACEMENT_UNDERPRICED`.

Rationale: the 10% bump requirement prevents free mempool churning where a sender repeatedly replaces transactions at negligible cost to manipulate ordering.

---

## 12. Fee Distribution

At finalization, the fee collected from a transaction is distributed as follows:

- **Block proposer share**: a portion of `tx.fee + tx.fee_tip` (split TBD, Phase 2)
- **Validator pool share**: the remainder of `tx.fee` is distributed among all validators who signed the commit for that block
- **Burned share**: a portion MAY be burned as a deflation mechanism (TBD, Phase 2 policy decision)

The exact split is a governance parameter and is deferred to TASK-011. This specification only establishes that fee distribution is a protocol operation that occurs at finalization, not at mempool admission.

The execution fee refund (`exec_fee_per_gas × (gas_limit - gas_used)`) is credited to the sender's balance before fee distribution. The refunded amount is NOT distributed to validators.

---

## 13. Registry Interaction Summary

This table summarizes how Algorithm Registry state interacts with the fee model:

| Scenario | `lifecycle_status` | `registry.min_fee` vs benchmark | Fee behavior |
|----------|--------------------|---------------------------------|-------------|
| Normal operation | `active` | at or below benchmark | `effective_sigverify_fee = benchmark_class_fee` |
| Governance signals concern | `active` | raised above benchmark | `effective_sigverify_fee = registry.min_fee` (penalty active) |
| Governance discourages | `discouraged` | significantly above benchmark | `effective_sigverify_fee = registry.min_fee` (penalty active); new keys blocked |
| Governance deprecates | `deprecated` | irrelevant | transaction REJECTED before fee computation |
| Governance bans | `banned` | irrelevant | transaction REJECTED before fee computation |

Raising `registry.min_fee` while `lifecycle_status = active` is the early warning signal: the algorithm is still usable, but the economic incentive to migrate is already present. This is the intended use of `min_fee` as a governance tool.

---

## 14. Security Considerations

### 14.1 Fee Model as DoS Control Surface

The fee formula is a security mechanism, not only an accounting model. Each component defends a specific attack surface:

| Fee component | Attack it defends against |
|---------------|--------------------------|
| `base_fee` | trivial transaction spam with near-zero operational content |
| `byte_fee × tx_bytes` | bandwidth flooding with large transactions; oversized payloads |
| `effective_sigverify_fee` | CPU exhaustion via expensive-to-verify signatures (especially V-C class) |
| `exec_fee_per_gas × gas_limit` | execution DoS via computationally expensive operations |

Removing or zeroing any component creates the corresponding attack surface. All components MUST be active from the first testnet.

### 14.2 V-C Class Attack Amplification

SLH-DSA verification is approximately 58× more expensive than ML-DSA-65 on reference hardware. Without a correctly calibrated `V-C` fee class, an attacker could submit transactions that consume ~58× more verification CPU per fee unit than standard transactions. The V-C premium class and the per-algorithm admission throttle (§10.2) are the two mitigations that together prevent this attack from being economically viable.

### 14.3 Fee Undercutting via Discouraged Algorithms

If `effective_sigverify_fee = max(benchmark, min_fee)` were not enforced and only the raw benchmark fee applied, then as governance raises `min_fee` for a discouraged algorithm, a sender could bypass the penalty by declaring a fee that covers only the benchmark class cost. The `max()` derivation rule makes this impossible: any `min_fee` above the benchmark is always reflected in the required transaction fee.

### 14.4 Rejection Before Verification for Deprecated/Banned Algorithms

Checking `lifecycle_status` before signature verification ensures that a spam attack using deprecated algorithm headers does not consume signature verification CPU. The lifecycle check is a single in-memory registry lookup; signature verification requires significant compute. Ordering matters.

### 14.5 Gas Limit as Execution Budget, Not Fee Overpayment

The fee formula uses `gas_limit` (the declared maximum), not `gas_used` (the actual consumption), to compute the required minimum fee. This is intentional: the node cannot know `gas_used` before executing, and requiring payment for the declared worst-case budget prevents a class of abuse where senders declare very low gas limits to minimize required fee while actually consuming more resources (the transaction would abort, but the setup cost is real).

---

## 15. Open TBDs (Phase 3)

TBD-FEE-01 through TBD-FEE-06 were resolved by the Linux reference benchmark (TASK-042, 2026-04-11). See §6.4 for the concrete values deployed in runnable configs.

| ID | Parameter | Status |
|----|-----------|--------|
| TBD-FEE-01 | `base_fee` value | **Resolved** → 500 (§6.4) |
| TBD-FEE-02 | `byte_fee` rate | **Resolved** → 2 (§6.4) |
| TBD-FEE-03 | `benchmark_class_fee[V-A]` | **Resolved** → 8 800 (§6.4) |
| TBD-FEE-04 | `benchmark_class_fee[V-B]` | **Resolved** → 14 000 (§6.4) |
| TBD-FEE-05 | `benchmark_class_fee[V-C]` | **Resolved** → 810 000 (§6.4, eBATS ratio) |
| TBD-FEE-06 | `exec_fee_per_gas` rate | **Resolved** → 1 placeholder (§6.4; update after TASK-007) |
| TBD-FEE-07 | Per-operation gas schedules | Open — deferred to SPEC-OPS (TASK-007) |
| TBD-FEE-08 | Minimum `gas_limit` floor | Open |
| TBD-FEE-09 | Per-sender verify budget window and cap | Open — node policy; Phase 3 calibration |
| TBD-FEE-10 | V-C per-block cap and `verify_budget_per_block` | Open — node policy; Phase 3 calibration |
| TBD-FEE-11 | Fee distribution split (proposer / validator pool / burn) | Open — deferred to TASK-011 |
| TBD-FEE-12 | Dynamic mempool pressure floor mechanics | Open — node implementation choice |
