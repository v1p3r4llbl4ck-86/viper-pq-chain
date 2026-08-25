# Fee Market Specification

**Spec ID**: SPEC-FEE-002
**Version**: 0.2
**Status**: Accepted
**Date**: 2026-04-25
**Depends on**: SPEC-FEE-001, ADR-053 §T2.1, ADR-053 §T2.2, ADR-022, ADR-032, ADR-024, ADR-019, ADR-031, SPEC-GOV-001, SPEC-TX-001
**Implementing TASK**: TASK-201 (commit `a8e94e4`); storage-fund framework TASK-199 (commit `eaa4b4d`)

> **Reserved — `token_economics` (parts of this spec).** The public chain `viper-testnet-2` has no native token. The multi-dimensional base-fee market (§5–§8, §10–§12, §14) is active as the node's admission and anti-DoS accounting. The token-dependent parts — §9 fee distribution and burn, and the §13 storage fund — are implemented behind the `token_economics` Cargo feature, compiled out of the public chain build, and kept as a design reserve. The launch parameters and worked examples in §6 are those fixed for the retired `viper-pq-1` chain; the `viper-testnet-2` values are assigned at genesis. Nothing in this document is an offer, a sale or a promise of any token or other asset.

---

## Revision history

| Version | Date | Notes |
|---------|------|-------|
| 0.1 | 2026-04-15 | Single-dimension AIMD adaptive base fee, status `Proposed`. Preserved as Appendix C ("Historical (pre-launch) approach"). |
| 0.2 | 2026-04-25 | Promoted to `Accepted`. Replaces single-dim AIMD with the **multi-dimensional EIP-4844 exponential** market that shipped at the `viper-pq-1` launch (ADR-053 §T2.1 / TASK-201). Adds storage-fund cross-reference (ADR-053 §T2.2). Worked example reflects the live launch parameters. |

---

## 1. Scope

This document specifies the multi-dimensional EIP-4844-style adaptive fee market for Viper PQ Chain, first activated at the `viper-pq-1` launch (chain since retired). It supersedes the static `base_fee` defined in SPEC-FEE-001 §4 *and* the v0.1 single-dim AIMD draft of this same SPEC ID, while preserving all other fee components (byte fee, signature verification fee, execution gas fee) unchanged.

This specification defines:

- the four fee-market dimensions (compute, storage, witness, contention)
- the per-dimension EIP-4844 exponential base-fee update with non-zero reserve floor
- per-dimension targets, limits, update fractions, and reserve floors
- per-msg_type fee lanes and their multipliers
- the burn mechanism and its phase activation model
- interaction with the existing fee distribution model (ADR-019)
- StateStore changes, serde layout, and backward-compatibility defaults
- error codes, API surface, and implementation checklist
- cross-reference to the storage fund (ADR-053 §T2.2)

This specification does **not** redefine:

- byte fee, signature verification fee, or exec gas fee (governed by SPEC-FEE-001 §4)
- static fee coefficient values (ADR-024 §7)
- the governance proposal lifecycle (SPEC-GOV-001)
- the transaction envelope format (SPEC-TX-001)
- the storage-fund accounting model itself (cross-ref §13 / ADR-053 §T2.2)

---

## 2. Normative Language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as described in RFC 2119.

---

## 3. Normative References

| Reference | Document |
|-----------|----------|
| SPEC-FEE-001 | Static fee model: base fee, byte fee, sigverify fee, exec gas fee |
| ADR-005 | Price bytes and signature verification explicitly |
| ADR-019 | Phase 3 fee distribution: proposer share + validator pool split |
| ADR-022 | Proposer priority share rationale |
| ADR-024 | Viper token economics: fixed supply, genesis distribution, staking parameters |
| ADR-031 | On-chain governance module: proposal lifecycle, stake-weighted voting |
| ADR-032 | AIMD fee market — superseded by ADR-053 §T2.1 for the compute dimension formula |
| ADR-053 §T2.1 | Multi-dimensional EIP-4844 exponential fee market with non-zero reserve floor |
| ADR-053 §T2.2 | Storage fund (Sui-style upfront perpetual storage) |
| EIP-4844 | Ethereum blob fee market — academic reference for the exponential update formula |
| EIP-7918 | 2024 reserve-floor lesson — base fee must not be allowed to reach zero |
| SPEC-GOV-001 | Governance specification |
| SPEC-TX-001 | Transaction envelope specification |

---

## 4. Motivation

### 4.1 Problem with Static Fees

SPEC-FEE-001 uses a static `base_fee` stored in `FeeParams`. Static fees are predictable but not adaptive: a sudden traffic spike does not raise fees, creating a spam vector; a quiet period does not lower fees, creating friction for legitimate users. Governance response to traffic spikes is too slow to be effective as an anti-spam mechanism.

### 4.2 Why EIP-4844 exponential, not AIMD

The v0.1 draft of this SPEC chose AIMD (additive increase, multiplicative decrease) following Cosmos `x/feemarket`. ADR-053 §T2.1 reversed that choice for three reasons that emerged from the 2024 EIP-7918 analysis:

1. **AIMD has no closed-form excess accumulator.** Each block's update is a function of the previous block's fee, not of an excess gauge that grows / shrinks over a window. Under sustained load, AIMD reacts geometrically per block rather than per accumulated excess, which makes the steady-state fee a function of block cadence — adversarial proposers can oscillate empty/full blocks to keep the fee artificially low.
2. **EIP-4844's `fake_exponential(reserve_floor, excess, reserve_floor × update_fraction)` has been proved sound under blob load** and is now production-tested across two years of Ethereum mainnet. The Taylor-series implementation in `crates/pqc-state/src/store.rs:330-352` (`fake_exponential`) is the same algorithm, in `u128` to avoid overflow.
3. **EIP-7918 ($78 M revenue miss on Ethereum)** demonstrated that allowing the base fee to drop to zero — which AIMD does in extended idle periods absent a `BASE_FEE_MIN` clamp — is an economic vulnerability, not a feature. ADR-053 §T2.1 makes the per-dimension `reserve_floor` **ungovernable to zero**: there is no on-chain knob to lower it, and governance proposals attempting to do so MUST be rejected at decode time.

### 4.3 Why four dimensions

EIP-4844 (Ethereum, 2024) introduced a separate fee market per resource type (blob fee vs. execution fee). The insight: different workloads have different supply curves. Coupling attestation fees to validator registration fees is economically incorrect.

Viper PQ Chain has an asymmetric workload that justifies a **structurally** four-dimensional model:

- **`compute`** — gas consumed by tx execution. The only dimension wired to real tx activity at launch.
- **`storage`** — bytes × epoch-lifetime growth of long-term state. Reserved at launch (`target = 0`); activation under P-COMPAT-001 will price upfront state-creation in concert with the storage fund (§13).
- **`witness`** — witness size in ePBS-ready blocks. Reserved at launch; activation lands with stateless-client / SPEC-STATELESS work.
- **`contention`** — per-account hot-spot pricing (Solana-style local fee markets). Reserved at launch; activation lands with the per-account scheduler.

Reserved dimensions carry `target = 0` so `excess` can never accumulate (`saturating_sub(prev_excess + 0, 0) = prev_excess` → still pinned at floor since `excess` never grows from zero load), and their `base_fee` stays pinned at `reserve_floor`. The data model is fixed at genesis (ADR-053 §T2.1) so a future activation does not require a state-format migration.

### 4.4 Viper-Specific Rationale

Viper PQ Chain has an asymmetric workload: `attestation_create` dominates by count, while `validator_register` and `governance_propose` are rare but expensive. A single adaptive base fee conflates these. Fee lanes (§7) and per-dimension pricing (§6) together prevent a burst of attestation traffic from pricing out governance participation, and vice versa.

The fixed 1B VPR supply (ADR-024) has no inflation. Without a burn mechanism, the supply is permanently constant. The phased burn model (Phase 9+) introduces mild deflationary pressure proportional to usage. The launch implementation activates the algorithm without burning — validators receive 100 % of fees, preserving the current economic model during the transition period.

---

## 5. Block Gas Limit

### 5.1 Definition

The **compute block gas limit** (`fee_market.compute.limit`) is the maximum number of gas units that may be consumed by all transactions in a single block. It is a consensus-layer parameter for the compute dimension.

A block MUST be rejected at validation if `sum(tx.gas_used for tx in block) > compute.limit`.

Block assemblers MUST NOT include a transaction that would cause cumulative gas to exceed `compute.limit`.

### 5.2 Initial Value

| Parameter | Initial Value |
|-----------|--------------|
| `compute.limit` (block gas limit) | 10,000,000 gas units |
| `compute.target` | 5,000,000 gas units (50 % of limit, EIP-4844 convention) |

The constant `DEFAULT_BLOCK_GAS_LIMIT = 10_000_000` is defined in `crates/pqc-state/src/store.rs:188`; `DEFAULT_COMPUTE_TARGET = DEFAULT_BLOCK_GAS_LIMIT / 2` at line 202.

### 5.3 Governance

`compute.limit` and `compute.target` are governance parameters. They MAY be adjusted via a `FeeParamUpdate` governance proposal (SPEC-GOV-001). Changes take effect at the next epoch boundary after proposal execution. Reserved dimensions' `limit` / `target` ride the same path; activating a reserved dimension means promoting `target` from 0 to a non-zero value.

### 5.4 Gas Schedule Reference

The current msg_type gas costs (SPEC-OPS-001) are:

| MsgType | Gas units |
|---------|-----------|
| `token_transfer` | 10 |
| `attestation_create` | 43 |
| `validator_register` | 50 |
| `governance_propose` | 20 |
| Other | per SPEC-OPS-001 |

These are distinct from the `exec_fee_per_gas` coefficient. Gas units measure resource consumption; `exec_fee_per_gas × gas_units` prices that consumption in venom.

---

## 6. Multi-Dimensional EIP-4844 Adaptive Base Fee

### 6.1 Overview

The `FeeMarketState` (`crates/pqc-state/src/store.rs:276-289`) carries four `FeeMarketDimension` records — `compute`, `storage`, `witness`, `contention` — plus a top-level `burn_rate_bps`. Each dimension is updated once per block during `apply_fee_market_step()` (line 1782) after every `apply_tx` call and after `distribute_block_fees`, and before `advance_height()`.

Per-dimension state:

| Field | Semantics |
|-------|----------|
| `base_fee: u64` | Current adaptive base fee for this dimension (venom). Output of the EIP-4844 exponential update, clamped to `[reserve_floor, BASE_FEE_MAX]`. |
| `limit: u64` | Hard per-block cap, governance-tunable. |
| `target: u64` | EIP-4844 target per-block utilisation. Zero disables the dimension (see §4.3). |
| `excess: u64` | Accumulated excess usage (`used − target`, floored at 0) since the last under-utilised block. |
| `reserve_floor: u64` | Non-zero reserve-price floor; ungovernable-to-zero (ADR-053 §T2.1, EIP-7918 lesson). |
| `update_fraction: u64` | EIP-4844 update fraction; controls reactivity of the exponential curve. Higher means slower growth per unit of excess. |

The compute dimension is wired to `block_gas_used`. Reserved dimensions receive `0` and stay pinned at their floor.

### 6.2 Per-dimension Update Formula

For each dimension `d` and per-block usage `used_d`:

```
new_excess_d = saturating_sub(prev_excess_d + used_d, target_d)
new_base_fee_d = clamp(
    fake_exponential(reserve_floor_d, new_excess_d, reserve_floor_d × update_fraction_d),
    reserve_floor_d,
    BASE_FEE_MAX,
)
```

Where:

- `fake_exponential(factor, numerator, denominator)` computes a Taylor-series approximation of `factor × e^(numerator / denominator)` in `u128` (`crates/pqc-state/src/store.rs:330-352`). The series converges in < 30 iterations for realistic inputs and is hard-bounded at 128 iterations.
- `BASE_FEE_MAX = 10_000_000` venom (`crates/pqc-state/src/store.rs:185`) — the global ceiling on any single dimension.
- `clamp(..)` is `(x.max(reserve_floor)).min(BASE_FEE_MAX)`.

The reserve floor is enforced at compile time. `COMPUTE_RESERVE_FLOOR = 100` (line 179) is a `pub const` — there is no on-chain knob to drive it below this constant. Governance proposals that attempt to lower a dimension's `reserve_floor` to zero MUST be rejected.

### 6.3 Launch parameters (compute dimension, as fixed for `viper-pq-1`)

Mirror of `FeeMarketDimension::compute_default()` (`crates/pqc-state/src/store.rs:238-247`):

| Parameter | Constant | Value |
|-----------|---------|-------|
| `base_fee` (initial) | `DEFAULT_BASE_FEE` | 0 → clamped to 100 on first update |
| `limit` | `DEFAULT_BLOCK_GAS_LIMIT` | 10,000,000 |
| `target` | `DEFAULT_COMPUTE_TARGET` | 5,000,000 |
| `excess` (initial) | — | 0 |
| `reserve_floor` | `COMPUTE_RESERVE_FLOOR` | 100 venom |
| `update_fraction` | `COMPUTE_FEE_UPDATE_FRACTION` | 3,338,477 (matches EIP-4844 `BLOB_BASE_FEE_UPDATE_FRACTION`) |

Reserved dimensions (`storage`, `witness`, `contention`) are constructed via `FeeMarketDimension::reserved_default(COMPUTE_RESERVE_FLOOR)` (line 253-262): `base_fee = 100`, `limit = 0`, `target = 0`, `excess = 0`, `reserve_floor = 100`, `update_fraction = 1`. Per the historical genesis JSON at `deploy/ansible/files/genesis-viper-pq-1.json`, `_status: "reserved"`.

### 6.4 Worked Example A — empty block at genesis (compute dimension)

```
prev_excess = 0
used_compute = 0
new_excess = saturating_sub(0 + 0, 5_000_000) = 0
denom = reserve_floor × update_fraction = 100 × 3_338_477 = 333_847_700
raw = fake_exponential(100, 0, 333_847_700) = 100   // numerator = 0 ⇒ returns factor unchanged
new_base_fee = clamp(100, 100, 10_000_000) = 100
```

The compute base fee remains at the reserve floor of 100 venom — observable on any node at `GET /v1/fee-market` (`compute.base_fee = 100`, `excess = 0`).

### 6.5 Worked Example B — full block (compute dimension, single iteration)

```
prev_excess = 0
used_compute = 10_000_000 (full block)
new_excess = saturating_sub(0 + 10_000_000, 5_000_000) = 5_000_000
denom = 100 × 3_338_477 = 333_847_700
raw = fake_exponential(100, 5_000_000, 333_847_700)
    ≈ 100 × e^(5_000_000 / 333_847_700)
    ≈ 100 × e^0.01497
    ≈ 100 × 1.01509
    ≈ 101 (after integer truncation in the Taylor series)
new_base_fee = clamp(101, 100, 10_000_000) = 101
```

A single full block raises the compute base fee by ≈ 1 venom. The exponential curve is mild per block and aggressive in aggregate; sustained full blocks at the launch parameters double the fee in roughly `ln(2) × (target / used_above_target) × update_fraction / target ≈ 46` blocks.

### 6.6 Worked Example C — end-to-end fee on the multi-dim model (`viper-pq-1` launch parameters)

This worked example pins the calculation that an external client must reproduce to compute `min_fee` for a transaction submitted at the `viper-pq-1` launch parameters.

**Inputs**:

- `msg_type = TokenTransfer` (lane `standard`, multiplier 10,000 bps = 1.0×)
- `tx.gas_limit = 5_000`
- `tx_raw_bytes = 200`
- `tx.sig_alg_id = 0x0002` (ML-DSA-65 → `SigClass::Standard` → `sigverify_fee_v_b`)
- Witness / contention dimensions: reserved at floor (no contribution)

**Genesis fee parameters**:

- `compute.base_fee = 100` venom (reserve floor — see Example A)
- `byte_fee = 2` venom/byte (SPEC-FEE-001 §6.4)
- `sigverify_fee_v_b = 14_000` venom (SPEC-FEE-001 §6.4)
- `exec_fee_per_gas = 43` venom/gas (SPEC-FEE-001 §6.4)
- `lane_multiplier_bps[standard] = 10_000`

**Per-dimension contribution**:

| Dimension | Calculation | Contribution (venom) |
|-----------|-------------|---------------------:|
| compute base × lane multiplier | 100 × 10_000 / 10_000 | 100 |
| byte | 2 × 200 | 400 |
| sigverify | 14_000 × 1 | 14,000 |
| exec | 43 × 5_000 | 215,000 |
| storage (reserved) | 0 (target = 0, no real-tx wiring) | 0 |
| witness (reserved) | 0 | 0 |
| contention (reserved) | 0 | 0 |
| **min_fee total** | sum | **229,500 venom** |

A `TokenTransfer` of 200 bytes with `gas_limit = 5_000` MUST carry `tx.fee >= 229_500` to be admitted to the mempool.

The same call shape is what `pqcd::devnet::handle_fee_market` and the SDK fee estimator (`sdk-ts/src/fee.ts`, `sdk-py/viper_sdk/fee.py` v0.2.0) reproduce client-side.

### 6.7 When the Update Runs

`advance_height()` in `crates/pqc-state/src/store.rs` MUST call `apply_fee_market_step(compute_used, storage_used, witness_used, contention_used)` after:

1. All transactions in the block are applied (`apply_tx` for each tx).
2. Fee distribution is performed (`distribute_block_fees`).

And before:

3. `advance_height()` writes the new block header to StateStore.

At launch, only `compute_used = block_gas_used` is non-zero; `storage_used / witness_used / contention_used` are passed as `0` until the corresponding P-COMPAT-001 activations land. The backward-compatible alias `apply_aimd_update(block_gas_used)` (line 1806) drives the compute dimension only and is retained for engine / recovery callers.

---

## 7. Fee Lanes

### 7.1 Lane Definitions

Each transaction is assigned to exactly one fee lane based on its `msg_type`. The lane determines the base fee multiplier applied at mempool admission and block assembly. Mirrors `lane_multiplier_bps` in `crates/pqc-tx/src/validate.rs:65-73`:

| Lane | MsgTypes | Base Fee Multiplier |
|------|----------|---------------------|
| `standard` / `attestation` / `system` | `token_transfer`, `key_add`, `key_rotate`, `key_revoke`, `attestation_create`, `attestation_revoke`, `proof_anchor`, `governance_deposit`, `governance_vote`, `submit_equivocation_evidence` | 1.0× (10,000 bips) |
| `heavy` | `validator_register`, `validator_exit`, `governance_propose` | 2.0× (20,000 bips) |

The `heavy` lane uses a 2.0× multiplier because `validator_register`, `validator_exit`, and `governance_propose` consume significantly more state resources and impose coordination costs on the validator set that do not scale with gas units alone.

### 7.2 Effective Lane Multiplier (Fixed-Point)

The effective base fee for a transaction in lane `L` is:

```
effective_base_fee(L) = compute.base_fee × lane_multiplier_bps(L) / 10_000
```

Intermediate multiplication MUST be computed in `u128` (see `crates/pqc-tx/src/validate.rs:80-89`) to avoid overflow when the heavy lane meets `BASE_FEE_MAX`.

### 7.3 Lane Assignment

`msg_type` to lane assignment MUST be deterministic and identical on all nodes. The mapping is embedded in the protocol as a match arm in `lane_multiplier_bps` (`crates/pqc-tx/src/validate.rs:65`). The mapping is NOT a governance parameter — changes require a hard fork.

Lane multipliers (`lane_multiplier_bps`) ARE governance parameters, adjustable via `FeeParamUpdate` proposals. Such proposals change only the multiplier, not the lane assignment table.

### 7.4 Unknown MsgTypes

If a transaction carries a `msg_type` not present in the `MsgType` enum, the node MUST reject the transaction at decode time with `MsgTypeUnknown` (SPEC-TX-001 §10 step 4). There is no default lane.

---

## 8. Complete Fee Formula

### 8.1 Minimum Required Fee at Mempool Admission

```
lane     = lane_assignment(tx.msg_type)
eff_base = compute.base_fee × lane_multiplier_bps(lane) / 10_000

min_fee = eff_base
        + byte_fee × len(tx_raw_bytes)
        + effective_sigverify_fee(tx.sig_alg_id)
        + exec_fee_per_gas × tx.gas_limit
```

All arithmetic is in u64; intermediate products use u128 with saturating_add for the final sum. A transaction MUST be rejected with `FeeBelowMarket` if `tx.fee < min_fee`.

### 8.2 Actual Fee Charged After Execution

```
fee_charged = eff_base
            + byte_fee × len(tx_raw_bytes)
            + effective_sigverify_fee(tx.sig_alg_id)
            + exec_fee_per_gas × gas_used
```

`gas_used` is measured at `apply_tx` time. `gas_used` MUST NOT exceed `tx.gas_limit`; if it would, the transaction is marked out-of-gas and charged using `gas_used = tx.gas_limit`.

### 8.3 Sender Debit

```
total_debit = fee_charged + tx.fee_tip
```

`tx.fee_tip` goes entirely to the block proposer (§9.2 / ADR-022). The sender MUST hold `balance >= total_debit` at the time of execution; otherwise reject with `BalanceInsufficient`.

### 8.4 Fee Budget Declaration

The transaction field `tx.fee` is the sender's declared fee budget. It MUST satisfy `tx.fee >= min_fee` (checked at admission using `tx.gas_limit`). The actual charged amount is `fee_charged <= tx.fee`. Any surplus (`tx.fee - fee_charged`) is returned to the sender.

---

## 9. Fee Distribution and Burn

### 9.1 Distribution Order

After `fee_charged` is debited from the sender, the distribution occurs in this order:

1. **Burn** (Phase 9+ only): send `burn_amount` to the zero address (§9.3).
2. **Proposer tip**: send `tx.fee_tip` to the block proposer address (unchanged, ADR-022 priority share rationale, §9.2).
3. **Fee distribution**: distribute `validator_amount = fee_charged - burn_amount` between the proposer and the validator pool using `proposer_share_bps` (ADR-019, §9.4).

### 9.2 Validator Tip (Unchanged)

`tx.fee_tip` goes entirely to the block proposer address (ADR-022). This is unchanged from SPEC-FEE-001. The tip is NOT subject to burn or the proposer/pool split.

### 9.3 Burn Mechanism

**Launch (`viper-pq-1` v0.1.0, default):**

```
burn_rate_bps = 0
burn_amount   = 0
```

Mirrors the live `FeeMarketState::default()` at line 311-321 of `crates/pqc-state/src/store.rs`.

**Phase 9+ (governance activation):**

```
burn_amount      = fee_charged × burn_rate_bps / 10_000
validator_amount = fee_charged - burn_amount
```

`burn_rate_bps` is a governance parameter with an initial target of 1,000 bips (10.00 %). It MUST be set between 0 and 5,000 bips (0 %–50 %); values outside this range MUST be rejected by governance execution.

**Burn address**: `[0x00; 32]` — the all-zeros 32-byte address. This address has no private key and is provably unspendable. Any transaction with `tx.sender = [0x00; 32]` MUST be rejected at mempool admission with `BurnAddressSender`.

**Activation**: burn is activated by a `BurnRateUpdate` governance proposal (SPEC-GOV-001 §4). The proposal carries a single field `burn_rate_bps: u16`. A `BurnRateUpdate` with `burn_rate_bps = 0` disables burn.

**Supply accounting**: burned tokens are credited to the zero address's balance in StateStore for accounting and counted in block receipts as `burned_amount`. Total supply visible on-chain is `genesis_supply - cumulative_burned`. Nodes MUST maintain `total_burned_cumulative: u128` in StateStore for supply verification.

### 9.4 Proposer/Pool Split (ADR-019 / ADR-022)

After burn, `validator_amount` is distributed using `FeeDistributionParams.proposer_share_bps`:

```
proposer_fee = validator_amount × proposer_share_bps / 10_000
pool_fee     = validator_amount - proposer_fee
```

`pool_fee` is divided equally among all validators in the active validator pool (rounded down; remainder goes to proposer).

### 9.5 Complete Distribution Example

Given:

- `fee_charged = 10,000 venom`
- `fee_tip = 500 venom`
- `burn_rate_bps = 1,000` (10 %)
- `proposer_share_bps = 5,000` (50 %)
- Active validator pool: 4 validators

```
burn_amount      = 10,000 × 1,000 / 10,000 = 1,000 venom  → zero address
validator_amount = 10,000 - 1,000           = 9,000 venom
proposer_fee     = 9,000 × 5,000 / 10,000  = 4,500 venom  → proposer
pool_fee         = 9,000 - 4,500           = 4,500 venom  → pool
each_validator   = 4,500 / 4               = 1,125 venom  → each of 4 validators
remainder        = 4,500 mod 4             = 0 venom

tip_to_proposer  = 500 venom               → proposer (additional)

Total proposer income: 4,500 + 500 = 5,000 venom
Total per pool validator: 1,125 venom
Total burned: 1,000 venom
Total debited from sender: 10,500 venom (= fee_charged + fee_tip)
```

---

## 10. StateStore Layout

### 10.1 Live shape (mirrors `crates/pqc-state/src/store.rs:276-321`)

```rust
pub struct FeeMarketDimension {
    pub base_fee: u64,
    pub limit: u64,
    pub target: u64,
    pub excess: u64,
    pub reserve_floor: u64,
    pub update_fraction: u64,
}

pub struct FeeMarketState {
    pub compute:    FeeMarketDimension,   // active at launch
    pub storage:    FeeMarketDimension,   // reserved (target = 0)
    pub witness:    FeeMarketDimension,   // reserved
    pub contention: FeeMarketDimension,   // reserved
    pub burn_rate_bps: u16,
}
```

`FeeMarketState` is included in `state_root` under the leaf domain `"VIPER-FEE-MARKET-V1"` (cached as `fee_market_leaf_hash` and recomputed on every `apply_fee_market_step`). The companion `total_burned_cumulative: u128` lives elsewhere in `StateStore` and is folded under its own domain.

### 10.2 Backwards-compatible accessors

`FeeMarketState::base_fee()` returns `compute.base_fee` and `set_base_fee(v)` writes it (`crates/pqc-state/src/store.rs:296-303`). `block_gas_limit()` returns `compute.limit`. These are retained so that pre-ADR-053 callers continue to function while the workspace migrates to `fee_market.compute.base_fee` directly.

### 10.3 `FeeParams` Struct

`FeeParams.base_fee` (`crates/pqc-tx/src/validate.rs:43`) continues to serve as a fallback minimum for callers that have not yet wired the dynamic state. The runtime field `base_fee_dynamic` is populated each call from `StateStore::base_fee_dynamic()` (`crates/pqc-tx/src/validate.rs:80-89`).

---

## 11. Upgrade Path and Checkpoint Migration

### 11.1 Activation height

The multi-dim fee market activated at the `viper-pq-1` genesis (height 0) — every Tier-2 commitment in ADR-053 was active from launch — and is active from genesis on every later chain, including `viper-testnet-2`. Any future per-dimension activation (storage, witness, contention) lands via a Policy P-COMPAT-001 upgrade with a published activation height (timestamp-keyed, ADR-053 §T2.3).

### 11.2 Serde Default for Old Snapshots

Snapshots produced by pre-ADR-053 binaries are not loadable on the `viper-pq-1` lineage; the previous chain (`viper-devnet-2`) was archived at launch. For any snapshot that originates within the `viper-pq-1` lineage but predates a future per-dimension activation, the reserved dimensions deserialise via:

| Field | Default |
|-------|---------|
| `storage.{limit, target, excess}` | 0 |
| `storage.{base_fee, reserve_floor}` | 100 |
| `storage.update_fraction` | 1 |
| `witness.*` | same shape as `storage` |
| `contention.*` | same shape as `storage` |
| `burn_rate_bps` | 0 |

Implementations MUST use `#[serde(default = "...")]` annotations for forward compatibility with future field additions. A missing field MUST NOT cause a deserialization error.

### 11.3 Replay Determinism

`apply_fee_market_step` is deterministic: given the same per-dimension `used` values and the same dimension parameters, all nodes produce the same `FeeMarketState`. `fake_exponential` runs in `u128` with saturating arithmetic and a hard 128-iteration bound (`crates/pqc-state/src/store.rs:346-348`); there is no external randomness and no platform dependence.

---

## 12. Error Codes

The following error codes are added to the mempool admission error set (extending SPEC-TX-001 §10):

| Code | Name | Condition |
|------|------|-----------|
| `E-FEE-010` | `FeeBelowMarket` | `tx.fee < min_fee` where `min_fee` uses `compute.base_fee × lane_multiplier_bps / 10_000` |
| `E-FEE-011` | `GasLimitExceedsBlock` | `tx.gas_limit > compute.limit` |
| `E-FEE-012` | `BlockGasLimitExceeded` | Adding this tx would push `cumulative_gas_used > compute.limit` (block assembler) |
| `E-FEE-013` | `BurnAddressSender` | `tx.sender = [0x00; 32]` |

`FeeBelowMarket` MUST include diagnostic fields in the error response:

- `required_fee: u64` — the computed `min_fee`
- `current_base_fee: u64` — `compute.base_fee`
- `lane: String` — the assigned lane for this msg_type
- `lane_multiplier_bips: u64` — the multiplier in effect

---

## 13. Storage Fund (cross-ref)

A separate fee-related state component, the **storage fund**, lives alongside the multi-dim fee market in `StateStore`. Spec-of-record is ADR-053 §T2.2 / TASK-199; framework code is at `crates/pqc-state/src/storage_fund.rs`. Genesis defaults (mirrored in the historical `deploy/ansible/files/genesis-viper-pq-1.json`):

| Field | Value | Source |
|-------|-------|--------|
| `balance` | 0 | `StorageFundState::default()` |
| `perpetual_cost_per_byte` | 1 venom/byte | `DEFAULT_PERPETUAL_COST_PER_BYTE` |
| `rebate_fraction_bps` | 9,900 (99 %) | `DEFAULT_REBATE_FRACTION_BPS` (mirrors Sui launch params) |

The framework is wired into the state root from launch; storage-fee debits in the tx validation path and storage-rebate credits in the delete path are a follow-up activation under P-COMPAT-001. Detailed mechanics (stake-delegated yield, Sui-style upfront-perpetual model, rebate accounting) are out of scope here and are tracked under a future SPEC-STORAGE-001.

---

## 14. API

### 14.1 Fee Market Endpoint

`GET /v1/fee-market` (handler: `crates/pqcd/src/devnet.rs::handle_fee_market`, line 2534-2560). Returns the current multi-dim fee market state. Response shape:

```json
{
  "base_fee": 100,
  "block_gas_limit": 10000000,
  "burn_rate_bps": 0,
  "compute":    { "base_fee": 100, "limit": 10000000, "target": 5000000, "excess": 0, "reserve_floor": 100, "update_fraction": 3338477 },
  "storage":    { "base_fee": 100, "limit": 0,        "target": 0,       "excess": 0, "reserve_floor": 100, "update_fraction": 1 },
  "witness":    { "base_fee": 100, "limit": 0,        "target": 0,       "excess": 0, "reserve_floor": 100, "update_fraction": 1 },
  "contention": { "base_fee": 100, "limit": 0,        "target": 0,       "excess": 0, "reserve_floor": 100, "update_fraction": 1 }
}
```

`base_fee` and `block_gas_limit` at the top level are backwards-compatible aliases for `compute.base_fee` and `compute.limit`.

### 14.2 Status Endpoint

`GET /v1/status` (handler: `crates/pqcd/src/devnet.rs::handle_status`, line 2493-2521). Surfaces `chain_id`, `height`, `tip_hash`, `state_root`, `node_id`, `syncing`, **`base_fee` (= `compute.base_fee`)**, `epoch_number`, `epoch_length_blocks`. Existing fields MUST NOT be renamed, removed, or retyped.

### 14.3 Fee Estimation

A client-side estimator MAY reproduce §6.6's formula. The SDKs at `sdk-ts/` and `sdk-py/` (release 0.2.0) ship a `fee_estimate(tx_shape)` helper that mirrors `crates/pqc-tx/src/validate.rs::required_fee_breakdown`. There is no dedicated estimation endpoint at launch; the authoritative check is mempool admission.

---

## 15. Audit Scope

The following code paths are in scope for external cryptographic audit:

- `pqc-state::store::apply_fee_market_step` — multi-dim update: per-dimension excess accounting, `fake_exponential` correctness, overflow safety, u128 intermediate width
- `pqc-state::store::fake_exponential` — Taylor-series approximation; convergence and saturating arithmetic
- `pqc-tx::validate::effective_base_fee` and `required_fee_breakdown` — lane multiplier application, effective base fee computation
- `pqc-state::apply::distribute_block_fees` — burn before proposer/pool split, zero-address accounting
- `StateStore` serialization / deserialization — serde defaults for `FeeMarketState`, leaf-hash determinism

These paths are not cryptographic in the signature-verification sense, but are economic-security paths. Errors in fee arithmetic could allow fee underpayment, double-counting, or supply inflation via incorrect burn accounting.

---

## 16. Implementation Status (post-launch)

All Tier-2 fee-market commitments shipped at the `viper-pq-1` launch (commit `a8e94e4`, TASK-201). Outstanding items:

- [ ] Per-account contention dimension wiring — activation under P-COMPAT-001.
- [ ] Storage-dimension wiring to real tx state-growth — joint activation with the storage-fund tx-path debits (TASK-199 follow-up).
- [ ] Witness dimension — activation with stateless-client / SPEC-STATELESS work.
- [ ] `BurnRateUpdate` governance proposal type (SPEC-GOV-001 §4 extension) — Phase 9+.
- [ ] SDK 0.2.0 fee-estimate parity tests across TS / Python / Rust — TASK-176 part 3.

---

## Appendix A — References

- ADR-053 §T2.1 — multi-dim EIP-4844 fee market
- ADR-053 §T2.2 — storage fund
- ADR-022 — proposer priority share rationale
- ADR-019 — fee distribution
- EIP-4844 — academic reference for the exponential update
- EIP-7918 — reserve-floor lesson (2024 Ethereum revenue miss)
- TASK-201 — multi-dim fee market implementation
- TASK-199 — storage fund framework
- `crates/pqc-state/src/store.rs:161-352` — fee market constants, `FeeMarketDimension`, `FeeMarketState`, `fake_exponential`
- `crates/pqc-state/src/store.rs:1782-1808` — `apply_fee_market_step` and `apply_aimd_update`
- `crates/pqc-state/src/storage_fund.rs` — storage fund state
- `crates/pqc-tx/src/validate.rs:43-89` — `FeeParams`, `lane_multiplier_bps`, `effective_base_fee`
- `crates/pqcd/src/devnet.rs::handle_fee_market` — `GET /v1/fee-market` handler
- `deploy/ansible/files/genesis-viper-pq-1.json` — historical `viper-pq-1` launch parameters

---

## Appendix B — Audit-trail commits

| Commit | Tier | Note |
|--------|------|------|
| `a8e94e4` | T2.1 | feat(fee): multi-dim fee market + EIP-4844 + reserve floor (TASK-201) |
| `eaa4b4d` | T2.2 | feat(state): storage fund framework (TASK-199) |
| `324d49c` | T2.4 | feat(crypto): BIP340 double-tagged tagged_hash primitive (TASK-202) — feeds the leaf-hash domains used by `FeeMarketState` and `StorageFundState` |
| `3c3ff4f` | T3.1 | feat(state): migrate state-root + leaves + roots to BIP340 double-tagged hash (TASK-202) |

---

## Appendix C — Historical (pre-launch) approach: single-dim AIMD

The v0.1 draft of this spec specified a single-dimension AIMD (additive increase, multiplicative decrease) base fee. The constants and update formula are preserved here for context; **this approach is superseded** by the multi-dim EIP-4844 model in §6 above and is **not active** on `viper-pq-1`.

```
TARGET_BIPS    = 5_000    // 50.00% target block utilisation
ALPHA_BIPS     = 1_000    // 10.00% additive increase rate
BETA_BIPS      = 5_000    // 50.00% multiplicative decrease rate
DENOM          = 10_000   // fixed-point denominator

// Per-block update:
utilization_bips = min(block_gas_used * DENOM / block_gas_limit, DENOM)
if utilization_bips > TARGET_BIPS:
    delta_bips = ALPHA_BIPS * (utilization_bips - TARGET_BIPS) / DENOM
    base_fee_next = base_fee * (DENOM + delta_bips) / DENOM
else:
    delta_bips = BETA_BIPS * (TARGET_BIPS - utilization_bips) / DENOM
    base_fee_next = base_fee * (DENOM - delta_bips) / DENOM
base_fee_next = clamp(base_fee_next, BASE_FEE_MIN, BASE_FEE_MAX)
```

Reasons for retirement (see §4.2):

1. AIMD reacts geometrically per block rather than per accumulated excess; adversarial proposers can oscillate empty / full blocks to keep the fee artificially low.
2. AIMD has no closed-form excess gauge — economic security analysis is harder and there is no production-tested reference.
3. EIP-7918 demonstrated that base fees that can drop arbitrarily low are an economic vulnerability. The new model's per-dimension `reserve_floor` is ungovernable to zero.

The single-dim AIMD parameters above are retained in `crates/pqc-state/src/store.rs` as `AIMD_*_DEPRECATED` constants for reference only; no live code path consults them.

---

*Spec ID: SPEC-FEE-002 v0.2 — Supersedes the static `base_fee` component of SPEC-FEE-001 §4 and the v0.1 single-dim AIMD draft of this same spec ID. All other SPEC-FEE-001 components remain normative.*
