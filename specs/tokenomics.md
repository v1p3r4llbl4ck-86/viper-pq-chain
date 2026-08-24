# SPEC-TOKEN-002: Viper Token Economics

**Spec ID**: SPEC-TOKEN-002
**Version**: 1.0
**Status**: Reserved
**Date**: 2026-04-12
**Supersedes**: SPEC-TOKEN-001 §2–§9 (numeric parameters, previously deferred)
**Produced by**: TASK-070 (Phase 5 — Mainnet Economics and Genesis Preparation)
**Decision authority**: ADR-024

> **Reserved — `token_economics`.** The public chain `viper-testnet-1` has no native token. Everything in this document (supply, distribution, staking minimums, slash amounts, fee coefficients denominated in VPR/venom) describes a design reserve: it is implemented behind the `token_economics` Cargo feature, which is compiled out of the public chain build, and it is not active on any network at the time of the public release. The parameters below were fixed for the retired `viper-pq-1` chain and are kept unchanged for reference. Nothing in this document is an offer, a sale or a promise of any token or other asset.

---

## 1. Scope

This document specifies all numeric economic parameters for the Viper native token. It supersedes the deferred-parameter placeholders in SPEC-TOKEN-001 and provides the definitive reference for the genesis block specification (ADR-025) and dress rehearsal (Phase 5).

Parameters marked **immutable** cannot be changed by governance. Parameters marked **governance-mutable** can be changed via `governance_proposal(registry_update)` or equivalent future governance operations.

---

## 2. Token Identity

| Property | Value |
|----------|-------|
| Token name | Viper |
| Ticker | VPR |
| Decimals | 18 |
| Atomic unit name | venom |
| Conversion | 1 VPR = 1,000,000,000,000,000,000 venom (10^18) |
| Internal representation | `u128` (balance in venom) |

The `u128` maximum is approximately 3.4 × 10^38 venom, providing ~3.4 × 10^11 multiples of the total supply before overflow. No overflow can occur in normal operation.

---

## 3. Supply Schedule

**Supply model: fixed.** No tokens are minted after genesis. There is no inflation mechanism, no block reward issuance, and no reserve minting path in the protocol.

```
total_supply = 1,000,000,000 VPR = 10^27 venom
```

**Immutable constraint**: no code path in `pqc-state` or `pqcd` may create balance out of thin air. The sum of all account balances must equal `total_supply` at every block height after genesis.

Fee revenue is redistributed from sender to proposer/validator pool (TASK-049, ADR-019); it does not change the total supply.

---

## 4. Genesis Distribution

| Allocation | Percentage | VPR amount | Venom amount | Vesting | Purpose |
|---|---|---|---|---|---|
| Founder | 20% | 200,000,000 | 2 × 10^26 | 4-year linear, 1-year cliff (off-chain custody) | Long-term alignment |
| Treasury | 30% | 300,000,000 | 3 × 10^26 | Governance-controlled | Ecosystem development, grants, partnerships |
| Genesis validators | 10% | 100,000,000 | 10^26 | No lockup; committed as self-bond at genesis | Bootstrap consensus |
| Reserved | 40% | 400,000,000 | 4 × 10^26 | Locked until governance vote | Future distribution: community, sales, partners |
| **Total** | **100%** | **1,000,000,000** | **10^27** | — | — |

### 4.1 Vesting Note

Phase 1 does not implement an on-chain vesting contract. Founder vesting (4-year linear, 1-year cliff) is enforced off-chain via custody arrangement. This document records the commitment; on-chain enforcement is deferred to a future governance-controlled vesting module.

### 4.2 Treasury Governance

The Treasury allocation is controlled by the on-chain governance mechanism (SPEC-GOV-001). No funds may be disbursed from the Treasury account without a ratified governance proposal.

### 4.3 Reserved Allocation

The Reserved account is governance-locked. Disbursement requires a governance proposal specifying the recipient, amount, and purpose. Until disbursed, Reserved tokens do not participate in staking, fee payment, or governance weight.

---

## 5. Staking Parameters

| Parameter | Value | Unit | Mutable |
|---|---|---|---|
| `min_stake` | 1,000,000 | VPR | Governance-mutable |
| `unbonding_period` | 14 days (in blocks at target block time) | blocks | Governance-mutable |
| `evidence_validity_window` | 28 days (2× unbonding period) | blocks | Governance-mutable |
| `max_active_set_size` | 24 (ADR-013) | validators | Governance-mutable (raise only) |

### 5.1 Minimum Stake Rationale

`min_stake = 1,000,000 VPR = 0.1% of total supply`

With 24 genesis validators each meeting `min_stake`, the minimum staked supply is 24,000,000 VPR (2.4% of total supply). This ensures meaningful skin-in-the-game without making validator participation prohibitively capital-intensive for early operators.

### 5.2 Unbonding Period

14 days provides sufficient time for slashing evidence to be submitted against an exiting validator before their bond is returned. The evidence validity window (28 days) covers the full unbonding period with a 2× safety margin.

---

## 6. Slashing Schedule

| Offense | Slash % | Slash amount at min_stake | Notes |
|---|---|---|---|
| Equivocation (double sign) | 5% | 50,000 VPR | Detected by `INVALID_COMMIT_SIGNATURE` in commit quorum validation |
| Liveness failure | 0.5% | 5,000 VPR | Exceeding `max_missed_blocks` in any `liveness_window` |
| Invalid vote (repeated) | 2% | 20,000 VPR | Between liveness and equivocation severity |

**Implementation status**: slashing execution code is not yet implemented. These values are the governance target; enforcement requires implementation of the slashing module and the evidence submission mechanism (Phase 5/6 deliverable). The `ValidatorStatus::Jailed` state is implemented (TASK-064); slash execution is not.

**Slashing destination**: slashed tokens are sent to the Treasury account, not burned. Burning would reduce total supply below the genesis cap; Treasury routing preserves the supply invariant while removing tokens from validator control.

---

## 7. Fee Coefficients

Fee coefficients are defined normatively in SPEC-FEE-001 §6.4 and were calibrated on reference hardware (Ubuntu Linux 6.8.0-107-generic, release build) in TASK-042 and TASK-062.

| Coefficient | Current value | Unit | Notes |
|---|---|---|---|
| `base_fee` | 500 | venom/tx | Minimum per-transaction cost |
| `byte_fee` | 2 | venom/byte | Bandwidth and storage cost |
| `sigverify_fee_v_b` | 14,000 | venom | ML-DSA-65 baseline verification cost |
| `exec_fee_per_gas` | 43 | venom/gas | State execution cost |

### 7.1 Fee Recalibration

The current coefficients represent the **technical cost floor** — the venom cost of the hardware resources consumed. With 18 decimals, a typical `token_transfer` (ML-DSA-65) costs approximately 15,000 venom = 0.000000000000015 VPR, which is economically negligible at any plausible token price.

**Target economic range**: a typical `token_transfer` should cost between 0.001 and 0.01 VPR at launch. The recalibration multiplier is determined during the Phase 5 dress rehearsal based on:
- The VPR reference price at launch planning time
- The hardware cost per transaction at reference node economics
- Competitive positioning versus Ethereum gas fees for attestation workflows

The multiplier is a governance-mutable parameter; the technical floor values above are never adjusted downward by governance.

---

## 8. Governance-Mutable Parameters

The following parameters can be changed by a ratified governance proposal:

| Parameter | Current value | Governance mechanism |
|---|---|---|
| `min_stake` | 1,000,000 VPR | `governance_proposal(registry_update)` or equivalent |
| `unbonding_period` | 14 days | Governance vote |
| `evidence_validity_window` | 28 days | Governance vote |
| `max_active_set_size` | 24 | Governance vote (raise only; lowering would remove active validators) |
| Fee coefficients (`base_fee`, `byte_fee`, `sigverify_fee_*`, `exec_fee_per_gas`) | See §7 | Governance vote; cannot go below technical floor |
| Treasury disbursements | N/A | Governance vote per disbursement |
| Algorithm Registry lifecycle state | Active/Discouraged/Deprecated/Banned | Governance vote per algorithm |

---

## 9. Immutable Constraints

The following are protocol-level invariants that governance cannot override:

1. **Supply cap**: `total_supply = 10^27 venom`. No governance action can mint tokens above this cap.
2. **No post-genesis minting**: the only code path that creates venom balance is the genesis block initialization. All subsequent supply changes are redistributions (fees, slashing).
3. **Address derivation**: `address = SHAKE-256(public_key_bytes, 32)`. Changing this would break existing address commitments.
4. **Signature algorithm for transactions**: ML-DSA as the mandatory baseline (ADR-006); algorithm changes require a new ADR and coordinated network upgrade.
5. **CBOR transaction format (SPEC-TX-001)**: no field change without an ADR and explicit migration path (Phase 4 backward-compatibility rule).
6. **Atomic unit**: 1 VPR = 10^18 venom. This conversion is embedded in all balance displays and fee calculations; changing it would require a coordinated migration.

---

## 10. Reference

- ADR-015 — token model and deferred parameters (superseded by ADR-024 for numeric values)
- ADR-019 — fee distribution model (proposer/pool split)
- ADR-024 — tokenomics finalization decision
- ADR-025 — genesis block specification
- SPEC-TOKEN-001 — token roles and mechanisms (still normative for non-numeric content)
- SPEC-FEE-001 — fee model specification (normative for fee mechanics)
- SPEC-GOV-001 — governance specification (normative for governance voting rules)
- SPEC-VAL-001 — validator staking specification
- `specs/genesis-spec.md` — genesis block normative spec
