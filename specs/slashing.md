# Slashing Specification

**Spec ID**: SPEC-SLASH-001  
**Version**: 0.3  
**Status**: Reserved  
**History**: v0.3 (2026-04-23) revised by ADR-042 and ADR-048; was active on the retired `viper-pq-1` chain.  
**Date**: 2026-04-23  
**Revised by**: ADR-042 (hardcoded offense parameters, pluggable verifier registry); ADR-048 (correlation penalty implementation, D-02 closed)  
**Depends on**: ADR-030, ADR-024, ADR-042, ADR-048, SPEC-CONSENSUS-001, SPEC-VAL-001, SPEC-TX-001, SPEC-FEE-001

> **Reserved — `token_economics`.** The public chain `viper-testnet-1` has no native token, so there is no bonded stake to slash. The on-chain slashing dispatch specified here (`SubmitEquivocationEvidence` apply path, slash amounts, treasury transfer, correlation penalty) is implemented behind the `token_economics` Cargo feature and compiled out of the public chain build; the evidence format and the `slashing_verifier_registry` schema remain seeded at genesis so the mechanism can be re-enabled by a software upgrade. Validator misbehaviour on the PoA public chain is handled by the operator-run validator set off-chain. Nothing in this document is an offer, a sale or a promise of any token or other asset.

---

## 1. Scope

This document specifies the on-chain slashing protocol for Viper PQ Chain. It defines the evidence format for equivocation, the validation rules that must be satisfied before slashing executes, the exact sequence of state mutations, the slash amount formula, the conditions under which evidence remains valid through the unbonding period, the pluggable verifier registry for extensible evidence types, and the correlation penalty.

This specification covers:
- **Equivocation slashing** (hardcoded, §4–§15): the act of signing two conflicting votes at the same `(height, round, step)`.
- **Downtime slashing** (hardcoded parameters, activation deferred, §19): persistent liveness failure.
- **Pluggable verifier registry** (ADR-042, §16): governance-extensible evidence types.
- **Correlation penalty** (ADR-042, §17): Ethereum-style correlated slash multiplier.

This specification does not define:

- the BFT consensus round-state machine (SPEC-CONSENSUS-001)
- validator lifecycle, registration, and unjail (SPEC-VAL-001)
- transaction envelope format (SPEC-TX-001)
- fee formula and sigverify cost (SPEC-FEE-001)
- governance proposal types for updating slash parameters (SPEC-GOV-001)

Normative references: ADR-030, ADR-024.

---

## 2. Normative Language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL are interpreted per RFC 2119.

---

## 3. Normative References

| Reference | Document |
|-----------|----------|
| ADR-024 | Viper token economics; slash fractions and evidence validity window |
| ADR-030 | On-chain slashing execution: equivocation evidence and stake reduction |
| ADR-042 | Dynamic validator set: hardcoded offense parameters, pluggable verifier registry, correlation penalty |
| SPEC-CONSENSUS-001 | BFT consensus protocol; vote format and signature preimage |
| SPEC-VAL-001 | Validator lifecycle states: Candidate, Active, Jailed, Unbonding, Exited |
| SPEC-TX-001 | Transaction envelope format |
| SPEC-FEE-001 | Fee model; benchmark class fees for signature verification |

---

## 4. Overview and Motivation

### 4.1 Why Equivocation Only

Equivocation — signing two conflicting votes at the same `(height, round, step)` — is the only BFT safety violation that can be proven on-chain from two signed messages alone. It requires no trusted reporter and no oracle: the evidence is self-contained and cryptographically verifiable.

Downtime (liveness failure) cannot be proven this way. A missing vote may be caused by network partition, hardware failure, or deliberate Byzantine behavior; the chain cannot distinguish these cases from a signed message. On a small BFT chain (3–7 validators), automatic downtime slashing would punish honest validators during partitions. Consensus halts naturally when `> f` validators are offline, and recovery is via manual unjail when the validator comes back online. This matches the Cosmos SDK approach (tombstone for equivocation, temporary jail for downtime), which is adopted here by ADR-030.

### 4.2 Why Tombstone Is Permanent

An equivocating validator has demonstrated that it will sign conflicting messages. Unlike a liveness failure, equivocation is an intentional safety attack. Allowing unjail after equivocation would permit a well-funded attacker to repeatedly attempt double-signing, suffer only temporary exclusion, and re-enter the set. Tombstone permanence removes this attack path. No governance proposal can unjail a tombstoned validator; removing the tombstone requires a hard fork.

### 4.3 Permissionless Evidence Submission

Any account may submit equivocation evidence. This removes the dependency on a privileged reporter and creates an economic alignment: in Phase 8, the submitter will receive a `slash_reward_bps` fraction of the slashed amount (governance parameter; default 0 until Phase 8). Permissionless submission means the protocol does not need to detect equivocation internally — relayers, watchers, or other validators can observe gossip-layer votes and submit evidence at their discretion.

---

## 5. Definitions

**Equivocation**: the act of signing two distinct messages with `step` ∈ {prevote, precommit} at the same `(height, round, step)` where the `block_hash` values differ (at least one is non-nil). Defined in SPEC-CONSENSUS-001 §4.

**Tombstone**: a permanent flag on a `ValidatorRecord` indicating that the validator has been irrevocably removed from eligibility for the active set. A tombstoned validator cannot be unjailed by any on-chain operation.

**Evidence validity window** (`evidence_validity_window`): the maximum number of blocks after the evidence height during which equivocation evidence may be submitted. Defined in ADR-024 as 28 days in blocks.

**Nil vote**: a vote with `block_hash = [0x00; 32]`. A nil vote does not identify a specific block.

**Treasury account**: the protocol account at address `[0x01; 32]` that receives slashed stake. The address is a placeholder; in Phase 8 it will become a governance-controlled parameter.

**self_bond**: the amount of Viper (in venom) that a validator has bonded as their own stake, stored in `ValidatorRecord.self_bond`. This is the amount slashed; delegated stake is not in scope for Phase 5.

---

## 6. EquivocationVote CBOR Encoding

An `EquivocationVote` represents one side of an equivocation: a single signed vote that was (or could have been) broadcast during BFT consensus.

**CBOR map encoding** (deterministic, per RFC 8949 §4.2):

| Field key (integer) | Field name | Type | Required | Notes |
|---------------------|------------|------|----------|-------|
| 1 | `height` | uint (u64) | required | Block height at which the vote was cast. |
| 2 | `round` | uint (u32) | required | BFT round within the height. |
| 3 | `block_hash` | bstr (32 bytes) | required | The hash voted on; `[0x00; 32]` encodes a nil vote. |
| 4 | `step` | uint (u8) | required | Vote phase: `0x01` = Prevote, `0x02` = Precommit. See SPEC-CONSENSUS-001 §7.4. |
| 5 | `signature` | bstr | required | ML-DSA-65 signature over the canonical vote preimage (see §6.1). Maximum 3,309 bytes. |

Keys MUST be encoded in ascending integer order. No additional fields are permitted. A decoder MUST reject any `EquivocationVote` with unknown keys.

### 6.1 Vote Preimage for Signature Verification

The signature in field 5 MUST be a valid ML-DSA-65 signature over the following preimage, as defined in SPEC-CONSENSUS-001 §7.4:

```
preimage = SHAKE-256(
  "VIPER-VOTE-V1"   ||   // domain separator (ASCII, no null terminator)
  height_be64       ||   // 8 bytes, big-endian
  round_be32        ||   // 4 bytes, big-endian
  step_u8           ||   // 1 byte: 0x01 = prevote, 0x02 = precommit
  block_hash,            // 32 bytes
  output_len = 32
)
```

Verification MUST use the validator's registered consensus public key at the evidence height (see §9.2 for key lookup).

### 6.2 Step Value Reference

| Value | Step | Phase in consensus round |
|-------|------|--------------------------|
| `0x01` | Prevote | First voting phase |
| `0x02` | Precommit | Second voting phase |

No other `step` values are valid in an `EquivocationVote`. An evidence record with a `step` value outside `{0x01, 0x02}` MUST be rejected with `INVALID_EVIDENCE_FORMAT`.

---

## 7. EquivocationEvidence Payload CBOR Encoding

The `submit_equivocation_evidence` transaction carries its operation payload as a CBOR map in the `payload` field of the transaction envelope (SPEC-TX-001). The payload CBOR encoding is:

**CBOR map encoding** (deterministic, per RFC 8949 §4.2):

| Field key (integer) | Field name | Type | Required | Notes |
|---------------------|------------|------|----------|-------|
| 1 | `validator_address` | bstr (32 bytes) | required | Operator address of the accused validator. |
| 2 | `height` | uint (u64) | required | Block height at which equivocation occurred. MUST equal `vote_a.height` and `vote_b.height`. |
| 3 | `vote_a` | map (EquivocationVote) | required | First signed vote. |
| 4 | `vote_b` | map (EquivocationVote) | required | Conflicting signed vote. |

Keys MUST be encoded in ascending integer order. No additional fields are permitted.

**MsgType**: `0x0403`. This extends the validator operations range (ADR-030):

| MsgType | Operation |
|---------|-----------|
| `0x0400` | `ValidatorRegister` |
| `0x0401` | `ValidatorExit` |
| `0x0402` | `ValidatorUnjail` |
| `0x0403` | `submit_equivocation_evidence` |

---

## 8. Validation Rules

The following rules MUST all pass before slashing execution begins. Rules are checked in the order listed; the first failing check produces the corresponding error code (see §11) and terminates validation without applying any state changes.

1. **FORMAT**: The payload MUST deserialize as a valid `EquivocationEvidence` CBOR map with all required fields present and correctly typed. Failure: `INVALID_EVIDENCE_FORMAT`.

2. **VOTE_FORMAT_A**: `vote_a` MUST deserialize as a valid `EquivocationVote` with all required fields present. `vote_a.step` MUST be `0x01` or `0x02`. Failure: `INVALID_EVIDENCE_FORMAT`.

3. **VOTE_FORMAT_B**: `vote_b` MUST deserialize as a valid `EquivocationVote` with all required fields present. `vote_b.step` MUST be `0x01` or `0x02`. Failure: `INVALID_EVIDENCE_FORMAT`.

4. **SAME_HEIGHT**: `vote_a.height` MUST equal `vote_b.height`, and both MUST equal the payload `height` field. Failure: `EVIDENCE_HEIGHT_MISMATCH`.

5. **SAME_ROUND**: `vote_a.round` MUST equal `vote_b.round`. Failure: `EVIDENCE_ROUND_MISMATCH`.

6. **SAME_STEP**: `vote_a.step` MUST equal `vote_b.step`. Two conflicting messages of different steps (e.g., a prevote and a precommit) are not equivocation. Failure: `EVIDENCE_STEP_MISMATCH`.

7. **CONFLICTING_HASHES**: `vote_a.block_hash` MUST NOT equal `vote_b.block_hash`. Additionally, at least one of `vote_a.block_hash` or `vote_b.block_hash` MUST be non-nil (i.e., not `[0x00; 32]`). Two nil votes at the same `(height, round, step)` are not equivocation (per SPEC-CONSENSUS-001 §4). Failure: `EVIDENCE_NOT_CONFLICTING`.

8. **VALIDITY_WINDOW**: The evidence MUST be submitted within the evidence validity window. The check is:

   ```
   current_block_height - evidence_height <= evidence_validity_window
   ```

   where `evidence_height` is the payload `height` field, `current_block_height` is the height of the block in which this transaction is being applied, and `evidence_validity_window` is the governance parameter (default: 28 days in blocks). If the difference exceeds the window, failure: `EVIDENCE_EXPIRED`.

9. **VALIDATOR_EXISTS**: A `ValidatorRecord` with `operator_address = validator_address` MUST exist in the state store. Failure: `NOT_A_VALIDATOR`.

10. **NOT_TOMBSTONED**: The validator MUST NOT already have `tombstoned = true`. If already tombstoned (from a prior equivocation), the same validator cannot be slashed again for equivocation. Failure: `ALREADY_TOMBSTONED`.

11. **SIG_A**: `vote_a.signature` MUST be a valid ML-DSA-65 signature over the canonical preimage derived from `vote_a` fields (per §6.1), verified against the validator's registered consensus public key at `evidence_height`. Failure: `INVALID_SIGNATURE`.

12. **SIG_B**: `vote_b.signature` MUST be a valid ML-DSA-65 signature over the canonical preimage derived from `vote_b` fields (per §6.1), verified against the same consensus key. Failure: `INVALID_SIGNATURE`.

**Note on ordering of rules 11 and 12**: Signature verification (rules 11 and 12) is intentionally placed last, after cheap structural and state checks. This prevents an attacker from forcing two expensive ML-DSA-65 verifications with a trivially invalid evidence record (e.g., wrong step or already tombstoned validator).

---

## 9. Execution Steps

If all validation rules in §8 pass, the following state mutations are applied **atomically** in the order listed. A failure in any step MUST roll back all prior mutations in the same transaction.

**Step 1 — Compute base slash amount.**

```
slash_amount = floor(validator.self_bond × slash_fraction_equivocation / 10_000)
```

where `slash_fraction_equivocation = 500` (500 basis points = 5%, hardcoded per ADR-042). The result is rounded toward zero (floor division). See §10 for the formula in full detail.

**Step 1a — Apply correlation penalty (if applicable).**

If the correlation penalty is active (§17.3), compute the adjusted slash:

```
slash_amount = min(slash_amount × (1 + correlation_multiplier), validator.self_bond)
```

See §17 for the full correlation penalty computation. The correlation penalty is applied after the base slash is computed but before the deduction in Step 2.

**Step 2 — Deduct from self_bond.**

```
validator.self_bond = validator.self_bond - slash_amount
```

The result MUST be non-negative. Because `slash_fraction_equivocation < 10_000`, this is always satisfied when `slash_amount = floor(self_bond × 500 / 10_000)`.

**Step 3 — Credit treasury.**

```
treasury_account.balance = treasury_account.balance + slash_amount
```

The treasury account address is `[0x01; 32]` (placeholder). This address will become a governance-controlled parameter in Phase 8. The credit is applied to the `balance` field of the account at that address; if the account does not exist, it is created with zero balance before the credit.

**Step 4 — Set jailed status.**

```
validator.status = ValidatorStatus::Jailed
```

This transition is valid from any source status: Active, Candidate, Unbonding, or Exited. A validator that was already Jailed (e.g., for a different infraction) remains Jailed.

**Step 5 — Set tombstone.**

```
validator.tombstoned = true
```

This flag is permanent. No subsequent on-chain operation (including `ValidatorUnjail`, msg_type `0x0402`) may clear it. The tombstone is a separate field from `ValidatorStatus::Jailed`; an implementation MUST check both independently where relevant.

**Step 6 — Remove from active set.**

If the validator's status was `Active` before step 4 (i.e., it was in the active validator set), it MUST be removed from the active set immediately. `CommitQuorumPolicy` MUST be recalculated to reflect the new active set before the next block is produced.

If the new active set size drops below the protocol minimum (1 validator), the chain continues with the remaining set. Phase 4 does not define a minimum active set threshold; this is a Phase 6 governance parameter.

**Step 7 — Persist the evidence record.**

The processed evidence MUST be stored in a persistent tombstone index keyed by `(validator_address, evidence_height)`. This index is used to satisfy rule 10 (NOT_TOMBSTONED) and for audit purposes. The stored record SHOULD include: `validator_address`, `height`, `submitter_address`, `block_height_applied`, `slash_amount`. The schema of this record is an implementation detail not constrained by this spec.

---

## 10. Slash Amount Formula

```
slash_fraction_equivocation = 500           // basis points (ADR-042, hardcoded)
slash_fraction_double_vote  = 500           // basis points (ADR-042, hardcoded)
slash_fraction_downtime     = 1             // basis points = 0.01% (ADR-042, hardcoded)
```

```
base_slash_amount = floor(self_bond × slash_fraction / 10_000)
```

**Rounding rule**: floor (truncate toward zero). This is standard integer division in Rust (`/` operator on `u128`).

**Hardcoded status**: the slash fractions for equivocation, double-vote, and downtime are **hardcoded protocol constants** per ADR-042. They are NOT governance parameters and MUST NOT be modifiable via `SlashParamUpdate`. Changing them requires a hard fork. This is intentional: these fractions are safety and liveness invariants; making them governance-mutable would allow a compromised or captured governance to reduce penalties to zero.

**Example (equivocation)**: a validator with `self_bond = 1_000_000 × 10^18` venom (1 M VPR):

```
slash_amount = floor(1_000_000_000_000_000_000_000_000 × 500 / 10_000)
             = floor(500_000_000_000_000_000_000_000_000_000 / 10_000)
             = 50_000_000_000_000_000_000_000   // 50_000 VPR
```

**Arithmetic precision**: `self_bond` is stored and computed as `u128` (venom units). The intermediate product `self_bond × 500` MUST be computed in `u128`. Overflow check: `u128::MAX ≈ 3.4 × 10^38`; `self_bond` is bounded by total supply (10^27 venom = 10^9 VPR × 10^18); `10^27 × 500 = 5 × 10^29 < u128::MAX`. No overflow is possible.

---

## 11. Treasury Destination

Slashed stake is credited to the treasury account at `[0x01; 32]`.

This is a placeholder address for Phase 5. It will be replaced by a governance-controlled parameter in Phase 8. The governance parameter name (proposed, not yet accepted) is `treasury_address: [u8; 32]`.

**Burn alternative**: ADR-030 notes that burning (sending to a provably unspendable address) is an alternative to crediting a treasury. This choice is deferred to Phase 8 governance. The implementation MUST accept a `treasury_address` governance parameter and route funds accordingly; hardcoding `[0x01; 32]` is acceptable only until Phase 8.

**Slash reward**: in Phase 8, the submitter of successful evidence will receive `slash_reward_bps` basis points of the slashed amount, deducted from the treasury credit before the remainder is deposited. This path is not implemented in Phase 5; `slash_reward_bps = 0` is the effective value.

---

## 12. Evidence Validity Window Enforcement

The evidence validity window ensures that slashing cannot be triggered arbitrarily far in the past, bounding the state that validators must maintain and the threat exposure for validators in unbonding.

**Condition (must hold at application time)**:

```
current_block_height - evidence_height <= evidence_validity_window
```

where:

- `current_block_height`: height of the block being applied (the block that contains the `submit_equivocation_evidence` transaction)
- `evidence_height`: the `height` field in the `EquivocationEvidence` payload
- `evidence_validity_window`: governance parameter (default: 28 days in blocks, per ADR-024)

**Block time assumption**: the implementation uses 1 second per block (2,419,200 blocks ≈ 28 days). Earlier drafts of this spec used a 6-second target (403,200 blocks); the current constant `EVIDENCE_VALIDITY_WINDOW_BLOCKS = 2_419_200` in `pqc-types` reflects the 1 s/block devnet target. The governance parameter is stored in blocks, not seconds, so changes in actual block time do not affect the window without a governance update.

**Edge cases**:

- If `evidence_height > current_block_height` (evidence claims a future height), the subtraction would underflow. This MUST be detected before the subtraction and rejected with `EVIDENCE_EXPIRED`. Implementations MUST use saturating or checked subtraction.
- If `evidence_height == current_block_height`, the condition holds (`0 <= evidence_validity_window`). Same-block evidence is valid.
- The window check uses the `height` field in the payload, not the heights inside `vote_a` or `vote_b`. Rules 4 enforces that all three are equal, so in practice they are the same.

---

## 13. Interaction with Unbonding

A validator in `ValidatorStatus::Unbonding` or `ValidatorStatus::Exited` status can still be slashed if equivocation evidence is submitted within the evidence validity window.

**Rationale**: the unbonding period is 21 days (ADR-042); the evidence validity window is 28 days (>1× unbonding). This means:

- During unbonding (days 0–21), the validator's stake is still locked and can be slashed.
- After exit (days 21–28), the validator has technically recovered their stake, but slashing can still reach returned funds within the window.

**Implementation note**: if the validator status is `Exited` and self_bond has been returned to the operator account balance, the slash MUST still be executed: deduct `slash_amount` from the operator account balance (not from `self_bond`, which may now be 0). If the operator balance is insufficient to cover `slash_amount`, deduct the entire available balance (no debt). This edge case applies only when `self_bond` was fully returned before evidence submission; the exact recovery of returned-but-slashable funds is deferred to Phase 8 refinement, but the tombstone and jailing MUST be applied regardless.

For the Phase 5 implementation, if `validator.self_bond < slash_amount` (because some bond was returned during unbonding), deduct `validator.self_bond` entirely (set it to 0) and do not attempt to recover additional funds from the operator account. Record the shortfall in the tombstone index for audit.

---

## 14. Gas Cost

Submitting equivocation evidence requires two ML-DSA-65 signature verifications (one for `vote_a`, one for `vote_b`). Each verification uses class V-B from SPEC-FEE-001 §6.

**Gas cost for `submit_equivocation_evidence`**:

```
sigverify_cost = 2 × sigverify_fee_v_b
               = 2 × 14_000
               = 28_000 fee units
```

The total transaction fee is computed per SPEC-FEE-001 §4:

```
fee = base_fee
    + byte_fee × tx_bytes
    + 28_000            // two ML-DSA-65 signature verifications
    + exec_fee_per_gas × gas_limit
```

The `exec_fee_per_gas × gas_limit` component is small relative to the sigverify cost (see SPEC-FEE-001 §4.4 for gas schedule). The per-operation gas cost for `submit_equivocation_evidence` is TBD; it MUST be added to SPEC-FEE-001 §4.4 before Phase 5 closes.

**Rationale for high cost**: the high fee disincentivizes spam evidence submissions (invalid evidence fails validation and the fee is still charged). It also reflects actual resource cost: two ML-DSA-65 verifications at ~233 µs each = ~466 µs of CPU time on the reference machine (SPEC-FEE-001 §6.4).

---

## 15. Error Codes

The following error codes MUST be returned when evidence submission fails. Error codes are part of the transaction receipt; they do not expose validator key material.

| Error code | Condition | Rule violated |
|------------|-----------|---------------|
| `INVALID_EVIDENCE_FORMAT` | Payload does not deserialize as `EquivocationEvidence`, or a sub-field has wrong type or length, or `step` is not `0x01` or `0x02`. | Rules 1, 2, 3 |
| `EVIDENCE_HEIGHT_MISMATCH` | `vote_a.height`, `vote_b.height`, and payload `height` are not all equal. | Rule 4 |
| `EVIDENCE_ROUND_MISMATCH` | `vote_a.round ≠ vote_b.round`. | Rule 5 |
| `EVIDENCE_STEP_MISMATCH` | `vote_a.step ≠ vote_b.step`. | Rule 6 |
| `EVIDENCE_NOT_CONFLICTING` | `vote_a.block_hash == vote_b.block_hash`, or both votes are nil. | Rule 7 |
| `EVIDENCE_EXPIRED` | `current_block_height - evidence_height > evidence_validity_window`, or `evidence_height > current_block_height`. | Rule 8 |
| `NOT_A_VALIDATOR` | No `ValidatorRecord` found for `validator_address`. | Rule 9 |
| `ALREADY_TOMBSTONED` | `validator.tombstoned == true`. | Rule 10 |
| `INVALID_SIGNATURE` | `vote_a.signature` or `vote_b.signature` fails ML-DSA-65 verification against the validator's registered consensus key. | Rules 11, 12 |

**Security note**: the error message for `INVALID_SIGNATURE` MUST NOT include: the raw signature bytes from the evidence (they are already in the transaction), the validator's private key material, or any intermediate verification state. The error message MUST only indicate which vote (`vote_a` or `vote_b`) failed verification.

All other processing errors (insufficient balance to cover fee, nonce mismatch, etc.) are handled by the standard transaction processing layer, not by this spec.

---

## 16. Pluggable Verifier Registry

ADR-042 introduces a governance-extensible registry of evidence verifiers for slash conditions beyond the hardcoded core offenses.

### 16.1 Registry Structure

The registry maps evidence type identifiers to verifier contract addresses:

```
evidence_type_id: u32  →  verifier_contract: [u8; 32]
```

Each registered verifier is a smart contract (or precompile) that implements the `EvidenceVerifier` interface:

```
fn verify(evidence: &[u8], state: &StateView) -> VerifyResult
fn slash_fraction(evidence: &[u8]) -> u16   // basis points
fn is_tombstone(evidence: &[u8]) -> bool
```

### 16.2 Adding a New Verifier

Adding a new `evidence_type_id → verifier_contract` mapping requires:
1. A governance proposal that includes the verifier contract bytecode or precompile address, the evidence type ID, and the proposed slash parameters.
2. A supermajority vote: ≥ 66% of active voting power must approve.
3. A 30-day timelock after approval before the verifier becomes active. During the timelock, the verifier contract is deployed but evidence of that type is not yet accepted.

Removing or disabling an existing verifier follows the same process (supermajority + 30-day timelock). A verifier MUST NOT be removed if there is pending evidence of that type in the evidence validity window.

### 16.3 Reserved Evidence Type IDs

| ID | Offense | Implementation |
|----|---------|----------------|
| `0x0001` | Equivocation (prevote/precommit) | Hardcoded (this spec) |
| `0x0002` | Double-vote (surround-vote) | Hardcoded |
| `0x0003` | Downtime (persistent liveness failure) | Hardcoded parameter, activation deferred (§19) |
| `0x0004`–`0x00FF` | Reserved for core protocol offenses | Future hard fork |
| `0x0100`+ | Pluggable verifier registry | Governance |

### 16.4 Candidate Future Verifiers

The following offense types are candidates for future registry entries (not yet specified):
- Non-attestation of data availability (relevant when DA layer is added)
- Incorrect PQ signature aggregation proof (when STARK aggregation is operational)
- RANDAO bias or manipulated VDF output
- MEV censorship proof (requires external proof system)

---

## 17. Correlation Penalty

ADR-042 adopts an Ethereum-style correlation penalty to deter coordinated validator misbehavior.

### 17.1 Motivation

A single validator slashed for equivocation may be a misconfiguration. Thirty validators slashed simultaneously is almost certainly a coordinated attack. The correlation penalty scales the slash fraction with the fraction of the active set slashed in a rolling window, making coordinated attacks disproportionately expensive.

### 17.2 Parameters (implemented — ADR-048)

| Parameter | Value | Governance-mutable |
|-----------|-------|-------------------|
| Correlation window | `CORRELATION_WINDOW_BLOCKS = 6_220_800` (36 days at 500 ms/block) | Yes, supermajority |
| Base multiplier | `CORRELATION_BASE_MULT = 3` | Yes, supermajority |
| Max multiplicative boost | `MAX_MULT_BOOST = 19` (→ 20× cap) | Yes, supermajority |
| Threshold for max penalty | 1/3 of active set slashed in window | No (hard fork only) |

### 17.3 Formula (implemented — ADR-048)

At the time of slash execution for a validator, all arithmetic is in u128 basis
points (denominator `BASIS_POINTS_TOTAL = 10_000`):

```
ratio_bps     = min(10_000, window_slashed_stake × 10_000 / active_stake)
multiplier    = min(10_000, ratio_bps × CORRELATION_BASE_MULT)       // capped at 1.0
boost         = 10_000 + multiplier × MAX_MULT_BOOST                  // 10_000 = ×1.0
effective_bps = min(10_000, base_fraction_bps × boost / 10_000)
final_slash   = floor(self_bond × effective_bps / 10_000)
```

Where `window_slashed_stake` is the sum of `slashed_stake` over all
`RecentSlashEntry` records with `height` within the last
`CORRELATION_WINDOW_BLOCKS` blocks, and `active_stake` is the sum of `self_bond`
over all currently-Active validators.

**At 1/3 of stake slashed in window**: `ratio_bps ≈ 3_333`; `multiplier = min(10_000, 9_999) = 9_999` (one-bps floor artifact of integer division); `boost = 10_000 + 9_999 × 19 = 199_981`; `effective_bps = 500 × 199_981 / 10_000 = 9_999` (one bps below saturation). Any slash ≥ 1/3 drives `multiplier = 10_000` exactly, producing `effective_bps = 10_000` (100% slash).

**Edge cases**:
- `active_stake == 0`: divide-by-zero guarded — function returns `base_fraction_bps` unchanged (treated as "no correlation applies"). Only reachable on an empty/all-jailed chain.
- Overflow: all products stay below `u128::MAX`. Max realistic `window_slashed_stake × 10_000 ≤ 10^31 ≪ u128::MAX`. `saturating_mul` is defensive belt-and-braces.
- Single-slash isolated case: window is empty at compute-time (the current slash is recorded AFTER computing the multiplier), so `ratio_bps = 0 → multiplier = 0 → effective_bps = base_fraction_bps`. §10 byte-stability is preserved.

### 17.4 Implementation (ADR-048, closed 2026-04-23)

The correlation penalty ledger is a `VecDeque<RecentSlashEntry>` on
`StateStore` — see `pqc-types::slashing::RecentSlashEntry` and
`pqc-state::store::StateStore::recent_slashes`. Each entry holds
`(height: u64, slashed_stake: u128)`, stored in apply-order (ascending by
height).

- **Consensus-critical**: the ledger is folded into `state_root()` under the
  leaf domain `"VIPER-RECENT-SLASHES-V1"`. Two nodes that apply the same
  sequence of slashes produce byte-identical ledgers and byte-identical state
  roots.
- **Lazy pruning**: `StateStore::prune_recent_slashes_before(cutoff)` is
  called at the start of each slash apply, BEFORE computing the multiplier.
  Entries with `height < current_height - CORRELATION_WINDOW_BLOCKS` are
  pop-front'd until the deque's head is inside the window. No per-block
  sweep is needed: every validator running the same slash at the same height
  runs the same prune.
- **Atomic**: the ledger update is inside the `apply_tx` working copy, so a
  failed slash (e.g., signature rejection after prune) rolls back the prune
  along with everything else. On success the ledger, state root, and the
  validator record all commit together.

No additional state columns beyond `recent_slashes` and the cached leaf hash.

---

## 18. Downtime Slash: Parameters Defined, Activation Deferred

Liveness failure slash is **not implemented** in Phase 8 but its parameters are defined by ADR-042 (hardcoded):

- **Slash fraction**: 0.01% of self-bond per liveness offense (`slash_fraction_downtime = 1` basis point)
- **Jail**: yes (unjailable after waiting period)
- **Tombstone**: no

**Rationale for deferral**: for a BFT chain with a small initial committee, automatic on-chain downtime slashing requires a reliable liveness oracle (heartbeat mechanism or ABCI liveness signal). Without such an oracle, a network partition could cause an honest validator to appear offline on the majority side; slashing would punish correct behavior. This is the same reasoning as ADR-030.

**Activation path**: downtime slashing activates once a heartbeat or liveness oracle mechanism is specified and implemented (target Phase 9). The `slash_fraction_downtime = 1` constant is stored in the slashing module from Phase 8 onwards to ensure the parameter is auditable and stable before activation.

The existing recovery path (`ValidatorUnjail`, msg_type `0x0402`) remains sufficient through Phase 8.

---

## 19. Implementation Checklist

The following items MUST be completed before `SPEC-SLASH-001` is considered implemented. Each item identifies the crate and the specific change.

### 19.1 `pqc-types`

- [ ] Define `EquivocationVote` struct with fields: `height: u64`, `round: u32`, `block_hash: [u8; 32]`, `step: u8`, `signature: Vec<u8>`.
- [ ] Implement deterministic CBOR serialization and deserialization for `EquivocationVote` using integer field keys `1`–`5` as specified in §6.
- [ ] Define `EquivocationEvidence` struct with fields: `validator_address: [u8; 32]`, `height: u64`, `vote_a: EquivocationVote`, `vote_b: EquivocationVote`.
- [ ] Implement deterministic CBOR serialization and deserialization for `EquivocationEvidence` using integer field keys `1`–`4` as specified in §7.
- [ ] Add `tombstoned: bool` field to `ValidatorRecord` (default `false`). This requires an ADR or amendment note if `ValidatorRecord` CBOR encoding is considered stable (SPEC-ACCOUNT-001 / Phase 4 backwards-compat rule).
- [ ] Add `MsgType::SubmitEquivocationEvidence = 0x0403` to the `MsgType` enum.
- [ ] Define typed error variants for all error codes in §15: `EvidenceExpired`, `AlreadyTombstoned`, `InvalidSignature`, `NotAValidator`, etc.

### 19.2 `pqc-state::apply::validator`

- [ ] Implement `apply_submit_equivocation_evidence(state, tx, current_block_height) -> Result<Receipt, SlashError>`.
- [ ] Enforce all 12 validation rules from §8 in the specified order.
- [ ] Implement the slash formula from §10 using `u128` arithmetic; verify no overflow is possible.
- [ ] Apply state mutations in the order specified in §9 (Steps 1–7), with rollback on failure.
- [ ] Implement the unbonding edge case from §13: if `self_bond < slash_amount`, slash to zero and record shortfall.
- [ ] Write the tombstone index entry (Step 7) with fields: `validator_address`, `height`, `submitter_address`, `block_height_applied`, `slash_amount`.
- [ ] No `unwrap()` or `expect()` in this function or any function it calls. All error paths MUST return typed errors (Phase 4 rule).
- [ ] No private key material, consensus key bytes, or intermediate signature-state in log output or error messages.

### 19.3 `CommitQuorumPolicy`

- [ ] Ensure `CommitQuorumPolicy::from_state_store()` (or equivalent factory) excludes validators with `tombstoned = true` or `status == Jailed` from the active set when computing quorum membership.
- [ ] Ensure that after Step 6 of execution (active set removal), `CommitQuorumPolicy` is recalculated before the next block is assembled. The recalculation MUST happen within the same block application as the slashing transaction.
- [ ] Verify that a quorum computed over a reduced active set (after tombstone removal) remains valid: `f = floor((n-1)/3)`, quorum = `f+1 ≥ 2/3+1`.

### 19.4 `pqcd::devnet` (admission pipeline)

- [ ] Route `MsgType::SubmitEquivocationEvidence` through the standard mempool admission pipeline.
- [ ] Charge two `sigverify_fee_v_b` (28,000 fee units total) at mempool admission, before executing validation rules 11–12.
- [ ] Ensure `submit_equivocation_evidence` transactions are not subject to sender-nonce deduplication that would prevent multiple evidence submissions by the same account (two different equivocations by different validators could be submitted by the same relayer in the same block).

### 19.5 Tests

- [ ] Unit test: valid equivocation evidence for an Active validator — verify `self_bond` reduced by 5%, status Jailed, `tombstoned = true`, treasury balance increased.
- [ ] Unit test: evidence for already-tombstoned validator returns `ALREADY_TOMBSTONED`.
- [ ] Unit test: expired evidence (outside window) returns `EVIDENCE_EXPIRED`.
- [ ] Unit test: `vote_a.block_hash == vote_b.block_hash` returns `EVIDENCE_NOT_CONFLICTING`.
- [ ] Unit test: both votes nil returns `EVIDENCE_NOT_CONFLICTING`.
- [ ] Unit test: invalid signature on `vote_a` returns `INVALID_SIGNATURE`.
- [ ] Unit test: evidence for validator in `Unbonding` status — verify slash applies to `self_bond`, tombstone set.
- [ ] Integration test: evidence submitted by an account that is not the accused validator (permissionless submission succeeds).
- [ ] Integration test: `CommitQuorumPolicy` recomputed after tombstone; subsequent block can be committed by remaining validators.

### 19.6 Audit Scope

All code in `pqc-types` (evidence structs, CBOR encoding), `pqc-state::apply::validator` (`apply_submit_equivocation_evidence`), and the signature verification calls into `pqc-crypto` are in scope for the Phase 4 cryptographic audit. The implementation MUST:

- use small, single-purpose functions (no function longer than ~50 lines)
- inline invariant reasoning as comments where the logic is not self-evident
- prefer explicit conditional checks over clever bit manipulation

---

## 20. Open Items

| ID | Item | Status |
|----|------|--------|
| TBD-SLASH-01 | Per-operation gas cost for `submit_equivocation_evidence` — to be added to SPEC-FEE-001 §4.4 | TBD |
| TBD-SLASH-02 | `slash_reward_bps` governance parameter and submitter reward distribution | Phase 8 target |
| TBD-SLASH-03 | Recovery of returned-but-slashable funds from operator account when `self_bond = 0` at evidence time | Phase 8 refinement |
| TBD-SLASH-04 | Minimum active set threshold after tombstone removal | Phase 8 governance parameter |
| TBD-SLASH-05 | `tombstoned` field CBOR encoding backward-compatibility | Requires ADR amendment before implementation |
| TBD-SLASH-06 | Correlation penalty ledger pruning efficiency — index structure for `total_effective_stake_slashed_in_window` | Phase 8 |
| TBD-SLASH-07 | Pluggable verifier registry on-chain storage schema and dispatch interface specification | Phase 8 / Phase 9 |
| TBD-SLASH-08 | Gas cost model for pluggable verifier calls — variable cost depending on verifier complexity | Phase 9 |
