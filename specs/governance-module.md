# Governance Module Specification

**Spec ID**: SPEC-GOV-001  
**Version**: 1.0  
**Status**: Accepted  
**Date**: 2026-04-15  
**Supersedes**: `specs/governance.md` v0.1 (draft, Phase 1 placeholder)  
**Depends on**: ADR-031 (governance module decision), ADR-024 (slash and staking parameters), ADR-032 (fee market; `FeeParamUpdate`), SPEC-VAL-001 (validator staking model), SPEC-TX-001 (transaction envelope), SPEC-ACCOUNT-001 (algorithm registry), SPEC-FEE-001 (fee model)

> **Reserved — `token_economics` (parts of this spec).** The public chain `viper-testnet-1` has no native token. The proposal lifecycle, proposal types, epoch-boundary execution, API and error codes in this document are active. The token-dependent parts — §1.4 stake-weighted voting power (with the feature off every active validator has a constant weight of 1), §3.1 `GovernanceDeposit` and §8 deposit mechanics including the deposit burn, and §5.5 `SlashParamUpdate` (its parameters have no effect while slashing dispatch is compiled out) — are implemented behind the `token_economics` Cargo feature, compiled out of the public chain build, and kept as a design reserve. Nothing in this document is an offer, a sale or a promise of any token or other asset.

---

## 1. Overview and Motivation

The governance module provides a formal on-chain mechanism for updating bounded protocol parameters without a coordinated operator restart or a hard fork. It replaces the minimal single-step `governance_proposal(registry_update)` path implemented in TASK-037, which had no deposit mechanism, no voting, and no quorum requirement.

### 1.1 What Governance Can Change

The following categories of protocol state are governable on-chain:

| Category | Proposal type | Governed values |
|----------|---------------|-----------------|
| Fee parameters | `FeeParamUpdate` | `base_fee`, `byte_fee`, `sigverify_fee_v_*`, `exec_fee_per_gas`, AIMD multipliers |
| Algorithm lifecycle | `AlgorithmLifecycleUpdate` | Lifecycle status (`Active` → `Discouraged` → `Deprecated` → `Banned`) and `min_fee` |
| Validator set size | `ValidatorSetSizeUpdate` | `VALIDATOR_MAX_ACTIVE_SET_SIZE` |
| Emergency halt | `EmergencyHalt` | Pause tx submission for up to 72 hours |
| Slash parameters | `SlashParamUpdate` | Slash fractions (bps), evidence validity window |

### 1.2 What Cannot Be Changed On-Chain (Hard Fork Only)

The following are structural protocol invariants and MUST NOT be modified through governance proposals. A proposal targeting these is rejected at mempool admission with `PROPOSAL_OUT_OF_SCOPE`.

- Transaction envelope format (SPEC-TX-001, CBOR field layout)
- Block header fields and state root derivation algorithm
- Cryptographic hash functions (SHAKE-256)
- Consensus rules (BFT round structure, quorum formula)
- Fee model architecture (lane assignment logic)
- `msg_type` namespace assignments
- Algorithm lifecycle acyclicity (no backward transitions, no re-activation of banned algorithms)

### 1.3 Relationship to the Existing Registry Update Path

The `governance_proposal` operation (`msg_type = 0x0300`) implemented in TASK-037 is a single-step, vote-free execution path. It is **superseded** by this specification. Implementations MUST refactor the existing path to route through the lifecycle defined here (deposit → voting → epoch-boundary execution). The `0x0300` `msg_type` is retired; new governance operations use `0x0500`–`0x0502` (§3). See §10 for the migration requirements.

### 1.4 Voting Power Model

Voting power is stake-weighted: each validator's vote weight equals its `self_bond` in venom at the time the vote is cast. Validators with `status ≠ active` (SPEC-VAL-001 §5.1) MUST NOT vote. Non-validators cannot vote directly; token delegation is deferred to Phase 8.

At the current prototype scale (3–24 validators, all self-bonded), the ⅔ quorum requirement means at least ⅔ of total bonded stake must participate for a vote to be valid. With 3 equal-weight validators, all three must participate — this is intentional (ADR-031: prevents unilateral governance at small validator counts).

---

## 2. Normative Language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL are to be interpreted as described in RFC 2119.

---

## 3. MsgType CBOR Encoding

Three new message types are defined in the `0x05xx` governance namespace. The existing `GovernanceProposal (0x0300)` is retired upon implementation of this module.

### 3.1 GovernanceDeposit — `msg_type = 0x0500`

Adds deposit toward a proposal that is in `DepositPeriod` state. Multiple deposits from the same or different senders are allowed; they accumulate until `min_deposit` is reached or the deposit period expires.

**Signer policy**: any account with sufficient liquid balance; no validator status required.

**CBOR field table**:

| Field key | CBOR type | Description |
|-----------|-----------|-------------|
| 1 | uint(u64) | `proposal_id` — numeric identifier assigned at proposal creation |
| 2 | uint(u64) | `amount` — deposit amount in venom |

**Preconditions**:
- `proposal_id` MUST reference an existing proposal in `DepositPeriod` state. Error: `PROPOSAL_NOT_FOUND` if absent; `WRONG_PROPOSAL_STATE` if not in `DepositPeriod`.
- `amount` MUST be > 0. Error: `INVALID_DEPOSIT_AMOUNT`.
- Sender liquid balance MUST be ≥ `amount` after fee deduction. Error: `INSUFFICIENT_BALANCE`.
- Current block height MUST be ≤ `deposit_deadline_height`. Error: `DEPOSIT_PERIOD_EXPIRED`.

**State effects**: lock `amount` from sender balance; add `amount` to `proposal.total_deposit`; record depositor entry `{depositor: sender, amount}`. If `proposal.total_deposit ≥ min_deposit`, transition proposal to `VotingPeriod` (§4.3).

**Gas tier**: L

### 3.2 GovernanceVote — `msg_type = 0x0501`

Casts or replaces a vote on a proposal in `VotingPeriod` state.

**Signer policy**: operator of an `active` validator (SPEC-VAL-001 §5.1). Bit 3 MUST be set in the signing key's `allowed_tx_types`.

**CBOR field table**:

| Field key | CBOR type | Description |
|-----------|-----------|-------------|
| 1 | uint(u64) | `proposal_id` |
| 2 | uint(u8) | `vote_option` — 1=Yes, 2=No, 3=NoWithVeto, 4=Abstain |

**Preconditions**:
- `proposal_id` MUST reference an existing proposal. Error: `PROPOSAL_NOT_FOUND`.
- Proposal MUST be in `VotingPeriod` state. Error: `WRONG_PROPOSAL_STATE`.
- Current block height MUST be ≤ `voting_deadline_height`. Error: `VOTING_PERIOD_EXPIRED`.
- `vote_option` MUST be 1–4. Error: `INVALID_VOTE_OPTION`.
- Sender MUST be the operator of a validator with `status = active`. Error: `NOT_AN_ACTIVE_VALIDATOR`.

**State effects**: if the sender has a prior vote on this proposal, remove its weight from the running tally accumulators. Record the new vote `{voter: sender, option: vote_option, weight: sender.validator.self_bond, height: current_height}`. Update tally accumulators on the proposal record.

A validator that re-votes replaces their prior vote; only the most recent vote counts in the tally.

**Gas tier**: L

### 3.3 GovernancePropose — `msg_type = 0x0502`

Opens a new governance proposal. Transitions it to `DepositPeriod`.

**Signer policy**: operator of a validator with `status ∈ {active, candidate}` (SPEC-VAL-001 §5.1). Bit 3 MUST be set in the signing key's `allowed_tx_types`.

**CBOR field table** (envelope-level fields, present in every proposal):

| Field key | CBOR type | Description |
|-----------|-----------|-------------|
| 1 | uint(u8) | `proposal_type` — type code (see §5) |
| 2 | bstr(32) | `title_hash` — SHAKE-256 of the human-readable title string (≤256 bytes) |
| 3 | bstr(32) | `rationale_hash` — SHAKE-256 of the off-chain rationale document |
| 4 | map | `payload` — proposal-type-specific fields (see §5) |
| 5 | uint(u64) | `initial_deposit` — initial deposit in venom from the proposer (MAY be 0; full deposit can be provided separately via `GovernanceDeposit`) |

**Preconditions**:
- `proposal_type` MUST be a recognized type code (§5). Error: `PROPOSAL_OUT_OF_SCOPE`.
- No other proposal in `DepositPeriod` or `VotingPeriod` state MUST target the same governable object (§4.1). Error: `CONFLICTING_PROPOSAL`.
- `payload` MUST validate against the schema for `proposal_type` (§5). Error: `INVALID_PROPOSAL_PAYLOAD`.
- If `initial_deposit > 0`, sender balance MUST cover it after fee deduction. Error: `INSUFFICIENT_BALANCE`.

**State effects**: assign `proposal_id` (next sequential uint64 from `gov_params.next_proposal_id`); write proposal record (§6.1); set `deposit_deadline_height = current_height + gov_params.deposit_period`; lock `initial_deposit` from sender; record as first depositor entry; advance `next_proposal_id`.

**Gas tier**: H

---

## 4. Proposal Lifecycle State Machine

### 4.1 States

| State | Description |
|-------|-------------|
| `DepositPeriod` | Proposal submitted; awaiting sufficient deposit |
| `VotingPeriod` | `min_deposit` reached; validators may cast votes |
| `Passed` | Voting period ended; quorum and threshold both met; queued for execution |
| `Rejected` | Voting period ended without meeting quorum or threshold |
| `Executed` | State change applied at epoch boundary |
| `Failed` | Proposal passed but execution encountered an error (rare; see §7.3) |
| `DepositBurned` | Deposit period expired without reaching `min_deposit`; deposits burned |
| `VetoBurned` | Voting period ended; veto threshold met; deposits burned |

### 4.2 State Transition Diagram

```
GovernancePropose
      │
      ▼
 DepositPeriod ──[deposit_deadline_height reached, total_deposit < min_deposit]──► DepositBurned
      │
      │ [total_deposit ≥ min_deposit (at any block within deposit period)]
      ▼
 VotingPeriod ──[voting_deadline_height reached, quorum not met]──────────────────► Rejected
      │
      │ [voting_deadline_height reached, quorum met]
      │
      ├─[veto_weight / total_voting_weight ≥ veto_threshold]─────────────────────► VetoBurned
      │
      ├─[yes_weight / non_abstain_weight < threshold]─────────────────────────────► Rejected
      │
      └─[yes_weight / non_abstain_weight ≥ threshold]──────────────────────────────► Passed
                                                                                        │
                                         [EmergencyHalt at emergency_threshold:         │
                                          next block after passing]                     │
                                         [all others: next epoch boundary]              │
                                                                                        ▼
                                                                                    Executed
                                                                                (or Failed on error)
```

### 4.3 Block-Level Triggers

The following checks MUST run as part of `advance_height` (block transition logic) for each block at height `h`:

1. **Deposit period expiry**: for each proposal in `DepositPeriod` where `deposit_deadline_height < h`:
   - burn all depositor balances (transfer to the null burn address)
   - set proposal state → `DepositBurned`

2. **Deposit → voting transition**: for each proposal in `DepositPeriod` where `total_deposit ≥ min_deposit` (this may also be triggered inline during `GovernanceDeposit` apply):
   - set `voting_start_height = current_height`
   - set `voting_deadline_height = current_height + gov_params.voting_period`
   - snapshot `total_bonded_stake` into `proposal.eligible_voting_weight` (sum of `self_bond` for all validators with `status = active` at this block)
   - set proposal state → `VotingPeriod`

3. **Voting period tally** (at `voting_deadline_height`): for each proposal in `VotingPeriod` where `voting_deadline_height ≤ h`:
   - compute quorum, threshold, and veto check (§5.2 formulas)
   - set state per §4.2 transition rules
   - if `VetoBurned`: burn all deposits
   - if `Passed`: compute `execution_height` (§7.1) and record on proposal

4. **Epoch-boundary execution**: at each epoch boundary height `h = k × epoch_length`:
   - for each proposal in `Passed` where `execution_height ≤ h`:
     - apply the proposal's payload (§5.x execution semantics)
     - set state → `Executed` or `Failed`
     - return deposits to all depositors (on `Executed`); do not return deposits on `Failed`
     - write execution receipt (§6.2)

5. **EmergencyHalt fast path** (checked at every block during voting period, not only at deadline):
   - for each `EmergencyHalt` proposal in `VotingPeriod`: if `yes_weight / eligible_voting_weight ≥ emergency_threshold` at any block, immediately set state → `Passed`, set `execution_height = current_height + 1`, and schedule execution for the next block. No epoch-boundary wait.

### 4.4 Conflicting Proposal Rule

At most one proposal in `{DepositPeriod, VotingPeriod, Passed}` may target the same governable object at any time. A second `GovernancePropose` for the same object MUST be rejected with `CONFLICTING_PROPOSAL`.

Same-object identity per type:
- `FeeParamUpdate`: same `param_key`
- `AlgorithmLifecycleUpdate`: same `alg_id`
- `ValidatorSetSizeUpdate`: no sub-key; at most one such proposal active
- `EmergencyHalt`: no sub-key; at most one active
- `SlashParamUpdate`: same `param_key`

Once a conflicting proposal reaches `{Rejected, DepositBurned, VetoBurned, Executed, Failed}`, a new proposal for the same object is permitted.

---

## 5. Proposal Types

Proposal type codes occupy the `proposal_type` field (field key 1) of `GovernancePropose`. Payload fields are carried inside the `payload` map (field key 4).

### 5.1 FeeParamUpdate — type code `0x01`

Changes a fee coefficient in the active fee schedule. Governed parameters include the static coefficients defined in SPEC-FEE-001 and the AIMD multipliers defined in ADR-032.

**Payload CBOR fields**:

| Field key | CBOR type | Description |
|-----------|-----------|-------------|
| 1 | uint(u16) | `param_key` — identifies the parameter (table below) |
| 2 | uint(u64) | `new_value` — new value in venom (for fee amounts) or bps (for multipliers) |

**Governable fee parameters**:

| `param_key` | Parameter | Type | Constraints |
|-------------|-----------|------|-------------|
| 0x0001 | `base_fee` | uint(u64) venom/tx | > 0 |
| 0x0002 | `byte_fee` | uint(u64) venom/byte | > 0 |
| 0x0003 | `exec_fee_per_gas` | uint(u64) venom/gas | > 0 |
| 0x0004 | `sigverify_fee_v_a` | uint(u64) venom | > 0 |
| 0x0005 | `sigverify_fee_v_b` | uint(u64) venom | > 0 |
| 0x0006 | `sigverify_fee_v_c` | uint(u64) venom | > 0 |
| 0x0007 | `aimd_alpha_bps` | uint(u16) bps | 1–1000 |
| 0x0008 | `aimd_beta_bps` | uint(u16) bps | 1–9000 |
| 0x0009 | `burn_rate_bps` | uint(u16) bps | 0–10000 |

A `FeeParamUpdate` with `param_key` not in this table MUST be rejected with `PROPOSAL_OUT_OF_SCOPE`.  
A `new_value = 0` for any parameter where zero is not a valid sentinel MUST be rejected with `INVALID_PARAMETER_VALUE`.

**Execution semantics**: at the epoch boundary execution point, write `new_value` to `StateStore.gov_params.fee[param_key]`. The updated value takes effect for all transactions in blocks at or after `execution_height`. Nodes MUST NOT apply the old value to any block at or after `execution_height`.

**Quorum rule**: standard (§5.2). No supermajority required.

### 5.2 AlgorithmLifecycleUpdate — type code `0x02`

Changes the lifecycle status of an entry in the Algorithm Registry (SPEC-ACCOUNT-001). Supersedes the existing `registry_update` path (`msg_type = 0x0300`).

**Payload CBOR fields**:

| Field key | CBOR type | Description |
|-----------|-----------|-------------|
| 1 | uint(u16) | `alg_id` — target algorithm identifier |
| 2 | uint(u8) | `target_status` — 1=Discouraged, 2=Deprecated, 3=Banned |
| 3 | uint(u64) | `new_min_fee` — (optional, 0 means no change) new `min_fee` for the algorithm in venom |
| 4 | bstr(32) | `rationale_hash` — SHAKE-256 of off-chain technical justification |

**Lifecycle transition constraints** (from SPEC-ACCOUNT-001):
- Only forward transitions are valid: `Active → Discouraged`, `Discouraged → Deprecated`, `Deprecated → Banned`.
- `Active → Deprecated` or `Active → Banned` direct transitions require an `EmergencyHalt` proposal, not this type.
- A transition that would move an algorithm backward (e.g. `Deprecated → Active`) MUST be rejected with `INVALID_LIFECYCLE_TRANSITION`; this is a structural invariant and cannot be overridden by any governance proposal.
- Only one `AlgorithmLifecycleUpdate` per `alg_id` may be in `{DepositPeriod, VotingPeriod, Passed}` at a time (§4.4).

**Execution semantics**: at the epoch boundary execution point:
1. Set `registry[alg_id].lifecycle_status = target_status`.
2. If `new_min_fee > 0`, set `registry[alg_id].min_fee = new_min_fee`.
3. If `target_status = Banned`, invalidate all pending transactions in the mempool that use `alg_id` as their signing algorithm. Transactions already in finalized blocks are unaffected; accounts must migrate keys before submitting new transactions.

**Quorum rule**: standard (§5.2). Supermajority (⅔ of non-abstain stake) RECOMMENDED for deprecation steps given user migration impact; enforced as standard majority.

### 5.3 ValidatorSetSizeUpdate — type code `0x03`

Changes `VALIDATOR_MAX_ACTIVE_SET_SIZE` (ADR-013, SPEC-VAL-001 §9.1).

**Payload CBOR fields**:

| Field key | CBOR type | Description |
|-----------|-----------|-------------|
| 1 | uint(u32) | `new_max_active_set_size` — new cap |

**Constraints**:
- `new_max_active_set_size` MUST be ≥ `current_active_validator_count`. Reducing the cap below the live active set count is not supported (would require involuntary exits). Error: `VALIDATOR_SET_CEILING_BELOW_ACTIVE_COUNT`.
- `new_max_active_set_size` MUST be ≤ 200 (hard ceiling; requires protocol upgrade to raise). Error: `VALIDATOR_SET_HARD_CEILING_EXCEEDED`.
- `new_max_active_set_size` MUST be ≥ 4 (minimum for BFT liveness: quorum ⌊2n/3⌋+1 requires n ≥ 4 to tolerate 1 failure). Error: `VALIDATOR_SET_BELOW_BFT_MINIMUM`.

**Execution semantics**: set `StateStore.gov_params.max_active_set_size = new_max_active_set_size` at epoch boundary. If the new cap is higher, candidates may immediately be admitted at the next epoch transition per SPEC-VAL-001 §5.3.2. If the new cap is equal to the current active count, no change to the active set occurs; new candidates queue.

**Quorum rule**: standard (§5.2).

### 5.4 EmergencyHalt — type code `0x04`

Pauses transaction submission (mempool admission and block inclusion) for up to 72 hours. Used for critical security responses.

**Payload CBOR fields**:

| Field key | CBOR type | Description |
|-----------|-----------|-------------|
| 1 | uint(u32) | `halt_duration_blocks` — duration of halt in blocks (max: 72 × 3600 = 259,200 blocks at 1 s/block) |
| 2 | uint(u8) | `scope` — 1=all_tx, 2=user_tx_only (validator consensus messages always pass) |
| 3 | bstr(32) | `justification_hash` — SHAKE-256 of the publicly accessible emergency justification |

**Constraints**:
- `halt_duration_blocks` MUST be > 0 and ≤ 259,200. Error: `INVALID_HALT_DURATION`.
- `scope` MUST be 1 or 2. Error: `INVALID_HALT_SCOPE`.
- `justification_hash` MUST be non-zero (all-zero hash is rejected as a placeholder). Error: `MISSING_JUSTIFICATION_HASH`.

**Quorum rule**: emergency (see §5.2). Requires `yes_weight / eligible_voting_weight ≥ emergency_threshold` (0.80), not the standard threshold. The fast-path trigger (§4.3 item 5) checks this at every block during the voting period.

**Execution semantics**:
- Set `StateStore.gov_params.halt_active = true`.
- Set `StateStore.gov_params.halt_resume_height = execution_height + halt_duration_blocks`.
- At each block in `[execution_height, halt_resume_height)`: the mempool admission pipeline MUST reject all transactions with error `CHAIN_HALT_ACTIVE` (or `USER_TX_HALTED` if `scope = 2`). Consensus messages (prevote, precommit, proposal) are not blocked regardless of scope.
- At `halt_resume_height`: automatically set `halt_active = false`. Normal mempool admission resumes.
- Governance may pass a second `EmergencyHalt` with `halt_duration_blocks` specifying the remaining desired window, or an `EmergencyResume` (if implemented) to lift the halt early.

### 5.5 SlashParamUpdate — type code `0x05`

Changes slashing fractions or the evidence validity window (ADR-024).

**Payload CBOR fields**:

| Field key | CBOR type | Description |
|-----------|-----------|-------------|
| 1 | uint(u16) | `param_key` — identifies the slash parameter (table below) |
| 2 | uint(u64) | `new_value` — new value |

**Governable slash parameters**:

| `param_key` | Parameter | Type | Current value (ADR-024) | Constraints |
|-------------|-----------|------|------------------------|-------------|
| 0x0101 | `slash_equivocation_bps` | uint(u16) bps | 500 (5%) | 1–10000; MUST NOT be 0 |
| 0x0102 | `slash_liveness_bps` | uint(u16) bps | 50 (0.5%) | 1–10000; MUST NOT exceed `slash_equivocation_bps` |
| 0x0103 | `slash_invalid_vote_bps` | uint(u16) bps | 200 (2%) | 1–10000 |
| 0x0104 | `evidence_validity_window` | uint(u64) blocks | 28 days in blocks | ≥ `unbonding_period` |

**Constraints**:
- `slash_liveness_bps` MUST NOT exceed `slash_equivocation_bps` (liveness slash cannot exceed equivocation slash). Error: `INVALID_SLASH_ORDERING`.
- `evidence_validity_window` MUST be ≥ `unbonding_period` (to preserve the "exit before evidence" prevention property of SPEC-VAL-001 §11.1). Error: `EVIDENCE_WINDOW_BELOW_UNBONDING_PERIOD`.

**Quorum rule**: supermajority required (⅔ of non-abstain stake, not standard 50%). Slash parameters are security-critical; a simple majority changing them would be insufficient protection against economic attacks.

**Execution semantics**: write updated value to `StateStore.gov_params.slash[param_key]` at epoch boundary. Slash events submitted at or after `execution_height` use the new fraction; slash events from evidence older than `execution_height` use the fraction that was in effect at the offense height (or evidence submission height, whichever produces the lesser slash — to be conservative).

---

## 5.2 Quorum, Threshold, and Veto Formulas

These formulas are evaluated at `voting_deadline_height` for standard proposals, and at every block for `EmergencyHalt` proposals.

**Definitions**:
- `eligible_voting_weight` = sum of `self_bond` over all validators with `status = active` at `voting_start_height` (snapshotted when the proposal transitions to `VotingPeriod`)
- `total_voting_weight` = `yes_weight + no_weight + noveto_weight + abstain_weight` (sum of weights of votes actually cast)
- `non_abstain_weight` = `yes_weight + no_weight + noveto_weight`

**Quorum check** (must pass before threshold or veto checks apply):
```
total_voting_weight / eligible_voting_weight ≥ quorum
```
where `quorum = 0.667` (66.7%).

If quorum is not met: proposal → `Rejected`. No further checks.

**Veto check** (evaluated if quorum is met):
```
noveto_weight / total_voting_weight ≥ veto_threshold
```
where `veto_threshold = 0.334` (33.4%).

If veto threshold is met: proposal → `VetoBurned`. No threshold check.

**Threshold check** (evaluated if quorum met and veto not met):
```
yes_weight / non_abstain_weight ≥ threshold
```
where `threshold = 0.50` (50%).

If threshold is met: proposal → `Passed`. Otherwise: proposal → `Rejected`.

**Emergency threshold** (for `EmergencyHalt` proposals only, checked at every block):
```
yes_weight / eligible_voting_weight ≥ emergency_threshold
```
where `emergency_threshold = 0.80` (80%).

**SlashParamUpdate supermajority check** (additional check applied before setting → `Passed`):
```
yes_weight / non_abstain_weight ≥ 0.667
```
If the standard threshold (50%) is met but supermajority (66.7%) is not, the `SlashParamUpdate` proposal → `Rejected`.

All fractions are computed in u128 integer arithmetic to avoid floating-point rounding. Implementation: multiply numerator by 1,000,000, compare to denominator × threshold_numerator (where threshold is expressed as a fraction with denominator 1,000,000).

---

## 6. StateStore Additions

### 6.1 Proposal Record

One record per proposal, keyed by `proposal_id` (uint64, sequential).

| Field | Type | Description |
|-------|------|-------------|
| `proposal_id` | uint64 | Sequential identifier, assigned at creation |
| `proposal_type` | uint8 | Type code (§5) |
| `proposer` | bstr(32) | Operator address of the submitting validator |
| `title_hash` | bstr(32) | SHAKE-256 of the title string |
| `rationale_hash` | bstr(32) | SHAKE-256 of the off-chain rationale |
| `payload_cbor` | bstr | Full CBOR-encoded payload (stored verbatim for auditability) |
| `state` | uint8 | Current lifecycle state (§4.1) |
| `submit_height` | uint64 | Block height at submission |
| `deposit_deadline_height` | uint64 | Block height at end of deposit period |
| `voting_start_height` | uint64 | Block height when deposit period closed successfully |
| `voting_deadline_height` | uint64 | Block height at end of voting period |
| `eligible_voting_weight` | uint128 | Total bonded stake snapshotted at `voting_start_height` |
| `yes_weight` | uint128 | Accumulated Yes vote weight |
| `no_weight` | uint128 | Accumulated No vote weight |
| `noveto_weight` | uint128 | Accumulated NoWithVeto weight |
| `abstain_weight` | uint128 | Accumulated Abstain weight |
| `total_deposit` | uint64 | Accumulated deposit in venom |
| `execution_height` | uint64 | Scheduled execution block (set when state → `Passed`) |
| `executed_at_height` | uint64 | Actual execution block (set when state → `Executed`) |

Fields `voting_start_height`, `voting_deadline_height`, `eligible_voting_weight`, and all vote weight accumulators are zero-valued until the proposal transitions to `VotingPeriod`.

Proposal records are **immutable once written** except for: `state`, vote weight accumulators (`yes_weight`, `no_weight`, `noveto_weight`, `abstain_weight`), `total_deposit`, `voting_start_height`, `voting_deadline_height`, `eligible_voting_weight`, `execution_height`, and `executed_at_height`. Historical records MUST NOT be pruned.

### 6.2 Depositor Records

Per-proposal list of `{depositor: bstr(32), amount: uint64}`. Needed to return deposits on successful execution or burn on rejection.

Keyed by `(proposal_id, depositor_address)`. A single depositor may add multiple deposits; amounts accumulate.

### 6.3 Vote Records

Per-proposal, per-validator vote record.

| Field | Type | Description |
|-------|------|-------------|
| `proposal_id` | uint64 | |
| `voter` | bstr(32) | Validator operator address |
| `vote_option` | uint8 | 1=Yes, 2=No, 3=NoWithVeto, 4=Abstain |
| `weight` | uint128 | `self_bond` at time of vote |
| `voted_at_height` | uint64 | Block height of the vote transaction |

Keyed by `(proposal_id, voter)`. A replacement vote overwrites the prior record (after adjusting tally accumulators). Historical vote records (pre-replacement) do not need to be retained, but the final vote record per `(proposal_id, voter)` MUST be retained permanently.

### 6.4 Execution Receipts

One receipt per executed proposal.

| Field | Type | Description |
|-------|------|-------------|
| `proposal_id` | uint64 | |
| `executed_at_height` | uint64 | Block height of execution |
| `param_key` | uint16 or uint8 | Parameter or `alg_id` modified (proposal-type-specific) |
| `value_before` | bstr | CBOR-encoded previous value |
| `value_after` | bstr | CBOR-encoded new value |
| `result` | uint8 | 0=success, 1=failed (with reason string in `error_detail`) |
| `error_detail` | bstr | (optional) UTF-8 error description if `result = 1` |

### 6.5 Governance Parameters

Stored as a single record `StateStore.gov_params`. All values are governance-adjustable (except the structural ceilings noted in §5.x constraints).

| Parameter | Type | Initial value | Description |
|-----------|------|---------------|-------------|
| `min_deposit` | uint64 venom | 10^22 (10,000 VPR) | Minimum total deposit to advance to voting |
| `deposit_period` | uint64 blocks | 604,800 (7 days at 1 s/block) | Maximum deposit period length |
| `voting_period` | uint64 blocks | 604,800 (7 days at 1 s/block) | Voting window length |
| `quorum_bps` | uint32 | 6670 (66.7%) | Minimum participation fraction of bonded stake |
| `threshold_bps` | uint32 | 5000 (50%) | Yes fraction of non-abstain stake required to pass |
| `veto_threshold_bps` | uint32 | 3340 (33.4%) | NoWithVeto fraction that triggers veto burn |
| `emergency_threshold_bps` | uint32 | 8000 (80%) | EmergencyHalt fast-path threshold |
| `supermajority_bps` | uint32 | 6670 (66.7%) | Supermajority threshold for SlashParamUpdate |
| `epoch_length` | uint64 blocks | 100 | Blocks per epoch (governs execution deferral) |
| `max_active_set_size` | uint32 | 24 | Current active validator cap (ADR-013) |
| `next_proposal_id` | uint64 | 1 | Auto-increment for `proposal_id` |
| `halt_active` | bool | false | Whether `EmergencyHalt` is currently in effect |
| `halt_resume_height` | uint64 | 0 | Block height at which halt automatically lifts |
| `slash[0x0101]` | uint16 bps | 500 | Equivocation slash fraction |
| `slash[0x0102]` | uint16 bps | 50 | Liveness slash fraction |
| `slash[0x0103]` | uint16 bps | 200 | Invalid vote slash fraction |
| `slash[0x0104]` | uint64 blocks | 2,419,200 (28 days) | Evidence validity window |
| `fee[0x0001..0x0009]` | see §5.1 | ADR-024 values | Fee coefficients |

`gov_params` is included in the state root computation (leaf hash domain: `"gov_params_v1"`).

---

## 7. Epoch-Boundary Execution

### 7.1 Execution Height Calculation

For all proposal types except `EmergencyHalt`:
```
execution_height = first epoch boundary ≥ (voting_deadline_height + 1)

epoch_boundary_height(k) = k × epoch_length, for integer k ≥ 1
execution_height = min { k × epoch_length : k × epoch_length > voting_deadline_height }
```

At `execution_height`, `advance_height` applies the proposal payload before processing any transactions in that block. Parameter changes are visible to all transactions in blocks with `height ≥ execution_height`.

### 7.2 Execution Order

When multiple proposals share the same `execution_height`, they are applied in ascending `proposal_id` order (oldest first). This is deterministic across all nodes.

### 7.3 Execution Failure

If applying a proposal's payload at the epoch boundary encounters an error (for example, the target `alg_id` was already banned by an emergency action before the epoch boundary arrived, making the `AlgorithmLifecycleUpdate` a no-op conflict), the proposal transitions to `Failed`. Deposits are NOT returned on `Failed`. An execution receipt is written with `result = 1` and an `error_detail` string.

Execution errors MUST be deterministic. An execution that succeeds on one node MUST succeed on all nodes. Any non-deterministic condition (e.g., external I/O) MUST NOT be part of proposal execution logic.

### 7.4 EmergencyHalt Execution

When the emergency threshold is crossed at block `h` during the voting period:
- Proposal immediately transitions to `Passed`.
- `execution_height = h + 1`.
- At block `h + 1` (before transaction processing), `advance_height` applies the halt: sets `halt_active = true`, `halt_resume_height = h + 1 + halt_duration_blocks`.
- All subsequent blocks check `halt_active` at mempool admission and at block assembly time; if `halt_active = true` and `height < halt_resume_height`, transaction inclusion is blocked per `scope`.
- At `halt_resume_height`, `advance_height` clears `halt_active = false` automatically.
- Deposits are returned to depositors at `execution_height` (not at `halt_resume_height`).

---

## 8. Deposit Mechanics

### 8.1 Deposit Accumulation

- Any account may contribute to a proposal in `DepositPeriod` via `GovernanceDeposit`.
- Deposits are locked immediately upon the `GovernanceDeposit` transaction being applied.
- The deposit period window is `[submit_height, deposit_deadline_height]`. A deposit submitted at exactly `deposit_deadline_height` is valid if `total_deposit < min_deposit` at the start of processing that block.
- If `total_deposit ≥ min_deposit` is reached before `deposit_deadline_height`, the proposal immediately transitions to `VotingPeriod` (within the same block).

### 8.2 Minimum Deposit

`min_deposit = 10,000 VPR = 10^22 venom` (initial value; governance-adjustable via `FeeParamUpdate` with `param_key = 0x000A` if added to the fee parameter table, or via a `gov_params` update proposal type to be defined in a future revision).

The proposer's `initial_deposit` in `GovernancePropose` counts toward `total_deposit`. Multiple depositors may combine contributions.

### 8.3 Deposit Return

| Outcome | Deposit return |
|---------|---------------|
| `Executed` | All depositors receive their full deposit back |
| `Rejected` (quorum not met) | All depositors receive their full deposit back |
| `Rejected` (threshold not met, no veto) | All depositors receive their full deposit back |
| `DepositBurned` | All deposits burned (transferred to null burn address) |
| `VetoBurned` | All deposits burned |
| `Failed` | Deposits are NOT returned (execution failed; deposits are burned as spam penalty) |

Return of deposits is processed automatically by `advance_height` at the block when the state transition occurs. Deposit return is a credit to the depositor's liquid balance; no explicit claim transaction is required.

### 8.4 Deposit Burn Address

The null burn address is `[0x00; 32]`. Deposits credited to this address are permanently unspendable. The state root leaf for the burn address is included in state root computation (domain: `"burn_address_v1"`).

---

## 9. Voting Mechanics

### 9.1 Who May Vote

Only the operator account of a validator with `status = active` (SPEC-VAL-001 §5.1) at the time the `GovernanceVote` transaction is applied may cast or replace a vote. Validators that become inactive (jailed, unbonding, or exited) after casting a vote do not have their vote withdrawn; however, the weight used is the `self_bond` at the time the vote was cast, and is not adjusted if the validator's bond changes subsequently.

### 9.2 Vote Weight

Each vote carries `weight = validator.self_bond` (in venom) at the time the vote transaction is applied. Vote weight is snapshotted per vote, not recalculated at tally time.

If a validator re-votes, the tally accumulators are adjusted: subtract the prior vote's weight from the prior option's accumulator, then add the new weight to the new option's accumulator.

### 9.3 Quorum Eligibility Snapshot

At the moment a proposal transitions from `DepositPeriod` to `VotingPeriod`, `eligible_voting_weight` is snapshotted as the sum of `self_bond` over all validators with `status = active` at that block. This snapshot is used in all quorum and emergency-threshold calculations for the lifetime of the proposal. Validators that join or leave the active set after this snapshot do not affect the quorum denominator.

### 9.4 Tally Computation

The running tally is maintained live in the proposal record (`yes_weight`, `no_weight`, `noveto_weight`, `abstain_weight`). At `voting_deadline_height`, the final tally is evaluated using the formulas in §5.2. The tally is deterministic because vote weights are recorded at the time of the `GovernanceVote` transaction and the proposal record is updated atomically.

---

## 10. Interaction with the Existing Registry Update Path

### 10.1 Supersession

The existing `governance_proposal` operation (`msg_type = 0x0300`, implemented in `pqc-state::apply::governance` as TASK-037) is superseded by this module. Upon implementation of the full governance module:

1. `msg_type = 0x0300` MUST be retired from `MsgType` (mark as `Deprecated` in `pqc-types::transaction`).
2. Any transaction in the mempool with `msg_type = 0x0300` MUST be rejected with `MSG_TYPE_DEPRECATED`.
3. Finalized blocks that contain `0x0300` transactions remain valid for replay (backward compatibility); `pqc-state::apply` MUST continue to handle them during historical replay.

### 10.2 Migration of In-Flight Registry Updates

If any `registry_update` was submitted via `0x0300` and not yet executed at the time of governance module activation:
- It is treated as if it had been submitted as an `AlgorithmLifecycleUpdate` proposal via `GovernancePropose` with `initial_deposit = min_deposit` (pre-funded from the treasury account as a migration subsidy).
- A governance module activation height MUST be announced at least one deposit period (7 days) in advance.
- All existing `GovernanceReceipt` records (from TASK-037 execution) remain valid and MUST NOT be modified.

### 10.3 Retained Compatibility

The existing `GET /v1/governance/receipts/{proposal_id}` endpoint (serving old `GovernanceReceipt` records from TASK-037) MUST continue to be served. Old proposal IDs use `TxHash` as the key; new proposals use sequential uint64. The API implementation MUST route based on key format:
- If the ID parses as a 64-character hex string: look up in old `governance_receipts` store.
- If the ID parses as a decimal integer: look up in new `proposals` store.

---

## 11. API Endpoints

These endpoints are additive to the existing API. Field names and types are stable per Phase 4 backwards-compatibility rules (AGENTS.md §Phase 4 Rules).

### 11.1 GET /v1/governance/proposals

Returns a paginated list of governance proposals.

**Query parameters**:
- `status` (optional): filter by state string (`deposit_period`, `voting_period`, `passed`, `rejected`, `executed`, `failed`, `deposit_burned`, `veto_burned`)
- `page` (optional, default 1): page number
- `per_page` (optional, default 20, max 100): items per page

**Response** (HTTP 200):
```json
{
  "proposals": [
    {
      "proposal_id": 1,
      "proposal_type": "AlgorithmLifecycleUpdate",
      "proposer": "<hex address>",
      "state": "voting_period",
      "submit_height": 1000,
      "deposit_deadline_height": 1604800,
      "voting_start_height": 1100,
      "voting_deadline_height": 1705600,
      "total_deposit": "10000000000000000000000",
      "yes_weight": "1000000000000000000000000",
      "no_weight": "0",
      "noveto_weight": "0",
      "abstain_weight": "0",
      "eligible_voting_weight": "3000000000000000000000000",
      "title_hash": "<hex>",
      "rationale_hash": "<hex>"
    }
  ],
  "total": 1,
  "page": 1,
  "per_page": 20
}
```

All venom amounts are returned as decimal strings (to avoid JSON integer overflow for u128 values).

### 11.2 GET /v1/governance/proposals/:id

Returns the full proposal record for a single proposal.

**Path parameter**: `id` — decimal uint64 proposal ID.

**Response** (HTTP 200): same fields as the list item above, plus:
```json
{
  ...,
  "payload": { /* proposal-type-specific decoded fields */ },
  "execution_height": 1800,
  "executed_at_height": 1800
}
```

**Error** (HTTP 404): `{"error": "PROPOSAL_NOT_FOUND", "proposal_id": 99}`

### 11.3 GET /v1/governance/proposals/:id/votes

Returns all votes cast on a proposal.

**Path parameter**: `id` — decimal uint64 proposal ID.

**Response** (HTTP 200):
```json
{
  "proposal_id": 1,
  "votes": [
    {
      "voter": "<hex address>",
      "vote_option": "Yes",
      "weight": "1000000000000000000000000",
      "voted_at_height": 1200
    }
  ],
  "tally": {
    "yes_weight": "1000000000000000000000000",
    "no_weight": "0",
    "noveto_weight": "0",
    "abstain_weight": "0",
    "total_voting_weight": "1000000000000000000000000",
    "eligible_voting_weight": "3000000000000000000000000",
    "quorum_reached": false,
    "passed": false,
    "veto_reached": false
  }
}
```

**Error** (HTTP 404): `{"error": "PROPOSAL_NOT_FOUND", "proposal_id": 99}`

### 11.4 GET /v1/governance/parameters

Returns the current governance parameters from `StateStore.gov_params`.

**Response** (HTTP 200):
```json
{
  "min_deposit": "10000000000000000000000",
  "deposit_period_blocks": 604800,
  "voting_period_blocks": 604800,
  "quorum_bps": 6670,
  "threshold_bps": 5000,
  "veto_threshold_bps": 3340,
  "emergency_threshold_bps": 8000,
  "supermajority_bps": 6670,
  "epoch_length": 100,
  "max_active_set_size": 24,
  "halt_active": false,
  "halt_resume_height": 0,
  "slash": {
    "equivocation_bps": 500,
    "liveness_bps": 50,
    "invalid_vote_bps": 200,
    "evidence_validity_window_blocks": 2419200
  },
  "fee": {
    "base_fee": "500",
    "byte_fee": "2",
    "exec_fee_per_gas": "43",
    "sigverify_fee_v_a": "14000",
    "sigverify_fee_v_b": "14000",
    "sigverify_fee_v_c": "14000",
    "aimd_alpha_bps": 1000,
    "aimd_beta_bps": 5000,
    "burn_rate_bps": 0
  }
}
```

---

## 12. Error Codes

All errors are returned as `ApplyError` variants in the Rust apply layer, and as JSON `{"error": "<CODE>", ...}` from the API layer.

| Code | Trigger |
|------|---------|
| `PROPOSAL_NOT_FOUND` | `proposal_id` does not exist in `StateStore` |
| `WRONG_PROPOSAL_STATE` | Operation invalid for the proposal's current state |
| `PROPOSAL_OUT_OF_SCOPE` | `proposal_type` not recognized, or `param_key` not in allowlisted set |
| `CONFLICTING_PROPOSAL` | A proposal for the same governable object is already in `{DepositPeriod, VotingPeriod, Passed}` |
| `INVALID_PROPOSAL_PAYLOAD` | Payload fields missing, wrong type, or fail constraint checks |
| `INSUFFICIENT_DEPOSIT` | `initial_deposit` or `GovernanceDeposit.amount` exceeds sender balance after fees |
| `INVALID_DEPOSIT_AMOUNT` | `amount = 0` in `GovernanceDeposit` |
| `DEPOSIT_PERIOD_EXPIRED` | `GovernanceDeposit` submitted after `deposit_deadline_height` |
| `NOT_AN_ACTIVE_VALIDATOR` | `GovernanceVote` sender is not an operator of a validator with `status = active` |
| `INVALID_VOTE_OPTION` | `vote_option` not in `{1, 2, 3, 4}` |
| `VOTING_PERIOD_EXPIRED` | `GovernanceVote` submitted after `voting_deadline_height` |
| `INVALID_LIFECYCLE_TRANSITION` | `AlgorithmLifecycleUpdate` targets a backward or invalid transition |
| `INVALID_PARAMETER_VALUE` | `new_value = 0` for a parameter where 0 is not valid, or violates type constraints |
| `VALIDATOR_SET_CEILING_BELOW_ACTIVE_COUNT` | `ValidatorSetSizeUpdate.new_max < current_active_count` |
| `VALIDATOR_SET_HARD_CEILING_EXCEEDED` | `ValidatorSetSizeUpdate.new_max > 200` |
| `VALIDATOR_SET_BELOW_BFT_MINIMUM` | `ValidatorSetSizeUpdate.new_max < 4` |
| `INVALID_HALT_DURATION` | `halt_duration_blocks = 0` or `> 259200` |
| `INVALID_HALT_SCOPE` | `scope` not in `{1, 2}` |
| `MISSING_JUSTIFICATION_HASH` | `justification_hash` is all-zero in `EmergencyHalt` payload |
| `INVALID_SLASH_ORDERING` | `slash_liveness_bps > slash_equivocation_bps` |
| `EVIDENCE_WINDOW_BELOW_UNBONDING_PERIOD` | `evidence_validity_window < unbonding_period` |
| `MSG_TYPE_DEPRECATED` | `GovernanceProposal (0x0300)` submitted after module activation |
| `CHAIN_HALT_ACTIVE` | Transaction submitted while `halt_active = true` and `scope = 1` |
| `USER_TX_HALTED` | User transaction submitted while `halt_active = true` and `scope = 2` |

---

## 13. Implementation Checklist

This checklist maps to TASK-098. Each item is an independently testable unit. Items in audit scope (§1.4 of AGENTS.md) are marked `[AUDIT]`.

### 13.1 Types (`pqc-types`)

- [ ] Define `ProposalType` enum: `FeeParamUpdate(0x01)`, `AlgorithmLifecycleUpdate(0x02)`, `ValidatorSetSizeUpdate(0x03)`, `EmergencyHalt(0x04)`, `SlashParamUpdate(0x05)`
- [ ] Define `VoteOption` enum: `Yes(1)`, `No(2)`, `NoWithVeto(3)`, `Abstain(4)`
- [ ] Define `ProposalState` enum (§4.1)
- [ ] Define `ProposalRecord` struct (§6.1 fields)
- [ ] Define `DepositorRecord` struct (§6.2)
- [ ] Define `VoteRecord` struct (§6.3)
- [ ] Define `ExecutionReceipt` struct (§6.4)
- [ ] Define `GovParams` struct (§6.5)
- [ ] Define payload structs: `FeeParamUpdatePayload`, `AlgorithmLifecyclePayload`, `ValidatorSetSizePayload`, `EmergencyHaltPayload`, `SlashParamPayload`
- [ ] Add `MsgType::GovernanceDeposit(0x0500)`, `MsgType::GovernanceVote(0x0501)`, `MsgType::GovernancePropose(0x0502)`
- [ ] Mark `MsgType::GovernanceProposal(0x0300)` as deprecated

### 13.2 StateStore (`pqc-state::store`)

- [ ] Add `proposals: BTreeMap<u64, ProposalRecord>` keyed by `proposal_id`
- [ ] Add `depositors: BTreeMap<(u64, Address), u64>` (proposal_id, depositor → amount)
- [ ] Add `votes: BTreeMap<(u64, Address), VoteRecord>` (proposal_id, voter → vote)
- [ ] Add `gov_receipts_v2: BTreeMap<u64, ExecutionReceipt>` (new receipts; keep old `governance_receipts` for TASK-037 backward compat)
- [ ] Add `gov_params: GovParams` with initial values from §6.5
- [ ] Include `proposals`, `votes`, `gov_params` in state root computation (separate leaf hashes per collection)
- [ ] Implement `StateStore::insert_proposal`, `update_proposal_state`, `insert_vote`, `get_votes_for_proposal`, `insert_gov_receipt_v2`, `get_gov_params`, `update_gov_params`

### 13.3 Apply Layer (`pqc-state::apply::governance`) `[AUDIT]`

- [ ] Implement `apply_governance_propose(store, tx)` — validate, assign ID, write record, lock deposit
- [ ] Implement `apply_governance_deposit(store, tx)` — validate, accumulate, trigger state transition if `min_deposit` reached
- [ ] Implement `apply_governance_vote(store, tx)` — validate, adjust tally accumulators, write vote record
- [ ] Implement `apply_epoch_boundary(store, height)` — deposit expiry, tally finalization, proposal execution dispatch
- [ ] Implement `execute_fee_param_update(store, payload)` `[AUDIT]`
- [ ] Implement `execute_algorithm_lifecycle_update(store, payload)` `[AUDIT]`
- [ ] Implement `execute_validator_set_size_update(store, payload)`
- [ ] Implement `execute_emergency_halt(store, payload)`
- [ ] Implement `execute_slash_param_update(store, payload)` `[AUDIT]`
- [ ] Implement tally formula evaluation in `evaluate_tally(proposal) → TallyResult` `[AUDIT]`
- [ ] Implement emergency threshold check in `advance_height` fast-path for `EmergencyHalt` proposals
- [ ] Handle `0x0300` replay in historical blocks (non-deprecated path for state replay only)
- [ ] Return typed `ApplyError` variants; no `unwrap()`/`expect()` in this module `[AUDIT]`

### 13.4 Mempool Admission (`pqcd::devnet`)

- [ ] Reject `GovernancePropose` if `CONFLICTING_PROPOSAL` exists in StateStore
- [ ] Reject `msg_type = 0x0300` with `MSG_TYPE_DEPRECATED` after module activation height
- [ ] Reject all user transactions with `CHAIN_HALT_ACTIVE` or `USER_TX_HALTED` when `gov_params.halt_active = true`

### 13.5 API (`pqcd::devnet` or API layer)

- [ ] Implement `GET /v1/governance/proposals` with state filter and pagination
- [ ] Implement `GET /v1/governance/proposals/:id` — new uint64 ID path
- [ ] Implement `GET /v1/governance/proposals/:id/votes` with live tally
- [ ] Implement `GET /v1/governance/parameters`
- [ ] Preserve `GET /v1/governance/receipts/:proposal_id` for old `TxHash`-keyed receipts (TASK-037 compat)

### 13.6 Tests (minimum 8 required by TASK-098)

- [ ] `test_proposal_deposit_period_expires_and_burns` — deposit period expires without `min_deposit`; verify burns and state = `DepositBurned`
- [ ] `test_proposal_advances_to_voting_on_min_deposit` — `total_deposit` crosses `min_deposit`; verify `VotingPeriod` transition and `eligible_voting_weight` snapshot
- [ ] `test_vote_quorum_not_met_rejected` — voting period closes with participation < quorum; verify `Rejected` and deposit return
- [ ] `test_vote_veto_threshold_burns_deposits` — `noveto_weight / total_voting_weight ≥ veto_threshold`; verify `VetoBurned` and deposit burn
- [ ] `test_fee_param_update_executes_at_epoch_boundary` — `FeeParamUpdate` passes and `base_fee` is updated in `gov_params.fee` at the correct epoch boundary
- [ ] `test_algorithm_lifecycle_update_supersedes_old_path` — `AlgorithmLifecycleUpdate` executes and updates `registry[alg_id].lifecycle_status`; verify `0x0300` is rejected after activation
- [ ] `test_emergency_halt_fast_path` — `EmergencyHalt` proposal crosses `emergency_threshold` before `voting_deadline_height`; verify immediate halt activation
- [ ] `test_conflicting_proposal_rejected` — second `GovernancePropose` targeting same `alg_id` while first is `VotingPeriod`; verify `CONFLICTING_PROPOSAL`
- [ ] `test_slash_param_update_requires_supermajority` — `SlashParamUpdate` passes standard threshold but not supermajority; verify `Rejected`
- [ ] `test_deposit_return_on_passed` — `FeeParamUpdate` executes; verify all depositors receive their venom back

---

## 14. Open Items

| ID | Item | Blocking TASK-098? |
|----|------|--------------------|
| TBD-GOV2-01 | `EmergencyResume` proposal type for early lift of halt | No — halt auto-expires |
| TBD-GOV2-02 | Governance parameter update via governance (meta-governance for `min_deposit`, `deposit_period`, etc.) | No — values are fixed at genesis and require a future spec amendment |
| TBD-GOV2-03 | Token delegation and non-validator participation | No — Phase 8 per ADR-031 |
| TBD-GOV2-04 | `BurnRateUpdate` proposal type for adjusting `burn_rate_bps` (ADR-032) | No — can be handled via `FeeParamUpdate` `param_key = 0x0009` |
| TBD-GOV2-05 | Governance scope extension (allowlist additions, validator allowlist) | No — Phase 5+ |
| TBD-GOV2-06 | Slash accountability for emergency action abuse | No — future governance revision |
