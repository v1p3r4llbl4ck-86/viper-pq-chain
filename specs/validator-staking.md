# Validator and Staking Model Specification

**Spec ID**: SPEC-VAL-001  
**Version**: 0.3  
**Status**: Reserved  
**History**: v0.2 2026-04-21 (ADR-042); v0.3 banner 2026-04-25 (ADR-053 §T1.5 stake-weighted churn supersedes count-based); the economic model was active on the retired `viper-pq-1` chain.  
**Date**: 2026-04-25  
**Revised by**: ADR-042 (dynamic validator set: epoch model, churn limits, unbonding, voting power soft-cap, economic parameters, eligibility progression); ADR-051 (distributed BFT signing); ADR-053 §T1.5 (stake-weighted churn)  
**Depends on**: ADR-007, ADR-013, ADR-014, ADR-015, ADR-042, ADR-051, ADR-053, SPEC-TX-001, SPEC-ACCOUNT-001

> **Reserved — `token_economics`.** The public chain `viper-testnet-2` has no native token: it runs a PoA, operator-run validator set. The validator lifecycle in this document (registration, epoch model, churn limit, unbonding period, ADR-051 distributed signing, operator responsibilities) is active; the economic parts — self-bond and minimum stake, bond-weighted voting power, slashing, rewards — are implemented behind the `token_economics` Cargo feature, compiled out of the public chain build, and kept as a design reserve. With the feature off every active validator has a constant stake weight of 1, so the stake-weighted formulas below degenerate to per-validator counts. Nothing in this document is an offer, a sale or a promise of any token or other asset.

> **Revision banner (2026-04-25)**: ADR-053 §T1.5 (TASK-194, commit `341aee9`) replaces the count-based churn formula `max(4, active/256)` with a **stake-weighted** churn cap (governance-tunable bips of total active stake). The body of this spec still references the count-based formula in the §"Churn limit" subsection; treat that subsection as historical and use the code in `crates/pqc-types/src/churn.rs::stake_weighted_activation_limit` (referenced by `crates/pqc-state/src/store.rs`) as the binding reference for every chain from `viper-pq-1` (retired) onwards. ADR-051 distributed BFT signing (every validator co-signs precommits under their own seed; proposer waits up to `quorum_wait_ms`) is in effect — see `specs/consensus.md` §10/§11 for the signing-mode dispatch + ForkDigest preimage prefix.

---

## 1. Scope

This document specifies the PQ Chain validator and staking model: validator lifecycle, staking and bonding semantics, validator responsibilities, slashing conditions, quorum rules, and commit material constraints. It defines the structure and invariants of the validator set, not the final parameter values.

All numeric parameters marked TBD (minimum stake, unbonding period, slash amounts, reward schedule) are deferred to Phase 2 after prototype benchmark data exists, per ADR-015. This document makes those deferral boundaries explicit so that the Phase 1 implementation can proceed without inventing parameters prematurely.

This specification does not define:

- block production timing and proposer selection algorithm (Tendermint/CometBFT-like; details in consensus implementation)
- governance vote mechanics (TASK-010)
- token economics and reward distribution model (TASK-011, Phase 2)
- fee coefficient values (Phase 2, ADR-015)
- built-in operation payloads for staking transactions (SPEC-OPS, TASK-007)

---

## 2. Normative Language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as described in RFC 2119.

---

## 3. Normative References

| Reference | Document |
|-----------|----------|
| ADR-007 | PoS BFT consensus direction, constrained validator set |
| ADR-013 | Validator set targets: 24 prototype, 32 testnet, 50 stress ceiling |
| ADR-014 | Operator API internal at first public testnet |
| ADR-015 | Token economics model Phase 1, parameters Phase 2 |
| ADR-042 | Dynamic validator set on-chain: epoch model, churn, unbonding, slashing registry, RANDAO+VDF proposer |
| SPEC-TX-001 | Transaction Envelope Specification |
| SPEC-ACCOUNT-001 | Account, KeySet, and Algorithm Registry Specification |

---

## 4. Validator Identity

A validator is identified by its **operator address** — a standard PQ Chain account address (32 bytes, derived as specified in SPEC-ACCOUNT-001 §4.2). The operator account MUST hold at least one active key with `allowed_tx_types` permitting governance operations (bit 3 set).

A validator MUST register a **consensus key** — a separate key pair used exclusively for signing BFT votes and block proposals. The consensus key:

- MUST use an algorithm with `lifecycle_status = active` in the Algorithm Registry
- MUST use ML-DSA (any parameter set) as the primary algorithm, or SLH-DSA-SHAKE-192s as a permitted fallback (ADR-042, ADR-043); SLH-DSA variants other than SLH-DSA-SHAKE-192s are not permitted for consensus signing due to their verification overhead
- MUST be registered on-chain prior to the validator becoming active
- is separate from the operator's account KeySet and does not participate in key rotation via SPEC-ACCOUNT-001; it has its own rotation procedure (see §8.3)
- MUST NOT be reused across different validator registrations

Rationale for the consensus key separation: the operator account key is used for staking transactions and governance votes; the consensus key is used at high frequency in BFT rounds. Separating them limits blast radius if either is compromised and allows independent rotation.

---

## 5. Validator Lifecycle

### 5.1 States

| State | Description |
|-------|-------------|
| `candidate` | has met staking requirements; queued to enter the active set |
| `active` | in the current active validator set; participates in block proposal and voting |
| `jailed` | suspended due to a slashing offense; excluded from consensus; cannot exit until unjailed |
| `unbonding` | has signaled voluntary exit; stake is locked for the unbonding period; no longer in active set |
| `exited` | unbonding period complete; stake fully unlocked; no protocol obligations |

### 5.2 State Transition Graph

```
                 ┌──────────────────────────────┐
                 │ stake ≥ min_stake             │
                 │ + register consensus key      │
[none] ──────────►  candidate                   │
                 │                              │
                 └────────────┬─────────────────┘
                              │ set has capacity
                              │ + validator elected
                              ▼
                           active  ◄───────── unjail (if allowed)
                           │    │                    ▲
                    slash  │    │ voluntary           │
                    offense│    │ exit signal         │
                           ▼    ▼                    │
                         jailed  unbonding           │
                           │         │               │
                 governance│         │ unbonding     │
                 may force │         │ period        │
                 unbonding │         │ complete      │
                           ▼         ▼               │
                         jailed ──► exited ──────────┘
                          (force     │           re-stake +
                          unbond)    │           register
                                     └──────────────►
```

### 5.3 Transition Rules

#### 5.3.1 `[none] → candidate`

Requirements:
- Operator submits a validator registration transaction
- Self-bond amount ≥ `min_stake` (TBD, Phase 2)
- Consensus key registered and valid
- Operator account is in good standing (not jailed or flagged)

Effect: validator is added to the candidate queue. Stake is locked immediately on registration.

#### 5.3.2 `candidate → active`

Requirements:
- Active set has capacity (size < `max_validator_set_size`, currently 64 for genesis; see §9.1 for trajectory)
- Validator is selected from the candidate queue by stake ranking (highest self-bond takes priority among candidates)
- The number of validators activating in the epoch does not exceed the activation churn limit (see §7)
- No governance veto is pending for this validator (if using the whitelist eligibility mode; see §9.2)

Effect: validator is added to the active set at the next epoch boundary. The active set MUST NOT exceed `max_validator_set_size` at any time.

#### 5.3.3 `active → jailed`

Trigger: a slashing offense is detected and confirmed (see §7).

Effect:
- Validator is removed from the active set immediately (mid-epoch removal is permitted)
- Stake is partially or fully slashed (amounts TBD, Phase 2)
- Validator enters `jailed` state; it MUST NOT participate in consensus
- The jailed validator's consensus key is suspended

#### 5.3.4 `active → unbonding`

Trigger: operator submits a voluntary exit transaction, signed by the operator account key.

Requirements:
- Operator account has permission for governance/staking operations
- Validator has no pending slashing accusations
- The number of validators exiting in the epoch does not exceed the exit churn limit (see §7)

Effect:
- Validator is removed from the active set at the next epoch boundary (not immediately, to avoid disrupting in-progress consensus rounds)
- Stake enters the unbonding lock for `unbonding_period = 21 days` in blocks (see §6.3)
- Validator MUST NOT sign new votes or proposals during unbonding
- Slashing liability for offenses committed while active continues through the full unbonding period

#### 5.3.5 `jailed → unbonding` (governance-forced)

Trigger: governance vote forces a jailed validator to begin unbonding, typically for severe or repeat offenses.

Effect: same as voluntary exit, except the remaining stake after slashing begins the unbonding lock.

#### 5.3.6 `jailed → candidate` (unjail)

Requirements:
- Governance policy permits unjailing for this offense class (minor liveness failures are unjailable; equivocation may not be)
- Operator submits an unjail transaction
- Any required penalty fee is paid
- Operator self-bond is restored to ≥ `min_stake` (operator may need to top up if slash reduced it below minimum)

Effect: validator returns to `candidate` state and must wait for re-election to `active`.

#### 5.3.7 `unbonding → exited`

Trigger: `unbonding_period` blocks have elapsed since the unbonding start height.

Effect: stake is unlocked and returned to the operator account. Validator has no further protocol obligations.

#### 5.3.8 `exited → candidate`

A validator that has exited may re-register by submitting a new validator registration transaction, satisfying all preconditions of §5.3.1.

### 5.4 Validator Set Invariants

The following MUST hold at all times:

1. **Set size bound**: the active set MUST NOT exceed `max_validator_set_size` (64 at genesis; governance-controlled; see §9.1 for trajectory)
2. **No jailed validator in active set**: a validator with `status = jailed` MUST NOT participate in block proposal or voting
3. **No unbonding validator in active set**: a validator with `status = unbonding` MUST NOT sign new votes or proposals
4. **Consensus key uniqueness**: no two validators in the active or candidate set may share the same consensus public key
5. **Non-empty active set**: the active set MUST NOT be reduced to zero; a transition that would empty the active set MUST be rejected
6. **Epoch-boundary transitions only**: activations and voluntary exits MUST NOT take effect mid-epoch; they are queued and applied at the next epoch boundary. Emergency removals via governance (ValidatorTransaction::Reconfig) are the sole exception.

---

## 6. Staking Model

### 6.1 Self-Bond Requirement

Every validator MUST provide a self-bond — stake locked from the operator's own account. Self-bond is required to ensure validators have direct economic exposure to their own behavior.

- Minimum self-bond: `min_stake` (TBD, Phase 2)
- Self-bond is locked at validator registration and remains locked until the validator reaches `exited`
- If a slashing event reduces the self-bond below `min_stake`, the validator is automatically jailed pending top-up or forced unbonding

### 6.2 Delegation

Delegation (third-party stake assigned to a validator) is **not included in Phase 1**. The staking model in Phase 1 is self-bond only.

Rationale: delegation adds significant complexity to slashing distribution, reward accounting, and unbonding mechanics. Phase 1 focuses on establishing correct validator behavior with minimal economic surface. Delegation is deferred to Phase 2 or later.

This means Phase 1 validators are not a general liquid staking market. Validator economics are intentionally simple: operators stake their own tokens, receive rewards from their own validation work, and bear slashing risk directly.

### 6.3 Stake Locking and Unbonding

When a validator registers, its self-bond is **immediately locked**. Locked stake:

- MUST NOT be transferred
- MUST NOT be used to pay fees (separate liquid balance is required for fee payment)
- remains subject to slashing through the full unbonding period

The unbonding period starts when the validator enters `unbonding` state and runs for `unbonding_period` blocks. After `unbonding_period` elapses, the remaining stake (post-slash) is returned to the operator's liquid balance.

**`unbonding_period` is set to 21 days in blocks** (ADR-042). At a 1-second block time this is 1,814,400 blocks. This value is a governance parameter subject to the following constraint:

- Governance MAY increase `unbonding_period` above 21 days.
- Governance MUST NOT decrease `unbonding_period` below 21 days. Any governance proposal that would reduce it MUST be rejected by the execution layer.

Rationale: the 21-day unbonding period must be at least as long as the weak subjectivity period for the chain's security model. Reducing it below 21 days could allow a validator to withdraw stake before evidence of a recent offense is submitted on-chain.

### 6.4 Voting Power Soft-Cap

The effective voting power of each validator is subject to a soft-cap:

```
effective_voting_power = min(self_bond + delegated_stake, 2 × median_stake)
```

where `median_stake` is the median of all active validators' total bonded stake at the epoch boundary.

Stake above the soft-cap threshold remains locked and is fully slashable but does not contribute additional voting power or proportional reward weight. This prevents a single well-capitalized validator from acquiring a disproportionate fraction of voting power without fully decentralizing their stake.

The soft-cap is applied at each epoch boundary when voting powers are recomputed. It is a governance-mutable parameter; governance may adjust the multiplier (default: 2×) but MUST NOT set it below 1× (which would cap all validators to the median and collapse incentives).

### 6.5 Stake Top-Up

An active or jailed validator MAY increase its self-bond by submitting a stake top-up transaction. Top-up does not change validator status. It is required when a slash reduces the bond below `min_stake`.

---

## 7. Churn Limits

To prevent large, destabilizing validator set changes within a single epoch, ADR-042 defines churn limits applied at each epoch boundary.

### 7.1 Activation Churn

The maximum number of new validators that may enter `active` state at a single epoch boundary is:

```
max_activations_per_epoch = max(4, floor(active_set_size / 256))
```

Where `active_set_size` is the size of the active set at the start of the epoch boundary processing.

### 7.2 Exit Churn

The maximum number of validators that may transition from `active` to `unbonding` at a single epoch boundary is:

```
max_exits_per_epoch = max(4, floor(active_set_size / 32))
```

### 7.3 Total Turnover Cap

The total turnover (activations + exits) in a single epoch MUST NOT exceed 25% of the active set size:

```
total_turnover ≤ floor(0.25 × active_set_size)
```

If the combined queue of pending activations and exits would exceed the 25% cap, exits take priority over activations (removing misbehaving validators takes precedence). Among exits, forced exits (governance-ordered) take priority over voluntary exits. Among activations, higher-stake candidates take priority.

### 7.4 Rationale

These limits prevent an adversary from rapidly cycling a large fraction of the validator set to exploit weak subjectivity windows or to disrupt liveness. The formulas are calibrated after Ethereum's churn model but adapted to the smaller Tendermint-like committee sizes: the floor of 4 ensures the set is never completely frozen at small sizes, while the linear term scales naturally with set growth.

---

## 8. Slashing

For full slashing specification see SPEC-SLASH-001. This section summarizes the offense taxonomy and cross-references the slashing parameters defined by ADR-042.

### 8.1 Offense Classes and Hardcoded Parameters

The following offenses and their slash fractions are **hardcoded** (not adjustable via the pluggable verifier registry):

| Offense | Slash fraction | Jail | Tombstone | Unjailable |
|---------|---------------|------|-----------|-----------|
| Equivocation (double-sign) | 5% of self-bond | Yes | Yes | No |
| Double-vote (surround-vote) | 5% of self-bond | Yes | Yes | No |
| Downtime (persistent liveness failure) | 0.01% of self-bond | Yes | No | Yes |

The 5% equivocation slash and 0.01% downtime parameters are hardcoded because they are safety and liveness invariants. They may only be changed by a hard fork.

### 8.2 Liveness Failure Details

Definition: a validator fails to sign a threshold number of blocks in a rolling window.

Measurement: within a rolling window of `liveness_window` blocks, if a validator has missed more than `max_missed_blocks` signing opportunities, a liveness violation is recorded.

Response (progressive):
- first violation within a governance-defined cooling period: warning logged on-chain; no economic penalty
- repeated violations: jail + 0.01% slash of self-bond
- jail from liveness failure is unjailable after a waiting period and an unjail transaction

### 8.3 Pluggable Verifier Registry

ADR-042 introduces a pluggable verifier registry for evidence types beyond the hardcoded core offenses:

```
evidence_type_id → verifier_contract
```

Adding a new evidence type to the registry requires:
- a governance proposal with supermajority approval (≥ 66% of voting power)
- a 30-day timelock before the new verifier becomes active

This allows new slashing conditions — such as non-attestation of data availability, incorrect PQ signature aggregation, or MEV censorship proofs — to be added without a hard fork. See SPEC-SLASH-001 for the full verifier registry specification.

### 8.4 Correlation Penalty

ADR-042 adopts an Ethereum-style correlation penalty to deter coordinated validator misbehavior:

```
slash_multiplier = min(3 × (fraction_slashed_in_window / 0.334), 1.0)
final_slash = base_slash × (1 + slash_multiplier)
```

Parameters:
- **Multiplier**: 3 (base)
- **Window**: 36 days in blocks
- **Cap**: 100% of self-bond when ≥ 33.4% of the active set is slashed in the 36-day window

The correlation penalty is computed at slash execution time based on the total slash events within the window. Individual validators slashed in isolation pay only the base rate. Validators slashed as part of a coordinated attack pay up to 4× the base rate (1 + 3), up to 100% of their self-bond.

---

## 9. Validator Responsibilities

### 9.1 Block Proposal

When selected as proposer for a round:

- the proposer MUST build a valid block that includes transactions from the mempool up to the block size limit
- the proposer MUST include the previous round's commit material (validator signatures) in the block header
- the block MUST be signed with the proposer's consensus key
- the proposer MUST broadcast the proposed block within the round timeout

### 9.2 Voting

Active validators MUST:

- vote on every proposed block within the vote timeout using their consensus key
- sign prevote and precommit messages using the consensus key's active algorithm
- not sign conflicting votes at the same height and round (equivocation)
- not replay historical votes in current rounds

Vote signatures contribute to the commit material (see §9.5).

### 9.3 Consensus Key Management

The consensus key may be rotated independently of the operator account KeySet:

- the operator submits a consensus key rotation transaction, signed by the operator account key
- the new consensus key MUST use ML-DSA (primary) or SLH-DSA-SHAKE-192s (fallback) as its algorithm (see §4)
- there MUST be a transition window of at least `consensus_key_rotation_window` blocks during which the old key remains valid for signing; this prevents vote gaps during the rotation
- once the window expires, only the new consensus key is valid

`consensus_key_rotation_window` is a governance parameter (TBD, Phase 2). It must be long enough for all validators to observe and register the new key before the old one is invalidated.

### 9.4 Availability

Active validators MUST maintain sufficient uptime to avoid triggering the liveness failure threshold. The operator is responsible for:

- running the node with a stable internet connection
- monitoring liveness metrics via the internal operator API (see ADR-014)
- responding to connectivity or configuration failures before they accumulate to a slashable threshold

### 9.5 Operator API

Validators operate an internal operator API (health, metrics, maintenance, snapshot controls) as specified in ADR-014. This surface:

- is not publicly exposed at the first public testnet
- is protected by strong operator authentication (mechanism TBD)
- is the primary channel for operators to monitor liveness, verify consensus participation, and manage snapshots

---

## 10. Quorum, Set Sizing, and Eligibility

### 10.1 Active Set Size Trajectory

The active set size is a governance-controlled protocol parameter. It MUST NOT be changed mid-epoch; changes take effect at the next epoch boundary.

| Period | `max_validator_set_size` | Quorum (2/3+1) | ML-DSA-65 commit |
|--------|--------------------------|----------------|------------------|
| Genesis (Phase 8) | 64 | 43 | ~142 KB/block |
| Year 2 | 256 | 171 | ~566 KB/block |
| Year 5+ | 1024 | 683 | requires STARK aggregation |

The protocol implementation MUST support growth along this trajectory. Scaling to 1024 validators is contingent on STARK-based commit aggregation being operational and audited.

### 10.2 Eligibility Mode

ADR-042 introduces a single governance parameter `eligibility_mode` that controls admission policy:

| Mode | Description | Active phase |
|------|-------------|-------------|
| `whitelist` | New validators require an explicit governance allowlist entry | Phase 8–9 |
| `hybrid` | Allowlist for large-stake validators; open for validators below a stake threshold | Phase 9–10 |
| `permissionless` | Any account meeting the stake requirement may become a candidate | Target: within 18 months post-mainnet |

The `eligibility_mode` parameter MUST be changed only by a governance supermajority vote (≥ 66%). A transition from a more restrictive mode to a less restrictive mode is a security-sensitive change and is subject to an extended timelock of 30 days before taking effect.

### 10.3 Quorum Rules

The consensus quorum is `⌊(2 × active_set_size / 3)⌋ + 1`.

A block is finalized when it collects precommit signatures from at least the quorum count of active validators. Finalization is deterministic: once a block is finalized, it is irreversible.

If the active set drops below quorum (e.g. due to mass jailing), consensus halts. This is a deliberate safety property: the chain halts rather than finalize with insufficient validator participation. Recovery from such an event requires governance intervention.

### 10.4 PQ Commit Material Budget

Commit material (the set of validator precommit signatures included in each block) is a first-class storage and bandwidth cost in a PQ-native chain.

At genesis scale (64 validators, quorum 43, ML-DSA-65):
- commit per block ≈ 43 × 3,309 B = ~142 KB
- at 1-second block time: ~142 KB/s of commit data on top of transaction data

At 256 validators (quorum 171):
- commit per block ≈ 171 × 3,309 B = ~566 KB
- storage accumulates at ~49 GB/day at 566 KB/block and 1-second blocks

This constrains:
- block propagation: validators and full nodes MUST have sufficient bandwidth to receive, verify, and re-propagate commit material within the block interval
- storage: commit material grows substantially with committee size; state-sync and snapshot infrastructure is required
- consensus key algorithm selection: SLH-DSA-SHAKE-192s is permitted as a minority fallback only; a quorum of SLH-DSA signers is impractical at these committee sizes

SNARK-based commit aggregation is the long-term path to scaling beyond 256 validators.

---

## 11. Economic Model

### 11.1 Inflation Schedule

| Year | Inflation rate |
|------|---------------|
| Y1 (genesis) | 8.0% |
| Y2 | 7.5% |
| Y3 | 7.0% |
| ... | −0.5 pp/year |
| Y15+ | 1.0% (floor) |

The floor of 1% is enforced in the execution layer; governance MUST NOT set inflation below the floor.

### 11.2 Issuance Split

New token issuance per epoch is distributed as follows:

| Recipient | Share |
|-----------|-------|
| Validators and delegators | 80% |
| Treasury (public goods) | 10% |
| Infrastructure diversity fund | 10% |

The infrastructure diversity fund is a governance-controlled account used to grant subsidies to validators in under-represented jurisdictions, hosting classes, or running minority client implementations.

### 11.3 Validator Commission

| Parameter | Value |
|-----------|-------|
| Commission floor | 3% |
| Commission ceiling | 25% |
| Default (genesis) | 7% |

A validator MUST NOT set a commission rate below the floor. The floor prevents a race to zero that would exclude smaller operators with legitimate infrastructure costs.

### 11.4 Fee Split

Transaction fees are distributed as follows:

| Recipient | Share |
|-----------|-------|
| Validators and delegators | 70% |
| Treasury | 20% |
| Burn | 10% |

These splits are governance-adjustable by simple majority vote.

### 11.5 Reward Distribution Formula

The per-validator reward weight for each epoch is:

```
reward_weight = α × (1 / N) + (1 − α) × (stake_effective / total_effective_stake)
```

where:
- `N` is the number of active validators in the epoch
- `stake_effective` is the validator's effective stake after applying the soft-cap (§6.4)
- `α` is a governance parameter in [0, 1] (default: 0.3)

A higher `α` favors equal distribution across validators (Polkadot-style), reducing stake concentration incentives. A lower `α` weights rewards toward higher-staked validators. The default `α = 0.3` provides moderate equalization while preserving performance incentives.

---

## 12. Governance Touchpoints

The following aspects of the validator model are protocol parameters controlled by governance:

| Parameter | Governance action | Phase 8 default |
|-----------|------------------|-----------------|
| `max_validator_set_size` | simple majority; effective next epoch | 64 |
| `eligibility_mode` | supermajority (66%); 30-day timelock | `whitelist` |
| `min_stake` | simple majority | TBD |
| `unbonding_period` | simple majority; increase only; floor 21 days | 21 days |
| `liveness_window` | simple majority | TBD |
| `max_missed_blocks` | simple majority | TBD |
| `evidence_validity_window` | simple majority | 28 days in blocks |
| `consensus_key_rotation_window` | simple majority | TBD |
| `inflation_rate` | supermajority (66%); floor 1% enforced | 8% |
| `issuance_split` (validator/treasury/diversity) | supermajority (66%) | 80/10/10 |
| `commission_floor` | supermajority (66%) | 3% |
| `commission_ceiling` | supermajority (66%) | 25% |
| `fee_split` (validator/treasury/burn) | simple majority | 70/20/10 |
| `reward_alpha` | simple majority | 0.3 |
| `voting_power_softcap_multiplier` | simple majority; floor 1× | 2× |
| Verifier registry additions | supermajority (66%); 30-day timelock | — |
| Unjail policy per offense class | supermajority (66%) | equivocation non-unjailable |
| Allowlist additions and removals (whitelist mode) | supermajority (66%) | defined at genesis |

---

## 13. Security Considerations

### 13.1 Slashing Liability Through Unbonding

A validator that exits via the voluntary unbonding path remains liable for slashing for offenses it committed while active, throughout the full 21-day unbonding period. Evidence submitted within `evidence_validity_window` (28 days) of the offense height is valid even if the validator is already in `unbonding` state. This prevents the "exit before evidence" attack.

### 13.2 Consensus Key Compromise

If a consensus key is compromised, the attacker can produce equivocation evidence that triggers immediate jailing and tombstoning. The operator MUST:

1. detect the compromise via anomalous signing activity in the operator API
2. submit a consensus key rotation transaction signed by the operator account key
3. contact governance if the compromise results in jailing, to begin the unjail process

Because the consensus key is separate from the operator account key, compromise of the consensus key does not grant the attacker access to the operator's staked funds directly. The attacker can trigger jailing and a 5% slash, but cannot initiate unbonding or transfer funds.

### 13.3 Minimum Active Set Safety

The quorum rule (`⌊2n/3⌋ + 1`) means that consensus halts if more than one-third of the active set is simultaneously unavailable. At 64 genesis validators, 22 simultaneous failures are sufficient to halt consensus. The whitelist eligibility policy and geographic diversification requirements are designed to reduce the probability of correlated failures.

### 13.4 SLH-DSA-SHAKE-192s as Fallback Only

SLH-DSA-SHAKE-192s is permitted as a fallback consensus key algorithm for defense-in-depth. At quorum 43, a fully SLH-DSA-192s quorum would require approximately 45 ms of sequential verification per block — approaching prevote timeouts. This is why SLH-DSA-192s validators SHOULD remain a minority of the active set. The restriction is enforced by monitoring, not by a hard protocol rule, to avoid excluding validators that have legitimate reasons to use the more conservative algorithm.

---

## 14. Open TBDs

| ID | Parameter | Blocking Phase 8? |
|----|-----------|------------------|
| TBD-VAL-01 | `min_stake` — minimum self-bond amount | No — structure defined; value deferred |
| TBD-VAL-02 | `unbonding_period` exact block count — set to 21 days; needs calibration at mainnet block time | No |
| TBD-VAL-03 | `liveness_window` and `max_missed_blocks` | No |
| TBD-VAL-04 | `evidence_validity_window` (default 28 days) | No |
| TBD-VAL-05 | `consensus_key_rotation_window` | No |
| TBD-VAL-06 | Correlation penalty implementation — ledger of 36-day slash events | No |
| TBD-VAL-07 | Reward distribution implementation — α parameter, per-epoch accounting | No — §11 defines structure |
| TBD-VAL-08 | `eligibility_mode` hybrid threshold — stake amount dividing open/closed admission in hybrid mode | No |
| TBD-VAL-09 | Delegation model | No — explicitly deferred beyond Phase 8 |
| TBD-VAL-10 | Infrastructure diversity fund governance — grant criteria, disbursement schedule | No |
