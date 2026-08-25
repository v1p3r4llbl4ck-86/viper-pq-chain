# SPEC-TOKEN-001: Token Utility and Economic Role

**Status**: Reserved
**History**: v0.2 (2026-04-12) was normative for the retired `viper-pq-1` chain; numeric parameters are in SPEC-TOKEN-002 (ADR-024).
**Version**: 0.2
**Date**: 2026-04-12 (updated from 2026-04-09)

> **Reserved — `token_economics`.** The public chain `viper-testnet-2` has no native token. The token model and mechanisms in this document are implemented behind the `token_economics` Cargo feature, compiled out of the public chain build, and kept as a design reserve; they are not active on any network at the time of the public release. Nothing in this document is an offer, a sale or a promise of any token or other asset.

---

## 1. Scope

This document defines the economic role of the Viper native token (VPR): what it does, who uses it, and what mechanisms govern its use in Phase 1. Numeric parameters (supply, distribution, staking minimum, slashing amounts, fee coefficients) are defined in SPEC-TOKEN-002 (`specs/tokenomics.md`), which was produced in Phase 5 (TASK-070, ADR-024). ADR-015 deferred these parameters pending benchmark data; ADR-024 resolves all deferred items.

The token exists to make the trust layer function correctly. It is not a speculative instrument, a governance token unmoored from protocol participation, or a mechanism for extracting rent from users. Every role listed here corresponds to a real protocol function.

---

## 2. Token Roles

The native token serves four distinct roles. Each role maps to a specific protocol mechanism. No other roles exist in Phase 1.

### 2.1 Fee Payment

Users pay the protocol fee denominated in the native token for every transaction. The fee covers three separate costs:

| Fee component | What it represents | Mechanism owner |
|--------------|-------------------|----------------|
| `base_fee` | minimum per-transaction network cost | protocol |
| `byte_fee × tx_bytes` | bandwidth and storage cost of the raw transaction | protocol |
| `effective_sigverify_fee` | CPU cost of verifying the post-quantum signature | protocol; calibrated to measured cycles |
| `exec_fee × gas_used` | state transition execution cost | protocol |

The fee formula is: `fee = base_fee + byte_fee × tx_bytes + effective_sigverify_fee + exec_fee × gas_used`

Formal definition: [SPEC-FEE-001](fee-model.md)

The fee MUST be paid in the native token. No alternative denomination is supported in Phase 1.

Fee payment is a trust mechanism, not only a revenue mechanism. It prices signature verification cost, which is materially higher for post-quantum algorithms than for classical ones, and prevents economic DoS attacks against the consensus layer.

### 2.2 Validator Self-Bond

Validators MUST bond native tokens in order to participate in consensus. The self-bond is the economic stake that makes slashing meaningful. There is no delegation in Phase 1 — only direct self-bond.

Self-bond serves two functions:

1. **Admission signal** — demonstrates that the validator has genuine skin in the game before being added to the validator allowlist
2. **Slashing collateral** — provides the economic collateral that is partially or fully seized in response to equivocation, persistent liveness failure, or other slashable events (see SPEC-VAL-001 §7)

The minimum self-bond amount is deferred to Phase 2. The requirement that a minimum self-bond MUST exist before becoming a candidate is not deferred — it is a Phase 1 invariant.

Formal definition: [SPEC-VAL-001](validator-staking.md)

### 2.3 Governance Participation

Voting weight in governance is denominated in self-bond. In Phase 1, only validator operators may propose and vote on governance proposals. A validator with more self-bond has proportionally greater voting weight.

Governance controls changes to the Algorithm Registry (lifecycle status, fee class, additions), protocol parameters from the allowlisted parameter set, and emergency actions. See SPEC-GOV-001 for the full scope.

No separate governance token exists. Governance participation is not separable from validator participation in Phase 1. This keeps governance weight aligned with economic commitment to the network's security.

Formal definition: [SPEC-GOV-001](governance-module.md)

### 2.4 Slashing Exposure

Staked tokens are at risk. Slashing is a direct economic consequence of provable validator misbehavior. This is not a separate role from self-bond, but it is a distinct economic function: slashing destroys token value proportional to the severity of the violation.

Slashing events:
- equivocation (double signing) — severe, defined percentage of self-bond
- persistent liveness failure — progressive, defined percentage per epoch after threshold
- invalid vote — minor, warnings first
- replay attempt — contextual

Slashing amounts are deferred to Phase 2. The existence of slashing as a mechanism is not deferred.

Formal definition: [SPEC-VAL-001](validator-staking.md) §7

---

## 3. Actor Model

### 3.1 Transaction Senders (Fee Payers)

Any account holder who submits a transaction pays a fee in the native token. This includes:

- individuals managing vault accounts
- enterprises running attestation workflows
- identity providers anchoring proofs
- custody operators performing key rotations
- any party submitting a governance proposal or vote

Fee payment requires holding a token balance. The account MUST have sufficient balance before a transaction is admitted to the mempool.

### 3.2 Validators

Validators hold native tokens as self-bond. The self-bond must be posted before the candidate state can be reached. Validators earn transaction fees as part of the fee distribution structure (split between proposer and validator pool; exact percentages deferred to Phase 2).

In Phase 1 the validator set is permissioned (allowlist governance). Economic participation through self-bond does not alone qualify an operator for the validator set.

### 3.3 Governance Participants

In Phase 1 governance participants are validator operators. Their effective vote weight is their self-bond amount at the time of the proposal snapshot. A validator who exits or reduces their self-bond loses proportional governance weight. There is no separate class of governance-only token holder in Phase 1.

### 3.4 Attesters and Institutional Operators

Institutional operators who submit attestations, proof anchors, or identity-linked proofs pay fees like any other transaction sender. No special token role exists for attesters in Phase 1 beyond fee payment. They hold tokens in the same way as any account.

There is no protocol-level distinction between an individual fee payer and an institutional fee payer. The distinction is a business-layer concern, not a protocol mechanism.

---

## 4. Phase 1 Mechanisms

These mechanisms are fully defined in Phase 1. Their behavior is normative. Their numeric parameters are not.

| Mechanism | Phase 1 status | Where defined |
|-----------|---------------|--------------|
| Fee computation formula | normative | SPEC-FEE-001 §3 |
| Fee classes per algorithm (V-A, V-B, V-C) | normative | SPEC-FEE-001 §4 |
| effective_sigverify_fee derivation | normative | SPEC-FEE-001 §5 |
| Mempool fee admission pipeline | normative | SPEC-FEE-001 §7 |
| Per-sender verify budget enforcement | normative | SPEC-FEE-001 §8 |
| V-C per-block cap | normative | SPEC-FEE-001 §8 |
| Self-bond requirement for validator candidacy | normative | SPEC-VAL-001 §4 |
| Slashing taxonomy and triggers | normative | SPEC-VAL-001 §7 |
| Governance weight = self-bond | normative | SPEC-GOV-001 §4 |
| Proposal and vote mechanics | normative | SPEC-GOV-001 §5–§7 |
| Fee distribution structure (components) | normative (structure only) | §5 below |

---

## 5. Fee Distribution Structure

Fees collected from transactions MUST be distributed across the following recipients. The split percentages are deferred to Phase 2.

| Recipient | Role |
|-----------|------|
| Block proposer | additional incentive for timely block proposal |
| Validator pool | distributed among all active validators proportional to their self-bond |
| Protocol treasury | optional reserve for ecosystem and development funding |
| Burn | optional permanent removal from supply |

**What is normative (all phases):**

- the proposer MUST receive a portion of collected fees
- no fee component is silently discarded; every collected token is accounted for — sender debit = total fee credit, zero fee created or destroyed

**What is normative from Phase 4 onward (validator-set protocol active):**

- the validator pool MUST receive a portion of collected fees
- the proposer's share MUST NOT exceed 100% (at least some must go to the pool)

**Phase 3 implementation (TASK-049, ADR-019 revised):**

The validator-pool requirement is **implemented** for Phase 3 with a static-config validator set. The SPEC-TOKEN-001 tension from the prior 100%-to-proposer provisional rule is resolved.

During Phase 3:

- `fees_collected` (Σ `fee_charged + fee_tip` across all included transactions) is split between the proposer and the validator pool
- the proposer receives a priority share (`proposer_share_bps / 10_000`; Phase 3 default 50%)
- the remaining pool share is split equally among all `pool_validators` (all active validators by config, including the proposer as a validator)
- integer-division rounding goes to the proposer
- the accounting invariant holds: `Σ proposer_credit + Σ validator_credit == fees_collected` exactly — no fee is created or destroyed
- empty blocks are a no-op: `distribute_block_fees` is called with `fees_collected = 0`, no balances are touched
- out-of-gas transactions still charge the full `tx.fee`; this amount enters `fees_collected`

Remaining Phase 3 provisional behavior: the validator pool is derived from `config.devnet.validators` (static config, no on-chain staking). The full on-chain validator lifecycle (registration, bonding, jailing, unbonding) is deferred to Phase 4 ADR-007.

**What is deferred to Phase 2/4:**

- the exact split percentages between proposer, pool, treasury, and burn
- whether a burn component exists and at what rate
- treasury governance and spending rules

---

## 6. What The Token Is Not

The following uses are explicitly outside Phase 1 scope and are not implied by the token's design:

| Non-use | Reason |
|---------|--------|
| RWA tokenization or transfer restriction | ADR-012: excluded from Phase 1 scope |
| Collateral for off-chain borrowing or DeFi | outside Phase 1 trust layer; no on-chain lending or margin protocol |
| Cross-chain bridging denomination | no bridge in Phase 1; out of threat model scope |
| Speculation vehicle or primary investment product | the network monetizes security and trust, not token appreciation |
| Proof of participation reward beyond fee distribution | no liquidity mining, no airdrops, no points system |
| Staking delegation to third parties | self-bond only in Phase 1; delegation deferred |
| NFT or fungible asset issuance platform | Phase 1 is vault + attestation + key management only |

These exclusions are not temporary oversights. They reflect the principle that token utility must be grounded in actual protocol function. Adding utility roles before the corresponding protocol mechanisms exist produces artificial demand detached from value delivery.

---

## 7. Deferred to Phase 2

The following are deliberately undefined until Phase 2 prototype benchmark data exists:

| Item | Why deferred |
|------|-------------|
| Total supply and issuance curve | requires knowing the target staking ratio and reward schedule, which require measured fee revenue |
| Validator reward amounts | must be calibrated to observed hardware costs and fee income |
| APR estimates | meaningless before supply, reward schedule, and staking ratio are known |
| Staking minimum (absolute amount) | requires knowing the target validator set economic profile |
| Slashing percentages | must be calibrated to be punishing but not permanently destructive; requires understanding typical self-bond levels |
| `byte_fee` and `sigverify_fee` coefficients | calibrated to measured cycles on reference hardware (SPEC-TEST-001 §6.1) |
| `exec_fee` per gas unit | calibrated to state transition benchmarks |
| Treasury allocation percentage | depends on total fee revenue and ecosystem funding needs |
| Burn rate | depends on issuance curve and monetary policy choice |
| Emission schedule | depends on launch design; not a Phase 1 commitment |

Publishing any of these numbers before Phase 2 benchmarks would produce arbitrary values that will need to change, damaging protocol credibility. The model is designed to be principled; the parameters will be evidence-based.

---

## 8. Design Principles

1. **Utility before narrative** — every token function corresponds to an actual protocol mechanism. There is no utility claim without a corresponding spec section.
2. **No artificial scarcity mechanisms** — fee levels are calibrated to real verification and storage costs, not manufactured to create token demand.
3. **Alignment between security stake and governance weight** — validators cannot govern without economic exposure; governance weight reflects actual commitment to network security.
4. **Fees price real costs** — signature verification is materially more expensive for post-quantum algorithms; the fee model reflects this honestly rather than subsidizing expensive operations.
5. **Parameters follow measurement** — no number is published before the corresponding benchmark exists.

---

## 9. Cross-References

| Document | Relevance |
|----------|-----------|
| ADR-015 | authoritative decision for Phase 1 model vs Phase 2 parameters split |
| ADR-012 | exclusion of RWA tokenization from Phase 1 |
| [SPEC-FEE-001](fee-model.md) | fee formula, classes, mempool admission |
| [SPEC-VAL-001](validator-staking.md) | self-bond, slashing, validator lifecycle |
| [SPEC-GOV-001](governance-module.md) | governance weight, proposal and vote mechanics |
| [SPEC-TEST-001](testnet-metrics.md) | benchmark measurement protocols; fee parameter calibration inputs |
| [WHITEPAPER.md](../WHITEPAPER.md) §13 | token utility narrative summary |
