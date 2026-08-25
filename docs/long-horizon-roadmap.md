# Long-Horizon Roadmap (Y2 → Y20+)

**Status:** strategy doc, not a commitment.
**Owners:** core protocol team.
**Last updated:** 2026-05-06 (token-economics sections re-labelled Reserved at the public release).
**Authority:** TASK-225 (essay items 21-25 consolidated), referenced from ROADMAP.md "Deferred" section.

> **Public-chain note.** `viper-testnet-2` has no native token: the
> `token_economics` feature is compiled out and its specs are
> `Reserved`. §4 below (fee-primacy crossover) and every stake-weighted
> measure in §5 apply only if token economics are ever activated by a
> future decision; on a PoA validator set every validator has equal
> weight. They are kept here because the direction was agreed, not
> because the timing is live.

This doc consolidates the long-horizon items the project has already
agreed *direction* on but where the *timing* depends on external
ecosystems (NIST, IETF, Ethereum Lean, FIPS-206 finalisation, audit
results) or on the network reaching scale that current architecture
does not yet warrant. Five workstreams are tracked here:

| § | Topic | Trigger | Y-band |
|---|-------|---------|--------|
| 1 | STARK signature aggregation for PQ sigs | Ethereum Lean STARK aggregation matures | Y4-Y6 |
| 2 | PQ-VRF migration | IETF/NIST PQ-VRF standardisation | Y3-Y5 |
| 3 | 3rd algorithm (NIST on-ramp 2028-2029) | NIST on-ramp winner announcement | Y3-Y4 |
| 4 | Fee-primacy crossover (Reserved — token economics) | On-chain fee revenue overtakes inflation | Y8-Y12 |
| 5 | Diversity targets enforcement | Operator cohort growth | rolling Y2-Y10 |

Numbers in this doc are best-guess at 2026-05; they update annually
or whenever an upstream milestone moves. Do not cite specific years
without checking the "Last updated" line at the top.

---

## 1. STARK signature aggregation for ML-DSA / SLH-DSA

### Why

Lattice signatures (ML-DSA-65 ≈ 3.3 KB) and hash-based signatures
(SLH-DSA-SHAKE-256s ≈ 29.8 KB) dominate Viper's per-block bandwidth
the moment the active set grows beyond a few dozen validators. At
3 commit signatures × 3.3 KB × 172 800 blocks/day (500 ms cadence)
the chain already produces ~1.7 GB/day of pure consensus signature
weight at zero traffic; with a 64-validator active set the same
arithmetic gives ~36 GB/day. KNOWN-ISSUES R-10 calls this out as
the intrinsic PQ blockchain footprint cost.

STARK aggregation collapses N independent ML-DSA / SLH-DSA verifications
into one O(log N)-sized proof. The Ethereum Lean Consensus track is
the obvious source: their stated direction is "STARK-aggregated
signatures across the entire active set per slot" with proof sizes in
the few-hundred-KB range regardless of N.

### Trigger conditions

1. A reference Lean STARK aggregator targeting BLS12-381 *or* a PQ
   curve is production-ready in Rust (or has Rust bindings) with a
   stable API.
2. Aggregator handles at least one of the algorithms Viper carries
   on chain: ML-DSA-65, SLH-DSA-SHAKE-192s, SLH-DSA-SHAKE-256s. ML-DSA
   gets aggregator support first historically (lattice arithmetic
   maps to STARK-friendly fields more naturally than hash-tree paths).
3. Verifier proof check fits the per-block budget — the gate is the
   *recipient-side* cost, not the producer-side proving cost. A 50 ms
   STARK verify on a typical validator is acceptable under the
   500 ms / 1000 ms / 2000 ms candidate block-time bands TASK-186 is
   measuring.

### Deferred design questions

- **Aggregator placement.** Producer-side aggregation (one proof per
  block) vs. relay-aggregator subnet (proofs aggregated across
  multiple blocks for late-arriving signatures). Producer-side is
  simpler; relay-aggregator absorbs the M2b distributed-signing
  latency tail. Choose at the day the aggregator lands.
- **Fork-digest binding.** STARK-aggregated proofs carry their own
  domain separator; whether to bind it to ADR-053 §T1.2 ForkDigest or
  use a distinct PROOF-AGGREGATION domain. Defer to ADR at landing.
- **Dual-path window.** P-COMPAT-001 §7 mandates a deprecation epoch
  for the legacy non-aggregated path; the window must be ≥ unbonding
  period. Initial estimate: 1 year on mainnet, 1 month on testnet.

### Non-goals

- Aggregating across blocks. The aggregator runs per-block; cross-block
  is a separate optimisation tracked under TASK-228 (scale-up plan)
  if the per-block path is not enough at the 256-validator band.
- Aggregating finality-gadget signatures only. The whole consensus
  signature flow goes through aggregation, including the slashing-
  evidence path (which has separate ADR-042 §16 invariants).

### Tracking

- Open ADR slot: ADR-061 (reserved for the aggregation cutover when
  the trigger conditions are met).
- TASK-228 (Phase 10+ scale-up) lists STARK aggregation maturity as
  one of three gates for scaling beyond 256 validators.
- KNOWN-ISSUES R-10 is the closure target — once aggregation lands
  the per-block signature footprint is bounded irrespective of
  active-set size.

### Y-band

Earliest plausible Y4 (2030) given Ethereum Lean's own pace; Y5-Y6
more realistic if Viper waits for a second independent implementation
(audit-readiness gate).

---

## 2. PQ-VRF migration

### Why

ADR-053 §T1.4 fixes the genesis randomness as `RANDAO + ML-DSA-65
signature commit-reveal`. ML-DSA signatures are the entropy source
for proposer selection per round; the chain treats the producer's
signature over the round preimage as the VRF output.

This is operationally fine but cryptographically suboptimal: a real
VRF (Verifiable Random Function) is the right primitive — single-
round, output is publicly verifiable from a static public key, no
commit-reveal latency. Today there is no PQ-VRF that is both:

1. Standardised (IETF / NIST / equivalent).
2. Audited at production scale.
3. Implemented with a credible Rust binding.

The PQ-VRF candidates worth tracking: lattice-based (ring-LWR), code-
based (CROSS-Vref variants), hash-based (XMSS-VRF). None of these
satisfy condition 1 as of 2026-05.

### Trigger conditions

1. IETF or NIST publishes a PQ-VRF reference; production library
   support follows within ~1 year.
2. The chosen scheme has a public key size compatible with the
   on-chain validator-record budget (≤ 2 KB; ML-DSA-65 sets the
   precedent at 1.95 KB).
3. The verify cost per leader-election round is < 5% of the total
   round budget at the operating block-time (TASK-186 outcome).

### Migration shape

Once the trigger fires:

- New `ProposalEffect::AddVrfScheme(scheme_id)` governance variant.
- Per-validator opt-in: a validator publishes a VRF public key
  alongside its consensus signing key. Mixed-mode operation during
  the transition: validators with a VRF key use the VRF path,
  validators without fall back to RANDAO+sig commit-reveal.
- Cutover when ≥ 90% of weight has registered a VRF key — at that
  point a P-COMPAT-001 §7 deprecation epoch removes the legacy path.
- Slashing-evidence registry adds a "double-VRF-output" rule
  (per-round equivocation), parallel to the existing double-sign rule.

### Non-goals

- Replacing the BFT signing flow. PQ-VRF is for leader-election
  randomness, not consensus signatures.
- Pre-standard adoption. Lattice / code-based VRFs are interesting
  research but the audit class makes them unsuitable for a pre-
  standardisation commitment that would be hard to reverse if the
  scheme broke.

### Tracking

- ADR-053 §T1.4 carries the placeholder commitment to RANDAO+sig.
- ADR-062 (reserved) for the PQ-VRF migration when the trigger fires.
- Spec slot: SPEC-VRF-001 (not yet drafted).

### Y-band

Y3-Y5 (2029-2031). Conservative because PQ-VRF standardisation has
no committed timeline at IETF as of 2026-05.

---

## 3. 3rd algorithm — NIST on-ramp 2028-2029

### Why

ADR-043 + ADR-044 already wire two PQ signature algorithms (ML-DSA-65
and SLH-DSA-SHAKE-192s) through the on-chain Algorithm Registry. The
"≥2 PQ schemes pre-registered per release" discipline (essay item 12)
is satisfied. The 3rd-algorithm goal is to:

1. Reduce all-eggs-one-basket exposure to the lattice family.
2. Add a smaller-bandwidth option for high-frequency tx classes (the
   2-3 KB ML-DSA-65 sig dominates per-tx bytes).
3. Stage a credible diversity-of-foundations narrative (lattice +
   hash-based + structured-code OR multivariate OR isogeny).

NIST's "Additional Digital Signature Schemes" Round-2 announcement
(2024) lists 14 candidates. The ones liboqs flags as on-ramp
(CROSS, MAYO, SNOVA, UOV) are the operational watch-list; the ones
explicitly preferred for foundational diversity (non-lattice) are:

- **MAYO** — multivariate, very small signatures (~420 B at NIST L1),
  fast verify, larger public keys (~1.2 KB at L1).
- **CROSS** — restricted-syndrome-decoding (code-based), larger
  signatures (~13 KB at L1) but very small public keys (~80 B).
- **FAEST** — symmetric-only (AES + VOLE-in-the-head), small public
  keys (~32 B), medium signatures (~5 KB at L1).
- **SQIsign** — isogeny-based, smallest signatures of any PQ scheme
  (~250 B at L1) but extremely slow signing (multi-second).

### Selection criteria (when the on-ramp standard fires)

| Criterion | Weight | Why |
|-----------|--------|-----|
| Foundational diversity (non-lattice, non-hash) | high | stated goal of this slot |
| Verify-time per signature | high | per-block budget already constrained |
| Signature size at L1 | medium | dominates per-tx storage |
| Public key size at L1 | medium | validator-record budget 2 KB |
| Sign-time per signature | low | offline / wallet-side; tolerable |
| FIPS / IETF standardisation status | hard gate | no pre-standard adoption |

### Migration shape

- Reserve `0x0011..0x0017` AlgId range for the on-ramp winners
  (parallel to the `0x0010` slot reserved for FN-DSA per TASK-226).
- Governance proposal `ProposalEffect::AddAlgorithm(alg_id, lifecycle)`
  promotes the chosen scheme to `Active`; same epoch-boundary
  activation pattern as ADR-043's SLH-DSA addition.
- TLV envelope (ADR-044) is unchanged — `algo_id: u16_le` already
  covers the new range.
- Wallet-side support: the SDK adds the new alg behind a feature flag
  for a release cycle before flipping default.

### Non-goals

- Pre-standard adoption (especially for SQIsign — Castryck-Decru
  lessons make pre-finalisation isogeny adoption a hard "no").
- Deprecating ML-DSA-65 or SLH-DSA-SHAKE-192s. The 3rd alg
  *adds* foundational diversity, does not replace the existing two.
- Forcing per-tx alg choice on the user. The wallet picks based on
  tx class (e.g. high-frequency token-transfer might default to MAYO
  for the bandwidth win; archival-overlay records continue to use
  SLH-DSA-SHAKE-256s for the conservatism).

### Tracking

- ADR-053 §T1.5 carries the genesis algorithm registry seed.
- ADR-063 (reserved) for the on-ramp winner addition.
- TASK-226 separately covers FN-DSA evaluation post-FIPS-206-final
  (Q4 2027) — that slot is tracked independently because FN-DSA is
  on the FIPS track, not the on-ramp track.

### Y-band

Y3-Y4 (2029-2030) for the first NIST on-ramp standardisation. The
Round-2 winner announcement is rumoured 2027-2028 but the *finalised
standard* (the gate Viper waits for) lags by 12-18 months.

---

## 4. Fee-primacy crossover (Reserved)

> Applies only if token economics are activated; dormant on `viper-testnet-2`.

### Why

The genesis tokenomics (ADR-022) provision an inflationary issuance
schedule that funds validator rewards in the early years. Long-term
sustainability requires fee revenue to overtake inflation as the
dominant validator income source — the "fee-primacy" crossover.

Without the crossover the chain becomes economically dependent on
inflation indefinitely; with it the chain becomes self-sustaining
and the inflation curve can taper toward zero without breaking the
validator economics.

### Definition

Fee-primacy crossover is the first month in which:

```
sum(fee_revenue_per_block) > sum(inflation_per_block)
```

aggregated across all validators, sustained for 90 consecutive days
(the "sustained" qualifier prevents one-off NFT-mint spikes from
triggering a premature signal).

### Trigger conditions

1. On-chain fee data (the TASK-118 30-day-window methodology, scaled
   to 90 days) shows the inequality holds for the threshold period.
2. Network throughput is in the regime where fees can plausibly
   match inflation (a sub-100-tps chain cannot generate the fee
   volume to overtake inflation regardless of fee model).
3. Active-set size is at the Phase 10 / Phase 11 target band
   (256+ validators) so fee-revenue measurements are statistically
   meaningful across operator cohort.

### Pre-crossover policy

- Inflation curve stays at the ADR-022 schedule until the trigger.
- Annual review of the fee model (fee classes, EIP-4844-style
  multi-dim base fees) per the existing ADR-022 governance hook.
- TASK-118-style 30-day windows run quarterly to track the trajectory.

### Post-crossover policy (the "tapering" decision)

When the trigger fires, governance opens an ADR for the inflation
taper schedule. Default proposal: linear taper to zero over 8-12
years, with a hard floor of ~0.5% / year for security-budget
reserves (the operator argument: even if fees dominate, a small
inflation residual prevents validators from defecting in low-fee
quarters). The actual schedule is governance-decided, not pinned
here.

### Non-goals

- Pre-emptive tapering. No taper before the crossover signal — the
  early-year validator economics depend on inflation being stable.
- Fee-burn. A burn mechanism is orthogonal to fee-primacy; if
  governance wants to burn a fraction, that's a separate ADR.
- Cross-validator subsidy. Fee-primacy is measured network-wide,
  not per-validator; per-validator fairness is the staking-reward
  mechanism's concern.

### Tracking

- ADR-022 carries the genesis tokenomics; an ADR-064 (reserved) will
  document the post-crossover taper schedule when the trigger fires.
- TASK-118 (30-day fee revenue window) is the recurring measurement
  vehicle.
- Quarterly fee-revenue reports (published alongside the release
  notes) track the trajectory.

### Y-band

Y8-Y12 (2034-2038). Earlier than Y8 is implausible because the
network needs years of organic traffic growth; later than Y12
suggests the fee model needs governance attention.

---

## 5. Diversity targets enforcement

### Why

Decentralisation isn't just validator count — it is *operational
diversity*. A chain with 1 000 validators all running the same
client on the same cloud region in the same legal jurisdiction is
less resilient than a chain with 100 validators across 25
jurisdictions on 5 client implementations.

Essay items 19 and 25 lay out the targets. This § consolidates them
and pins the measurement methodology.

### Targets

| Dimension | Phase 9 floor | Y5 target | Y10 target |
|-----------|---------------|-----------|------------|
| Distinct legal jurisdictions | ≥ 10 | ≥ 25 | ≥ 50 |
| Distinct geographic regions (continent-level) | ≥ 4 | ≥ 5 | ≥ 6 |
| Nakamoto coefficient (equal weight under PoA; on stake if token economics are activated) | ≥ 6 | ≥ 10 | ≥ 30 |
| Top-client implementation share | ≤ 50% | ≤ 33% | ≤ 25% |
| Distinct hosting providers | ≥ 5 | ≥ 15 | ≥ 30 |

### Measurement methodology

- **Jurisdictions / regions / hosting** — operator-self-declared at
  registration time, verifiable against `validator-onboarding.md`
  evidence (a tax-ID-bound contract, infrastructure invoices).
  Recompute quarterly and publish the result with the release notes.
- **Nakamoto coefficient** — computed from `StateStore::active_validators()`;
  equal weight per validator on the PoA set, weighted by self-bond
  only if token economics are ever activated (the consensus-relevant
  number, not a delegated-stake total). Pin script:
  `scripts/compute-nakamoto.py` (TASK-227 deliverable).
- **Top-client share** — operator-self-declared client implementation
  string at registration; one vote per validator. Recompute quarterly.
  Initial state Y0-Y1: 100% pqcd (single client) — that is fine for
  bootstrapping but the target arc requires a 2nd client by Y3.

### Enforcement

Diversity targets are *targets*, not on-chain hard gates. Two
enforcement mechanisms:

1. **Public reporting**. Quarterly dashboard under `/diversity` on
   the explorer (TASK-227 frontend deliverable). Operators see the
   network-level numbers; cohort governance sees the trajectory.
2. **Cohort-recruitment gating**. New validator slots open only
   when the next-quarter forecast diversity numbers stay within
   the band; if a target slips below floor, recruitment focuses on
   under-represented dimensions until the floor is restored.

No protocol-level slashing for diversity miss. Hard gates would
create perverse incentives (operators gaming jurisdiction declaration);
the public-reporting + cohort-gating combination has worked for
Ethereum / Cosmos and is the right precedent.

### Non-goals

- On-chain enforcement of jurisdictional diversity. This belongs in
  the cohort-recruitment process, not in consensus rules.
- Geographic-region-level KYC. Operators self-declare; the
  methodology accepts attestation-grade evidence (not litigation-grade).
- Forcing client diversity. The target arc *encourages* a 2nd client
  but does not mandate one — that is a 3rd-party decision.

### Tracking

- TASK-227 (this slot) — the first-quarter implementation: pin the
  measurement script, build the `/diversity` dashboard, publish the
  Y0 baseline report.
- ADR-053 §T1.6 Validator Record schema already carries the optional
  `jurisdiction_iso2` + `region` fields needed for the measurement.
- KNOWN-ISSUES has no R-* slot for this; diversity is a gradient,
  not a defect.

### Y-band

Quarterly cadence starting Y2 (post-cohort-launch); the Y-band is
not a "trigger" so much as a "measurement clock". The targets above
are Y5 / Y10 milestones; the *act of measuring + publishing* starts
the quarter the cohort opens.

---

## How this doc relates to the rest

| Doc | What it owns | Relation to this doc |
|-----|--------------|----------------------|
| `ROADMAP.md` | Phase-by-phase plan to mainnet (Phase 8.5 → 9 → 10+) | Cross-links here in "Deferred Until After The Trust Layer Proves Itself"; this doc fills out the *deferred* half |
| `DECISIONS.md` (ADRs) | Per-decision context + commitment | Each § above names a reserved ADR slot for when its trigger fires |
| `KNOWN-ISSUES.md` | Active risks + their offsetting controls | R-10 (PQ signature footprint) is the closure target for §1 |
| `TASKS.md` | Open work items with assignee + status | TASK-225 (this doc), TASK-228 (scale-up — depends on §1 maturity), TASK-226 (FN-DSA — parallel to §3) |
| Essay (`docs/historical/deep-research-report.md`) | Source material — items 18-25 cited above | This doc is the operational consolidation; essay is the discursive original |

When a §-trigger fires, the deliverable is:

1. Promote the reserved ADR slot to a real ADR.
2. Open the corresponding TASK with a real estimate.
3. Update this doc's Y-band table with "**closed (commit `<hash>`,
   YYYY-MM-DD)**" so the timeline becomes a record rather than a
   forecast.

---

## Update cadence

- **Annually** (every January): rebase Y-bands against the previous
  year's actuals; refresh the trigger conditions if upstream
  (NIST / IETF / Lean) has moved.
- **On trigger fire**: same-day update the Y-band table for that §
  and reference the new ADR / TASK.
- **On policy change**: any time governance accepts an ADR that
  touches a § here, add a "Last touched: YYYY-MM-DD" marker to the §.

The doc is intentionally short — multi-decade roadmaps drift if
they try to be exhaustive. The five workstreams above are the ones
the project has *already agreed direction on*; new long-horizon
items belong in their own essay first, then graduate here when
direction stabilises.
