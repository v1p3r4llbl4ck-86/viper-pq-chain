# Viper BFT consensus — Quint model (first draft)

**File**: `specs/bft_consensus.qnt`
**Task**: TASK-153 — machine-checkable formal model of SPEC-CONSENSUS-001
**Status**: Draft
**Scope**: starting kit for the external consensus audit engagement
**Reference prose spec**: `specs/consensus.md` (SPEC-CONSENSUS-001 v0.2)
**Mirrored Rust code**: `crates/pqc-consensus/src/{round,commit,quorum,epoch}.rs`

This is a **first-draft Quint model** of the three-phase BFT consensus
protocol. It is intentionally a 60–70 %-there baseline: enough to typecheck
and symbolically verify safety at small configurations, not yet the polished
audit deliverable. The intent is to reduce the bootstrap cost of the external
protocol/consensus audit (Informal Systems, Runtime Verification, or similar)
by about two weeks of calendar time.
The vendor is expected to iterate from here toward the final audit artifact.

---

## 1. What is covered

| Area | Where in the model | Maps to Rust |
|------|--------------------|--------------|
| Three-phase round state machine (Propose → Prevote → Precommit → Decided) | §6–§8, actions `propose` / `prevote` / `precommit` / `commit` | `crates/pqc-consensus/src/round.rs::ConsensusRound` |
| BFT quorum `(2n)/3 + 1` | §3, `quorum` / `Q` | `crates/pqc-consensus/src/quorum.rs::quorum_size` |
| Polka and commit quorum detection | §6, `hasPolka` / `hasCommitQuorum` | `VoteStore::{has_polka, has_commit_quorum}` |
| Timeout-driven round advancement | §8, `onTimeout` | `ConsensusRound::on_*_timeout` |
| Locking rules (precommit → lockedValue / lockedRound) | §8, `precommit` | `ConsensusRound::on_prevote` polka branch |
| RANDAO-seeded proposer selection (abstracted) | §4, `proposer` | `pqc-consensus::round::select_proposer` (Phase 8 devnet form) |
| Byzantine fault injection (equivocating prevote / precommit) | §9, `byzantinePrevote` / `byzantinePrecommit` | `VoteStore::record` equivocation path |
| **Agreement** (safety) invariant | §11, `agreement` | SPEC-CONSENSUS-001 §17.1 theorem |
| **Validity** (weak form) invariant | §11, `validity` | SPEC-CONSENSUS-001 §17.1 |
| **Accountable safety bound** `f ≤ (n−1)/3` | §11, `accountableSafetyBound` | SPEC-CONSENSUS-001 §17.1 fault bound |
| Locking & step-well-formed sanity invariants | §11, `lockingInvariant` / `stepWellFormed` / `noDoubleDecide` | implementation-level assertions |
| Default n=4, f=1, 2 values instantiation | Trailing `bft_consensus_n4` module | audit baseline per ADR-042 |

---

## 2. What is NOT covered (deferred)

These are deliberately deferred to the audit engagement. Each one is flagged
inline in the source at §13 (`(L1) … (L7)`):

1. **Liveness / termination under partial synchrony (GST)** — the hardest
   part. Requires a clock variable, a fairness constraint on round
   increments, and either TLC exhaustive search or a hand-proof in the
   Malachite TLA+ companion. The current model does not assert
   `◇ decided != nil` for any validator.
2. **Strong validity** — that decided values are proposed by an *honest*
   validator (not just *some* validator). Requires proposer-rotation
   coverage argument.
3. **Accountable-safety evidence emission** — `SlashEvidence` transactions
   and on-chain slashing (`specs/slashing.md`). The model detects
   equivocation implicitly via duplicate votes in the `votes` set but does
   not route evidence to the state store.
4. **Epoch boundary / validator-set mutation** — ADR-042 churn limits
   (activation / exit per epoch, unbonding period). The current model has
   a fixed `Validators` set.
5. **Exact timeout schedule** — SPEC-CONSENSUS-001 §12 linear-growth
   `timeout(step, r) = base + delta × r`. Safety is insensitive to the
   schedule; liveness is not.
6. **Equivocation → fork-creation counter-example at |Byzantine| = f+1**.
   Useful for the audit story "where does safety break?". A one-line edit
   to the `Byzantine` constant reproduces it.
7. **PQ-signature algorithm handling** — ADR-046 consensus-allowed set
   (`MlDsa65 / MlDsa87 / SlhDsaShake192s`) and the rotate-key flow. Votes
   are assumed-authenticated in the abstract model.

---

## 3. How to install Quint

Quint is distributed via npm. On the auditor's workstation:

```bash
# Quint >= 0.21 is recommended (matches Malachite's current models).
npm install -g @informalsystems/quint

quint --version
```

Reference documentation: <https://quint-lang.org>.
Malachite's Quint models (for style): <https://github.com/informalsystems/malachite>.

---

## 4. How to typecheck

```bash
cd <repo-root>
quint typecheck specs/bft_consensus.qnt
```

Expected output: `module bft_consensus: OK` and
`module bft_consensus_n4: OK`. Any type error is a bug to fix before
invoking the model checker.

---

## 5. How to run the model checker

Quint ships with two backends:

### 5.1 TLC (exhaustive, small configurations)

```bash
# Check the top-level safety bundle on the default n=4 instantiation.
quint verify --invariant safety specs/bft_consensus.qnt --main bft_consensus_n4
```

Individual sub-invariants can be checked in isolation for tighter
counter-examples:

```bash
quint verify --invariant agreement              specs/bft_consensus.qnt --main bft_consensus_n4
quint verify --invariant validity               specs/bft_consensus.qnt --main bft_consensus_n4
quint verify --invariant accountableSafetyBound specs/bft_consensus.qnt --main bft_consensus_n4
quint verify --invariant lockingInvariant       specs/bft_consensus.qnt --main bft_consensus_n4
```

### 5.2 Apalache (SMT-based, scales further)

Apalache is the recommended backend for richer configurations (n≥7):

```bash
quint verify --backend apalache --invariant safety \
  specs/bft_consensus.qnt --main bft_consensus_n4
```

Apalache install: <https://apalache-mc.org/docs/apalache/installation/index.html>.
A JVM is required.

### 5.3 Simulation (smoke test)

For a quick sanity pass before the full verification:

```bash
quint run specs/bft_consensus.qnt --main bft_consensus_n4 --max-samples=1000
```

---

## 6. Properties encoded (by symbol)

| Symbol | Kind | What it asserts |
|--------|------|------------------|
| `agreement` | safety invariant | no two honest validators decide different values at the same height |
| `validity` | safety invariant | any decided value was proposed by some validator |
| `accountableSafetyBound` | configuration invariant | `|Byzantine| ≤ f` where `f = ⌊(n−1)/3⌋` |
| `lockingInvariant` | local invariant | an honest validator's lockedRound ≤ currentRound |
| `noDoubleDecide` | local invariant | after deciding at height h, the validator's height > h |
| `stepWellFormed` | housekeeping | non-negative height/round |
| `safety` | bundle | conjunction of all of the above |

---

## 7. Properties deferred (by symbol)

| Deferral | Rationale |
|----------|-----------|
| `termination` / liveness | needs GST + fairness; Malachite `consensus_liveness.qnt` is the template |
| `strongValidity` | needs proposer-rotation coverage argument |
| `evidenceEmitted` | needs model of `SlashEvidence` transactions + state store |
| `churnBounded` | needs epoch-boundary model of ADR-042 |
| `pqSignatureValid` | needs AlgId registry + ADR-046 wire-up |

These are listed as inline `(L1)..(L7)` deferral markers in the source.

---

## 8. How to extend

Common next steps for the audit engagement:

1. **Scale configuration**: add `bft_consensus_n7` with `Validators = 1..7`,
   `Byzantine = Set(6, 7)` for f=2; check that `safety` still holds and that
   `Byzantine = Set(5, 6, 7)` (|Byzantine| = f+1 = 3) produces a counter-example.
2. **Add validator-set mutation**: replace `const Validators` with
   `var activeAt : Height -> Set[Address]` and introduce an
   `epochBoundary` action that mutates it subject to
   `max_activations_per_epoch` / `max_exits_per_epoch` from
   `crates/pqc-consensus/src/epoch.rs`.
3. **Add VRF / RANDAO state**: replace the `proposer` abstraction with a
   RANDAO accumulator variable advanced by a modelled `advance_randao`
   function; tie proposer selection to it.
4. **Add liveness**: introduce a `gst : Height` variable and a clock
   `now : int`. Assert `<> (exists v in Honest. decided.get(v).height >= h)`
   for the liveness theorem.
5. **Add equivocation evidence**: a new `var evidence : Set[EvidenceRecord]`
   variable and a transition that flips evidence from the vote store to
   the slashing registry on observing two conflicting votes.

---

## 9. Conventions

- `camelCase` for actions / defs / variables (matches Malachite).
- `PascalCase` for types and constants that denote a set.
- `/// doc comment` for top-level declarations.
- `// inline` for procedural commentary.
- Each property / action links back to the corresponding SPEC-CONSENSUS-001
  section and the Rust source location.

---

## 10. Cross-reference table

| Quint symbol | Prose spec | Rust symbol |
|--------------|------------|-------------|
| `quorum(n)` | §4 "Commit" | `pqc-consensus::quorum::quorum_size` |
| `proposer(vs, h, r)` | §6 "Proposer Selection" | `pqc-consensus::round::select_proposer` |
| `hasPolka` | §4 "Polka" / §7.4 | `VoteStore::has_polka` |
| `hasCommitQuorum` | §10.1 | `VoteStore::has_commit_quorum` |
| `propose` action | §7.2 NewRound | `ConsensusRound::new` + proposer branch |
| `prevote` action | §7.3 | `ConsensusRound::on_proposal_received` / `on_propose_timeout` |
| `precommit` action | §7.4 | `ConsensusRound::on_prevote` polka path / `on_prevote_timeout` |
| `commit` action | §7.5 | `ConsensusRound::on_precommit` commit path |
| `onTimeout` action | §12 | `ConsensusRound::on_*_timeout` |
| `byzantinePrevote` / `byzantinePrecommit` | §11 | `VoteStore::record` equivocation branch |
| `agreement` | §17.1 | `byzantine_fault_tests` (commit-side partial coverage) |

---

## 11. Known limitations of this draft

- **Quint's ordering of `Set.fold`** has no guaranteed permutation; the
  current `proposer` abstraction is a modelling compromise. For
  counter-example-driven analysis the vendor should replace it with an
  explicit list variable.
- **The `proposalFor` helper** uses a sentinel record instead of
  `Option[Proposal]`; this keeps the model Apalache-compatible but is less
  idiomatic than Malachite's `Option` usage.
- **The network model is a shared broadcast bag**, not per-validator
  inboxes with gossip-level asynchrony. Safety is preserved under any
  reception-subset, but liveness proofs will need a richer model.
- **Byzantine actions are unrestricted** (any value at any time); the model
  does not restrict them to "at most f distinct equivocations" which would
  tighten the state space.

These are all acceptable for a first-draft starting kit; the vendor is
expected to refine them during the audit engagement.
