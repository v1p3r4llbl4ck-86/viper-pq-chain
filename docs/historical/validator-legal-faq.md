# Validator Legal FAQ — viper-pq-1

**Audience.** Prospective external operators evaluating onboarding to the
`viper-pq-1` mainnet (per `docs/validator-onboarding.md`).
**Status.** Pre-cohort outreach material (TASK-220, Phase 9 follow-up plan).
**Last updated.** 2026-05-07.

> **Disclaimer.** This is informational, not legal advice. Validator
> regulation varies by jurisdiction; the framing below reflects how
> the protocol is *engineered* and how analogous projects have been
> classified in the EU and US. Operators should consult counsel
> familiar with their own jurisdiction before relying on any
> characterisation. Nothing here creates a contractual relationship
> between the operator and the protocol team.

This doc is the legal counterpart of `docs/validator-onboarding.md`
(operational guide). The onboarding guide answers *how* you run a node;
this doc answers *what kind of activity is that, legally*. Both pair with
TASK-185 (external operator onboarding validation) and the closed-cohort
gate at the chain's launch state.

---

## §1 — What a validator does, and what it does *not*

A `viper-pq-1` validator runs the `pqcd` binary on infrastructure they
own or rent, holds their own consensus signing keys, and signs their
own commit material at every block. The activity is, in protocol
terms:

1. Receive blocks gossiped over libp2p.
2. Verify each block (signatures, state transition, parent hash).
3. Sign a `Precommit` vote when elected for the round.
4. Submit `EquivocationEvidence` if a peer is observed double-signing.
5. Apply the resulting state change locally.

A validator does **not**:

- Hold or transfer end-user funds. The chain has no end-user balances
  beyond its own native token (VENOM) used for fees + self-bond. Notary
  use cases (`docs/use-cases.md`) anchor *hashes* of off-chain documents;
  the documents themselves never leave the originator (per the
  "no-custody" principle codified in `docs/use-cases.md` §"Principio di
  base").
- Act as an exchange, custodian, or money transmitter. There is no
  trading pair, no fiat off-ramp, no escrow, no margin lending in the
  protocol. The validator's economic role is to bond their own VENOM
  and earn protocol-level rewards, in the same way a Bitcoin miner
  earns block rewards by consuming electricity.
- Take instruction from end-users. Validators have a relationship with
  the protocol (deterministic state-transition rules); they do not
  enter into bilateral agreements with users of the chain. There is no
  on-chain mechanism for an end-user to direct a validator to do
  anything — every state transition is the deterministic output of
  every node applying the same rules to the same blocks.

Because of (a)+(b)+(c), a validator is closer to a network operator —
analogous to running a Tor relay or an autonomous-system BGP router —
than to a financial intermediary.

This is the **pure-validation vs SaaS distinction**: a SaaS operator
holds customer credentials, custodies customer data, and provides
service availability under a contractual SLA. A validator does none of
those things. Note that a *staking-as-a-service* business — where a
third party runs the validator on a customer's behalf and remits
rewards — *is* a SaaS, and that operator may incur additional
regulatory obligations (custody, MiCA CASP, money-transmission). This
FAQ assumes the operator runs the validator for their own account.

---

## §2 — Regulatory posture: MiCA / eIDAS / GDPR (EU)

### MiCA (EU 2023/1114)

MiCA Article 3(1)(15) defines a *crypto-asset service provider* (CASP)
by enumerating the activities that require authorisation: custody,
exchange, transfer, advice, portfolio management, etc. Pure validation
is **not on the list**. The European Securities and Markets Authority's
2024 MiCA Q&A (ESMA-MICA-2024-Q&A) explicitly distinguishes blockchain
infrastructure operation from CASP activities, citing validators and
miners as examples of non-CASP roles.

Where a validator could trip into CASP territory:

- **Operating a staking pool** that accepts delegations from third
  parties (custody-like service). Out of scope for `viper-pq-1` Phase
  8.5 — the chain does not yet implement delegation; `self_bond` is
  validator-only.
- **Bundling node operation with a token-sale or yield product**. Do
  not market validator services as an investment offering; the
  characterisation may flip.
- **Holding KYC'd user data** in connection with the validator role
  (e.g. as part of a SaaS arrangement). Then GDPR + e-money / CASP
  rules attach to the service wrapper, not the validator role itself.

### eIDAS 2.0 (Regulation EU 910/2014 as amended in 2024)

The relevant articles are eIDAS Article 24a (qualified electronic
attestation of attributes — QEAA) and the wallet-related Article 6a.
`viper-pq-1` provides infrastructure on which a *qualified trust
service provider* (QTSP) could anchor attestations: the chain's
attestation primitives are the on-chain hash anchor; the QTSP carries
the regulatory burden of identification + qualified signature, and
remains the legal issuer of the attestation (per `docs/use-cases.md`
§"Notarizzazione documentale" and the ADR-055 timestamping/evidence
endpoints). A validator running `pqcd` is not itself a QTSP — the
QTSP is the upstream entity that authored the attestation transaction.

### GDPR (EU 2016/679)

The chain does not store personal data on-chain. Notary attestations
anchor SHA3-512 / SHAKE-256 hashes of off-chain documents; the hashes
are not "personal data" under Article 4(1) because they are not
identifiable to a natural person without external information that is
withheld by the data controller (the document originator). The
"no-custody" principle in `docs/use-cases.md` §"Principio di base"
("Viper non emette documenti e non custodisce dati personali") is the
GDPR posture: every personal-data flow happens *off-chain* between the
data controller (e.g. a notary, a university) and the data subject.
The validator's role does not involve processing personal data.

The one place a validator *does* process some data is the on-chain
metadata they self-declare for the diversity baseline (`reports/
diversity/operator-metadata.json` per TASK-227). That data is *the
operator's own* — jurisdiction, hosting region, etc. — and there is no
data-subject-rights claim against another natural person.

---

## §3 — US carve-out (precautionary)

US securities law (Howey test, *SEC v. W.J. Howey Co.*, 328 U.S. 293
(1946)) defines an "investment contract" as (1) an investment of
money, (2) in a common enterprise, (3) with an expectation of profits,
(4) derived primarily from the efforts of others. Pure validation
fails prong (4): a validator's rewards depend on their *own* uptime,
slashing avoidance, and infrastructure operation — not on the efforts
of a promoter or central team. The SEC's 2018 *Hinman speech* on
sufficient decentralisation and the courts' 2023 reasoning in *SEC v.
Ripple* and *SEC v. Coinbase* (denying portions of the SEC's claims on
secondary-market sales of certain tokens) all support distinguishing
node operation from securities offerings, but the picture is far from
settled and the SEC's stated positions on proof-of-stake have shifted
across recent administrations.

That said: US securities law is unusually fact-specific, the SEC
position has shifted with administration changes, and the protocol
team is not in a position to opine on US compliance. Two posture
choices that prospective US-resident operators should weigh:

1. **Run a validator for own account**, with own bond, own keys, own
   infrastructure, no third-party delegation. This is the analogue of
   running a Bitcoin miner — pure participation in consensus.
2. **Do not market validator services to US persons or accept
   delegated stake from them** while the US regulatory picture is
   unsettled. If the cohort moves to permissionless (per
   `docs/permissionless-transition.md` ADR-066), the US position will
   need re-assessment.

The protocol does not implement geo-fencing — every operator who can
reach the libp2p mesh and stake a self-bond can run a node. The
"carve-out" is therefore an *operator-side compliance posture*, not a
protocol-level enforcement.

US-resident operators should consult securities counsel before staking
material amounts. The closed-cohort onboarding (TASK-185) gives the
protocol team and the operator visibility to make this assessment
before bonding; permissionless onboarding shifts the burden entirely
to the operator.

---

## §4 — Bond, unbonding, slashing — the operator's economic exposure

### Self-bond

`ValidatorRegister` requires `self_bond > 0` (validator's own VENOM,
locked from operator balance, see SPEC-VAL-001 §3.1). The bond is
the operator's "skin in the game" against equivocation. The bond is
*not* user-facing collateral and does not back any external
obligation — it backs only the operator's own honest behaviour as a
consensus participant. Phase 8.5 did not pin a minimum-bond floor;
the planned `permissionless` transition (ADR-066, Batch B of the
Phase 9 follow-up plan) reserves a `min_self_bond` governance
parameter for the cohort-opening decision, with three candidate
values (Low / Medium / High) under economic-security analysis.

### Unbonding

To exit, an operator submits `ValidatorExit`. The bond enters the
`Unbonding` state for `VALIDATOR_UNBONDING_PERIOD` (mainnet default:
21 days, configurable per `EpochConfig`). The bond returns to the
operator's balance only when the unbonding period elapses (engine.rs
`process_validator_unbonding_expirations`, ADR-050). The unbonding
window exists so that slashable evidence (equivocation, double-sign)
discovered after the operator exits can still be enforced.

### Slashing

The protocol slashes the validator's bond on confirmed equivocation.
The base rate is **5% of `self_bond`** per equivocation (SPEC-SLASH-001
§10, ADR-024 tokenomics ratification). The correlation multiplier
(ADR-048, Ethereum-style penalty boost) scales the rate up to **100%**
of bond when ≥ 1/3 of the active set is slashed in the same window.
Practical implications:

- A single-validator misconfiguration causing one equivocation at a
  small validator costs ~5% of bond (ADR-051 base rate).
- Coordinated multi-validator equivocation by an attacker controlling
  significant stake costs up to 100% of bond per participant.
- Operators are responsible for their own infrastructure: hardware
  redundancy, network reliability, key custody. There is no
  insurance pool at the protocol level. Third-party slashing
  insurance is offered by some custodians (e.g. for ETH staking);
  none is currently offered for `viper-pq-1` and operators should
  not rely on its existence.

### Tax treatment

Staking rewards are typically taxed as ordinary income in the year
received in most EU jurisdictions; some treat them as capital gains
realised at sale of the underlying asset. The protocol does not
withhold taxes. Operators should consult a local accountant or tax
adviser; the protocol team cannot give jurisdiction-specific tax
advice.

---

## §5 — Frequently asked

### Q1. Is operating a validator regulated activity in the EU?

Pure validation (run own node, own keys, own bond, no third-party
delegation) is not on the MiCA CASP activity list. Wrapper
activities — staking-as-a-service, custody, exchange — are. See §2.

### Q2. Can a US person operate a validator?

The protocol does not block it. The compliance posture is
operator-side: see §3. Most prospective US operators should consult
securities counsel before bonding.

### Q3. Can the protocol team take my bond?

No. The bond is held by the chain's deterministic state transition
and is released to the operator's address by the unbonding flow
(SPEC-VAL-001 §3.4). The protocol team has no privileged key that
can move the bond. Slashing happens by deterministic rule on
on-chain evidence (`apply_submit_equivocation_evidence`), not by
discretion.

### Q4. What if `pqcd` has a bug that causes my validator to equivocate?

The slashing rule applies regardless of intent. The protocol team
ships testing + cold-sync replay invariants (TASK-198) to keep this
class of bug at zero, but the operator carries the residual risk.
ADR-046 + `docs/operators/RUNBOOK.md` §16 outline the consensus-key rotation flow for
a validator that suspects key compromise; rotation happens before
activation height, so a fresh key is available before the old one
needs to retire.

### Q5. What data is published on-chain about me as a validator?

Your operator address (32 bytes, derived from your consensus key),
your consensus public key (~1.9 KB ML-DSA-65 / configurable per
ADR-067), your `self_bond` amount, your validator status (Active /
Unbonding / Exited), and any slashing history. No personal data,
no off-chain identifier. The optional diversity-metadata file
(jurisdiction, hosting provider) you self-declare for the
quarterly Nakamoto coefficient report (TASK-227) is published in
`reports/diversity/<UTC quarter>.md`.

### Q6. Is there a contract between me and the protocol?

No. The protocol is a deterministic open-source codebase. Running
`pqcd` puts you under the same rules as every other operator, and
the operator is bound by their own decision to participate, not by
a bilateral agreement. The closest analogue is a peering agreement
in BGP routing — there is no contractual relationship beyond the
shared protocol.

### Q7. How do I exit if I want out?

Submit `ValidatorExit`. Wait the unbonding period (21 days
mainnet). The bond returns to your balance. After that, you can
move the VENOM as ordinary balance (subject to whatever transfer
rules apply at that height).

### Q8. Can I be sued by an end-user for chain downtime or bad data?

The chain does not custody end-user assets, does not enter into
bilateral agreements with users, and does not serve "data" in the
SaaS sense — it serves *consensus state*, which is the deterministic
output of every honest validator running the same code on the same
inputs. Liability theories that work against custodians (failure to
return funds, breach of fiduciary duty) do not map onto a consensus
participant. That said: an operator running a *staking-as-a-service*
business on top of `viper-pq-1` may have direct contractual
exposure to its customers — this FAQ does not address SaaS
operators.

### Q9. Where is the protocol legal entity?

There is no single legal entity that owns the protocol. The
codebase is open-source. Hosting infrastructure for `viper-pq-1`
is currently operated by the launching team for the closed cohort;
the explicit direction in `docs/permissionless-transition.md`
(ADR-066) is to open membership to external operators and to
publish a multi-operator validator set, removing the launching
team as a critical path for liveness.

### Q10. Where can I find the technical operations guide?

`docs/validator-onboarding.md` — it covers hardware spec, the
keystore layout, the systemd unit, and the consensus-key rotation
procedure. This FAQ is the legal counterpart, not a replacement.

---

## §6 — How this doc evolves

- This FAQ was authored by the protocol team and reflects the
  state of `viper-pq-1` at 2026-05-07. The framing is informed by
  ADR-053 (genesis architecture), ADR-066 (permissionless transition
  design), MiCA Article 3 + ESMA Q&A current at the date above, and
  the public state of the *Ripple* / *Coinbase* / *Binance* US
  regulatory record.
- It is **not legal advice**. Operators should consult counsel for
  any meaningful bond.
- It will be updated when (a) the permissionless cohort opens, (b)
  staking-as-a-service is contemplated as a protocol-level feature,
  (c) MiCA Level 2 or US legislative guidance materially changes the
  picture, or (d) a serious legal challenge to a comparable
  proof-of-stake protocol creates new precedent. The "Last updated"
  line at the top is the freshness signal.

---

## Cross-references

- `docs/validator-onboarding.md` — how to actually run a validator (operator-side).
- `docs/use-cases.md` — what the chain certifies and the no-custody framing.
- `docs/permissionless-transition.md` (ADR-066, planned) — opening the cohort.
- `DECISIONS.md` ADR-046, ADR-050, ADR-051 — bond, slashing, BFT.
- `SPEC-VAL-001` (under `specs/`) — validator lifecycle and self-bond mechanics.
- `docs/operators/RUNBOOK.md` §16 (original text: the private runbook) — operator-side rotation procedure.
