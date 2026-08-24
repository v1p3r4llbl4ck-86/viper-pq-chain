# Historical documents

Everything in this directory describes **retired chains** —
`viper-pq-1` (2026-04-25 → 2026-05-12, archived at height 33,976),
`viper-research-1` (tokenless research network, retired) and the
internal single-validator lab — or workstreams that shipped or were
abandoned before the public release. Nothing here is current guidance
for `viper-testnet-1`; the files are kept for the audit trail and as
design rationale that current code comments and specs still cite.

Conventions:

- Spec-style status of every file here is `Historical` (see
  `CONVENTIONS.md`): a report of a retired chain, kept as evidence.
- Files are not edited except to redact infrastructure identifiers.
  Host names of the retired fleet are replaced with documentation
  addresses (`203.0.113.x`) or `<host>` placeholders; the technical
  content is otherwise verbatim, including dates, task numbers and
  chain ids that no longer exist.
- Several files are in Italian, as they were written.
- Anything that references a native token (`VENOM`), bonds, staking
  rewards or slashing economics describes `viper-pq-1`. The public
  chain has no token and those specs are `Reserved`; do not read the
  economics below as a description of `viper-testnet-1`.

## Index

### Phase-8 plans and design rationale (pre-`viper-pq-1`)

| File | What it is | Why it is kept |
|---|---|---|
| `phase-8-spec.md` | Italian strategic essay ("Architettura a prova di futuro"): P2P layer, dynamic validator set, second PQ algorithm, validator onboarding strategy. | Origin of the three-network topology (`docs/examples/three-network/`) and of several ADRs. |
| `phase-8-m1-plan.md` | M1 cutover plan (SSH tunnels → libp2p). | Executed 2026-04-22; retained as the record of the cutover. Hosts redacted. |
| `phase-8-m1-routing-plan.md` | Message-class routing plan for M1. | Work shipped; superseded by `specs/p2p-messaging.md`. |
| `phase-8-m2-plan.md` | M2 dynamic-validator-set plan with retrospective. | Still cited from `crates/pqc-consensus/src/engine.rs` and `storage_rocksdb.rs` (design rationale for `validator_pool` and the stateless chain store). |
| `phase-8-m4-plan.md` | M4 archival overlay + external cohort plan. | Cited from `specs/archival-overlay.md`; workstream (b) was never completed before the retirement. |
| `phase-8-audit-plan.md` | Multi-vendor audit coordination playbook (Italian). | Reference for the external-audit gate. |
| `phase-8-audit-readiness.md` | Self-assessment against the audit plan (2026-04-22). | Superseded by later audits; kept as evidence of the gap list. |
| `phase-9-followup-plan.md` | Open-task batch after the Phase 8.5 launch (2026-05-06). | Retired with `viper-pq-1`; its long-horizon half lives on in `docs/long-horizon-roadmap.md`. |
| `pq_chain_foundation_v2.md` | Original product-thesis input (2026-04-09). | Superseded by `WHITEPAPER.md` and `specs/`. |
| `deep-research-report.md` | Original technical blueprint (Italian, 2026-04-09). | Superseded by `ARCHITECTURE.md` and `specs/`; source of the "essay items" cited by the long-horizon roadmap. |
| `dress-rehearsal-procedure.md` | Pre-launch rehearsal procedure. | Overtaken by the actual `viper-pq-1` launch ceremony. |

### Reports and runbooks of retired chains

| File | What it is | Why it is kept |
|---|---|---|
| `audit-report.md` | 2026-04-17 codebase audit (static analysis + manual review, rev 3). | Chain of evidence; findings were fixed the same day. References sibling audits that are not in the public tree. |
| `security-testing-roadmap.md` | One-week security-testing plan for `viper-pq-1` (fuzzing, sanitiser CI, chaos runner, malicious-node mode, k6, Falco, ZAP) with the completion table. | All items landed or were deferred with a trigger; the deliverables (`fuzz/`, `scripts/chaos-runner.sh`, `--features attack-modes`) are in tree. |
| `demo-runbook.md` | Italian demo script for the `viper-pq-1` notary front-end. | Retired chain and private product; kept as record only. |
| `validator-legal-faq.md` | Legal FAQ for `viper-pq-1` validators (bond, unbonding, slashing, MiCA/eIDAS/GDPR, US posture). | Entirely token-era; `viper-testnet-1` has no bond, no rewards and no slashing economics. Not legal advice. |
| `viper-notary-spec.md` | Product specification of the notary service. | The notary is a private product outside the public tree; the chart's notary deployment is optional. Kept for the record; the author may remove it. |
| `ir-drill-001-2026-04-20.md` | Outage drill debrief on the pre-launch devnet. | Lessons folded into `docs/operators/RUNBOOK.md`. |

### Pre-pivot funding and outreach material

| File | What it is |
|---|---|

## Files that still name retired infrastructure

The following files mention the public host name of the retired
`viper-pq-1` front (a name that will be reused for `viper-testnet-1`
at genesis) or CI configuration file names that do not exist in the
public tree. They carry no private addresses after redaction; exclude
them from a public build if that is still too much:

- `demo-runbook.md` — retired front host name, notary API paths.
- `security-testing-roadmap.md` — retired front host name, `.gitlab-ci.yml` job names, hosting-provider names.
- `phase-9-followup-plan.md` — retired front host name.
- `phase-8-m4-plan.md` — retired front host name.
- `phase-8-audit-readiness.md` — `.gitlab-ci.yml` job names.
- `audit-report.md` — paths under `reports/audits/` that are not in the public tree.

## For current material see

- `docs/INDEX.md` — the canonical document index.
- `docs/validator-onboarding.md` — joining `viper-testnet-1`.
- `docs/operators/RUNBOOK.md` — operations.
- `docs/long-horizon-roadmap.md` — direction-decided long-horizon items.
- `CHANGELOG.md`, `DECISIONS.md`, `TASKS.md` — release narrative, ADRs, task ledger.
