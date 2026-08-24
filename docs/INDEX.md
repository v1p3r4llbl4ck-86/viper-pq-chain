# `docs/` — index

The root of the repository holds the canonical documents (README, WHITEPAPER, ARCHITECTURE,
API, DECISIONS, CONVENTIONS, TESTING, ROADMAP, KNOWN-ISSUES, SECURITY, CONTRIBUTING, AGENTS,
LICENSE). `specs/` is the normative protocol contract. This directory holds what an operator,
an integrator or an auditor needs beyond that.

## Quick reads by role

| You are | Start with |
|---|---|
| running a node | [operators/RUNBOOK.md](operators/RUNBOOK.md) → [validator-onboarding.md](validator-onboarding.md) → [observability.md](observability.md) |
| integrating a client | [../API.md](../API.md), [openapi.yaml](openapi.yaml), the SDKs under `../sdk/`, [use-cases.md](use-cases.md) |
| auditing | [../audit/README.md](../audit/README.md) → [../specs/audit-scope.md](../specs/audit-scope.md), [../specs/threat-model.md](../specs/threat-model.md), [../KNOWN-ISSUES.md](../KNOWN-ISSUES.md) |
| deploying on Kubernetes | [../charts/viper-pq-chain/README.md](../charts/viper-pq-chain/README.md) (`pqcd ceremony` + Helm) |
| deploying on hosts | [../deploy/ansible/README.md](../deploy/ansible/README.md) |
| reading the plan | [../ROADMAP.md](../ROADMAP.md) → [long-horizon-roadmap.md](long-horizon-roadmap.md) |

## Current documents

| File | What |
|---|---|
| [operators/RUNBOOK.md](operators/RUNBOOK.md) | build, configure, run, join, troubleshoot a node; `pqcd` command reference |
| [validator-onboarding.md](validator-onboarding.md) | joining `viper-testnet-1` as a full/rpc/archive node; how validators are admitted |
| [observability.md](observability.md) | metrics, logs, tracing, alert expressions |
| [use-cases.md](use-cases.md) | what the chain is for: attestations, anchors, key-rotation records |
| [long-horizon-roadmap.md](long-horizon-roadmap.md) | the multi-year direction behind ROADMAP.md |
| [multicodec-mapping.md](multicodec-mapping.md) | multicodec / multihash identifiers used on the wire |
| [openapi.yaml](openapi.yaml) | OpenAPI 3.0 description of the HTTP API (served by the node at `/openapi.yaml`) |
| [examples/three-network/](examples/three-network/) | worked example of the validator / VFN / public P2P networks |
| [site/](site/) | static explorer and Swagger pages (the deployable frontend ships in the Helm chart) |
| [outputs/viper-explorer.jsx](outputs/viper-explorer.jsx) | explorer component source |

## `historical/` — retained for the audit trail

Everything under [historical/](historical/README.md) describes the private chains that preceded
the public release (`viper-pq-1`, `viper-research-1`) or plans that were executed and closed:
phase plans, audit readiness and audit plan, incident-response drill, dress rehearsal, demo
runbook, the original product thesis and technical blueprint, the notary service specification.
Nothing in it is current; it is kept because ADRs and reports cite it.

## Not in the public tree

Business material and internal plans (decks, funding material, pivot plans,
archived-chain snapshots, the token-economics reserve design) stay in the private repository.
Internal deployment, soak and audit reports are summarised in [../reports/README.md](../reports/README.md).

## Conventions

- English, precise, no hype ([../CONVENTIONS.md](../CONVENTIONS.md)).
- Status vocabularies: decisions `Accepted / Proposed / Deferred / Rejected / Superseded / Reserved`;
  specs `Draft / Proposed / Accepted / Normative / Reserved / Historical`.
- Deployment roles: `validator`, `sentry`, `full`, `rpc`, `archive`, `bootnode`, `single_node` (ADR-069).
- Relative links are checked by `scripts/check-links.sh` (part of `make ci`).
