# Audit entry point

No external cryptographic or protocol audit has been completed yet (TASK-115). This
directory is the entry point for one.

- Scope, assets and threat assumptions: [specs/audit-scope.md](../specs/audit-scope.md) and
  [specs/threat-model.md](../specs/threat-model.md).
- Consensus starter kit for auditors, including the Quint model:
  [specs/bft_consensus_README.md](../specs/bft_consensus_README.md), `specs/bft_consensus.qnt`.
- Cryptographic conformance evidence: `tests/acvp/` (ACVP vectors) exercised by
  `crates/pqc-crypto/tests/acvp_conformance.rs`.
- Accepted risks and known gaps: [KNOWN-ISSUES.md](../KNOWN-ISSUES.md).
- Internal reports available on request: [reports/README.md](../reports/README.md).
- Disclosure and contact: [SECURITY.md](../SECURITY.md).

The verification path (`pqc-crypto`, `pqc-types`, `pqc-tx`, `pqc-light-client`,
`pqc-keystore`, `pqc-tsa`) is Apache-2.0 and, by ADR-068, never links the node core —
an audit can start there and stay there.
