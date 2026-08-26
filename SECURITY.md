# Security Policy

The Viper PQ Chain project takes security seriously. If you believe you
have found a vulnerability in this codebase, the node software, the
libp2p transport, the cryptographic envelope, or any
component under this repository, please report it to us privately before
any public disclosure.

This policy applies to `main` (default branch) and any release branches.
Issues discovered on ephemeral feature branches should be raised to the
author of that branch directly before escalating here.

## Reporting a vulnerability

**Primary contact**: `security@agwswebconsulting.it` (see `.well-known/security.txt`).
Alternatively, use GitHub's private vulnerability reporting on the public
repository ("Report a vulnerability" under the Security tab): it reaches the
author only.

**Encryption**: a PGP key will be published at
`https://pqchain.agwswebconsulting.it/.well-known/pgp.asc` before the P-COMPAT-001
binding window opens (before `viper-testnet-2` accepts external state from
operators outside the author's control — see `AGENTS.md` §"Repository Status").

**What to include**:
- A concise description of the issue and its impact.
- Reproduction steps, ideally a minimal PoC.
- The commit hash (SHA) at which you reproduced the issue.
- Your preferred contact, and whether you want public credit on
  disclosure.

## Our response SLA

We aim to meet the following response SLA for any report judged to
be in scope:

| Step | Target |
|---|---|
| Acknowledgement | 24 h |
| Preliminary triage + severity | 72 h |
| Fix target — Critical | 30 days |
| Fix target — High     | 60 days |
| Fix target — Medium   | 90 days |
| Public disclosure embargo | 90 days after fix ships, or shorter by agreement |

Severity is assessed against **CVSS 4.0** (enterprise / EU compliance
documentation) plus **Immunefi Vulnerability Severity Classification
System v2.3** (for bug-bounty payouts once the bounty is live).

## Scope — in

- The Rust workspace in `/crates/`: consensus, crypto, mempool, P2P,
  state, transaction codec, the node daemon `pqcd`.
- Ansible deployment playbooks and roles in `/deploy/`.
- Signed release artifacts (once published).

## Scope — out

- The underlying Rust standard library, the libp2p family, RocksDB, or
  any transitive dependency whose vulnerability is already publicly
  tracked on <https://rustsec.org> or <https://nvd.nist.gov>. Please
  report to the upstream instead; we will pick up the fix after an
  advisory lands.
- Development tooling, benches, and fuzz-target code in `/fuzz/` and
  `/crates/pqc-consensus/benches/`.
- Social engineering, physical security, client-side browser issues
  not rooted in this codebase.

## Safe harbour

We will not pursue civil or criminal action against a researcher who:

1. Makes a **good-faith effort** to avoid harm to availability,
   confidentiality, or integrity of our systems, and to the privacy of
   any user data;
2. **Does not exfiltrate data** beyond what is necessary to demonstrate
   the issue;
3. **Does not publicly disclose** the issue until we have had a
   reasonable opportunity (at least the SLA above) to respond and fix,
   or the embargo has expired;
4. Otherwise complies with this policy and applicable law.

For on-chain whitehat rescue operations during an exploit in progress,
we intend to adopt the SEAL / Immunefi **Safe Harbor framework**
(<https://frameworks.securityalliance.org/safe-harbor>) once the
P-COMPAT-001 binding window opens (see `AGENTS.md`). Until then, contact
us first — we will coordinate rapidly. `viper-testnet-2` is live since 2026-08-25
(single validator, public notary in anonymous mode): it carries real cryptographic state and
public-facing services, with no guarantee of persistence. Findings against the
node, the P2P layer, the cryptographic envelope or the public API are in scope and should be
reported privately, not exercised on the network.

## Bug bounty

A formal bug-bounty programme will launch **after** the first external
security audit closes (TASK-115) and **before** the P-COMPAT-001 binding
window opens. Scope, prize tiers, and payout rules will be published at
that time on Immunefi or Cantina (to be selected). This policy document
will be updated with the link once the programme is live.

## Public disclosure

After a fix ships and the embargo window expires, we will publish an
advisory describing the issue, the fix, and (with the researcher's
consent) a credit. Advisories live under `/security/advisories/` once
they exist.

---

Last updated: 2026-05-03
