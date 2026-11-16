# Security Policy

Viper PQ Chain is a research project run by one person. `viper-testnet-4` is a
**test network**: no token, nothing of value, and it may be reset at any time.
No external security audit has been completed. Do not use this software to
protect anything of value.

## Reporting a vulnerability

Please report privately, not in a public issue:

- **GitHub private vulnerability reporting** — "Report a vulnerability" under
  the Security tab of this repository (preferred);
- or e-mail `agalassi@agwswebconsulting.it`.

There is no PGP key. If a report needs encryption, say so in a first short
message and we will agree a channel.

Please include a description and its impact, reproduction steps (a minimal
PoC if you have one), the commit or release you tested, and whether you want
to be credited.

## What you can expect

This is best effort from a single maintainer:

- an acknowledgement, normally **within 7 days**;
- an assessment and, for a confirmed issue, a fix or a mitigation in a
  following release as soon as practical;
- coordinated disclosure: we publish an advisory (GitHub Security
  Advisories) once a fix is out, crediting you if you wish. If we go silent
  for 90 days after your report, you are free to disclose.

There is **no bug bounty** and no paid programme.

## Scope

In scope: the Rust workspace in `crates/`, `vendor/` patches, the Helm chart,
`deploy/`, `docker/`, `scripts/join-testnet.sh` and the release artefacts.
Findings against the test network itself (`boot1.pqchain.agwswebconsulting.it`,
`pqchain.agwswebconsulting.it`) are welcome as reports; please do not degrade
the network for others to demonstrate them — no load or denial-of-service
testing.

Out of scope: vulnerabilities already tracked upstream (RustSec, NVD) in
dependencies — report those upstream; social engineering; physical attacks.

## Good faith

We will not take action against anyone who reports in good faith, avoids
harm to the network and to other people's data, and gives us a reasonable
chance to fix before disclosing.

Last updated: 2026-11-16
