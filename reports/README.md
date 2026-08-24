# Reports

The private repository keeps the full record of every deployment, drift audit, soak,
load test, fuzzing campaign, SBOM and container scan produced while the private chains
(`viper-pq-1`, `viper-research-1`) were running. Those documents name hosts, dates and
incidents, so they are not published as files.

What exists, by category:

| Category | What is recorded |
|---|---|
| audits | internal audit (2026-04), documentation-drift audits (2026-04, 2026-05) |
| deploys | launch and relaunch reports of the retired chains, the post-quantum TLS activation and its forensic follow-up (2026-05) |
| soak | multi-day soak observations after each launch |
| block-time, timing | block-time and commit-latency measurements |
| fuzzing | cargo-fuzz campaign summaries per target |
| sbom, trivy | software bill of materials and container scans of the release images |
| diversity, external-validation | validator-diversity notes and external validation runs |

The parts that matter to a reader of the public repository are folded into
[KNOWN-ISSUES.md](../KNOWN-ISSUES.md) (accepted risks, gaps), [TESTING.md](../TESTING.md)
(load-test baselines, fuzz harnesses) and [DECISIONS.md](../DECISIONS.md) (what was decided
and why). Auditors and prospective validators can request specific reports from the author
under NDA; see [SECURITY.md](../SECURITY.md) for the contact.
