# `scripts/zap/` — OWASP ZAP baseline scan (TASK-222 / L6b)

OWASP ZAP (Zed Attack Proxy) is the de-facto baseline scanner for
HTTP applications. It spiders the target, observes responses, and
matches them against the OWASP Top-10 Web Application Security Risks.
Baseline mode is **passive only** — it does NOT actively attack
endpoints (no SQL injection, no XSS payloads, no auth-fuzzing). Safe
against the live production frontend.

## When to run

- **Once per release window** of the notary frontend, the docs site,
  or any URL exposed at `pqchain.agwswebconsulting.it/`.
- **Pre-audit** as one of the standard L6 deliverables.
- **Post-incident** if a finding from a different layer (Falco,
  semgrep, daily-check) suggests a frontend exposure.

## Why NOT in CI

The frontend has only 7 routes (mostly static — landing, docs/users,
docs/developers, explorer, /v1/* RPC proxy, /api/notarize,
/api/verify/:id, /api/health). Re-running ZAP on every push generates
noise without new signal; a finding is novel only when the frontend's
HTTP surface actually changes.

## Run

```bash
scripts/zap/baseline-scan.sh
# or against a non-default target:
scripts/zap/baseline-scan.sh https://staging.example.com
```

The script:
1. Pulls `ghcr.io/zaproxy/zaproxy:stable` if missing (~600 MB, cached after).
2. Runs `zap-baseline.py` against the target with a 5-minute spider +
   5-minute passive scan budget.
3. Writes three artefacts under `reports/zap/`:
   - `baseline-<UTC-ts>.html` — full report with per-finding context
   - `baseline-<UTC-ts>.json` — machine-readable form
   - `baseline-<UTC-ts>.md` — at-a-glance summary table for the audit log

Wallclock: ~6-8 minutes total.

## Triage

Open the HTML report. For each finding:

- **High / Medium**: file an entry in `KNOWN-ISSUES.md` §3 (Active bugs)
  with the alert ID + the route + the proposed fix or a "wontfix" with
  rationale.
- **Informational / Low**: log it in the markdown summary; revisit at
  the next release window.

The frontend is mostly static + a thin nginx proxy to the chain RPC,
so the realistic finding surface is HTTP-header hardening:
`Content-Security-Policy`, `X-Content-Type-Options: nosniff`,
`Strict-Transport-Security` (HSTS), `X-Frame-Options`. Most of those
are configured on nginx; the baseline confirms.

## Cross-references

- `docs/security-testing-roadmap.md` §3 / TASK-222
- `scripts/k6/notarize-abuse.js` — TASK-220 (load + abuse on the same
  surface; complementary to ZAP's passive spider)
- `deploy/ansible/roles/nginx/` — where the response-header config lives
