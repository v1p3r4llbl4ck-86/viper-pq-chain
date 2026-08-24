# `scripts/k6/` — Notary API abuse + race tests

TASK-220 / L6a — k6 scenarios that exercise the Viper Notary HTTP surface
beyond what the every-5-minute canary cron probes. The cron measures
nominal-load latency; these scripts measure failure modes under bursty
load + concurrency races + malformed input + auth-bypass attempts.

## When to run

- **After a notary backend release** (post-deploy verification).
- **After a fee-market dimension change** (ADR-053 §T2.1) — race scenario
  surfaces fee-market regression on identical-payload concurrency.
- **Manually during an audit prep window** — k6 generates a single JSON
  summary that auditors can ingest as load evidence.

NOT in CI by default — the notary backend is a live production service
on the 3-host cluster; we don't want every push to hammer it.

## Running

The simplest path uses the official k6 docker image:

```bash
docker run --rm -i grafana/k6 run --quiet \
    --summary-export=reports/k6/$(date +%F-%H%M).json \
    - < scripts/k6/notarize-abuse.js
```

If k6 is installed locally:

```bash
k6 run --quiet \
    --summary-export=reports/k6/$(date +%F-%H%M).json \
    scripts/k6/notarize-abuse.js
```

Override the target URL via env:

```bash
NOTARY_HTTPS=https://staging.example.com NOTARY_HTTP=http://staging.example.com \
    k6 run scripts/k6/notarize-abuse.js
```

## Scenarios

| Stage | Scenario | Purpose | Pass criterion |
|---|---|---|---|
| 0–60 s | `burst` | 100 RPS sustained | No 5xx; p95 e2e ≤ 30 s; status code = 201 OR 429 |
| 65–95 s | `race` | 50 concurrent VUs submit the SAME doc_hash | At most 1 × 201; rest dedup with 4xx; never 5xx |
| 100–160 s | `malformed` | 200 random byte / bad-hex payloads | Always 4xx; never 5xx; never timeout |
| 165–185 s | `auth_bypass` | POST plain HTTP (no TLS) | 426 Upgrade Required OR 30x redirect to HTTPS (rate ≥ 0.95) |

Total wall-clock: ~3 minutes.

## What the summary tells you

The exported `summary.json` carries:
- `metrics.burst_201`, `burst_429`, `burst_5xx` — distribution under load
- `metrics.burst_e2e_ms.p(95)` — tail latency under load
- `metrics.race_201`, `race_dedup` — race outcome shape
- `metrics.malformed_400`, `malformed_5xx` — robustness against junk
- `metrics.auth_bypass_426_rate` — TLS enforcement posture
- `metrics.http_req_failed.rate` — overall failure rate

Any sustained `burst_5xx > 0`, `malformed_5xx > 0`, or
`auth_bypass_426_rate < 0.95` is worth a follow-up issue in
`KNOWN-ISSUES.md`.

## Cross-references

- `docs/security-testing-roadmap.md` — TASK-220 roadmap entry
- `scripts/canary-tx-soak.sh` — the every-5-min nominal-load canary
- `scripts/daily-check.sh` — the daily health snapshot
- `notary/README.md` — backend env vars + service-account setup
