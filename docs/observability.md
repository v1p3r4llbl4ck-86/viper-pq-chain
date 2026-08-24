# Observability — Viper PQ Chain

End-to-end guide to reading, correlating and alerting on what `pqcd` does
in production. Covers everything that ships in-tree; **log centralization
across hosts is intentionally NOT covered** — it requires Loki / ELK /
Datadog or equivalent and lives outside this repo (see "Deferred" at the
bottom).

This document tracks the codebase at the time of writing; the role
vocabulary is the ADR-069 one (`validator`, `sentry`, `full`, `rpc`,
`archive`, `bootnode`). If a field name or path drifts, trust the code
(`grep` for the field name) over the doc.

---

## 1. The four signals

| Signal           | Where to look                                                        | Cadence    |
|------------------|----------------------------------------------------------------------|------------|
| **Live logs**    | `journalctl -u pqcd -f` on the node (systemd deploy) or the pod logs (Helm deploy) | streaming  |
| **Metrics**      | `GET http://<host>:26657/v1/metrics` (Prometheus exposition)          | scrape pull |
| **Audit log**    | `/var/log/pqchain/audit/audit-YYYYMMDD.jsonl` (hash-chained JSONL)    | per-event  |
| **Local alerts** | `/var/log/viper-alerts/alerts.jsonl` + `pqchain_alert_total{pattern}` | every 60 s |

All four exist on every node whatever its role (validator, sentry,
full, rpc, archive, bootnode). They are independent: removing or breaking one does not silently degrade the
others.

---

## 2. Live logs (journald)

`pqcd` runs as a `simple` systemd service (`pqcd.service`) and emits to
the journal. The unit pins the destination explicitly:

```ini
StandardOutput=journal
StandardError=journal
Environment=RUST_LOG=info
```

Default level is `INFO`. Override per-process via `RUST_LOG`:

```bash
sudo systemctl set-environment RUST_LOG="debug,pqcd::p2p=trace"
sudo systemctl restart pqcd
```

### Read commands

```bash
# Live tail
journalctl -u pqcd -f

# Last 200 lines, no pager
journalctl -u pqcd -n 200 --no-pager

# Errors and warnings only
journalctl -u pqcd -p err

# Time-bounded
journalctl -u pqcd --since "10 min ago"
journalctl -u pqcd --since "2026-04-27 07:00" --until "2026-04-27 07:30"

# Follow a specific block through every consensus event on this host
# (block_hash IS the trace_id — it is identical on every node of the network)
journalctl -u pqcd | grep "block_hash=09ef5872eda6a5ebc5c38aa3497d0c3e855dccdd16895dd4020ce12bbd05c8f6"

# JSON format (parseable; future shipping to Loki etc.)
journalctl -u pqcd -n 100 --output=json
```

### Tracing targets to know

| Target                 | What it covers                                          |
|------------------------|---------------------------------------------------------|
| `pqcd::devnet`         | Consensus loop, block proposal, precommit handling      |
| `pqcd::p2p`            | libp2p gossip, block-fetch, snapshot fetch              |
| `pqcd::api`            | HTTP API request/response                               |
| `pqcd::keystore`       | Key load/save, signing operations                       |
| `pqc_consensus::*`     | Lower-level consensus engine internals                  |
| `viper.demo_banner`    | Single-shot DEMO disclosure at startup (`tracing::warn!`) |
| `viper.audit`          | Audit-log layer captures these (see §4) — they ALSO appear in journald at INFO unless filtered out |

### Block correlation: use `block_hash` as trace ID

Every consensus event carries `block_hash=<hex>` as a structured field.
This includes:

- `proposer emitted PROPOSAL block` (proposer side)
- `gossip block ingested (Next)` (every receiver)
- `buffered precommit` (every receiver)
- `block produced and committed` / `block committed (consensus loop, …)`
- `drop precommit with invalid signature` (when applicable)
- `drop stale precommit (at/below tip)` (when applicable)

Grep for the block_hash and you reconstruct the entire lifecycle of one
block across one node. To reconstruct it across your whole fleet, run the
same grep on each node (or, once log centralization lands, in one query).

---

## 3. Metrics (`/v1/metrics`)

Prometheus text exposition format, exposed by every node on
`http://<host>:26657/v1/metrics` (and the internal
`/internal/metrics`). All counter/gauge names are stable — a rename is
a breaking change documented in `CHANGELOG.md`.

### New (this iteration) — log-event counters

```
# HELP pqchain_log_events_total Total log events emitted, partitioned by tracing level.
# TYPE pqchain_log_events_total counter
pqchain_log_events_total{level="error"} 0
pqchain_log_events_total{level="warn"}  3
pqchain_log_events_total{level="info"}  142891
pqchain_log_events_total{level="debug"} 0
pqchain_log_events_total{level="trace"} 0
```

Implementation: `crates/pqcd/src/log_metrics.rs::LogMetricsLayer` —
a `tracing_subscriber::Layer` that increments per-level atomic counters
on `on_event`. Counters reflect events that **survived `EnvFilter`**, i.e.
what was actually emitted to stderr / journald.

### Useful PromQL once a Prometheus is scraping

```promql
# Error rate per minute, alert if > 0
rate(pqchain_log_events_total{level="error"}[5m]) * 60

# Warn-rate spike compared to 1h baseline
rate(pqchain_log_events_total{level="warn"}[5m])
  / rate(pqchain_log_events_total{level="warn"}[1h])

# Local-watcher counters (see §5)
sum by (pattern) (rate(pqchain_alert_total[5m]))
```

### Reading without Prometheus

Pure `curl`:

```bash
curl -s http://<host>:26657/v1/metrics | grep '^pqchain_log_events_total'
```

---

## 4. Audit log (tamper-evident)

A separate, append-only, hash-chained JSONL log for security-relevant
events. Lives outside the journald firehose so an auditor can ingest it
without filtering noise.

### File layout

```
/var/log/pqchain/audit/
├── audit-20260427.jsonl
├── audit-20260428.jsonl
└── audit-20260429.jsonl
```

Files rotate on UTC date change. Owner: `pqchain:pqchain`, mode `0750`.

### Line format

```jsonl
{
  "unix_secs":   1777268402,
  "unix_nanos":  123456789,
  "level":       "INFO",
  "target":      "viper.audit",
  "event":       "block_finalized",
  "height":      90080,
  "block_hash":  "5ea51bd6b2fd61fdf56ab42d32177bedf0cfe93c40b20b56e94fff134ff3ae9e",
  "included_tx_count": 1,
  "prev_hash":   "a3f2…",
  "hash":        "7e91…"
}
```

- `prev_hash` of the very first line of a file is `""` (empty string).
- `hash = sha256(canonical_payload_bytes)` where `canonical_payload_bytes`
  is the JSON object serialized with **keys sorted alphabetically**, and
  **excluding the `hash` field itself** (the chain hash hashes every
  other field, including the previous chain hash).

### Currently-emitted events

Search the codebase for `target: "viper.audit"` to see the canonical
list. As of this iteration:

| `event`                       | Emission site                                           |
|-------------------------------|---------------------------------------------------------|
| `process_started`             | `main.rs::main` once per process boot                   |
| `block_proposed`              | `devnet.rs` proposer emit (after own signature)         |
| `block_finalized`             | `devnet.rs` after `append_block_trusted` (both branches: legacy single-proposer loop and distributed-signing consensus loop) |
| `block_finalized_via_gossip`  | `devnet.rs` non-proposer ingest path (libp2p gossip)    |

Add new emission sites with:

```rust
tracing::info!(
    target: "viper.audit",
    event = "your_event_name",
    height = ...,
    block_hash = %hex::encode(...),
    // any additional context fields
);
```

### Verifying the chain (manual)

```bash
# Pseudo: read each line, parse, recompute sha256 of the canonical
# payload (sorted keys, sans `hash`), compare to the line's `hash`,
# also check that this line's `prev_hash` equals the previous line's
# `hash`. A real verifier will live in scripts/verify-audit-log.sh
# (deferred — see "Deferred").
```

### What this gives you (and what it doesn't)

✅ Detects insertion, deletion or modification of any line within a file.
The `prev_hash` chain breaks immediately.

✅ Survives an attacker with `root` who tries to silently rewrite history
inside the file.

❌ Does NOT detect file truncation at an arbitrary point. An attacker can
roll back to any past line and continue forging a valid-looking chain
from there. Mitigation requires external pinning — daily roots
published to a different chain, a witness server, or shipped to a
write-once log store. Falls under "Deferred".

❌ Does NOT detect file deletion (the file just disappears). Mitigation
is the same: external pinning + alert-on-missing-recent-entry.

❌ Does NOT survive the post-restart hash-chain reset — each process
start emits a new `process_started` event with `prev_hash=""`. The
discontinuity is **explicit and audited**: you can detect a stealth
restart because there will be a new `process_started` line followed by
a new chain segment.

### Configuration

| Env var                 | Default                       | Effect                       |
|-------------------------|-------------------------------|------------------------------|
| `VIPER_AUDIT_LOG_DIR`   | `/var/log/pqchain/audit`      | Audit file base directory    |
| `VIPER_NODE_ID`         | `unknown`                     | Tagged onto `process_started` |

The systemd unit sets `VIPER_NODE_ID` from the Ansible inventory
(`viper_node_id` per node); the Helm chart sets it from the pod name.
`VIPER_NODE_ID` also overrides `node_id` from `node.json` (ADR-069).

---

## 5. Local alert watcher (no external infra)

A 60-second systemd timer that scans `journalctl -u pqcd` for known-bad
patterns and exposes counters via the node_exporter textfile collector.
Everything stays on the host; no Slack / PagerDuty / mail required.

### Deployment

| Path                                                 | Role                                       |
|------------------------------------------------------|--------------------------------------------|
| `/usr/local/sbin/viper-log-alert-watcher.sh`         | Scanner script                             |
| `/etc/systemd/system/viper-log-alert-watcher.service` | systemd oneshot service                   |
| `/etc/systemd/system/viper-log-alert-watcher.timer`   | systemd timer (30s after boot, then 60s) |
| `/var/log/viper-alerts/alerts.jsonl`                  | append-only matched-line log              |
| `/var/log/viper-alerts/state`                         | journalctl cursor (replay-resistance)     |
| `/var/log/viper-alerts/totals`                        | persisted cumulative counts               |
| `/var/lib/node_exporter/textfile_collector/viper_alerts.prom` | Prometheus textfile-collector output |

### Patterns watched

Defined at the top of `scripts/log-alert-watcher.sh`. Each pattern
becomes a `pqchain_alert_total{pattern="<label>"}` counter:

| Label              | Triggers on                                                    |
|--------------------|----------------------------------------------------------------|
| `error_level`      | Any line with `level=ERROR` or `ERROR` token                   |
| `panic`            | `panicked at`, `RUST_BACKTRACE`, `fatal runtime error`         |
| `peer_sync_error`  | `peer_sync_errors`, "peer sync failure"                        |
| `equivocation`     | `equivocation`, `double_propose`, `DoubleProposeAtHeight`       |
| `block_gap`        | `p2p_block_gap_total`, "height-gap detected", "gap > 1"        |
| `invalid_signature`| "drop precommit with invalid signature", same for tx           |
| `oom`              | "Out of memory", killed.*pqcd, OOMPolicy                       |
| `chain_halted`     | "chain halted", "consensus stuck", "no progress for"           |

### Operating instructions

```bash
# Manually trigger one tick
sudo systemctl start viper-log-alert-watcher.service

# See last firing
sudo systemctl status viper-log-alert-watcher.timer

# See current counters
cat /var/lib/node_exporter/textfile_collector/viper_alerts.prom

# See matched lines
sudo tail -f /var/log/viper-alerts/alerts.jsonl

# Reset counters (only if you've manually verified the underlying
# issue is resolved; node_exporter expects monotonic counters!):
sudo systemctl stop viper-log-alert-watcher.timer
sudo rm /var/log/viper-alerts/totals
sudo systemctl start viper-log-alert-watcher.timer
```

### Adding a pattern

Edit `scripts/log-alert-watcher.sh`, add to the `PATTERNS` associative
array. Redeploy the script to every node (re-run the `configure`
Ansible role).
Patterns are **regular expressions** matched against the journal line
content as rendered by `journalctl --output=short-iso`.

**Discipline rule:** if a line matches your new pattern in normal
healthy operation, the pattern is wrong — refine the regex. Counters
must mean "operator should investigate".

---

## 6. Putting it together: a typical investigation

> "Why did block 90243 take 4 seconds to finalize?"

```bash
# Placeholders: <rpc> is any node serving the read API; <validator>,
# <sentry-1>, <sentry-2> are SSH aliases for the nodes you operate.

# 1. Find the block hash
curl -s http://<rpc>:26657/v1/blocks/90243 | jq -r .block_hash
# → 9e94106210ce2ba3...

# 2. Trace it across the validator's journal
ssh <validator> "journalctl -u pqcd | grep 9e94106210ce2ba3"

# 3. Trace it across the sentries / full nodes
for h in <sentry-1> <sentry-2>; do
  ssh $h "journalctl -u pqcd | grep 9e94106210ce2ba3"
done

# 4. Check the audit log on each node
for h in <validator> <sentry-1> <sentry-2>; do
  ssh $h "grep 9e94106210ce2ba3 /var/log/pqchain/audit/audit-*.jsonl"
done

# 5. Were there alert hits in that window? (<window> = ISO-8601 prefix)
for h in <validator> <sentry-1> <sentry-2>; do
  ssh $h "grep '<window>' /var/log/viper-alerts/alerts.jsonl"
done

# 6. Cross-check the error-rate metric
curl -s http://<rpc>:26657/v1/metrics | grep pqchain_log_events_total
```

---

## 7. Zabbix integration — server-side aggregation

The same metrics + counters can flow into a Zabbix server via a
`zabbix-agent` on each node. The agent is configured by
`deploy/ansible/roles/zabbix/`; on top of the stock Linux checks it
exposes a custom UserParameter set under `viper.*` (file:
`deploy/ansible/roles/zabbix/templates/viper-agent-params.conf.j2`).

The Zabbix template + dashboard is in
the private monitoring templates; full operator notes in
the private monitoring templates. After import:

- 30 items per host: chain height, mempool depth, p2p peers, log-event
  counters, alert-watcher pattern counters, audit-line totals, canary
  status, process uptime/RSS, etc.
- 9 triggers covering ERROR-level logs, panics, equivocation, chain
  halt, canary failure rate, p2p peer drop, and the "stale-tip
  recovery" firings.
- 4 graphs (height, log levels, p2p + recovery, alert patterns).

This covers **operator-facing aggregation** across the fleet without
adding a new dependency: someone sees a failure within ~60 s on a
single dashboard.

What Zabbix does NOT replace: free-text search across raw log content
("show me every line with block_hash=09ef…"). That still wants a
proper log backend (Loki / ELK), which remains deferred until there's
volume to justify it.

## 8. Deferred (intentional gaps)

These are NOT in scope yet. They require external infrastructure or
significantly more code, and will land separately.

| Item                                  | What it would give us                                   | Why deferred              |
|---------------------------------------|---------------------------------------------------------|---------------------------|
| **Free-text log search across hosts** | Ad-hoc ` block_hash=…` queries across all journald output, regardless of which host produced the line | Needs Loki/Promtail/ELK or paid SaaS — Zabbix covers metrics + alert rates but is not a log-search index |
| **Audit-root anchoring**              | Daily Merkle root of audit JSONL committed to a different chain (or to the chain itself) for cross-system tamper-evidence | Needs design on which chain to anchor to and what the on-chain envelope looks like |
| **Audit log verification CLI**        | `pqcd audit verify <file>` that re-walks the chain and reports the first break | Easy to write; deferred only because manual verification is enough at present volume |
| **Alertmanager / Slack / e-mail dispatch** | Push notifications instead of pull-only counters       | The brief was explicitly "no external components" |
| **OpenTelemetry export**              | Trace_id propagation in the OTel sense (spans across services) | block_hash already provides correlation at the granularity that matters today |

---

## 9. Source map

| Concern                | File / function                                                           |
|------------------------|---------------------------------------------------------------------------|
| Subscriber stack       | `crates/pqcd/src/main.rs::setup_tracing`                                  |
| Per-level counters     | `crates/pqcd/src/log_metrics.rs`                                          |
| Audit log layer        | `crates/pqcd/src/audit_log.rs`                                            |
| Audit emission sites   | `grep -rn 'target: "viper.audit"' crates/pqcd/src/`                        |
| Demo banner            | `crates/pqcd/src/devnet.rs::print_demo_chain_banner` (called from `main.rs::cmd_api_serve`) |
| Metrics endpoint       | `crates/pqcd/src/devnet.rs::handle_metrics`                               |
| Alert watcher script   | `scripts/log-alert-watcher.sh`                                            |
| Systemd unit           | `deploy/ansible/roles/configure/templates/pqcd.service.j2`                |
| Watcher unit + timer   | `deploy/ansible/roles/configure/templates/log-alert-watcher.{service,timer}.j2` |
| Ansible deploy tasks   | `deploy/ansible/roles/configure/tasks/main.yml`                           |
| Zabbix UserParameters  | `deploy/ansible/roles/zabbix/templates/viper-agent-params.conf.j2`        |
| Zabbix template export | the private monitoring templates                                  |
| Zabbix operator notes  | the private monitoring templates                                                 |
