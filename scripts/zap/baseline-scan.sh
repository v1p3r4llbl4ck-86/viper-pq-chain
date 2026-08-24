#!/usr/bin/env bash
# baseline-scan.sh — TASK-222 / L6b — OWASP ZAP baseline scan against the
# viper-pq-1 public HTTPS frontend.
#
# Runs zap-baseline.py from the official OWASP container against
# https://pqchain.agwswebconsulting.it/. Baseline (passive) scan only —
# does not actively attack endpoints, just spiders + observes responses
# for the OWASP Top-10 Web Application Security Risks. Safe to run
# against the production frontend.
#
# Output:
#   reports/zap/baseline-<UTC-timestamp>.html       Human readable
#   reports/zap/baseline-<UTC-timestamp>.json       JSON for triage
#   reports/zap/baseline-<UTC-timestamp>.md         Markdown summary
#
# Usage:
#   scripts/zap/baseline-scan.sh
#   scripts/zap/baseline-scan.sh https://staging.example.com   # alt target
#
# Run frequency: once per release window (manual). NOT in CI — the
# frontend has only 7 routes (mostly static); rerunning every push
# generates noise without new signal.

set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TARGET="${1:-https://pqchain.agwswebconsulting.it}"
REPORT_DIR="${REPO_DIR}/reports/zap"
TS=$(date -u +%Y-%m-%dT%H%M%SZ)

mkdir -p "$REPORT_DIR"

echo "=== ZAP baseline scan ==="
echo "  target : $TARGET"
echo "  output : $REPORT_DIR/baseline-${TS}.{html,json,md}"
echo ""

if ! command -v docker >/dev/null 2>&1 ; then
    echo "ERROR: docker is required (the official zap2docker-stable image is the supported way to run zap-baseline.py)" >&2
    exit 1
fi

# Pull image if missing (the first run is ~600 MB; cached after).
docker pull -q ghcr.io/zaproxy/zaproxy:stable >/dev/null 2>&1 || \
    docker pull -q owasp/zap2docker-stable:latest

# zap-baseline.py exit codes:
#   0  no findings above threshold
#   1  warning(s) found
#   2  fatal error
#
# We accept any of {0,1,2} and rely on the report file to triage; the
# script's own exit code is 0 unless we cannot even produce a report.
docker run --rm \
    -v "$REPORT_DIR:/zap/wrk:rw" \
    -t ghcr.io/zaproxy/zaproxy:stable \
    zap-baseline.py \
        -t "$TARGET" \
        -r "baseline-${TS}.html" \
        -J "baseline-${TS}.json" \
        -m 5  \
        -T 5  \
        || ZAP_EXIT=$?

# Markdown summary (extract counts from JSON for at-a-glance triage).
if [[ -f "$REPORT_DIR/baseline-${TS}.json" ]]; then
    python3 <<PYEOF >"$REPORT_DIR/baseline-${TS}.md"
import json, sys
d = json.load(open("$REPORT_DIR/baseline-${TS}.json"))
print(f"# ZAP baseline summary — $TS\n")
print(f"**Target**: $TARGET\n")
print(f"**ZAP version**: {d.get('@version','unknown')}\n\n")
sites = d.get("site", [])
total = sum(len(s.get("alerts", [])) for s in sites)
print(f"## Findings: {total}\n")
print("| risk | confidence | name | count |")
print("|---|---|---|---|")
for s in sites:
    for a in s.get("alerts", []):
        print(f'| {a.get("riskdesc","").split(" (")[0]:8} | {a.get("confidence","?"):8} | {a.get("name","")[:60]} | {a.get("count","?")} |')
print("\n\n## Next steps\n")
print("1. Open the HTML report ($REPORT_DIR/baseline-${TS}.html) for the per-finding context (URL, evidence, CWE).")
print("2. Triage each finding: file an issue under KNOWN-ISSUES.md if actionable, or a 'wontfix' note if it's a known framework limitation.")
print("3. Compare against the previous baseline run to spot regressions.")
PYEOF
    echo ""
    echo "=== Markdown summary written: $REPORT_DIR/baseline-${TS}.md ==="
    cat "$REPORT_DIR/baseline-${TS}.md"
else
    echo "ERROR: ZAP did not produce a JSON report — manual triage needed" >&2
    exit 2
fi

echo ""
echo "✓ done. HTML report: $REPORT_DIR/baseline-${TS}.html"
