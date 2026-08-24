#!/usr/bin/env python3
"""
analyze-block-time.py — TASK-186 deliverable preparation.

Projects chain disk-growth across candidate `block_time_ms` values
from a sample of `pqchain_chain_data_bytes` observations. Closes the
"tooling" half of TASK-186; the actual ADR decision still requires a
7-day soak with the metric live (TASK-187 landed those metrics on
2026-05-05; this tool consumes them).

Inputs (mutually exclusive):

  --metrics-url URL [--interval SEC] [--duration SEC]
        Poll `pqchain_chain_data_bytes` from a `/v1/metrics` endpoint
        every `--interval` seconds for a total of `--duration` seconds.
        Writes the raw samples to `reports/block-time/<UTC>.jsonl` and
        runs the analysis on them. Fast smoke (300 s / 5 s interval)
        only catches the empty-block baseline; the spec-grade run is
        7 d.

  --samples-file PATH
        Ingest a JSONL file with `{"t_unix": <int>, "bytes": <int>}`
        entries (one per line). Use to re-run analysis against a
        prior `--metrics-url` capture or a Prometheus snapshot.

Outputs an ASCII table on stdout + (with `--json`) a machine-readable
summary on the same stream.

Notes:

  - Linear scaling assumption: empty-block consensus chatter is
    ~3.3 KB × N_validators × commit signatures per block (ADR-053
    §T1.1). Doubling `block_time_ms` halves blocks/day and therefore
    halves growth (to first order). User-traffic growth adds linearly
    on top and is NOT projected here — the soak signal feeds it.

  - Output is decision-input, NOT a decision. The ADR-186 deliverable
    must combine this with finality-latency measurements + throughput
    benchmarks before committing to a value.
"""

import argparse
import json
import os
import statistics
import sys
import time
import urllib.request
from datetime import datetime, timezone

CURRENT_BLOCK_TIME_MS = 500
DEFAULT_CANDIDATES_MS = (500, 1000, 2000, 5000)


def parse_metric(text: str, name: str) -> int:
    """Pull the first integer value of a Prometheus metric line.

    `pqchain_chain_data_bytes 12345` → 12345. Returns 0 if the
    metric is absent (fresh-start node before its first sample).
    """
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("#") or not line:
            continue
        if line.startswith(name + " "):
            try:
                return int(line.split()[1])
            except (IndexError, ValueError):
                return 0
    return 0


def poll_metric(url: str) -> int:
    """One scrape of `/v1/metrics`, return `pqchain_chain_data_bytes`.

    Rejects any URL whose scheme is not `http` or `https` — guards
    against `file://` (and similar) being passed via `--metrics-url`
    (this is operator tooling, but the urllib `file://` handler is
    present by default and a typo could read arbitrary local files).
    """
    if not url.startswith(("http://", "https://")):
        raise ValueError(
            f"refusing non-HTTP url for metrics scrape: {url!r}"
        )
    with urllib.request.urlopen(url, timeout=10) as resp:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        text = resp.read().decode("utf-8", "replace")
    return parse_metric(text, "pqchain_chain_data_bytes")


def collect_samples(url: str, interval: float, duration: float) -> list:
    """Poll the metric at `interval` seconds for `duration` seconds.

    Returns a list of `{t_unix, bytes}` dicts, one per scrape. The
    last sample is included even if it overshoots `duration` slightly
    (single-shot tail capture).
    """
    samples = []
    t0 = time.time()
    while True:
        now = time.time()
        try:
            b = poll_metric(url)
        except Exception as e:
            print(f"# warn: scrape failed at t={int(now - t0)}s: {e}", file=sys.stderr)
            b = 0
        samples.append({"t_unix": int(now), "bytes": b})
        if now - t0 >= duration:
            break
        time.sleep(interval)
    return samples


def write_samples(samples: list, out_dir: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = os.path.join(out_dir, f"{stamp}.jsonl")
    with open(path, "w") as f:
        for s in samples:
            f.write(json.dumps(s) + "\n")
    return path


def load_samples(path: str) -> list:
    samples = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            samples.append(json.loads(line))
    return samples


def compute_baseline(samples: list) -> dict:
    """Simple least-squares slope of bytes vs t_unix (bytes/sec).

    Reports both the slope and an "endpoint" estimate (last - first
    over t_last - t_first) — the slope is robust to small noise; the
    endpoint matches the Prometheus rate(...) intuition.
    """
    if len(samples) < 2:
        return {
            "samples": len(samples),
            "span_seconds": 0,
            "bytes_per_second_slope": 0.0,
            "bytes_per_second_endpoint": 0.0,
            "bytes_per_hour": 0.0,
            "bytes_per_day": 0.0,
        }
    xs = [s["t_unix"] for s in samples]
    ys = [s["bytes"] for s in samples]
    span = xs[-1] - xs[0]
    endpoint = (ys[-1] - ys[0]) / span if span > 0 else 0.0

    # Least-squares slope.
    mean_x = statistics.fmean(xs)
    mean_y = statistics.fmean(ys)
    num = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    den = sum((x - mean_x) ** 2 for x in xs)
    slope = num / den if den > 0 else 0.0

    return {
        "samples": len(samples),
        "span_seconds": int(span),
        "bytes_per_second_slope": slope,
        "bytes_per_second_endpoint": endpoint,
        "bytes_per_hour": slope * 3600.0,
        "bytes_per_day": slope * 86400.0,
    }


def project_candidates(baseline: dict, current_ms: int, candidates_ms) -> list:
    """For each candidate `block_time_ms`, project daily / weekly /
    30-day / annual disk growth assuming linear inverse scaling.
    """
    base_per_day = baseline["bytes_per_day"]
    out = []
    for cand_ms in candidates_ms:
        scale = current_ms / cand_ms if cand_ms > 0 else 0.0
        per_day = base_per_day * scale
        out.append(
            {
                "block_time_ms": cand_ms,
                "scaling_factor_vs_baseline": scale,
                "growth_bytes_per_day": per_day,
                "growth_bytes_per_week": per_day * 7,
                "growth_bytes_per_month": per_day * 30,
                "growth_bytes_per_year": per_day * 365,
            }
        )
    return out


def humanise_bytes(n: float) -> str:
    """Format an ASCII-friendly size: 1.7 GB / 4.0 GB / 47 MB / etc."""
    if n is None:
        return "—"
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    idx = 0
    val = float(n)
    while abs(val) >= 1024 and idx < len(units) - 1:
        val /= 1024
        idx += 1
    return f"{val:.2f} {units[idx]}"


def render_table(baseline: dict, projections: list, current_ms: int) -> str:
    lines = []
    lines.append("┌─" + "─" * 78 + "─┐")
    lines.append("│ TASK-186 — block_time projection (live data, NOT a decision)" + " " * 18 + "│")
    lines.append("├─" + "─" * 78 + "─┤")
    lines.append(
        f"│ baseline samples = {baseline['samples']:>4d}   span = {baseline['span_seconds']:>6d} s   current = {current_ms:>4d} ms".ljust(80) + "│"
    )
    lines.append(
        f"│ slope            = {baseline['bytes_per_second_slope']:>10.2f} B/s  ({humanise_bytes(baseline['bytes_per_hour'])}/h, {humanise_bytes(baseline['bytes_per_day'])}/day)".ljust(80) + "│"
    )
    lines.append("├─" + "─" * 78 + "─┤")
    lines.append("│ block_time   scale     /day        /week       /month      /year       │")
    for p in projections:
        marker = "  ← current" if p["block_time_ms"] == current_ms else ""
        lines.append(
            f"│ {p['block_time_ms']:>5d} ms"
            f"   {p['scaling_factor_vs_baseline']:>4.2f}x"
            f"   {humanise_bytes(p['growth_bytes_per_day']):>9s}"
            f"   {humanise_bytes(p['growth_bytes_per_week']):>9s}"
            f"   {humanise_bytes(p['growth_bytes_per_month']):>9s}"
            f"   {humanise_bytes(p['growth_bytes_per_year']):>9s}"
            f"  {marker}".ljust(80)[:80] + "│"
        )
    lines.append("└─" + "─" * 78 + "─┘")
    return "\n".join(lines)


# ───────────────────────────────────────────────────────────── self-test ──

def self_test() -> int:
    """Synthetic-data validation. Runs without network access; pins the
    arithmetic so a refactor to `compute_baseline` / `project_candidates`
    that silently drifts results gets caught.
    """
    # 2 GB growth over 1 hour = ~556 KB/s slope.
    samples = [
        {"t_unix": 1_700_000_000, "bytes": 1_000_000_000},
        {"t_unix": 1_700_000_000 + 3600, "bytes": 3_000_000_000},
    ]
    base = compute_baseline(samples)
    assert base["samples"] == 2, base
    assert base["span_seconds"] == 3600, base
    expected_per_sec = 2_000_000_000 / 3600
    assert abs(base["bytes_per_second_slope"] - expected_per_sec) < 1, base
    expected_per_day = expected_per_sec * 86400
    assert abs(base["bytes_per_day"] - expected_per_day) < 1, base

    proj = project_candidates(base, current_ms=500, candidates_ms=(500, 1000, 2000, 5000))
    assert len(proj) == 4, proj
    # 500 ms → 1.0x (current). 1000 ms → 0.5x. 5000 ms → 0.1x.
    assert proj[0]["scaling_factor_vs_baseline"] == 1.0, proj[0]
    assert abs(proj[1]["scaling_factor_vs_baseline"] - 0.5) < 1e-9, proj[1]
    assert abs(proj[3]["scaling_factor_vs_baseline"] - 0.1) < 1e-9, proj[3]
    # 5000 ms candidate produces 1/10th the growth.
    assert (
        abs(proj[3]["growth_bytes_per_day"] - proj[0]["growth_bytes_per_day"] / 10)
        < 1
    ), proj

    # parse_metric: pulls integer from a Prometheus exposition snippet.
    text = (
        "# HELP foo bar\n# TYPE foo gauge\nfoo 42\n"
        "# HELP pqchain_chain_data_bytes ...\n"
        "# TYPE pqchain_chain_data_bytes gauge\n"
        "pqchain_chain_data_bytes 12345\n"
    )
    assert parse_metric(text, "pqchain_chain_data_bytes") == 12345
    assert parse_metric(text, "missing_metric") == 0

    print("self-test: OK (arithmetic + parse_metric pinned)")
    return 0


# ────────────────────────────────────────────────────────────────── main ──

def main(argv) -> int:
    p = argparse.ArgumentParser(
        description="Project chain disk growth across block_time candidates (TASK-186).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = p.add_mutually_exclusive_group()
    src.add_argument("--metrics-url", help="Live /v1/metrics URL to poll")
    src.add_argument("--samples-file", help="JSONL file with {t_unix, bytes} samples")
    src.add_argument("--self-test", action="store_true", help="Run synthetic-data validation and exit")
    p.add_argument("--interval", type=float, default=30.0, help="Poll interval seconds (live mode)")
    p.add_argument("--duration", type=float, default=600.0, help="Total poll duration seconds (live mode)")
    p.add_argument("--out-dir", default="reports/block-time", help="Where to archive captured samples")
    p.add_argument(
        "--current-block-time-ms",
        type=int,
        default=CURRENT_BLOCK_TIME_MS,
        help="Block time of the live chain the samples come from",
    )
    p.add_argument(
        "--candidates-ms",
        default=",".join(str(x) for x in DEFAULT_CANDIDATES_MS),
        help="Comma-separated candidate block_time values",
    )
    p.add_argument("--json", action="store_true", help="Emit machine-readable JSON instead of the table")
    args = p.parse_args(argv)

    if args.self_test:
        return self_test()

    if not args.metrics_url and not args.samples_file:
        p.error("one of --metrics-url / --samples-file / --self-test is required")

    if args.metrics_url:
        samples = collect_samples(args.metrics_url, args.interval, args.duration)
        path = write_samples(samples, args.out_dir)
        print(f"# captured {len(samples)} samples → {path}", file=sys.stderr)
    else:
        samples = load_samples(args.samples_file)
        print(f"# loaded {len(samples)} samples from {args.samples_file}", file=sys.stderr)

    candidates_ms = tuple(int(x) for x in args.candidates_ms.split(",") if x.strip())
    baseline = compute_baseline(samples)
    projections = project_candidates(baseline, args.current_block_time_ms, candidates_ms)

    if args.json:
        print(json.dumps({
            "current_block_time_ms": args.current_block_time_ms,
            "baseline": baseline,
            "projections": projections,
        }, indent=2))
    else:
        print(render_table(baseline, projections, args.current_block_time_ms))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
