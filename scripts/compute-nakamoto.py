#!/usr/bin/env python3
"""Compute the Nakamoto coefficient + diversity metrics from a Viper Chain
node's `/v1/validators` API.

TASK-227 / ADR-066 — operator-side script for the diversity-targets
quarterly report. Reads:

  GET <node>/v1/validators
    [{"address": "...", "node_id": "...", "consensus_alg_id": <u16>,
      "status": "active|candidate|...", "self_bond": "<u128 str>",
      "registered_height": <u64>}, ...]

and a sidecar JSON file mapping each validator's address → operator
metadata (jurisdiction, region, hosting provider, client implementation,
attestation_hash). The sidecar file is operator-self-declared per the
TASK-185 cohort onboarding workflow.

Outputs JSON to stdout AND a markdown summary to a path passed via
--report-out, suitable for committing under reports/diversity/<UTC>.md.

Usage:

    ./scripts/compute-nakamoto.py \
        --node-url http://localhost:26657 \
        --metadata-file reports/diversity/operator-metadata.json \
        --report-out reports/diversity/2026-Q2.md

    ./scripts/compute-nakamoto.py --self-test

The --self-test mode runs a deterministic offline fixture and pins the
arithmetic. Use this in CI to verify the script does not silently
regress on an upstream Python / requests / json change.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen


def fetch_validators(node_url: str) -> list[dict[str, Any]]:
    """GET <node-url>/v1/validators → list of validator records.

    Rejects any node-url whose scheme is not `http` or `https` — guards
    against `file://` (and similar) being passed via `--node-url`
    (this is operator tooling, but the urllib `file://` handler is
    present by default and a typo could read arbitrary local files).
    """
    if not node_url.startswith(("http://", "https://")):
        raise SystemExit(
            f"refusing non-HTTP node-url: {node_url!r}"
        )
    url = node_url.rstrip("/") + "/v1/validators"
    try:
        with urlopen(url, timeout=10) as resp:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            return json.load(resp)
    except URLError as e:
        raise SystemExit(f"failed to fetch {url}: {e}")


def load_metadata(path: Path) -> dict[str, dict[str, Any]]:
    """Sidecar metadata file:

    {
      "<address_hex>": {
        "jurisdiction": "<ISO 3166-1 alpha-2>",
        "region": "<continent / aws-region / ...>",
        "hosting_provider": "<aws | gcp | hetzner | bare-metal | ...>",
        "client_impl": "<pqcd | other>",
        "attestation_hash": "<32-byte hex or null>"
      },
      ...
    }
    """
    if not path.exists():
        # Empty metadata is fine for the Y0 baseline — every validator
        # falls into the "unknown" bucket and the report flags this
        # explicitly. A real cohort fills the file at TASK-185 onboarding.
        return {}
    with path.open() as f:
        return json.load(f)


def nakamoto_coefficient(stake_by_operator: dict[str, int], threshold_bps: int = 3333) -> int:
    """Smallest set of operators whose combined stake ≥ threshold_bps.

    Default threshold = 33.33% (the BFT-correctness third). At
    threshold_bps = 3333, NC is the byzantine-failure floor: NC operators
    colluding can stop the chain. At threshold_bps = 5001 (50%+), NC is
    the censorship floor: NC operators colluding can dictate the chain.

    Both numbers are interesting; the report renders both.
    """
    total = sum(stake_by_operator.values())
    if total == 0:
        return 0
    threshold = total * threshold_bps // 10_000
    sorted_operators = sorted(stake_by_operator.values(), reverse=True)
    cumulative = 0
    for n, s in enumerate(sorted_operators, 1):
        cumulative += s
        if cumulative >= threshold:
            return n
    return len(sorted_operators)


def compute(
    validators: list[dict[str, Any]],
    metadata: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Compute the diversity metrics + Nakamoto coefficient."""
    active = [v for v in validators if v.get("status") == "active"]

    # Stake per validator (string u128 → int).
    stake_by_address: dict[str, int] = {
        v["address"]: int(v["self_bond"]) for v in active
    }
    total_active_stake = sum(stake_by_address.values())

    # Group by attestation_hash (per-entity grouping, ADR-066 §4.2).
    # Validators with no attestation_hash count as their own entity
    # (one validator = one entity); the Y0 baseline almost all fall here.
    stake_by_entity: dict[str, int] = defaultdict(int)
    for addr, stake in stake_by_address.items():
        meta = metadata.get(addr, {})
        entity_id = meta.get("attestation_hash") or addr
        stake_by_entity[entity_id] += stake

    nc_bft = nakamoto_coefficient(stake_by_entity, threshold_bps=3333)
    nc_majority = nakamoto_coefficient(stake_by_entity, threshold_bps=5001)

    # Distinct buckets — count uniques across active validators.
    jurisdictions = Counter(
        metadata.get(v["address"], {}).get("jurisdiction", "unknown") for v in active
    )
    regions = Counter(
        metadata.get(v["address"], {}).get("region", "unknown") for v in active
    )
    hosting = Counter(
        metadata.get(v["address"], {}).get("hosting_provider", "unknown") for v in active
    )
    clients = Counter(
        metadata.get(v["address"], {}).get("client_impl", "pqcd") for v in active
    )

    # Top-client share by stake (not by validator count).
    client_stake: dict[str, int] = defaultdict(int)
    for v in active:
        impl = metadata.get(v["address"], {}).get("client_impl", "pqcd")
        client_stake[impl] += int(v["self_bond"])
    top_client_share_bps = (
        max(client_stake.values()) * 10_000 // total_active_stake
        if total_active_stake > 0
        else 0
    )

    # Per-entity stake share — flag the top entity.
    if stake_by_entity:
        top_entity_stake = max(stake_by_entity.values())
        top_entity_share_bps = (
            top_entity_stake * 10_000 // total_active_stake
            if total_active_stake > 0
            else 0
        )
    else:
        top_entity_share_bps = 0

    return {
        "active_validator_count": len(active),
        "total_active_stake": str(total_active_stake),
        "distinct_entities": len(stake_by_entity),
        "nakamoto_coefficient_bft": nc_bft,
        "nakamoto_coefficient_majority": nc_majority,
        "distinct_jurisdictions": len(jurisdictions),
        "jurisdictions_breakdown": dict(jurisdictions),
        "distinct_regions": len(regions),
        "regions_breakdown": dict(regions),
        "distinct_hosting_providers": len(hosting),
        "hosting_breakdown": dict(hosting),
        "distinct_clients": len(clients),
        "clients_breakdown": dict(clients),
        "top_client_share_bps": top_client_share_bps,
        "top_entity_share_bps": top_entity_share_bps,
    }


def render_markdown(metrics: dict[str, Any], node_url: str) -> str:
    """Render the metrics dict as a markdown report.

    Output format intentionally stable across runs — operators commit
    the report under reports/diversity/<UTC>.md and a future quarterly
    diff is meaningful.
    """
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    lines: list[str] = []
    lines.append(f"# Diversity Report — {ts}")
    lines.append("")
    lines.append(f"**Source:** `{node_url}/v1/validators`")
    lines.append(f"**Authority:** TASK-227 / ADR-066")
    lines.append(f"**Active validator count:** {metrics['active_validator_count']}")
    lines.append(f"**Distinct entities (per attestation_hash):** {metrics['distinct_entities']}")
    lines.append(f"**Total active self-bond:** {metrics['total_active_stake']}")
    lines.append("")
    lines.append("## Nakamoto coefficients")
    lines.append("")
    lines.append("| Threshold | Coefficient | Interpretation |")
    lines.append("|-----------|------------:|----------------|")
    lines.append(
        f"| 33.33% (BFT) | **{metrics['nakamoto_coefficient_bft']}** | "
        f"smallest set of entities that can halt consensus by colluding |"
    )
    lines.append(
        f"| 50%+1 (majority) | **{metrics['nakamoto_coefficient_majority']}** | "
        f"smallest set of entities that can dictate the chain by colluding |"
    )
    lines.append("")
    lines.append("Targets per `docs/long-horizon-roadmap.md` §5: BFT NC ≥ 6 "
                 "(Phase 9), ≥ 10 (Y5), ≥ 30 (Y10).")
    lines.append("")
    lines.append("## Diversity buckets")
    lines.append("")
    lines.append("| Dimension | Count | Breakdown |")
    lines.append("|-----------|------:|-----------|")
    for label, count_key, breakdown_key in [
        ("Jurisdictions", "distinct_jurisdictions", "jurisdictions_breakdown"),
        ("Regions", "distinct_regions", "regions_breakdown"),
        ("Hosting providers", "distinct_hosting_providers", "hosting_breakdown"),
        ("Client implementations", "distinct_clients", "clients_breakdown"),
    ]:
        breakdown = ", ".join(
            f"{k}: {v}" for k, v in sorted(metrics[breakdown_key].items())
        )
        lines.append(f"| {label} | {metrics[count_key]} | {breakdown} |")
    lines.append("")
    lines.append("## Concentration flags")
    lines.append("")
    top_client = metrics["top_client_share_bps"] / 100
    top_entity = metrics["top_entity_share_bps"] / 100
    lines.append(f"- **Top client share:** {top_client:.2f}% "
                 f"(target ≤ 50% Phase 9, ≤ 33% Y5, ≤ 25% Y10)")
    lines.append(f"- **Top entity share:** {top_entity:.2f}% "
                 f"(ADR-066 D6 cap: 20% per attestation_hash entity)")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("Generated by `scripts/compute-nakamoto.py` "
                 "(TASK-227). Commit this file under "
                 "`reports/diversity/<UTC>.md` to track quarterly drift.")
    lines.append("")
    return "\n".join(lines)


def self_test() -> int:
    """Offline pin: validate the arithmetic on a known fixture."""
    # 6 validators across 4 entities. Stakes pinned so the BFT-NC
    # arithmetic is deterministic.
    fixture = [
        {"address": "01" * 32, "node_id": "v1", "consensus_alg_id": 0x0002,
         "status": "active", "self_bond": "100", "registered_height": 1},
        {"address": "02" * 32, "node_id": "v2", "consensus_alg_id": 0x0002,
         "status": "active", "self_bond": "80", "registered_height": 2},
        {"address": "03" * 32, "node_id": "v3", "consensus_alg_id": 0x0002,
         "status": "active", "self_bond": "60", "registered_height": 3},
        {"address": "04" * 32, "node_id": "v4", "consensus_alg_id": 0x0002,
         "status": "active", "self_bond": "40", "registered_height": 4},
        {"address": "05" * 32, "node_id": "v5", "consensus_alg_id": 0x0002,
         "status": "active", "self_bond": "30", "registered_height": 5},
        {"address": "06" * 32, "node_id": "v6", "consensus_alg_id": 0x0002,
         "status": "active", "self_bond": "20", "registered_height": 6},
    ]
    metadata = {
        # v1 + v2 share an entity (same attestation_hash) — should aggregate
        "01" * 32: {"jurisdiction": "IT", "region": "EU", "client_impl": "pqcd",
                    "attestation_hash": "ee" * 32},
        "02" * 32: {"jurisdiction": "IT", "region": "EU", "client_impl": "pqcd",
                    "attestation_hash": "ee" * 32},
        # v3 + v4 + v5 + v6 are individual entities
        "03" * 32: {"jurisdiction": "DE", "region": "EU", "client_impl": "pqcd"},
        "04" * 32: {"jurisdiction": "FR", "region": "EU", "client_impl": "pqcd"},
        "05" * 32: {"jurisdiction": "US", "region": "NA", "client_impl": "pqcd-v2"},
        "06" * 32: {"jurisdiction": "JP", "region": "AS", "client_impl": "pqcd"},
    }
    metrics = compute(fixture, metadata)

    # Expected aggregations:
    # - 6 active validators
    # - Total stake 100+80+60+40+30+20 = 330
    # - 5 distinct entities (v1+v2 grouped)
    # - Entity stakes: ee_hash=180, v3=60, v4=40, v5=30, v6=20
    # - Sorted desc: 180, 60, 40, 30, 20
    # - 33.33% threshold = 109.89, the entity with 180 alone (1 op) crosses → NC_bft = 1
    # - 50%+1 threshold = 165.495, again 180 alone crosses → NC_maj = 1
    # - 5 jurisdictions, 3 regions, 2 client impls
    # - Top client share: pqcd has 100+80+60+40+20 = 300 / 330 ≈ 90.9%
    # - Top entity share: 180 / 330 ≈ 54.5%
    assert metrics["active_validator_count"] == 6, f"got {metrics}"
    assert metrics["distinct_entities"] == 5, f"got {metrics['distinct_entities']}"
    assert metrics["nakamoto_coefficient_bft"] == 1, f"got {metrics['nakamoto_coefficient_bft']}"
    assert metrics["nakamoto_coefficient_majority"] == 1, f"got {metrics['nakamoto_coefficient_majority']}"
    assert metrics["distinct_jurisdictions"] == 5
    assert metrics["distinct_regions"] == 3
    assert metrics["distinct_clients"] == 2
    # Top client = pqcd at 300/330 = 9090 bps
    assert metrics["top_client_share_bps"] == 9090, f"got {metrics['top_client_share_bps']}"
    # Top entity = 180/330 = 5454 bps (integer division)
    assert metrics["top_entity_share_bps"] == 5454, f"got {metrics['top_entity_share_bps']}"
    print("self-test ok")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--node-url", default="http://localhost:26657",
                   help="Viper node base URL")
    p.add_argument("--metadata-file", type=Path,
                   default=Path("reports/diversity/operator-metadata.json"),
                   help="Operator-self-declared metadata sidecar JSON")
    p.add_argument("--report-out", type=Path, default=None,
                   help="Markdown report path; if absent, only JSON to stdout")
    p.add_argument("--self-test", action="store_true",
                   help="Run offline pin and exit 0 on pass")
    args = p.parse_args()

    if args.self_test:
        return self_test()

    validators = fetch_validators(args.node_url)
    metadata = load_metadata(args.metadata_file)
    metrics = compute(validators, metadata)

    print(json.dumps(metrics, indent=2))

    if args.report_out:
        md = render_markdown(metrics, args.node_url)
        args.report_out.parent.mkdir(parents=True, exist_ok=True)
        args.report_out.write_text(md)
        print(f"\nreport written to {args.report_out}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
