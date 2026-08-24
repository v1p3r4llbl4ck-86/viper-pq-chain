#!/usr/bin/env python3
# TASK-176 part 2 — generate libp2p bootstrap_peers multiaddr array from an
# operator roster. Each entry is /ip4/<ip>/tcp/<port>/p2p/<peer_id>, where
# peer_id is derived deterministically from node_id via `pqcd peer-id <node_id>`.
#
# Python stdlib only (no pyyaml, no pip). Roster is JSON so operators don't
# need extra deps on cutover day.
"""
generate-bootstrap-peers.py --roster <path> [--output <path>] [--exclude-self <node_id>] [--pqcd-binary <path>]

Generates the libp2p bootstrap_peers multiaddr array for each devnet-3 operator.
Each entry is /ip4/<ip>/tcp/<port>/p2p/<peer_id>, where peer_id is derived
deterministically from node_id via `pqcd peer-id <node_id>`.

Options:
  --roster <path>        JSON roster file (schema: see devnet-3-roster.json.example)
  --output <path>        Write to file instead of stdout
  --exclude-self <id>    Omit the operator with this node_id from the output
                         (use on each operator's machine to generate their own list)
  --pqcd-binary <path>   Path to pqcd binary (default: pqcd in PATH)
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
from typing import Any

NODE_ID_RE = re.compile(r"^[a-zA-Z0-9_-]+$")
PEER_ID_RE = re.compile(r"^12D3KooW[1-9A-HJ-NP-Za-km-z]+$")
PORT_MIN = 1024
PORT_MAX = 65535


def die(msg: str, code: int = 1) -> None:
    print(f"generate-bootstrap-peers: error: {msg}", file=sys.stderr)
    sys.exit(code)


def validate_operator(idx: int, entry: Any) -> tuple[str, str, int]:
    if not isinstance(entry, dict):
        die(f"operators[{idx}] must be an object, got {type(entry).__name__}")
    missing = [k for k in ("node_id", "public_ip", "listen_port") if k not in entry]
    if missing:
        die(f"operators[{idx}] missing required fields: {', '.join(missing)}")

    node_id = entry["node_id"]
    public_ip = entry["public_ip"]
    listen_port = entry["listen_port"]

    if not isinstance(node_id, str) or not NODE_ID_RE.match(node_id):
        die(
            f"operators[{idx}].node_id {node_id!r} invalid: "
            f"must match ^[a-zA-Z0-9_-]+$"
        )
    if not isinstance(public_ip, str):
        die(f"operators[{idx}].public_ip must be a string, got {type(public_ip).__name__}")
    try:
        ipaddress.ip_address(public_ip)
    except ValueError:
        die(f"operators[{idx}].public_ip {public_ip!r} is not a valid IPv4/IPv6 address")
    if not isinstance(listen_port, int) or isinstance(listen_port, bool):
        die(f"operators[{idx}].listen_port must be an integer")
    if not (PORT_MIN <= listen_port <= PORT_MAX):
        die(
            f"operators[{idx}].listen_port {listen_port} out of range "
            f"[{PORT_MIN}..{PORT_MAX}]"
        )
    return node_id, public_ip, listen_port


def load_roster(path: str) -> list[dict[str, Any]]:
    if not os.path.isfile(path):
        die(f"roster file not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        die(f"roster {path!r} is not valid JSON: {e}")
    except OSError as e:
        die(f"cannot read roster {path!r}: {e}")

    if not isinstance(data, dict):
        die("roster root must be a JSON object")
    operators = data.get("operators")
    if not isinstance(operators, list) or not operators:
        die("roster must contain a non-empty 'operators' array")
    return operators


def multiaddr_format(ip: str, port: int, peer_id: str) -> str:
    # Pick /ip4 vs /ip6 based on address family; libp2p multiaddrs are strict.
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        # Already validated upstream; belt-and-suspenders.
        die(f"internal: invalid ip {ip!r} reached multiaddr_format")
    proto = "ip4" if isinstance(addr, ipaddress.IPv4Address) else "ip6"
    return f"/{proto}/{ip}/tcp/{port}/p2p/{peer_id}"


def derive_peer_id(pqcd_binary: str, node_id: str) -> str:
    try:
        result = subprocess.run(
            [pqcd_binary, "peer-id", node_id],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        die(
            f"pqcd binary not found at {pqcd_binary!r}. "
            "Install pqcd or pass --pqcd-binary <path>."
        )
    except OSError as e:
        die(f"failed to invoke pqcd: {e}")

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        die(
            f"`{pqcd_binary} peer-id {node_id}` exited {result.returncode}: "
            f"{stderr or '(no stderr)'}"
        )
    peer_id = (result.stdout or "").strip()
    if not peer_id:
        die(f"`{pqcd_binary} peer-id {node_id}` produced empty output")
    if not PEER_ID_RE.match(peer_id):
        die(
            f"`{pqcd_binary} peer-id {node_id}` produced unexpected output "
            f"{peer_id!r} (expected base58 libp2p PeerId starting with 12D3KooW)"
        )
    return peer_id


def resolve_pqcd_binary(user_arg: str | None) -> str:
    if user_arg:
        if not (os.path.isfile(user_arg) and os.access(user_arg, os.X_OK)):
            die(f"--pqcd-binary {user_arg!r} is not an executable file")
        return user_arg
    found = shutil.which("pqcd")
    if not found:
        die(
            "pqcd not found in PATH. Install pqcd (cargo install --path crates/pqcd) "
            "or pass --pqcd-binary <path>."
        )
    return found


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="generate-bootstrap-peers.py",
        description=(
            "Generate the libp2p bootstrap_peers multiaddr array for each "
            "devnet-3 operator. Each entry is /ip4/<ip>/tcp/<port>/p2p/<peer_id>, "
            "where peer_id is derived deterministically from node_id via "
            "`pqcd peer-id <node_id>`."
        ),
    )
    parser.add_argument(
        "--roster",
        required=True,
        metavar="<path>",
        help="JSON roster file (schema: see devnet-3-roster.json.example)",
    )
    parser.add_argument(
        "--output",
        metavar="<path>",
        help="Write to file instead of stdout",
    )
    parser.add_argument(
        "--exclude-self",
        metavar="<node_id>",
        help=(
            "Omit the operator with this node_id from the output "
            "(use on each operator's machine to generate their own list)"
        ),
    )
    parser.add_argument(
        "--pqcd-binary",
        metavar="<path>",
        help="Path to pqcd binary (default: pqcd in PATH)",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    if args.exclude_self is not None and not NODE_ID_RE.match(args.exclude_self):
        die(
            f"--exclude-self {args.exclude_self!r} invalid: "
            f"must match ^[a-zA-Z0-9_-]+$"
        )

    operators = load_roster(args.roster)
    pqcd_binary = resolve_pqcd_binary(args.pqcd_binary)

    validated: list[tuple[str, str, int]] = []
    seen: set[str] = set()
    for i, entry in enumerate(operators):
        node_id, ip, port = validate_operator(i, entry)
        if node_id in seen:
            die(f"duplicate node_id {node_id!r} in roster")
        seen.add(node_id)
        validated.append((node_id, ip, port))

    if args.exclude_self is not None and args.exclude_self not in seen:
        die(
            f"--exclude-self {args.exclude_self!r} not present in roster "
            f"(known: {', '.join(sorted(seen))})"
        )

    multiaddrs: list[str] = []
    for node_id, ip, port in validated:
        if node_id == args.exclude_self:
            continue
        peer_id = derive_peer_id(pqcd_binary, node_id)
        multiaddrs.append(multiaddr_format(ip, port, peer_id))

    rendered = json.dumps(multiaddrs, indent=2) + "\n"

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(rendered)
        except OSError as e:
            die(f"cannot write --output {args.output!r}: {e}")
    else:
        sys.stdout.write(rendered)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
