# Three-Network Deployment Examples

**Authority:** TASK-219 (essay item 3) — operationalises the
validator-private / VFN / public-RPC three-network split per
SPEC-P2P-002 §4 and `docs/historical/phase-8-spec.md` §3.

This directory contains three companion `node.json` examples — one
per hop in the recommended topology. Operators copy the file
matching their hop, fill in the `<placeholder>` tokens, and deploy.

In ADR-069 vocabulary the three hops are `validator`
(`validator.node.json`), `sentry` (`vfn.node.json` — the VFN dials the
validator and relays for it) and `rpc` (`public-rpc.node.json` — a full
node dedicated to the public API). `configs/roles/<role>.json` carries
the current reference config for each role; these files show the
three-network listener layout on top of it.

## Topology

```
                     ┌────────────────────┐
                     │  Public Internet   │
                     └─────────┬──────────┘
                               │
                       (port 26676 public)
                               │
                     ┌─────────▼──────────┐
                     │ sentry / public RPC│  ← public-rpc.node.json
                     │  (no signing keys) │
                     └─────────┬──────────┘
                               │
                       (port 26666 VFN)
                               │
                     ┌─────────▼──────────┐
                     │  VFN (full node)   │  ← vfn.node.json
                     │  (no signing keys) │
                     └─────────┬──────────┘
                               │
                       (port 26656 priv)
                               │
                     ┌─────────▼──────────┐
                     │  Validator         │  ← validator.node.json
                     │  (signing keys!)   │
                     └────────────────────┘
                       (no public bind!)
```

## When to use which

| Role | Example file | Listens on | Signing keys |
|------|--------------|------------|--------------|
| Validator | `validator.node.json` | `validator_listen` only (private) | YES — keystore configured |
| VFN | `vfn.node.json` | `validator_listen` (out) + `vfn_listen` (in) | NO |
| Sentry / Public RPC | `public-rpc.node.json` | `vfn_listen` (out) + `public_listen` (in) | NO |

Each non-validator hop is a separate machine. The validator never
binds a publicly-routable address; it dials VFN(s) outbound and
gossips through them. The VFN proxies block / vote / tx traffic
between the validator-private network and the public-facing sentry
nodes.

## Sentry pattern (≥3 outbound, diverse)

A validator behind NAT or VPN SHOULD use ≥3 persistent outbound
connections to sentry / VFN nodes, chosen out-of-band:

- ≥3 distinct ASNs (avoid single-AS eclipse)
- ≥3 distinct geographic regions (continent-level)
- ≥3 distinct operator entities (don't pin all 3 to your own VFN)

Add the bootstrap multiaddrs to `libp2p.bootstrap_peers[]` in
`validator.node.json`. The libp2p connection manager keeps these
sticky; if one drops, the validator continues to operate via the
remaining ≥2 paths while the cold-start retry logic (TASK-234) re-
dials the dropped peer.

## Defence-in-depth: pqcd's startup lint

If a validator-class role (`devnet.role = "validator"` or
`"single_node"`) is configured with a publicly-bound `public_listen`
(`0.0.0.0` / `[::]` / wildcard multiaddr), pqcd emits a WARN at
boot referencing this directory. The lint is informational — the
node still starts — but it surfaces the mis-config in journald
where the log-alert watcher (`docs/observability.md` §5) picks it up.

To intentionally collapse the three networks onto one host (devnet
/ test rig), bind `public_listen` to a loopback address (`127.0.0.1`
or `::1`); the lint treats loopback bindings as explicit operator
opt-in and stays silent.

## See also

- `docs/operators/RUNBOOK.md` — operator deployment procedure
- `specs/p2p-libp2p.md` §4 — wire-protocol spec for the three networks
- `specs/p2p-messaging.md` §6 — message-class routing per network
- `docs/historical/phase-8-spec.md` §3 — original three-network rationale
- ADR-041 / ADR-042 — libp2p adoption + validator identity binding
