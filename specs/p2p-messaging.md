# Peer-to-Peer Messaging Specification

**Spec ID**: SPEC-P2P-001  
**Version**: 0.2  
**Status**: Accepted  
**History**: v0.1 draft; v0.2 revised by ADR-041 (libp2p/QUIC/X25519MLKEM768 transport), 2026-04-21.  
**Date**: 2026-04-21  
**Depends on**: SPEC-CONSENSUS-001, ADR-010, ADR-027, ADR-041 (P2P libp2p/QUIC/X25519MLKEM768)

> **Revised by ADR-041** — replaces the Phase 6 SSH-tunnel and HTTP-polling transport with a production rust-libp2p stack (QUIC primary, TCP/TLS 1.3 fallback, X25519MLKEM768 hybrid PQ default, GossipSub v1.2). SSH tunnel is deprecated; see §3a for the new transport architecture.

---

## 1. Scope

This document defines the requirements that the Viper PQ Chain consensus protocol places on the peer-to-peer messaging layer. It specifies what the P2P layer must provide, not how it is implemented. Architectural options are enumerated in §3; the implementation decision is deferred to ADR-028 (open).

This spec does not cover:

- block propagation and sync (block fetch is handled via the libp2p request-response protocol; separate from consensus-message routing)
- peer discovery and handshake protocols beyond what is specified in §3a (ML-KEM-768 session establishment is superseded by X25519MLKEM768 TLS 1.3 hybrid in ADR-041)
- application-layer APIs (`/v1/`, `/internal/`)

---

## 2. Normative Language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL are interpreted per RFC 2119.

---

## 3. Normative References

| Reference | Document |
|-----------|----------|
| ADR-010 | ML-KEM-768 for P2P transport key agreement (superseded by ADR-041 for transport layer) |
| ADR-027 | Adopt Tendermint-like BFT consensus with PQ signatures |
| ADR-041 | P2P transport: rust-libp2p/QUIC/X25519MLKEM768 hybrid PQ |
| SPEC-CONSENSUS-001 | Viper BFT consensus protocol specification |
| SPEC-VAL-001 | Validator and staking model |
| draft-ietf-tls-ecdhe-mlkem-04 | X25519MLKEM768 codepoint 0x11EC |

---

## 3a. Transport Architecture (ADR-041)

This section specifies the production P2P transport stack adopted in Phase 8. It replaces the Phase 6 transitional mechanisms (SSH tunnel, HTTP polling) which are deprecated as of ADR-041.

### 3a.1 Library and Crate Structure

| Component | Crate |
|-----------|-------|
| Core networking | `libp2p-core` (vendored fork, pinned) |
| Noise handshake (legacy path) | `libp2p-noise` |
| QUIC transport | `libp2p-quic` |
| Gossip protocol | `libp2p-gossipsub` |
| DHT discovery | `libp2p-kad` |

rust-libp2p is used as a vendored sub-crate fork (not the omnibus `libp2p` crate) to manage the 0.x semver churn. A staff-designated maintainer is responsible for tracking and rebasing upstream security patches.

### 3a.2 Transport Layer

| Property | Value |
|----------|-------|
| Primary transport | QUIC (UDP) |
| Fallback transport | TCP with TLS 1.3 |
| TLS handshake default | X25519MLKEM768 hybrid PQ (codepoint `0x11EC`, draft-ietf-tls-ecdhe-mlkem-04) |
| Fallback key exchange | X25519 (classical, negotiated when peer does not support 0x11EC) |

Nodes MUST attempt QUIC first. Nodes MUST fall back to TCP/TLS 1.3 if QUIC is blocked or unreachable. The X25519MLKEM768 hybrid MUST be the default preferred group in ClientHello; nodes MUST NOT disable PQ key exchange without a governance-approved configuration flag.

Note: X25519MLKEM768 increases ClientHello size by approximately 1.2 KB. Implementations MUST test fragmentation behaviour with real network MTUs before deployment to avoid QUIC Initial datagram fragmentation issues.

### 3a.3 Gossip Protocol

GossipSub v1.2 is used for consensus message propagation. The IDONTWANT control message (introduced in GossipSub v1.2) is REQUIRED and MUST be enabled. This is critical for PQ payload sizes (2–16 KB per signed message), where duplicate delivery without IDONTWANT would multiply bandwidth consumption unacceptably.

Peer scoring MUST be configured; using all-default scores without tuning for validator set size is NOT permitted.

### 3a.4 Network Topology — Three Separate Networks

The validator stack runs three logically and physically separate networks:

| Network | Default port | Participants | Notes |
|---------|-------------|-------------|-------|
| Validator private | 26656 | Active validators only | Consensus messages (Proposal, Prevote, Precommit) |
| Trusted VFN | 26666 | Validator Full Nodes (VFN) with signed attestation | State sync, block propagation |
| Public | 26676 | Full nodes, light clients | Read-only, no consensus routing |

Validators MUST NOT expose port 26656 to the public network. Connections on the validator network MUST require a valid binding of the peer's node ID to an on-chain validator public key (see §3a.6).

### 3a.5 Peer Discovery

Discovery is layered; each layer is a fallback for the one above:

1. **Hardcoded signed bootstrap nodes** — 8–16 nodes across independent operators; rotatable via governance without code changes
2. **ENR-over-DNS with DNSSEC** (EIP-1459 pattern) — resilient to restrictive firewalls
3. **discv5 + Kademlia DHT** — ambient discovery
4. **On-chain validator registry** — authoritative source; binding of node ID to validator pubkey; queried at startup and on epoch boundary

Nodes MUST validate that peers on the validator network (port 26656) have a node ID that corresponds to an active validator on-chain. Peers that do not pass this check MUST be rejected at the transport level.

### 3a.6 Anti-Eclipse Measures

- **Node ID binding**: each validator's libp2p node ID MUST be cryptographically bound to its on-chain validator public key. Unbounded node IDs MUST NOT be admitted to the validator network.
- **ASN diversity**: no more than N connections (implementation-defined, RECOMMENDED ≤ 3 per /24, ≤ 5 per ASN) may originate from the same BGP ASN or /24 prefix. ASN lookup SHOULD use a MaxMind-compatible database updated at least monthly.
- **Sentry pattern**: validators behind NAT or VPN SHOULD use ≥ 3 persistent outbound connections to sentry nodes chosen out-of-band (different operators, different ASNs, different jurisdictions).
- **Address book rate-limit**: inbound peer advertisements MUST be rate-limited to prevent address book poisoning (lesson from Tendermint MConn).

### 3a.7 Deprecation of SSH Tunnel and HTTP Polling

The SSH tunnel mechanism and HTTP-polling block sync used in Phase 6 (transitional) are **removed as of Phase 8**. They MUST NOT be present in Phase 8 binaries. Any configuration referencing `ssh_tunnel_*` parameters MUST produce a fatal startup error with a migration notice.

---

## 4. Requirements from the Consensus Protocol

The consensus protocol (SPEC-CONSENSUS-001) requires the P2P layer to provide the following capabilities.

### 4.1 Broadcast

A validator MUST be able to send a consensus message (Proposal, Prevote, Precommit) to all other active validators within the current round's timeout budget. "Broadcast" means delivery to all validators in the active set, not just a subset of peers.

**Latency requirement**: a broadcasted message SHOULD reach all correct validators within `prevote_timeout_base_ms / 2 = 500ms` under normal network conditions. This ensures that a validator can issue prevotes and observe quorum before the prevote timer fires in round 0.

### 4.2 Reliability

The P2P layer is REQUIRED to make best-effort delivery. Messages MAY be lost (the consensus timeout handlers are designed to tolerate loss). The P2P layer MUST NOT guarantee delivery of messages from Byzantine validators.

Retransmission of its own consensus messages is the responsibility of the consensus engine, not the P2P layer. A validator that has not observed quorum by the prevote timeout broadcasts a nil vote and advances — it does not wait for redelivery.

### 4.3 Authentication

Every consensus message carries a signature from the sender's consensus key (SPEC-CONSENSUS-001 §7.4). The P2P layer does NOT add a second layer of per-message authentication on top of the consensus signature.

The P2P transport uses TLS 1.3 with X25519MLKEM768 hybrid PQ key agreement (ADR-041; codepoint 0x11EC, draft-ietf-tls-ecdhe-mlkem-04) which provides session-level confidentiality and peer identity for the transport channel. This is orthogonal to, and does not replace, the consensus message signatures. ADR-010 (ML-KEM-768 standalone) is superseded by ADR-041 for the transport layer.

### 4.4 Confidentiality

Consensus messages (Proposal, Prevote, Precommit) are NOT confidential. A validator's vote at `(h, r)` is a public commitment that every node in the network should be able to observe. The ML-KEM session provides point-to-point encryption for transport; individual validators MAY decrypt and re-gossip received messages.

### 4.5 Message Ordering

The P2P layer MUST NOT guarantee ordered delivery. Consensus messages may arrive out of order (e.g., a precommit may arrive before the prevote for the same round). The consensus engine MUST buffer and process messages independently of arrival order.

### 4.6 Validator-to-Validator Only

Consensus messages (Proposal, Prevote, Precommit) MUST only be sent between active validators. Full nodes and read-only nodes MUST NOT participate in consensus-message routing. Forwarding of finalized blocks to full nodes uses the existing block-sync path and is out of scope for this spec.

---

## 5. Architecture Options

> **ADR-041 status note**: the topology decision previously deferred to ADR-028 has been resolved. For Phase 8 (validator set ≤ 64), the chosen topology is **Option A (full mesh) over QUIC with GossipSub v1.2 overlay** for consensus messages. Option B (gossip-only) becomes the primary topology at validator set ≥ 256 (Phase 9+). Option C (HTTP relay) is deprecated and removed.

### Option A — Full Mesh Direct TCP/QUIC Connections

Each validator maintains a persistent authenticated connection to every other validator. Consensus messages are sent directly over the established connection.

| Aspect | Value |
|--------|-------|
| Connection count | `n × (n-1) / 2` total; 276 for n=24, 1225 for n=50 |
| Latency | Lowest (single hop) |
| Bandwidth overhead | Highest (each message sent n-1 times by the sender) |
| Failure mode | Peer disconnection requires reconnect; no cascading failure |
| Implementation complexity | Low — extend existing ML-KEM session handling |

Preferred for Phase 1 (n ≤ 24): full mesh is manageable at 24 validators and provides the lowest latency.

### Option B — Gossip Protocol

Each validator maintains connections to a subset of peers (fan-out `k`). Received messages are re-broadcast to the remaining peers. The network converges in `O(log n)` hops.

| Aspect | Value |
|--------|-------|
| Connection count | `n × k` (k typically 4–8) |
| Latency | Higher (log-hop delivery) |
| Bandwidth overhead | Lower per node |
| Failure mode | Individual peer failure is transparent |
| Implementation complexity | Higher — requires anti-entropy and dedup |

Preferred for n ≥ 50: full mesh becomes impractical; gossip scales better.

### Option C — HTTP Polling (deprecated, removed in Phase 8)

> **DEPRECATED** — This option was the Phase 6 transitional mechanism. It is removed as of Phase 8 / ADR-041. The description is retained for historical reference only.

The Phase 6 `sync_loop` polled for blocks over HTTP. Consensus messages were not routed through this path; it was used only for block fetch.

NOT recommended for consensus-critical paths: the relay is a single point of failure, and HTTP latency exceeds the prevote timeout budget at high message rates. Replaced by libp2p request-response over QUIC (§3a.2).

---

## 6. Message Format

Consensus messages are defined in SPEC-CONSENSUS-001 §7. The P2P layer transports them as opaque byte sequences. No additional framing, routing headers, or P2P-layer signatures are added.

Message type disambiguation (for the P2P router) uses the `msg_type` byte at offset 0 of the CBOR-encoded message (SPEC-CONSENSUS-001 §7):

| `msg_type` | Message |
|-----------|---------|
| `0xC1` | Proposal |
| `0xC2` | Prevote |
| `0xC3` | Precommit |

**Note on envelope vs inner tag**: the `msg_type` byte above lives inside the CBOR-encoded consensus message payload. The Phase 8 libp2p gossip transport (SPEC-P2P-002) wraps this payload in an outer `GossipMessage` envelope whose own `MessageType` enum uses disjoint values (`0x01 Block`, `0x02 ConsensusVote`, `0x03 Transaction`, `0x04 ValidatorUpdate`) for topic routing and IDONTWANT suppression. The outer `MessageType::ConsensusVote` corresponds to any of the three inner `0xC1`/`0xC2`/`0xC3` values — envelope decoding does not reveal which. See SPEC-P2P-002 §4.2 and `crates/pqc-p2p/src/message.rs`; the split is tracked in TASK-131.

**Wire format (resolved 2026-04-22 — TASK-147)**: the envelope `MessageType` discriminants (`0x01`..`0x04`) are enforced on the wire by `serde_repr::Serialize_repr`/`Deserialize_repr` in `crates/pqc-p2p/src/message.rs`. Each variant encodes as a single CBOR unsigned-integer byte equal to its discriminant. Unknown discriminants fail to decode. Two pin tests (`message_type_wire_format_is_u8_discriminant`, `message_type_rejects_unknown_discriminant`) block any regression to the pre-TASK-147 behaviour, in which default serde derives encoded the variant NAME as a CBOR text string.

---

## 7. Connection to Implementation (Phase 8)

The Phase 8 P2P implementation uses rust-libp2p as specified in §3a. The legacy `pqc-p2p::session` ML-KEM-768 session establishment (TASK-045, ADR-010) is **superseded** by TLS 1.3 + X25519MLKEM768 via libp2p-quic and libp2p-noise (ADR-041). The `pqc-p2p::session` crate MUST NOT be used for new connections; it may be retained in the codebase only if needed for reading historical data from Phase 6 testnet snapshots.

The consensus message routing path requires:
- persistent libp2p connections on the validator network (port 26656)
- a routing table: `validator_pubkey → multiaddr` derived from the on-chain validator registry
- a receive buffer per `(validator_address, h, r)` fed into the consensus engine (TASK-083)

Block fetch and snapshot serve endpoints use libp2p request-response over QUIC on the VFN network (port 26666).

---

## 8. Open Questions

Questions resolved by ADR-041 are marked. Remaining questions are open.

| # | Question | Options | Status |
|---|----------|---------|--------|
| P2P-Q1 | Full mesh vs. gossip for Phase 1 (n=24)? | **Resolved (ADR-041)**: full mesh over QUIC for Phase 8 (n≤64); GossipSub v1.2 overlay for n≥256 | Closed |
| P2P-Q2 | Persistent connections vs. per-message sessions? | **Resolved (ADR-041)**: persistent libp2p connections | Closed |
| P2P-Q3 | Should full nodes receive consensus messages (read-only observation)? | No — validator network (26656) is closed; full nodes use VFN (26666) | Open — light client observation path TBD |
| P2P-Q4 | Validator discovery mechanism? | **Resolved (ADR-041)**: layered (signed bootstrap → ENR-over-DNS/DNSSEC → discv5/Kademlia → on-chain registry) | Closed |
| P2P-Q5 | Message deduplication for re-gossip scenarios? | GossipSub v1.2 IDONTWANT + in-memory seen-set per `(validator, h, r, step)`; TTL-based expiry | Open — TTL value TBD |
| P2P-Q6 | Maximum message size enforcement? | ML-DSA-65 Proposal ~3.4 KB + block data; cap at `max_block_size + 16 KB` | Open — cap value MUST be set before mainnet |

---

## 9. Non-Functional Requirements

These requirements constrain the implementation independent of topology choice.

| Requirement | Value | Rationale |
|-------------|-------|-----------|
| Max one-way latency (validator to validator) | ≤ 200 ms (target) | Ensures prevote_timeout_base (1000ms) is reachable in round 0 |
| Max connection setup time | ≤ 500 ms | TLS 1.3 + X25519MLKEM768 handshake over QUIC; acceptable for startup, not per-message |
| Backpressure | required | A slow validator MUST NOT block broadcasts to fast validators |
| No single point of failure | required | No relay or broker; peer-to-peer direct or gossip only |
| DoS resistance | required | Rate-limit inbound messages per sender; discard messages from non-active validators |

---

## 10. Future Scope

The following items are explicitly out of scope for SPEC-P2P-001 v0.2 and will be addressed in later spec versions or separate specs:

- Light client protocol (partial block headers + commit proof download without full node participation)
- Peer reputation and ban scoring (GossipSub peer scoring tuning is in scope for Phase 9)
- NAT traversal and hole-punching for validators behind firewalls (DCUtR + circuit-relay-v2 are relevant for light clients; validators are expected to have public IPs)
- SNARK-based signature aggregation to reduce commit material size at large validator sets (mentioned in WHITEPAPER.md §8.3; target Phase 9–10 when validator set reaches 256+)
- Turbine-style stake-weighted erasure coding for blocks exceeding ~100 KB (relevant when PQ signature payload bloat becomes significant at large validator sets)
- Multipath QUIC support
