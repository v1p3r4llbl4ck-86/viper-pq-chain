// SPDX-License-Identifier: BUSL-1.1
//! cargo-fuzz target: fuzz the GossipMessage CBOR envelope decoder.
//!
//! Every libp2p gossipsub message arrives as opaque bytes that pqcd then
//! deserialises into a `GossipMessage { msg_type, version, chain_id, payload }`
//! envelope BEFORE inspecting the inner payload. A panic in this layer is a
//! peer-controlled DoS: any peer can submit a malformed envelope and crash
//! every node that receives it.
//!
//! # Running
//!
//! ```bash
//! cargo +nightly fuzz run fuzz_p2p_envelope --manifest-path fuzz/Cargo.toml
//! ```
//!
//! # Invariant
//!
//! Deserialising arbitrary bytes as a `GossipMessage` via ciborium must never
//! panic, abort, overflow, or allocate unbounded memory. The result is either
//! Ok(GossipMessage) or Err(_).
//!
//! # Why this target matters
//!
//! TASK-216 / L2 fuzzing. The envelope decoder is the FIRST line of defence
//! against hostile gossip — it runs before any topic-specific routing,
//! signature checking, or consensus logic. SPEC-P2P-002 §10 T2 covers the
//! happy-path round-trip; this fuzzer covers the adversarial path.

#![no_main]
use libfuzzer_sys::fuzz_target;
use pqc_p2p::message::GossipMessage;

fuzz_target!(|data: &[u8]| {
    let _: Result<GossipMessage, _> = ciborium::from_reader(data);
});
