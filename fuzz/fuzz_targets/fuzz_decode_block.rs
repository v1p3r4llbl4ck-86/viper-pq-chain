// SPDX-License-Identifier: BUSL-1.1
//! cargo-fuzz target: fuzz the StoredBlock CBOR decoder.
//!
//! Block bytes arrive over libp2p gossip from arbitrary peers — including
//! adversarial ones. The decoder is the first code that touches those bytes
//! after the gossipsub envelope is unwrapped, and it must never panic / OOM /
//! UB on any byte sequence. The only acceptable outcomes are Ok(StoredBlock)
//! or Err(StorageError).
//!
//! # Running
//!
//! ```bash
//! cargo +nightly fuzz run fuzz_decode_block --manifest-path fuzz/Cargo.toml
//! ```
//!
//! # Invariant
//!
//! `RocksDbChainStore::decode_block_bytes(arbitrary_bytes)` must always return
//! either Ok or Err — never panic, abort, overflow, or read out of bounds.
//!
//! # Why this target matters
//!
//! TASK-216 / L2 fuzzing. The block decoder is the highest-value fuzz target
//! after the tx decoder because it processes data from untrusted peers on the
//! consensus hot path. A panic here halts the receiving node; a slow decoder
//! enables resource-exhaustion DoS on every honest peer in the gossip mesh.

#![no_main]
use libfuzzer_sys::fuzz_target;
use pqc_consensus::storage_rocksdb::RocksDbChainStore;

fuzz_target!(|data: &[u8]| {
    let _ = RocksDbChainStore::decode_block_bytes(data);
});
