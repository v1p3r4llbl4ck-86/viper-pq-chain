// SPDX-License-Identifier: Apache-2.0
//! Tests for `hash`.
//!
//! Extracted from `hash.rs` 2026-05-10. `use super::*;`
//! brings every private item from the parent module into scope.

use super::*;

#[test]
fn tagged_hash_matches_manual_double_tag() {
    let tag = b"VIPER-TEST-TAG";
    let data = b"the quick brown fox";
    let tag_h = shake256_32(tag);
    let mut manual = Shake256::default();
    manual.update(&tag_h);
    manual.update(&tag_h);
    manual.update(data);
    let mut expected = [0u8; 32];
    manual.finalize_xof().read(&mut expected);

    assert_eq!(tagged_hash(tag, data), expected);
}

#[test]
fn different_tags_produce_different_digests() {
    let data = b"same body";
    let h1 = tagged_hash(b"VIPER-TAG-A", data);
    let h2 = tagged_hash(b"VIPER-TAG-B", data);
    assert_ne!(h1, h2, "tagged hashes MUST be domain-separated");
}

#[test]
fn tagged_hash_differs_from_untagged_concat() {
    // H(tag || data) != tagged_hash(tag, data) — this is the whole
    // point of the double-tag construction.
    let tag = b"VIPER-TEST-TAG";
    let data = b"body";
    let mut concat = Vec::with_capacity(tag.len() + data.len());
    concat.extend_from_slice(tag);
    concat.extend_from_slice(data);
    let untagged = shake256_32(&concat);
    assert_ne!(tagged_hash(tag, data), untagged);
}

#[test]
fn tagged_hasher_matches_tagged_hash_for_single_chunk() {
    // Streaming a single raw chunk through TaggedHasher MUST produce
    // the same digest as the one-shot helper (given push_raw, since
    // tagged_hash does not length-prefix the data).
    let tag = b"VIPER-TEST-TAG";
    let data = b"streamed";
    let mut h = TaggedHasher::new(tag);
    h.push_raw(data);
    assert_eq!(h.finish(), tagged_hash(tag, data));
}

#[test]
fn tagged_hasher_push_chunk_is_length_prefixed() {
    // push_chunk frames data as u64_be(len)||bytes, so equal-total-bytes
    // streams with different chunk boundaries MUST diverge from each other
    // AND from the raw push.
    let tag = b"VIPER-TEST-TAG";
    let mut a = TaggedHasher::new(tag);
    a.push_chunk(b"abc");
    a.push_chunk(b"def");

    let mut b = TaggedHasher::new(tag);
    b.push_chunk(b"abcdef");

    let mut c = TaggedHasher::new(tag);
    c.push_raw(b"abcdef");

    assert_ne!(a.finish(), b.finish(), "chunk boundaries MUST matter");
    assert_ne!(
        TaggedHasher::new(tag).finish_chunk(b"abcdef"),
        c.finish(),
        "push_chunk must length-prefix; push_raw must not"
    );
}

#[test]
fn tagged_hasher_is_deterministic() {
    let tag = b"VIPER-TEST-TAG";
    let mut a = TaggedHasher::new(tag);
    a.push_chunk(b"one");
    a.push_u64(42);
    let mut b = TaggedHasher::new(tag);
    b.push_chunk(b"one");
    b.push_u64(42);
    assert_eq!(a.finish(), b.finish());
}

// Convenience used by the chunk-vs-raw test above.
impl TaggedHasher {
    fn finish_chunk(mut self, bytes: &[u8]) -> [u8; 32] {
        self.push_chunk(bytes);
        self.finish()
    }
}
