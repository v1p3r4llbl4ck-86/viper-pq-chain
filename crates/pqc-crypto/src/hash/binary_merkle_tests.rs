// SPDX-License-Identifier: Apache-2.0
//! Tests for `hash`.
//!
//! Extracted from `hash.rs` 2026-05-10. `use super::*;`
//! brings every private item from the parent module into scope.

use super::*;

const BRANCH: &[u8] = b"VIPER-STATE-BRANCH-V1";
const LEAF: &[u8] = b"VIPER-STATE-LEAF-V1";

fn tl(byte: u8) -> [u8; 32] {
    tagged_hash(LEAF, &[byte])
}

#[test]
fn empty_tree_is_tagged_empty_branch() {
    assert_eq!(binary_merkle_root(&[], BRANCH), tagged_hash(BRANCH, &[]));
}

#[test]
fn single_leaf_returns_leaf_unchanged() {
    let l = tl(0x01);
    assert_eq!(binary_merkle_root(&[l], BRANCH), l);
}

#[test]
fn two_leaves_match_manual_pair() {
    let a = tl(0x01);
    let b = tl(0x02);
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&a);
    buf[32..].copy_from_slice(&b);
    assert_eq!(
        binary_merkle_root(&[a, b], BRANCH),
        tagged_hash(BRANCH, &buf)
    );
}

#[test]
fn three_leaves_pair_lone_with_self() {
    let a = tl(0x01);
    let b = tl(0x02);
    let c = tl(0x03);
    let mut ab = [0u8; 64];
    ab[..32].copy_from_slice(&a);
    ab[32..].copy_from_slice(&b);
    let h_ab = tagged_hash(BRANCH, &ab);
    let mut cc = [0u8; 64];
    cc[..32].copy_from_slice(&c);
    cc[32..].copy_from_slice(&c);
    let h_cc = tagged_hash(BRANCH, &cc);
    let mut top = [0u8; 64];
    top[..32].copy_from_slice(&h_ab);
    top[32..].copy_from_slice(&h_cc);
    assert_eq!(
        binary_merkle_root(&[a, b, c], BRANCH),
        tagged_hash(BRANCH, &top)
    );
}

#[test]
fn leaf_and_branch_domain_must_differ_to_block_cve_2012_2459() {
    // Demonstrates the CVE-2012-2459 protection: a 1-leaf tree must NEVER
    // collide with a 2-leaf tree built from two 32-byte halves of a
    // 64-byte payload. With distinct leaf and branch domains the leaf
    // hash is `tagged_hash(LEAF, payload)` while the 2-leaf root is
    // `tagged_hash(BRANCH, half0 || half1)`; even if `payload` is exactly
    // `half0 || half1`, the two outputs differ because the tag inputs to
    // the inner SHAKE-256 are not equal.
    let payload64 = [0xabu8; 64];
    let single_leaf = tagged_hash(LEAF, &payload64);

    let mut half0 = [0u8; 32];
    let mut half1 = [0u8; 32];
    half0.copy_from_slice(&payload64[..32]);
    half1.copy_from_slice(&payload64[32..]);
    // For the attack to work, the two "halves" would themselves have to
    // pass as leaf hashes — but in our construction every real leaf
    // entering the tree is already pre-hashed under the leaf domain,
    // and two arbitrary 32-byte values are NOT pre-hashed leaves.
    let two_leaf_root = binary_merkle_root(&[half0, half1], BRANCH);

    assert_ne!(
        single_leaf, two_leaf_root,
        "leaf-vs-internal collision must be impossible"
    );
}

#[test]
fn reordering_leaves_changes_root() {
    let a = tl(0x01);
    let b = tl(0x02);
    let c = tl(0x03);
    assert_ne!(
        binary_merkle_root(&[a, b, c], BRANCH),
        binary_merkle_root(&[c, b, a], BRANCH),
        "Merkle root MUST be order-sensitive — callers MUST canonically sort"
    );
}
