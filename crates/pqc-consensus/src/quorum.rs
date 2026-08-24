// SPDX-License-Identifier: BUSL-1.1
//! Quorum size computation — SPEC-VAL-001 §5.
//!
//! Quorum = ⌊2n/3⌋ + 1 (BFT 2/3+1 threshold).

/// Returns the quorum size required for a validator set of size `n`.
///
/// | n  | quorum | ML-DSA-65 commit | FN-DSA commit |
/// |----|--------|------------------|---------------|
/// | 24 | 17     | ~56 KB           | ~11 KB        |
/// | 32 | 22     | ~73 KB           | ~15 KB        |
/// | 50 | 34     | ~113 KB          | ~23 KB        |
pub fn quorum_size(n: usize) -> usize {
    (2 * n) / 3 + 1
}

#[cfg(test)]
mod tests;
