// SPDX-License-Identifier: BUSL-1.1
//! Tests for `metrics`.
//!
//! Extracted from `metrics.rs` 2026-05-10. `use super::*;`
//! brings every private item from the parent module into scope.

//! TASK-187 — pin tests for the chain-size sampling helpers used by
//! `pqchain_chain_data_bytes` + `pqchain_chain_growth_rate_bytes_per_hour`
//! in `handle_metrics`.
use super::*;
use std::fs;

#[test]
fn chain_data_dir_bytes_sums_files_recursively() {
    // Std-only tempdir: nanosecond-stamped path under env::temp_dir().
    // Cleanup at end is best-effort (lifetime-tied via a guard struct
    // would be nicer, but std-only keeps the dep graph tight).
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("pqcd-task187-{nanos}"));
    fs::create_dir_all(&dir).unwrap();

    // Top-level file, 100 bytes.
    fs::write(dir.join("a.bin"), vec![0u8; 100]).unwrap();
    // Nested file in subdir, 200 bytes.
    let sub = dir.join("sub");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join("b.bin"), vec![0u8; 200]).unwrap();
    // Doubly-nested file, 50 bytes.
    let subsub = sub.join("deeper");
    fs::create_dir(&subsub).unwrap();
    fs::write(subsub.join("c.bin"), vec![0u8; 50]).unwrap();

    let total = chain_data_dir_bytes(&dir);
    let _ = fs::remove_dir_all(&dir);
    assert_eq!(total, 100 + 200 + 50);
}

#[test]
fn chain_data_dir_bytes_returns_zero_on_missing_dir() {
    let path = std::path::Path::new("/definitely/does/not/exist/anywhere");
    assert_eq!(chain_data_dir_bytes(path), 0);
}

#[test]
fn growth_rate_returns_zero_with_one_sample() {
    let mut samples = VecDeque::new();
    let now = Instant::now();
    let rate = update_chain_size_samples_and_compute_rate(&mut samples, now, 1_000);
    assert_eq!(rate, 0.0);
    assert_eq!(samples.len(), 1);
}

#[test]
fn growth_rate_returns_zero_when_window_too_short() {
    let mut samples = VecDeque::new();
    let t0 = Instant::now();
    // Two samples 30 s apart — under the 60 s minimum span.
    update_chain_size_samples_and_compute_rate(&mut samples, t0, 1_000);
    let rate = update_chain_size_samples_and_compute_rate(
        &mut samples,
        t0 + Duration::from_secs(30),
        10_000,
    );
    assert_eq!(rate, 0.0);
}

#[test]
fn growth_rate_extrapolates_to_per_hour() {
    let mut samples = VecDeque::new();
    let t0 = Instant::now();
    // Sample 0: 1 GB at t=0.
    update_chain_size_samples_and_compute_rate(&mut samples, t0, 1_000_000_000);
    // Sample 1: 2 GB at t=30 min → +1 GB over 30 min = +2 GB/hour.
    let rate = update_chain_size_samples_and_compute_rate(
        &mut samples,
        t0 + Duration::from_secs(30 * 60),
        2_000_000_000,
    );
    // Allow 1% tolerance for f64 conversion / saturating_duration_since rounding.
    let expected = 2_000_000_000.0_f64;
    assert!(
        (rate - expected).abs() / expected < 0.01,
        "expected ~{expected} bytes/hour, got {rate}"
    );
}

#[test]
fn growth_rate_can_be_negative_after_prune() {
    let mut samples = VecDeque::new();
    let t0 = Instant::now();
    update_chain_size_samples_and_compute_rate(&mut samples, t0, 5_000_000_000);
    // 1 hour later, RocksDB compaction shrunk the data dir by 2 GB.
    let rate = update_chain_size_samples_and_compute_rate(
        &mut samples,
        t0 + Duration::from_secs(60 * 60),
        3_000_000_000,
    );
    assert!(
        rate < 0.0,
        "shrinking chain must report a negative rate, got {rate}"
    );
    // Magnitude check: -2 GB over 1 hour ≈ -2e9.
    assert!(
        (rate + 2_000_000_000.0).abs() / 2_000_000_000.0 < 0.01,
        "expected ~-2e9 bytes/hour, got {rate}"
    );
}

#[test]
fn samples_older_than_window_are_evicted() {
    let mut samples = VecDeque::new();
    let t0 = Instant::now();
    // Stale sample, 70 minutes ago — outside the 65-minute retention window.
    update_chain_size_samples_and_compute_rate(&mut samples, t0, 1);
    // Newer sample, current. The retention sweep runs on every call —
    // simulating "now is 70 min after t0" requires forging an Instant in
    // the future, which std doesn't support. Instead drive the retention
    // sweep by pushing a sample whose timestamp is t0 + 70 min: the
    // first call did NOT have a "now" arg ahead of its own sample, so the
    // sweep there saw `now == sample.t` (delta 0, kept). On the second
    // call `now` is t0 + 70 min and the older sample at t0 is > 65 min
    // behind, so it is evicted.
    update_chain_size_samples_and_compute_rate(&mut samples, t0 + Duration::from_secs(70 * 60), 2);
    assert_eq!(
        samples.len(),
        1,
        "stale sample must be evicted, only the newest remains"
    );
}
