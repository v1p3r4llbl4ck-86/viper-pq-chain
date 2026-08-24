// SPDX-License-Identifier: BUSL-1.1
//! Per-level log-event counters exposed as Prometheus metrics.
//!
//! Hooked into the tracing dispatcher as a `Layer` so every `tracing::error!`,
//! `warn!`, `info!`, `debug!`, `trace!` call increments a global atomic
//! counter. Counters are published by `handle_metrics` as
//! `pqchain_log_events_total{level="error"}` etc., letting an external
//! Prometheus / alertmanager (or the local alert watcher in
//! `scripts/log-alert-watcher.sh`) graph and alert on log volume without
//! parsing journald.
//!
//! Cost is one relaxed atomic increment per event — negligible. No allocation,
//! no formatting; we never look at the event's fields or message.

use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{Level, Subscriber};
use tracing_subscriber::{layer::Context, Layer};

static EVENTS_ERROR: AtomicU64 = AtomicU64::new(0);
static EVENTS_WARN: AtomicU64 = AtomicU64::new(0);
static EVENTS_INFO: AtomicU64 = AtomicU64::new(0);
static EVENTS_DEBUG: AtomicU64 = AtomicU64::new(0);
static EVENTS_TRACE: AtomicU64 = AtomicU64::new(0);

/// Counter snapshot for a single level — used by `handle_metrics`.
pub fn events_total(level: Level) -> u64 {
    let counter = match level {
        Level::ERROR => &EVENTS_ERROR,
        Level::WARN => &EVENTS_WARN,
        Level::INFO => &EVENTS_INFO,
        Level::DEBUG => &EVENTS_DEBUG,
        Level::TRACE => &EVENTS_TRACE,
    };
    counter.load(Ordering::Relaxed)
}

/// `tracing-subscriber` layer that increments the per-level atomic counters.
///
/// Compose with `Registry::default().with(LogMetricsLayer).with(fmt_layer)…`
/// in `main.rs::setup_tracing`. Independent of any `EnvFilter` placed earlier
/// in the stack: events filtered out by the env filter never reach this
/// layer, which matches the intuition "metrics reflect what was actually
/// emitted, not what was theoretically possible".
pub struct LogMetricsLayer;

impl<S: Subscriber> Layer<S> for LogMetricsLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let counter = match *event.metadata().level() {
            Level::ERROR => &EVENTS_ERROR,
            Level::WARN => &EVENTS_WARN,
            Level::INFO => &EVENTS_INFO,
            Level::DEBUG => &EVENTS_DEBUG,
            Level::TRACE => &EVENTS_TRACE,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::Level;

    #[test]
    fn counters_start_at_zero_and_load_independently() {
        // Other tests in this binary may have already emitted events, so we
        // can't assert exact values — only that reads are independent and the
        // accessor returns the same value as the underlying atomic.
        let before_warn = events_total(Level::WARN);
        let before_err = events_total(Level::ERROR);
        EVENTS_WARN.fetch_add(2, Ordering::Relaxed);
        assert_eq!(events_total(Level::WARN), before_warn + 2);
        assert_eq!(events_total(Level::ERROR), before_err);
    }
}
