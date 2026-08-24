// SPDX-License-Identifier: BUSL-1.1
//! Bin-only CLI subcommand modules.
//!
//! Reachable only from main.rs's `mod cli;` — the lib (`lib.rs`) does
//! not declare this directory, so nothing here contributes to the
//! `pqcd` library API.

pub mod ceremony;
pub mod cold_storage;
pub mod keygen;
pub mod peer;
pub mod snapshot;
pub mod validate;
pub mod wallet;
