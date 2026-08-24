// SPDX-License-Identifier: BUSL-1.1
//! HTTP client for RFC 3161 TSA requests.
//!
//! One function: `post_timestamp_request` — POST the DER `TimeStampReq`
//! to a TSA URL, receive the `TimeStampResp` bytes verbatim. No DER
//! parsing; the chain treats the response opaquely (SPEC §6.1).

use std::time::Duration;

use reqwest::{header::CONTENT_TYPE, Client};
use thiserror::Error;

use crate::config::TsaEndpoint;

/// Upper bound on the TSA response body. RFC 3161 replies are small —
/// 2–6 KB in practice; 64 KiB covers every compliant TSA with headroom.
pub const MAX_TST_BYTES: usize = 64 * 1024;

/// TSA client error — opaque to the caller; wrap in `Result<T, TsaError>`.
#[derive(Debug, Error)]
pub enum TsaError {
    /// Network or TLS failure talking to the TSA.
    #[error("TSA request failed: {0}")]
    Transport(#[from] reqwest::Error),

    /// Non-2xx HTTP status from the TSA.
    #[error("TSA returned HTTP {status}")]
    HttpStatus { status: u16 },

    /// Response body exceeded `MAX_TST_BYTES`.
    #[error("TSA response too large: {got} bytes (max {MAX_TST_BYTES})")]
    ResponseTooLarge { got: usize },

    /// Any other protocol-layer oddity.
    #[error("TSA protocol error: {0}")]
    Protocol(String),
}

/// POST an RFC 3161 `TimeStampReq` DER to a configured TSA. Returns the
/// opaque `TimeStampResp` DER bytes.
///
/// `basic_auth` is an optional `(username, password)` pair resolved from
/// the sidecar config's `basic_auth_env`.
pub async fn post_timestamp_request(
    client: &Client,
    endpoint: &TsaEndpoint,
    basic_auth: Option<(String, String)>,
    request_der: &[u8],
) -> Result<Vec<u8>, TsaError> {
    let mut req = client
        .post(&endpoint.url)
        .header(CONTENT_TYPE, "application/timestamp-query")
        .body(request_der.to_vec())
        .timeout(Duration::from_secs(30));
    if let Some((user, pass)) = basic_auth {
        req = req.basic_auth(user, Some(pass));
    }
    let resp = req.send().await?;
    let status = resp.status();
    if !status.is_success() {
        return Err(TsaError::HttpStatus {
            status: status.as_u16(),
        });
    }
    let body = resp.bytes().await?;
    if body.len() > MAX_TST_BYTES {
        return Err(TsaError::ResponseTooLarge { got: body.len() });
    }
    Ok(body.to_vec())
}

#[cfg(test)]
mod tests {
    #[test]
    fn max_tst_bytes_matches_spec_note() {
        // The apply path's `TIMESTAMP_ANCHOR_EXTERNAL_HASH_MAX_LEN` is
        // 16 KiB per SPEC §4.4. The TSA reply envelope is larger than
        // just the TST proper (includes cert chain) — 64 KiB upper bound
        // is operational headroom, not a spec constraint.
        assert_eq!(super::MAX_TST_BYTES, 64 * 1024);
    }
}
