// SPDX-License-Identifier: BUSL-1.1
//! OpenAPI spec + Swagger UI static handlers.
//!
//! Extracted from `devnet.rs` 2026-05-10. Both endpoints are pure
//! `include_str!` static-file serving with a content-type header — no
//! state, no async work, no dependencies beyond axum and the embedded
//! files at compile-time.

use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};

/// Embedded OpenAPI spec (compiled from docs/openapi.yaml).
const OPENAPI_YAML: &str = include_str!("../../../../docs/openapi.yaml");

/// Embedded Swagger UI page (compiled from docs/site/swagger.html).
const SWAGGER_HTML: &str = include_str!("../../../../docs/site/swagger.html");

/// GET /openapi.yaml — serves the OpenAPI 3.0 spec as YAML.
pub(super) async fn handle_openapi_yaml() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/yaml; charset=utf-8")],
        OPENAPI_YAML,
    )
        .into_response()
}

/// GET /docs — serves the Swagger UI page.
pub(super) async fn handle_swagger_ui() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        SWAGGER_HTML,
    )
        .into_response()
}
