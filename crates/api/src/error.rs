//! API error type and the standard JSON response envelope.
//!
//! Every response (success or error) is `{ statusCode, message, data }`. Errors never leak
//! internal detail (DB messages, key material, stack traces) — they map to coarse, safe messages.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use serde_json::json;

/// The uniform API result type.
pub type ApiResult<T> = Result<T, ApiError>;

/// Errors that map to HTTP responses.
#[derive(Debug)]
pub enum ApiError {
    /// 400 — the request was malformed (bad address, bad network, etc.).
    BadRequest(String),
    /// 401 — missing or invalid authentication.
    Unauthorized,
    /// 403 — the request is valid but the server refuses to act on it (e.g. sponsorship disabled).
    Forbidden(String),
    /// 404 — resource not found.
    NotFound,
    /// 409 — conflict (e.g. duplicate idempotency key / already exists).
    Conflict,
    /// 409 — a conflict with a specific, actionable message for the client.
    ConflictWith(String),
    /// 410 — the endpoint was removed (custodial signing paths, post non-custodial cutover).
    Gone(String),
    /// 429 — a rate limit or budget would be exceeded.
    TooManyRequests(String),
    /// 400 — inner transaction sequence number does not match current on-chain sequence.
    StaleSequence(String),
    /// 500 — an internal error. The detail is logged, never returned to the client.
    Internal,
    /// 504 — an upstream dependency (e.g. Horizon) did not answer within the route's time budget.
    GatewayTimeout(String),
}

impl ApiError {
    fn parts(&self) -> (StatusCode, String) {
        match self {
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".into()),
            ApiError::Forbidden(m) => (StatusCode::FORBIDDEN, m.clone()),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not found".into()),
            ApiError::Conflict => (StatusCode::CONFLICT, "already exists".into()),
            ApiError::ConflictWith(m) => (StatusCode::CONFLICT, m.clone()),
            ApiError::Gone(m) => (StatusCode::GONE, m.clone()),
            ApiError::TooManyRequests(m) => (StatusCode::TOO_MANY_REQUESTS, m.clone()),
            ApiError::StaleSequence(m) => (StatusCode::BAD_REQUEST, m.clone()),
            ApiError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal server error".into(),
            ),
            ApiError::GatewayTimeout(m) => (StatusCode::GATEWAY_TIMEOUT, m.clone()),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = self.parts();
        let body = Json(json!({
            "statusCode": status.as_u16(),
            "message": message,
            "data": serde_json::Value::Null,
        }));
        (status, body).into_response()
    }
}

/// Map store errors to API errors without leaking DB internals.
impl From<octo_store::StoreError> for ApiError {
    fn from(e: octo_store::StoreError) -> Self {
        match e {
            octo_store::StoreError::Conflict => ApiError::Conflict,
            octo_store::StoreError::NotFound => ApiError::NotFound,
            octo_store::StoreError::WalletArchived => {
                ApiError::Forbidden("wallet is archived".into())
            }
            octo_store::StoreError::InvalidMemoId => {
                ApiError::BadRequest("memo id must be nonnegative".into())
            }
            octo_store::StoreError::BudgetExceeded => {
                ApiError::TooManyRequests("daily sponsorship budget exceeded".into())
            }
            // Database/migration errors are logged by the caller; never echoed.
            _ => ApiError::Internal,
        }
    }
}

/// Map wallet-core errors. Bad inputs become 400; secret/crypto failures become 500 (opaque).
impl From<octo_wallet_core::WalletError> for ApiError {
    fn from(e: octo_wallet_core::WalletError) -> Self {
        use octo_wallet_core::WalletError as W;
        match e {
            W::InvalidMnemonic
            | W::InvalidChecksum
            | W::InvalidAddress
            | W::InvalidAssetCode
            | W::InvalidAmount
            | W::InvalidDerivationPath
            | W::InvalidXdr
            | W::InvalidSignature => ApiError::BadRequest("invalid input".into()),
            W::ReservedNativeAssetCode => ApiError::BadRequest(
                "native asset codes cannot be used as credit asset codes".into(),
            ),
            W::StaleSequence => ApiError::StaleSequence(
                "Stale sequence number — refresh signing info and rebuild the transaction.".into(),
            ),
            ),
            W::KeyDerivation | W::Signing | W::SeedDecryption => ApiError::Internal,
        }
    }
}

/// Wrap any serializable value in the standard success envelope with a status code.
#[derive(Serialize)]
pub struct Envelope<T: Serialize> {
    #[serde(rename = "statusCode")]
    pub status_code: u16,
    pub message: String,
    pub data: T,
}

impl<T: Serialize> Envelope<T> {
    pub fn ok(data: T) -> Json<Envelope<T>> {
        Json(Envelope {
            status_code: 200,
            message: "OK".into(),
            data,
        })
    }

    pub fn created(data: T) -> (StatusCode, Json<Envelope<T>>) {
        (
            StatusCode::CREATED,
            Json(Envelope {
                status_code: 201,
                message: "Created".into(),
                data,
            }),
        )
    }
}

impl Envelope<Option<()>> {
    /// Build an error envelope so failures raised in middleware (e.g. an oversized body
    /// rejected before any handler runs) use the same `{statusCode, message, data}` shape as
    /// every other response.
    pub fn error(
        status: StatusCode,
        message: String,
        data: Option<()>,
    ) -> (StatusCode, Json<Envelope<Option<()>>>) {
        (
            status,
            Json(Envelope {
                status_code: status.as_u16(),
                message,
                data,
            }),
        )
    }
}
