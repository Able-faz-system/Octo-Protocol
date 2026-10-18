//! Webhook endpoint registration.

use crate::auth::{authorize_wallet, authorize_wallet_scope};
use crate::error::{ApiError, ApiResult, Envelope};
use crate::json::parse_optional;
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

#[derive(Debug, Default, Deserialize)]
pub struct CreateWebhookRequest {
    pub url: Option<String>,
    /// Optional shared secret; one is generated if omitted.
    pub secret: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WebhookView {
    pub id: Uuid,
    pub url: String,
    /// Returned once on creation so the caller can verify signatures.
    pub secret: String,
    pub active: bool,
    pub recent_failure_count: i64,
    pub last_successful_delivery_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// `POST /v1/wallets/:id/webhooks`
pub async fn create_webhook(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<Envelope<WebhookView>>)> {
    authorize_wallet_scope(&headers, &state, wallet_id, "write").await?;
    let req: CreateWebhookRequest = parse_optional(&body)?;
    let url = req
        .url
        .filter(|u| !u.is_empty())
        .ok_or_else(|| ApiError::BadRequest("url is required".into()))?;

    if !octo_webhooks::is_safe_url(&url) {
        return Err(ApiError::BadRequest(
            "url must be a public http(s) endpoint".into(),
        ));
    }

    if let Some(api_host) = state.public_api_host() {
        if targets_host(&url, api_host) {
            return Err(ApiError::BadRequest(
                "url must not point to this API's public host".into(),
            ));
        }
    }

    // Confirm the wallet exists (404 otherwise).
    let _ = state.store().get_wallet(wallet_id).await?;

    // Generate a secret if none supplied.
    let secret = req.secret.unwrap_or_else(generate_secret);

    let ep = state
        .store()
        .create_webhook_endpoint(wallet_id, &url, &secret)
        .await?;

    let view = WebhookView {
        id: ep.id,
        url: ep.url,
        secret: ep.secret,
        active: ep.active,
        recent_failure_count: 0,
        last_successful_delivery_at: None,
    };
    let (status, json) = Envelope::created(view);
    Ok((status, json))
}

// This blocks direct host matches only; an alternate hostname or proxy can still route back here.
fn targets_host(url: &str, expected_host: &str) -> bool {
    Url::parse(url)
        .ok()
        .and_then(|parsed| {
            parsed
                .host_str()
                .map(|host| host.eq_ignore_ascii_case(expected_host))
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::targets_host;

    #[test]
    fn webhook_host_guard_rejects_only_the_configured_host() {
        assert!(targets_host("https://API.octo.dev:8443/hooks", "api.octo.dev"));
        assert!(!targets_host("https://customer.example/hooks", "api.octo.dev"));
    }
}

#[derive(Debug, Deserialize)]
pub struct DeliveriesQuery {
    /// Maximum rows to return (default 50, max 200).
    pub limit: Option<i64>,
}

/// Generate a random hex secret for HMAC signing.
fn generate_secret() -> String {
    // A v4 UUID (122 bits of randomness) rendered without dashes is a fine webhook secret.
    let a = Uuid::new_v4().simple().to_string();
    let b = Uuid::new_v4().simple().to_string();
    format!("{a}{b}")
}

#[derive(Debug, Serialize)]
pub struct WebhookDeliveryView {
    pub id: Uuid,
    pub endpoint_id: Uuid,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub status: String,
    pub attempts: i32,
    pub response_code: Option<i32>,
    /// First ≤ 1 KiB of the endpoint's last response body, for self-service diagnosis.
    pub response_body_snippet: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// `DELETE /v1/wallets/:id/webhooks/:endpoint_id` — soft-delete an endpoint.
///
/// Soft-deletes rather than hard-deletes so the delivery history (an audit trail) survives.
/// Returns 404 if the endpoint belongs to a different wallet, so existence is not leaked.
pub async fn delete_webhook(
    State(state): State<AppState>,
    Path((wallet_id, endpoint_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<serde_json::Value>>> {
    authorize_wallet_scope(&headers, &state, wallet_id, "write").await?;

    let endpoint = state.store().get_webhook_endpoint(endpoint_id).await?;
    if endpoint.wallet_id != wallet_id {
        return Err(ApiError::NotFound);
    }

    state
        .store()
        .delete_webhook(endpoint_id)
        .await?;

    Ok(Envelope::ok(serde_json::json!({
        "id": endpoint_id,
        "active": false,
    })))
}

#[derive(Debug, Default, Deserialize)]
pub struct ListWebhooksQuery {
    pub include_deleted: Option<bool>,
}

/// `GET /v1/wallets/:id/webhooks`
pub async fn list_webhooks(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
    Query(q): Query<ListWebhooksQuery>,
) -> ApiResult<Json<Envelope<Vec<WebhookView>>>> {
    authorize_wallet(&headers, &state, wallet_id).await?;

    // Confirm the wallet exists (404 otherwise).
    let _ = state.store().get_wallet(wallet_id).await?;

    let eps = state.store().active_webhook_endpoints(wallet_id).await?;
    let health_map = state
        .store()
        .wallet_webhook_delivery_health(wallet_id)
        .await
        .map_err(|_| ApiError::Internal)?;
    let views: Vec<WebhookView> = eps
        .into_iter()
        .map(|ep| {
            let health = health_map.get(&ep.id).cloned().unwrap_or_default();
            WebhookView {
                id: ep.id,
                url: ep.url,
                secret: ep.secret,
                active: ep.active,
                recent_failure_count: health.recent_failure_count,
                last_successful_delivery_at: health.last_successful_delivery_at,
            }
        })
        .collect();

    Ok(Envelope::ok(views))
}

/// `GET /v1/wallets/:id/webhooks/:endpoint_id/deliveries` — an endpoint's delivery history,
/// newest first. `?limit=` (default 50, max 200).
pub async fn list_deliveries(
    State(state): State<AppState>,
    Path((wallet_id, endpoint_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Query(q): Query<DeliveriesQuery>,
) -> ApiResult<Json<Envelope<Vec<WebhookDeliveryView>>>> {
    authorize_wallet(&headers, &state, wallet_id).await?;

    let limit = q.limit.unwrap_or(50);
    if !(1..=200).contains(&limit) {
        return Err(ApiError::BadRequest(
            "limit must be between 1 and 200".into(),
        ));
    }

    // Confirm the wallet exists (404 otherwise).
    let _ = state.store().get_wallet(wallet_id).await?;

    // Confirm the endpoint exists and belongs to the wallet — don't leak whether it exists
    // under a different wallet.
    let endpoint = state.store().get_webhook_endpoint(endpoint_id).await?;
    if endpoint.wallet_id != wallet_id {
        return Err(ApiError::NotFound);
    }

    // Honour the validated `?limit=` (previously ignored in favour of a hardcoded 50).
    let deliveries = state
        .store()
        .list_webhook_deliveries(endpoint_id, limit)
        .await?;

    let views: Vec<WebhookDeliveryView> = deliveries
        .into_iter()
        .map(|d| WebhookDeliveryView {
            id: d.id,
            endpoint_id: d.endpoint_id,
            event_type: d.event_type,
            payload: d.payload,
            status: d.status,
            attempts: d.attempts,
            response_code: d.response_code,
            response_body_snippet: d.response_body_snippet,
            created_at: d.created_at,
            updated_at: d.updated_at,
        })
        .collect();

    Ok(Envelope::ok(views))
}
