//! Withdrawal address allowlist: an anti-fraud control restricting outbound payments to a set
//! of pre-approved destinations. Enforcement lives in `submit.rs`; this module is management
//! only (toggle + CRUD on entries).
//!
//! Management requires a dashboard login JWT, not an API key — the whole point of the allowlist
//! is to bound what a compromised API key/session can do, so the credential that can widen the
//! allowlist must be stronger than the one the allowlist is meant to contain.

use crate::auth::require_login;
use crate::error::{ApiError, ApiResult, Envelope};
use crate::json::parse_optional;
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

async fn owned_wallet(
    state: &AppState,
    headers: &HeaderMap,
    wallet_id: Uuid,
) -> Result<octo_store::Wallet, ApiError> {
    let user_id = require_login(headers, state).await?;
    let wallet = state.store().get_wallet(wallet_id).await?;
    if wallet.user_id != Some(user_id) {
        // Don't reveal existence of someone else's wallet.
        return Err(ApiError::NotFound);
    }
    Ok(wallet)
}

#[derive(Debug, Serialize)]
pub struct AllowlistConfigView {
    pub enabled: bool,
}

#[derive(Debug, Default, Deserialize)]
pub struct AllowlistConfigRequest {
    pub enabled: Option<bool>,
}

/// `GET /v1/wallets/:id/whitelist/config`
pub async fn get_config(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<AllowlistConfigView>>> {
    owned_wallet(&state, &headers, wallet_id).await?;
    let enabled = state
        .store()
        .get_withdrawal_allowlist_config(wallet_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .is_some_and(|c| c.enabled);
    Ok(Envelope::ok(AllowlistConfigView { enabled }))
}

/// `PUT /v1/wallets/:id/whitelist/config`; requires at least one field (see `docs/api.md`).
pub async fn put_config(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Envelope<AllowlistConfigView>>> {
    owned_wallet(&state, &headers, wallet_id).await?;
    let req: AllowlistConfigRequest = parse_optional(&body)?;
    if req.enabled.is_none() {
        return Err(ApiError::BadRequest(
            "at least one field must be provided".into(),
        ));
    }
    let enabled = req.enabled.unwrap_or(false);

    // Enabling with an empty list would lock the wallet out of every destination — including
    // ones it might legitimately need. Require at least one entry first, so "enable" always
    // leaves at least one valid destination reachable.
    if enabled {
        let entries = state
            .store()
            .list_whitelisted_addresses(wallet_id)
            .await
            .map_err(|_| ApiError::Internal)?;
        if entries.is_empty() {
            return Err(ApiError::BadRequest(
                "add at least one address before enabling the withdrawal allowlist".into(),
            ));
        }
    }

    state
        .store()
        .upsert_withdrawal_allowlist_config(wallet_id, enabled)
        .await
        .map_err(|_| ApiError::Internal)?;
    Ok(Envelope::ok(AllowlistConfigView { enabled }))
}

#[derive(Debug, Serialize)]
pub struct WhitelistedAddressView {
    pub id: Uuid,
    pub address: String,
    pub label: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<octo_store::WhitelistedAddress> for WhitelistedAddressView {
    fn from(w: octo_store::WhitelistedAddress) -> Self {
        Self {
            id: w.id,
            address: w.address,
            label: w.label,
            created_at: w.created_at,
        }
    }
}

/// `GET /v1/wallets/:id/whitelist`
pub async fn list_addresses(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<Vec<WhitelistedAddressView>>>> {
    owned_wallet(&state, &headers, wallet_id).await?;
    let rows = state
        .store()
        .list_whitelisted_addresses(wallet_id)
        .await
        .map_err(|_| ApiError::Internal)?;
    Ok(Envelope::ok(rows.into_iter().map(Into::into).collect()))
}

#[derive(Debug, Default, Deserialize)]
pub struct AddWhitelistedAddressRequest {
    pub address: Option<String>,
    pub label: Option<String>,
}

/// `POST /v1/wallets/:id/whitelist`
pub async fn add_address(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<Envelope<WhitelistedAddressView>>)> {
    owned_wallet(&state, &headers, wallet_id).await?;
    let req: AddWhitelistedAddressRequest = parse_optional(&body)?;
    let raw_address = req
        .address
        .filter(|a| !a.is_empty())
        .ok_or_else(|| ApiError::BadRequest("address is required".into()))?;

    // Normalize to the base G... account before storing: an entry saved verbatim as an M...
    // address would never match the same account's G... form (or vice versa) at enforcement
    // time, silently defeating the allowlist for that entry.
    let base_address = octo_wallet_core::to_base_account(&raw_address)
        .map_err(|_| ApiError::BadRequest("address must be a valid G... or M... address".into()))?;

    let row = state
        .store()
        .add_whitelisted_address(wallet_id, &base_address, req.label.as_deref())
        .await?;
    let (code, json) = Envelope::created(row.into());
    Ok((code, json))
}

/// `DELETE /v1/wallets/:id/whitelist/:entry_id`
pub async fn remove_address(
    State(state): State<AppState>,
    Path((wallet_id, entry_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<serde_json::Value>>> {
    owned_wallet(&state, &headers, wallet_id).await?;
    state
        .store()
        .remove_whitelisted_address(wallet_id, entry_id)
        .await?;
    Ok(Envelope::ok(serde_json::json!({ "removed": true })))
}
