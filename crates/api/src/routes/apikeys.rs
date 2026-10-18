//! Per-wallet API keys for developer integration.
//!
//! A key is `octo_sk_<network>_<random>`. Only its SHA-256 hash and a short display prefix are
//! stored — the full key is returned **once**, on generation/regeneration. Ownership is enforced:
//! the authenticated user must own the wallet.

use crate::auth::authenticate;
use crate::error::{ApiError, ApiResult, Envelope};
use crate::json::parse_optional;
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Optional body for `generate_key`. An empty body is valid for first-time generation.
#[derive(Debug, Default, Deserialize)]
pub struct GenerateKeyRequest {
    /// Must be `true` to rotate an existing key (which immediately invalidates the old one).
    #[serde(default)]
    pub confirm: Option<bool>,
    pub scopes: Option<Vec<String>>,
    pub expires_in_days: Option<u32>,
}

/// Returned once when a key is generated — includes the full secret.
#[derive(Debug, Serialize)]
pub struct GeneratedKey {
    pub wallet_id: Uuid,
    /// The full API key. Shown once; store it securely.
    pub api_key: String,
    pub prefix: String,
}

/// Returned on GET — metadata only, never the secret.
#[derive(Debug, Serialize)]
pub struct ApiKeyInfo {
    pub wallet_id: Uuid,
    pub configured: bool,
    /// Non-secret display prefix, e.g. "octo_sk_test_ab12".
    pub prefix: Option<String>,
    pub scopes: Vec<String>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Confirm the authenticated user owns the wallet; returns the wallet network.
async fn owned_wallet(
    state: &AppState,
    headers: &HeaderMap,
    wallet_id: Uuid,
) -> Result<octo_store::Wallet, ApiError> {
    let user_id = authenticate(headers, state).await?;
    let wallet = state.store().get_wallet(wallet_id).await?;
    if wallet.user_id != Some(user_id) {
        // Don't reveal existence of someone else's wallet.
        return Err(ApiError::NotFound);
    }
    Ok(wallet)
}

fn hash_key(key: &str) -> String {
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    hex::encode(h.finalize())
}

fn checksum(value: &str) -> String {
    hash_key(value)[..8].to_string()
}

/// `POST /v1/wallets/:id/api-key` — generate the wallet's API key, or rotate it with
/// `{"confirm": true}`. Without confirmation an existing key is never replaced (409), so a
/// double-click or retried request can't silently break every integration using the old key.
pub async fn generate_key(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<Envelope<GeneratedKey>>)> {
    let wallet = owned_wallet(&state, &headers, id).await?;
    let req: GenerateKeyRequest = parse_optional(&body)?;
    let rotate = req.confirm == Some(true);
    let scopes = req
        .scopes
        .unwrap_or_else(|| vec!["read".into(), "write".into(), "sponsor".into()]);
    if scopes.is_empty()
        || scopes
            .iter()
            .any(|scope| !matches!(scope.as_str(), "read" | "write" | "sponsor"))
    {
        return Err(ApiError::BadRequest("invalid API key scopes".into()));
    }
    let expires_at = req.expires_in_days.map(|days| {
        chrono::Utc::now() + chrono::Duration::days(i64::from(days.clamp(1, 365)))
    });

    // octo_sk_<network>_<32 hex chars>
    let mut raw = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let net = if wallet.network == "mainnet" {
        "live"
    } else {
        "test"
    };
    let key_body = format!("octo_sk_{net}_{}", hex::encode(raw));
    let api_key = format!("{key_body}_{}", checksum(&key_body));
    // Display prefix: scheme + first 4 random chars.
    let prefix = format!("octo_sk_{net}_{}", &hex::encode(raw)[..4]);

    // Insert-only unless rotation is confirmed: atomic on wallet_id, so no check-then-write race.
    let (store, key_hash) = (state.store(), hash_key(&api_key));
    let stored = if rotate {
        store
            .upsert_api_key(id, &prefix, &key_hash, &scopes, expires_at)
            .await
    } else {
        store
            .create_api_key(id, &prefix, &key_hash, &scopes, expires_at)
            .await
    };
    match stored {
        Ok(_) => {}
        Err(octo_store::StoreError::Conflict) => {
            return Err(ApiError::ConflictWith(
                "an API key already exists; pass confirm=true to rotate it".into(),
            ))
        }
        Err(_) => return Err(ApiError::Internal),
    }

    if let Some(uid) = wallet.user_id {
        crate::audit::record(
            &state,
            uid,
            if rotate {
                "rotated an API key"
            } else {
                "generated an API key"
            },
            crate::audit::category::CREDENTIALS,
            wallet.label.as_deref(),
            &headers,
        )
        .await;
    }

    let (code, json) = Envelope::created(GeneratedKey {
        wallet_id: id,
        api_key,
        prefix,
    });
    Ok((code, json))
}

/// `DELETE /v1/wallets/:id/api-key` — revoke the wallet's API key without regenerating.
///
/// Dashboard JWT only (not an API key). A no-op if no key exists.
pub async fn delete_key(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<&'static str>>> {
    let wallet = owned_wallet(&state, &headers, id).await?;

    state
        .store()
        .delete_api_key(id)
        .await
        .map_err(|_| ApiError::Internal)?;

    if let Some(uid) = wallet.user_id {
        crate::audit::record(
            &state,
            uid,
            "revoked API key",
            crate::audit::category::CREDENTIALS,
            wallet.label.as_deref(),
            &headers,
        )
        .await;
    }

    Ok(Envelope::ok("api key revoked"))
}

/// `GET /v1/wallets/:id/api-key` — key metadata (prefix + whether configured). Never the secret.
pub async fn get_key(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<ApiKeyInfo>>> {
    owned_wallet(&state, &headers, id).await?;
    let key = state
        .store()
        .get_api_key(id)
        .await
        .map_err(|_| ApiError::Internal)?;
    Ok(Envelope::ok(ApiKeyInfo {
        wallet_id: id,
        configured: key.is_some(),
        prefix: key.as_ref().map(|key| key.prefix.clone()),
        scopes: key.as_ref().map(|key| key.scopes.clone()).unwrap_or_default(),
        last_used_at: key.as_ref().and_then(|key| key.last_used_at.clone()),
        expires_at: key.and_then(|key| key.expires_at),
    }))
}
