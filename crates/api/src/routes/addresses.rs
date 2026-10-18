//! Address endpoints: generate a customer deposit address, list them with pagination.
//!
//! Each address is returned in **both** forms — the muxed `M...` (default) and the
//! `G...` + numeric `memo_id` fallback for senders that don't support muxed (see
//! `docs/deposit-model.md`).

use crate::auth::{authorize_wallet, authorize_wallet_scope};
use crate::error::{ApiResult, Envelope};
use crate::json::parse_optional;
use crate::routes::wallets::ListParams;
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use octo_wallet_core::encode_muxed;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Request body for creating an address.
#[derive(Debug, Default, Deserialize)]
pub struct CreateAddressRequest {
    /// Opaque caller reference for their own user.
    #[serde(default)]
    pub customer_ref: Option<String>,
    /// Arbitrary metadata echoed back in webhooks.
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

/// An address in both deposit forms.
#[derive(Debug, Serialize)]
pub struct AddressView {
    pub id: Uuid,
    pub customer_ref: Option<String>,
    /// Default form handed to customers.
    pub muxed_address: String,
    /// Fallback for `G...`+memo senders (same id as the muxed address).
    pub base_address: String,
    pub memo_id: i64,
    pub metadata: serde_json::Value,
    /// Lifetime total (stroops) of confirmed deposits credited to this address. Historical
    /// bookkeeping, not a live balance — deposits to any address land in the wallet's single
    /// master account (the point of muxed addresses is that there is nothing to sweep), so this
    /// will not match a per-address on-chain balance query.
    pub received_stroops: i64,
}

/// Paginated list response for addresses.
#[derive(Debug, Serialize)]
pub struct AddressListResponse {
    pub data: Vec<AddressView>,
    /// UUID of the last row in this page, or null if there are no more rows.
    pub next_cursor: Option<Uuid>,
}

/// `POST /v1/wallets/{id}/addresses`
pub async fn create_address(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<Envelope<AddressView>>)> {
    // Authorize via login JWT (wallet owner) or API key (key's wallet).
    authorize_wallet_scope(&headers, &state, wallet_id, "write").await?;
    let req: CreateAddressRequest = parse_optional(&body)?;

    // Fetch the wallet to learn its base G... account (the muxed addresses encode it).
    let wallet = state.store().get_wallet(wallet_id).await?;
    if wallet.is_archived() {
        return Err(ApiError::Forbidden("wallet is archived".into()));
    }
    let base = wallet.stellar_account_g.clone();

    let metadata = req.metadata.unwrap_or_else(|| serde_json::json!({}));

    // allocate_address bumps the muxed-id counter atomically and derives the M... via this closure.
    let address = state
        .store()
        .allocate_address(
            wallet_id,
            |id| {
                // muxed_id is a positive i64 from the counter; encode needs u64.
                let id_u64 = u64::try_from(id).map_err(|_| ())?;
                encode_muxed(&base, id_u64).map_err(|_| ())
            },
            req.customer_ref.as_deref(),
            metadata,
        )
        .await?;

    if let Some(uid) = wallet.user_id {
        crate::audit::record(
            &state,
            uid,
            "generated a deposit address",
            crate::audit::category::ADDRESS,
            wallet.label.as_deref(),
            &headers,
        )
        .await;
    }

    // A brand-new address has no deposits yet, so this is always 0 — no query needed.
    let view = AddressView {
        id: address.id,
        customer_ref: address.customer_ref,
        muxed_address: address.muxed_address,
        base_address: wallet.stellar_account_g,
        memo_id: address.muxed_id,
        metadata: address.metadata,
        received_stroops: 0,
    };
    let (status, json) = Envelope::created(view);
    Ok((status, json))
}

/// `GET /v1/wallets/{id}/addresses` — list deposit addresses for a wallet, with optional
/// `?limit=` and `?before=` cursor pagination.
pub async fn list_addresses(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
    Query(q): Query<ListParams>,
) -> ApiResult<Json<Envelope<AddressListResponse>>> {
    authorize_wallet(&headers, &state, wallet_id).await?;
    let wallet = state.store().get_wallet(wallet_id).await?;
    // Every address view echoes the wallet's base (G...) account alongside its muxed form.
    let base = wallet.stellar_account_g.clone();

    let limit = crate::routes::wallets::validated_limit(q.limit)?;

    // Fetch limit+1 to detect whether a next page exists.
    let rows = state
        .store()
        .list_addresses(wallet_id, limit + 1, q.before)
        .await?;

    let has_more = rows.len() > limit as usize;
    let mut items = rows;
    if has_more {
        items.truncate(limit as usize);
    }
    let next_cursor = if has_more {
        items.last().map(|a| a.id)
    } else {
        None
    };

    // One batched query for all rows on this page instead of N — see
    // Store::sum_deposits_for_addresses.
    let ids: Vec<Uuid> = items.iter().map(|a| a.id).collect();
    let totals = state
        .store()
        .sum_deposits_for_addresses(&ids)
        .await
        .map_err(|_| crate::error::ApiError::Internal)?;
    let totals: std::collections::HashMap<Uuid, i64> = totals.into_iter().collect();

    let views = items
        .into_iter()
        .map(|a| AddressView {
            id: a.id,
            customer_ref: a.customer_ref,
            muxed_address: a.muxed_address,
            base_address: base.clone(),
            memo_id: a.muxed_id,
            metadata: a.metadata,
            received_stroops: totals.get(&a.id).copied().unwrap_or(0),
        })
        .collect();

    Ok(Envelope::ok(AddressListResponse {
        data: views,
        next_cursor,
    }))
}
