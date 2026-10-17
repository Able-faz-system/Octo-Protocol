//! Gas sponsorship configuration: enable/disable sponsorship and set spend controls.

use crate::auth::{authorize_wallet, authorize_wallet_scope};
use crate::error::{ApiError, ApiResult, Envelope};
use crate::json::parse_optional;
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Default, Deserialize)]
pub struct SponsorshipConfigRequest {
    pub enabled: Option<bool>,
    pub per_tx_fee_cap_stroops: Option<i64>,
    pub daily_budget_stroops: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct SponsorshipConfigView {
    pub enabled: bool,
    pub per_tx_fee_cap_stroops: Option<i64>,
    pub daily_budget_stroops: Option<i64>,
    pub fees_spent_today_stroops: i64,
    pub spent_today_stroops: i64,
}

/// `GET /v1/wallets/:id/sponsorship`
pub async fn get_config(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<SponsorshipConfigView>>> {
    authorize_wallet(&headers, &state, wallet_id).await?;

    let config = state.store().get_gas_sponsorship_config(wallet_id).await?;
    let spent_today = state
        .store()
        .sum_sponsored_fees_today(wallet_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let view = match config {
        Some(c) => SponsorshipConfigView {
            enabled: c.enabled,
            per_tx_fee_cap_stroops: c.per_tx_fee_cap_stroops,
            daily_budget_stroops: c.daily_budget_stroops,
            fees_spent_today_stroops: spent_today,
            spent_today_stroops: spent_today,
        },
        None => SponsorshipConfigView {
            enabled: false,
            per_tx_fee_cap_stroops: None,
            daily_budget_stroops: None,
            fees_spent_today_stroops: spent_today,
            spent_today_stroops: spent_today,
        },
    };

    Ok(Envelope::ok(view))
}

/// `PUT /v1/wallets/:id/sponsorship`; requires at least one field (see `docs/api.md`).
pub async fn put_config(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Envelope<SponsorshipConfigView>>> {
    authorize_wallet_scope(&headers, &state, wallet_id, "sponsor").await?;
    let wallet = state.store().get_wallet(wallet_id).await?;
    if wallet.is_archived() {
        return Err(ApiError::Forbidden("wallet is archived".into()));
    }
    let req: SponsorshipConfigRequest = parse_optional(&body)?;
    if req.enabled.is_none()
        && req.per_tx_fee_cap_stroops.is_none()
        && req.daily_budget_stroops.is_none()
    {
        return Err(ApiError::BadRequest(
            "at least one field must be provided".into(),
        ));
    }

    let enabled = req.enabled.unwrap_or(false);
    if let Some(cap) = req.per_tx_fee_cap_stroops {
        if cap < 0 {
            return Err(ApiError::BadRequest(
                "per_tx_fee_cap_stroops must be >= 0".into(),
            ));
        }
    }
    if let Some(budget) = req.daily_budget_stroops {
        if budget < 0 {
            return Err(ApiError::BadRequest(
                "daily_budget_stroops must be >= 0".into(),
            ));
        }
    }
    // A per-tx cap above the daily budget can never be fully used; reject the contradiction.
    if let (Some(cap), Some(budget)) = (req.per_tx_fee_cap_stroops, req.daily_budget_stroops) {
        if cap > budget {
            return Err(ApiError::BadRequest(format!(
                "per_tx_fee_cap_stroops ({cap}) must not exceed daily_budget_stroops ({budget}); \
                 lower the per-transaction cap or raise the daily budget"
            )));
        }
    }

    let config = state
        .store()
        .upsert_gas_sponsorship_config(
            wallet_id,
            enabled,
            req.per_tx_fee_cap_stroops,
            req.daily_budget_stroops,
        )
        .await?;

    let spent_today = state
        .store()
        .sum_sponsored_fees_today(wallet_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let wallet = state.store().get_wallet(wallet_id).await?;
    if let Some(uid) = wallet.user_id {
        crate::audit::record(
            &state,
            uid,
            &format!("updated sponsorship config (enabled: {enabled})"),
            crate::audit::category::SPONSORSHIP,
            Some(&wallet_id.to_string()),
            &headers,
        )
        .await;
    }

    Ok(Envelope::ok(SponsorshipConfigView {
        enabled: config.enabled,
        per_tx_fee_cap_stroops: config.per_tx_fee_cap_stroops,
        daily_budget_stroops: config.daily_budget_stroops,
        fees_spent_today_stroops: spent_today,
        spent_today_stroops: spent_today,
    }))
}
