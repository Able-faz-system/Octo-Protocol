//! Non-custodial trustline endpoint: returns what a client needs to build and sign a ChangeTrust.
//!
//! The server never signs for a user wallet. The client builds the ChangeTrust locally with the
//! data returned here, signs it with its own key, and relays it via
//! `POST /v1/wallets/:id/submit-signed` (whose op allowlist already admits change-trust).

use crate::auth::authorize_wallet_scope;
use crate::error::{ApiError, ApiResult, Envelope};
use crate::json::parse_optional;
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use octo_wallet_core::{validate_change_trust, WalletError};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Stellar's minimum base fee per operation, in stroops (matches `signing_info`).
const BASE_FEE_STROOPS: i64 = 100;

#[derive(Debug, Default, Deserialize)]
pub struct TrustlineRequest {
    /// Asset code to trust (1–12 bytes, e.g. `"USDC"`).
    pub asset_code: Option<String>,
    /// Issuer of the asset (`G...`).
    pub asset_issuer: Option<String>,
    /// Trust limit in stroops. Omitted => unlimited; `0` removes the trustline.
    pub limit_stroops: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct TrustlineSigningInfo {
    /// The wallet's account — the ChangeTrust source.
    pub account: String,
    /// Current sequence, as a string (see `SigningInfo::sequence` for why).
    #[serde(with = "crate::json::i64_as_string")]
    pub sequence: i64,
    pub network_passphrase: String,
    pub base_fee_stroops: i64,
    pub asset_code: String,
    pub asset_issuer: String,
    /// Limit to put on the operation, as a string (`i64::MAX` = unlimited exceeds JS safe ints).
    #[serde(with = "crate::json::i64_as_string")]
    pub limit_stroops: i64,
    /// Where to send the signed envelope.
    pub submit_url: String,
}

/// `POST /v1/wallets/:id/trustlines` — validate a ChangeTrust request and return signing info.
pub async fn add_trustline(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Envelope<TrustlineSigningInfo>>> {
    authorize_wallet_scope(&headers, &state, wallet_id, "write").await?;
    let req: TrustlineRequest = parse_optional(&body)?;
    let asset_code = req
        .asset_code
        .ok_or_else(|| ApiError::BadRequest("asset_code is required".into()))?;
    let asset_issuer = req
        .asset_issuer
        .ok_or_else(|| ApiError::BadRequest("asset_issuer is required".into()))?;

    // Same validator the ChangeTrust signer uses, so both paths agree on what's acceptable.
    validate_change_trust(&asset_code, &asset_issuer, req.limit_stroops).map_err(|e| {
        ApiError::BadRequest(
            match e {
                WalletError::InvalidAssetCode => "asset_code must be 1-12 bytes",
                WalletError::InvalidAddress => "asset_issuer must be a valid G... account",
                _ => "limit_stroops must be >= 0",
            }
            .into(),
        )
    })?;

    let wallet = state.store().get_wallet(wallet_id).await?;
    // A trustline to one's own asset is malformed on-chain; fail fast instead of burning a fee.
    if asset_issuer == wallet.stellar_account_g {
        return Err(ApiError::BadRequest(
            "a wallet cannot add a trustline to an asset it issues".into(),
        ));
    }

    let sequence = state
        .horizon()
        .account_sequence(&wallet.stellar_account_g)
        .await
        .map_err(|e| match e {
            ApiError::NotFound => ApiError::BadRequest(
                "This wallet is not funded on-chain yet. Fund it with XLM (testnet friendbot) first."
                    .into(),
            ),
            other => other,
        })?;

    Ok(Envelope::ok(TrustlineSigningInfo {
        account: wallet.stellar_account_g,
        sequence,
        network_passphrase: state.network().passphrase().to_string(),
        base_fee_stroops: BASE_FEE_STROOPS,
        asset_code,
        asset_issuer,
        // Stellar treats a missing limit as 0 (= remove), so "unlimited" must be explicit.
        limit_stroops: req.limit_stroops.unwrap_or(i64::MAX),
        submit_url: format!("/v1/wallets/{wallet_id}/submit-signed"),
    }))
}
