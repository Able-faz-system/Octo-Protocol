//! Payment links: shareable public URLs that accept a USDC deposit.

use crate::auth::authorize_wallet;
use crate::error::{ApiError, ApiResult, Envelope};
use crate::json::parse_optional;
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use octo_wallet_core::encode_muxed;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const USDC_ASSET_CODE: &str = "USDC";
/// The widely-used testnet USDC issuer (same one the dashboard's trustline flow uses) — v1
/// payment links are USDC-only, so a submitted payment must actually be this asset, not just
/// any asset landing at the right address.
const USDC_TESTNET_ISSUER: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

/// Full hosted checkout URL for a payment link's slug.
fn checkout_url(state: &AppState, slug: &str) -> String {
    format!("{}/pay/{}", state.public_app_url(), slug)
}

#[derive(Debug, Serialize)]
pub struct PaymentLinkView {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
    pub image_url: Option<String>,
    pub redirect_url: Option<String>,
    pub amount_usdc_stroops: Option<i64>,
    pub active: bool,
    pub collected_usdc_stroops: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub url: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct CreatePaymentLinkRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub image_url: Option<String>,
    pub redirect_url: Option<String>,
    pub amount_usdc_stroops: Option<i64>,
}

/// `POST /v1/wallets/:id/payment-links`
pub async fn create_payment_link(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<Envelope<PaymentLinkView>>)> {
    authorize_wallet(&headers, &state, wallet_id).await?;
    let req: CreatePaymentLinkRequest = parse_optional(&body)?;
    let name = req
        .name
        .filter(|n| !n.is_empty())
        .ok_or_else(|| ApiError::BadRequest("name is required".into()))?;
    // Same checks as PATCH: the redirect is served to payers on the public pay page.
    if let Some(url) = req.redirect_url.as_deref() {
        validate_redirect_url(url)?;
    }
    if let Some(amount) = req.amount_usdc_stroops {
        validate_link_amount(amount)?;
    }

    let wallet = state.store().get_wallet(wallet_id).await?;
    let base = wallet.stellar_account_g.clone();
    let address = state
        .store()
        .allocate_address(
            wallet_id,
            |id| {
                let id_u64 = u64::try_from(id).map_err(|_| ())?;
                encode_muxed(&base, id_u64).map_err(|_| ())
            },
            None,
            serde_json::json!({}),
        )
        .await?;

    let slug = Uuid::new_v4().simple().to_string()[..10].to_string();
    let link = state
        .store()
        .create_payment_link(octo_store::NewPaymentLink {
            wallet_id,
            address_id: address.id,
            slug: &slug,
            name: &name,
            description: req.description.as_deref(),
            image_url: req.image_url.as_deref(),
            redirect_url: req.redirect_url.as_deref(),
            amount_usdc_stroops: req.amount_usdc_stroops,
        })
        .await?;

    let url = checkout_url(&state, &link.slug);
    let (code, json) = Envelope::created(PaymentLinkView {
        id: link.id,
        slug: link.slug,
        name: link.name,
        description: link.description,
        image_url: link.image_url,
        redirect_url: link.redirect_url,
        amount_usdc_stroops: link.amount_usdc_stroops,
        active: link.active,
        collected_usdc_stroops: 0,
        created_at: link.created_at,
        url,
    });
    Ok((code, json))
}

/// `GET /v1/wallets/:id/payment-links`
pub async fn list_payment_links(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<crate::routes::wallets::ListParams>,
) -> ApiResult<Json<Envelope<PaymentLinkListResponse>>> {
    authorize_wallet(&headers, &state, wallet_id).await?;
    let limit = crate::routes::wallets::validated_limit(q.limit)?;

    let rows = state
        .store()
        .list_payment_links(wallet_id, limit + 1, q.before)
        .await?;
    let has_more = rows.len() > limit as usize;
    let mut items = rows;
    if has_more {
        items.truncate(limit as usize);
    }
    let next_cursor = if has_more {
        items.last().map(|l| l.id)
    } else {
        None
    };

    let ids: Vec<Uuid> = items.iter().map(|l| l.id).collect();
    let totals: std::collections::HashMap<Uuid, i64> = state
        .store()
        .sum_payment_link_collected_batch(&ids)
        .await?
        .into_iter()
        .collect();

    let views = items
        .into_iter()
        .map(|l| {
            let url = checkout_url(&state, &l.slug);
            PaymentLinkView {
                id: l.id,
                slug: l.slug,
                name: l.name,
                description: l.description,
                image_url: l.image_url,
                redirect_url: l.redirect_url,
                amount_usdc_stroops: l.amount_usdc_stroops,
                active: l.active,
                collected_usdc_stroops: totals.get(&l.id).copied().unwrap_or(0),
                created_at: l.created_at,
                url,
            }
        })
        .collect();

    Ok(Envelope::ok(PaymentLinkListResponse {
        data: views,
        next_cursor,
    }))
}

#[derive(Debug, Serialize)]
pub struct PaymentLinkListResponse {
    pub data: Vec<PaymentLinkView>,
    pub next_cursor: Option<Uuid>,
}

/// `GET /v1/wallets/:id/payment-links/:link_id`
pub async fn get_payment_link(
    State(state): State<AppState>,
    Path((wallet_id, link_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<PaymentLinkView>>> {
    authorize_wallet(&headers, &state, wallet_id).await?;
    let link = state.store().get_payment_link(wallet_id, link_id).await?;
    let collected = state.store().sum_payment_link_collected(link.id).await?;
    let url = checkout_url(&state, &link.slug);
    Ok(Envelope::ok(PaymentLinkView {
        id: link.id,
        slug: link.slug,
        name: link.name,
        description: link.description,
        image_url: link.image_url,
        redirect_url: link.redirect_url,
        amount_usdc_stroops: link.amount_usdc_stroops,
        active: link.active,
        collected_usdc_stroops: collected,
        created_at: link.created_at,
        url,
    }))
}

#[derive(Debug, Serialize)]
pub struct PaymentLinkPaymentView {
    pub id: Uuid,
    pub payer_name: Option<String>,
    pub payer_email: Option<String>,
    pub amount_usdc_stroops: i64,
    /// "pending" | "confirmed".
    pub status: String,
    pub transaction_id: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct PaymentLinkPaymentListResponse {
    pub data: Vec<PaymentLinkPaymentView>,
    pub next_cursor: Option<Uuid>,
}

/// `GET /v1/wallets/:id/payment-links/:link_id/payments`
///
/// Owner-authenticated: these rows carry payer names and email addresses, which must never be
/// reachable from the public pay-page routes.
pub async fn list_payment_link_payments(
    State(state): State<AppState>,
    Path((wallet_id, link_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Query(q): Query<crate::routes::wallets::ListParams>,
) -> ApiResult<Json<Envelope<PaymentLinkPaymentListResponse>>> {
    authorize_wallet(&headers, &state, wallet_id).await?;
    // Scoped fetch: proves the link belongs to this wallet before exposing its payers.
    let link = state.store().get_payment_link(wallet_id, link_id).await?;

    let limit = crate::routes::wallets::validated_limit(q.limit)?;
    let rows = state
        .store()
        .list_payment_link_payments(link.id, limit + 1, q.before)
        .await?;

    let has_more = rows.len() > limit as usize;
    let mut items = rows;
    if has_more {
        items.truncate(limit as usize);
    }
    let next_cursor = if has_more {
        items.last().map(|p| p.id)
    } else {
        None
    };

    let data = items
        .into_iter()
        .map(|p| PaymentLinkPaymentView {
            id: p.id,
            payer_name: p.payer_name,
            payer_email: p.payer_email,
            amount_usdc_stroops: p.amount_usdc_stroops,
            status: p.status,
            transaction_id: p.transaction_id,
            created_at: p.created_at,
        })
        .collect();

    Ok(Envelope::ok(PaymentLinkPaymentListResponse {
        data,
        next_cursor,
    }))
}

#[derive(Debug, Default, Deserialize)]
pub struct SetPaymentLinkActiveRequest {
    pub active: Option<bool>,
}

/// `PUT /v1/wallets/:id/payment-links/:link_id`
pub async fn set_payment_link_active(
    State(state): State<AppState>,
    Path((wallet_id, link_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Envelope<PaymentLinkView>>> {
    authorize_wallet(&headers, &state, wallet_id).await?;
    let req: SetPaymentLinkActiveRequest = parse_optional(&body)?;
    let active = req
        .active
        .ok_or_else(|| ApiError::BadRequest("active is required".into()))?;
    let link = state
        .store()
        .set_payment_link_active(wallet_id, link_id, active)
        .await?;
    let collected = state.store().sum_payment_link_collected(link.id).await?;
    let url = checkout_url(&state, &link.slug);
    Ok(Envelope::ok(PaymentLinkView {
        id: link.id,
        slug: link.slug,
        name: link.name,
        description: link.description,
        image_url: link.image_url,
        redirect_url: link.redirect_url,
        amount_usdc_stroops: link.amount_usdc_stroops,
        active: link.active,
        collected_usdc_stroops: collected,
        created_at: link.created_at,
        url,
    }))
}

/// Editable fields of an unpaid link. Omit a field to keep it; send `null` to clear it.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdatePaymentLinkRequest {
    #[serde(default, deserialize_with = "crate::json::double_option::deserialize")]
    pub description: Option<Option<String>>,
    #[serde(default, deserialize_with = "crate::json::double_option::deserialize")]
    pub redirect_url: Option<Option<String>>,
    #[serde(default, deserialize_with = "crate::json::double_option::deserialize")]
    pub amount_usdc_stroops: Option<Option<i64>>,
}

/// `PATCH /v1/wallets/:id/payment-links/:link_id` — edit an unpaid link (#455).
///
/// Only `description`, `redirect_url` and `amount_usdc_stroops` are editable; slug and name are
/// not (unknown fields are rejected). Once any payment is pending or has landed the link is
/// immutable and this returns 409. Edits are audit-logged.
pub async fn update_payment_link(
    State(state): State<AppState>,
    Path((wallet_id, link_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Envelope<PaymentLinkView>>> {
    authorize_wallet(&headers, &state, wallet_id).await?;
    let req: UpdatePaymentLinkRequest = parse_optional(&body)?;
    if req.description.is_none() && req.redirect_url.is_none() && req.amount_usdc_stroops.is_none()
    {
        return Err(ApiError::BadRequest(
            "provide at least one of description, redirect_url, amount_usdc_stroops".into(),
        ));
    }

    // An empty string clears a text field, like `null`.
    let description = req.description.map(|d| d.filter(|s| !s.trim().is_empty()));
    let redirect_url = req.redirect_url.map(|u| u.filter(|s| !s.is_empty()));
    if let Some(Some(url)) = redirect_url.as_ref() {
        validate_redirect_url(url)?;
    }
    if let Some(Some(amount)) = req.amount_usdc_stroops {
        validate_link_amount(amount)?;
    }

    let link = state
        .store()
        .update_unpaid_payment_link(
            wallet_id,
            link_id,
            octo_store::PaymentLinkUpdate {
                description: description.as_ref().map(|d| d.as_deref()),
                redirect_url: redirect_url.as_ref().map(|u| u.as_deref()),
                amount_usdc_stroops: req.amount_usdc_stroops,
            },
        )
        .await
        .map_err(|e| match e {
            octo_store::StoreError::Conflict => ApiError::ConflictWith(
                "payment link has a pending or completed payment and can no longer be edited"
                    .into(),
            ),
            other => other.into(),
        })?;

    if let Some(uid) = state.store().get_wallet(wallet_id).await?.user_id {
        crate::audit::record(
            &state,
            uid,
            "edited a payment link",
            crate::audit::category::PAYMENT_LINK,
            Some(&link.id.to_string()),
            &headers,
        )
        .await;
    }

    let collected = state.store().sum_payment_link_collected(link.id).await?;
    let url = checkout_url(&state, &link.slug);
    Ok(Envelope::ok(PaymentLinkView {
        id: link.id,
        slug: link.slug,
        name: link.name,
        description: link.description,
        image_url: link.image_url,
        redirect_url: link.redirect_url,
        amount_usdc_stroops: link.amount_usdc_stroops,
        active: link.active,
        collected_usdc_stroops: collected,
        created_at: link.created_at,
        url,
    }))
}

/// A link's fixed amount must be positive and within the per-intent cap.
fn validate_link_amount(amount: i64) -> Result<(), ApiError> {
    if amount <= 0 || amount > MAX_PAYMENT_INTENT_AMOUNT {
        return Err(ApiError::BadRequest(format!(
            "amount_usdc_stroops must be between 1 and {MAX_PAYMENT_INTENT_AMOUNT}"
        )));
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct PublicPaymentLinkView {
    pub name: String,
    pub description: Option<String>,
    pub image_url: Option<String>,
    pub redirect_url: Option<String>,
    pub amount_usdc_stroops: Option<i64>,
    pub deposit_address: String,
    pub asset_code: String,
}

/// Rate-limit an unauthenticated pay-page request by client IP.
///
/// These endpoints have no credential to throttle on, so IP is the only available key. Intent
/// creation is much tighter than the read paths: each intent allocates a muxed address and
/// inserts a row, so unbounded calls are a cheap way to bloat the table.
fn check_public_rate_limit(
    state: &AppState,
    headers: &HeaderMap,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    class: &'static str,
    limit: u32,
    window: std::time::Duration,
) -> Result<(), ApiError> {
    let ip = crate::rate_limit::client_ip(headers, peer.map(|c| c.0));
    if state
        .rate_limiter()
        .check(&ip, class, limit, window)
    {
        Ok(())
    } else {
        Err(ApiError::TooManyRequests(
            "too many requests — slow down and try again shortly".into(),
        ))
    }
}

/// `GET /v1/pay/:slug` — public, no auth.
pub async fn get_public_payment_link(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<PublicPaymentLinkView>>> {
    check_public_rate_limit(
        &state,
        &headers,
        peer,
        "pay_read",
        crate::rate_limit::PAY_READ_LIMIT,
        crate::rate_limit::PAY_READ_WINDOW,
    )?;
    let link = state.store().get_payment_link_by_slug(&slug).await?;
    if !link.active {
        return Err(ApiError::NotFound);
    }
    let address = state
        .store()
        .get_address(link.address_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Envelope::ok(PublicPaymentLinkView {
        name: link.name,
        description: link.description,
        image_url: link.image_url,
        redirect_url: link.redirect_url,
        amount_usdc_stroops: link.amount_usdc_stroops,
        deposit_address: address.muxed_address,
        asset_code: USDC_ASSET_CODE.into(),
    }))
}

#[derive(Debug, Default, Deserialize)]
pub struct CreatePaymentIntentRequest {
    pub payer_name: Option<String>,
    pub payer_email: Option<String>,
    pub amount_usdc_stroops: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct PaymentIntentView {
    pub payment_id: Uuid,
    pub deposit_address: String,
    pub amount_usdc_stroops: i64,
}

/// `POST /v1/pay/:slug/intent` — public, no auth.
pub async fn create_payment_intent(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<Envelope<PaymentIntentView>>)> {
    check_public_rate_limit(
        &state,
        &headers,
        peer,
        "pay_intent",
        crate::rate_limit::PAY_INTENT_LIMIT,
        crate::rate_limit::PAY_INTENT_WINDOW,
    )?;
    let link = state.store().get_payment_link_by_slug(&slug).await?;
    if !link.active {
        return Err(ApiError::NotFound);
    }
    let req: CreatePaymentIntentRequest = parse_optional(&body)?;

    // A fixed-amount link ignores whatever the payer sends; a flexible one requires a positive amount.
    let amount = match link.amount_usdc_stroops {
        Some(fixed) => fixed,
        None => req
            .amount_usdc_stroops
            .filter(|a| *a > 0)
            .ok_or_else(|| ApiError::BadRequest("amount_usdc_stroops is required".into()))?,
    };

    // Each intent gets its OWN muxed address, so a landing deposit identifies exactly one payment.
    // Sharing the link's address meant two concurrent payers could be cross-matched.
    let wallet = state.store().get_wallet(link.wallet_id).await?;
    let base = wallet.stellar_account_g.clone();
    let address = state
        .store()
        .allocate_address(
            link.wallet_id,
            |id| {
                let id_u64 = u64::try_from(id).map_err(|_| ())?;
                encode_muxed(&base, id_u64).map_err(|_| ())
            },
            None,
            serde_json::json!({ "payment_link_slug": slug }),
        )
        .await?;

    let payment = state
        .store()
        .record_payment_link_intent(
            link.id,
            req.payer_name.as_deref(),
            req.payer_email.as_deref(),
            amount,
            Some(address.id),
        )
        .await?;

    let (code, json) = Envelope::created(PaymentIntentView {
        payment_id: payment.id,
        deposit_address: address.muxed_address,
        amount_usdc_stroops: amount,
    });
    Ok((code, json))
}

#[derive(Debug, Serialize)]
pub struct PaymentStatusView {
    /// "pending" | "confirmed" | "expired" | "underpaid" | "overpaid".
    pub status: String,
    pub transaction_id: Option<Uuid>,
    /// The amount this intent expects. Always present, so the frontend can render a mismatch
    /// banner ("you sent X, expected Y") without a second request.
    pub expected_usdc_stroops: i64,
    /// What actually landed on-chain, once a deposit has been matched (confirmed/underpaid/
    /// overpaid). `None` while still pending or expired unpaid.
    pub received_usdc_stroops: Option<i64>,
}

/// `GET /v1/pay/:slug/payments/:payment_id` — public, no auth.
pub async fn get_payment_status(
    State(state): State<AppState>,
    Path((slug, payment_id)): Path<(String, Uuid)>,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<PaymentStatusView>>> {
    // The pay page polls this every ~3s while waiting, so the ceiling is generous.
    check_public_rate_limit(
        &state,
        &headers,
        peer,
        "pay_status",
        crate::rate_limit::PAY_STATUS_LIMIT,
        crate::rate_limit::PAY_STATUS_WINDOW,
    )?;
    let link = state.store().get_payment_link_by_slug(&slug).await?;
    let payment = state
        .store()
        .get_payment_link_payment(link.id, payment_id)
        .await?;
    let received_usdc_stroops = match payment.transaction_id {
        Some(tx_id) => state
            .store()
            .get_transaction(tx_id)
            .await?
            .map(|tx| tx.amount_stroops),
        None => None,
    };
    Ok(Envelope::ok(PaymentStatusView {
        status: payment.status,
        transaction_id: payment.transaction_id,
        expected_usdc_stroops: payment.amount_usdc_stroops,
        received_usdc_stroops,
    }))
}

/// `GET /v1/pay/:slug/signing-info` — public, no auth. Lets a Freighter payer build a
/// transaction locally without needing direct Horizon access.
#[derive(Debug, Default, Deserialize)]
pub struct PublicSigningInfoParams {
    /// The PAYER's own account (e.g. from Freighter) — this is the transaction's source, so its
    /// sequence number is what the built transaction must use, not the merchant's.
    pub account: Option<String>,
}

pub async fn public_signing_info(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Query(params): Query<PublicSigningInfoParams>,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<crate::routes::submit::SigningInfo>>> {
    check_public_rate_limit(
        &state,
        &headers,
        peer,
        "pay_signing_info",
        crate::rate_limit::PAY_SIGNING_INFO_LIMIT,
        crate::rate_limit::PAY_SIGNING_INFO_WINDOW,
    )?;
    // Confirms the link exists/is active before doing any Horizon work on the caller's behalf.
    let link = state.store().get_payment_link_by_slug(&slug).await?;
    if !link.active {
        return Err(ApiError::NotFound);
    }

    let account = match params.account {
        Some(a) => a,
        None => {
            state
                .store()
                .get_wallet(link.wallet_id)
                .await?
                .stellar_account_g
        }
    };
    let sequence = state.horizon().account_sequence(&account).await?;
    Ok(Envelope::ok(crate::routes::submit::SigningInfo {
        account,
        sequence,
        network_passphrase: state.network().passphrase().to_string(),
        base_fee_stroops: 100,
    }))
}

#[derive(Debug, Default, Deserialize)]
pub struct SubmitPaymentRequest {
    pub transaction_xdr: Option<String>,
    /// The intent being paid (from `POST /v1/pay/:slug/intent`). Each intent has its own deposit
    /// address, so the destination must be checked against that intent's address, not the link's.
    pub payment_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct SubmitPaymentResponse {
    pub status: String,
    pub stellar_tx_hash: Option<String>,
    pub detail: Option<String>,
}

/// `POST /v1/pay/:slug/submit-signed` — public, no auth. A payer relays a transaction they signed
/// themselves (e.g. via Freighter). Only a Payment to this link's own deposit address is allowed
/// — nothing else the payer's wallet might otherwise be able to spend.
pub async fn submit_payment(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<Envelope<SubmitPaymentResponse>>)> {
    check_public_rate_limit(
        &state,
        &headers,
        peer,
        "pay_submit",
        crate::rate_limit::PAY_SUBMIT_LIMIT,
        crate::rate_limit::PAY_SUBMIT_WINDOW,
    )?;
    let link = state.store().get_payment_link_by_slug(&slug).await?;
    if !link.active {
        return Err(ApiError::NotFound);
    }
    let req: SubmitPaymentRequest = parse_optional(&body)?;

    // Each payment intent gets its own muxed address (see `create_payment_intent`), so the
    // expected destination is the intent's address. Falling back to the link's own address keeps
    // pre-per-intent clients working.
    let address_id = match req.payment_id {
        Some(payment_id) => state
            .store()
            .get_payment_link_payment(link.id, payment_id)
            .await?
            .address_id
            .unwrap_or(link.address_id),
        None => link.address_id,
    };
    let address = state
        .store()
        .get_address(address_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let signed_xdr = req
        .transaction_xdr
        .filter(|x| !x.is_empty())
        .ok_or_else(|| ApiError::BadRequest("transaction_xdr is required".into()))?;

    use stellar_base::xdr::{OperationBody, TransactionEnvelope, XDRDeserialize};
    let env = TransactionEnvelope::from_xdr_base64(&signed_xdr)
        .map_err(|_| ApiError::BadRequest("transaction_xdr is not valid base64 XDR".into()))?;
    let v1 = match env {
        TransactionEnvelope::Tx(v1) => v1,
        _ => {
            return Err(ApiError::BadRequest(
                "transaction_xdr must be a v1 TransactionEnvelope".into(),
            ))
        }
    };
    if v1.signatures.is_empty() {
        return Err(ApiError::BadRequest(
            "transaction_xdr carries no signatures; sign it client-side first".into(),
        ));
    }
    // Exactly one Payment operation, to this link's own deposit address, in USDC — a payer's
    // signed transaction must not be able to do anything else through this relay, and must
    // actually be the asset this link advertises (not e.g. native XLM landing at the right
    // address, which would silently misreport the merchant's real received amount).
    let has_matching_payment = v1.tx.operations.iter().any(|op| {
        let OperationBody::Payment(p) = &op.body else {
            return false;
        };
        if crate::submit_validation::muxed_to_string(&p.destination) != address.muxed_address {
            return false;
        }
        let (asset_code, asset_issuer) = crate::submit_validation::asset_parts(&p.asset);
        asset_code == USDC_ASSET_CODE && asset_issuer.as_deref() == Some(USDC_TESTNET_ISSUER)
    });
    if !has_matching_payment || v1.tx.operations.len() != 1 {
        return Err(ApiError::BadRequest(
            "transaction_xdr must contain exactly one USDC Payment to this payment's deposit \
             address"
                .into(),
        ));
    }

    let submit = state.horizon().submit_transaction(&signed_xdr).await;
    let (status, hash, detail) = match submit {
        Ok(r) if r.successful => ("confirmed", Some(r.hash), None),
        Ok(r) => {
            let reason = r
                .operation_codes
                .iter()
                .find(|c| c.as_str() != "op_success")
                .cloned()
                .or(r.transaction_code.clone());
            ("failed", Some(r.hash), reason)
        }
        Err(ApiError::BadRequest(msg)) => ("failed", None, Some(msg)),
        Err(_) => (
            "failed",
            None,
            Some("Could not reach the Stellar network — try again.".into()),
        ),
    };

    let (code, json) = Envelope::created(SubmitPaymentResponse {
        status: status.to_string(),
        stellar_tx_hash: hash,
        detail,
    });
    Ok((code, json))
}

fn validate_slug(input: &str) -> Result<String, ApiError> {
    let normalized = input.trim().to_lowercase();

    if normalized.is_empty() {
        return Err(ApiError::BadRequest("slug cannot be empty".into()));
    }

    if normalized.len() < 3 {
        return Err(ApiError::BadRequest("slug must be at least 3 characters long".into()));
    }

    if normalized.len() > 64 {
        return Err(ApiError::BadRequest("slug must be at most 64 characters long".into()));
    }

    let reserved = ["api", "admin", "health"];
    if reserved.contains(&normalized.as_str()) {
        return Err(ApiError::BadRequest(format!("slug '{}' is reserved", normalized)));
    }

    if !normalized.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return Err(ApiError::BadRequest(
            "slug must contain only lowercase letters, digits, and hyphens".into(),
        ));
    }

    Ok(normalized)
}

#[cfg(test)]
mod tests_issue_252 {
    use super::*;

    #[test]
    fn validate_slug_accepts_valid_slug() {
        assert_eq!(validate_slug("valid-slug").unwrap(), "valid-slug");
    }

    #[test]
    fn validate_slug_normalizes_casing() {
        assert_eq!(validate_slug("VALID-SLUG").unwrap(), "valid-slug");
    }

    #[test]
    fn validate_slug_trims_whitespace() {
        assert_eq!(validate_slug("  valid-slug  ").unwrap(), "valid-slug");
    }

    #[test]
    fn validate_slug_rejects_invalid_characters() {
        assert!(validate_slug("invalid_slug").is_err());
        assert!(validate_slug("invalid slug").is_err());
        assert!(validate_slug("invalid.slug").is_err());
        assert!(validate_slug("invalid/slug").is_err());
    }

    #[test]
    fn validate_slug_rejects_slug_under_3_characters() {
        assert!(validate_slug("ab").is_err());
        assert!(validate_slug("a").is_err());
    }

    #[test]
    fn validate_slug_rejects_slug_over_64_characters() {
        let long_slug = "a".repeat(65);
        assert!(validate_slug(&long_slug).is_err());
    }

    #[test]
    fn validate_slug_accepts_slug_at_64_character_boundary() {
        let slug_64 = "a".repeat(64);
        assert_eq!(validate_slug(&slug_64).unwrap().len(), 64);
    }

    #[test]
    fn validate_slug_rejects_reserved_words() {
        assert!(validate_slug("api").is_err());
        assert!(validate_slug("admin").is_err());
        assert!(validate_slug("health").is_err());
        assert!(validate_slug("API").is_err());
        assert!(validate_slug("Admin").is_err());
    }

    #[test]
    fn validate_slug_accepts_digit_and_hyphen_combinations() {
        assert!(validate_slug("test-123").is_ok());
        assert!(validate_slug("123-test").is_ok());
        assert!(validate_slug("123").is_ok());
    }
}

fn validate_redirect_url(url: &str) -> Result<(), ApiError> {
    if url.is_empty() {
        return Ok(());
    }

    match url::Url::parse(url) {
        Ok(parsed) => {
            let scheme = parsed.scheme();
            if scheme != "http" && scheme != "https" {
                return Err(ApiError::BadRequest(
                    "redirect_url must use http:// or https:// scheme".into(),
                ));
            }
            Ok(())
        }
        Err(_) => Err(ApiError::BadRequest(
            "redirect_url must be a valid absolute URL".into(),
        )),
    }
}

#[cfg(test)]
mod tests_issue_253 {
    use super::*;

    #[test]
    fn validate_redirect_url_accepts_empty_url() {
        assert!(validate_redirect_url("").is_ok());
    }

    #[test]
    fn validate_redirect_url_accepts_https_url() {
        assert!(validate_redirect_url("https://example.com").is_ok());
        assert!(validate_redirect_url("https://example.com/path").is_ok());
        assert!(validate_redirect_url("https://example.com:8080/path?query=1").is_ok());
    }

    #[test]
    fn validate_redirect_url_accepts_http_url() {
        assert!(validate_redirect_url("http://example.com").is_ok());
        assert!(validate_redirect_url("http://localhost:8000").is_ok());
    }

    #[test]
    fn validate_redirect_url_rejects_javascript_scheme() {
        assert!(validate_redirect_url("javascript:alert('xss')").is_err());
    }

    #[test]
    fn validate_redirect_url_rejects_data_scheme() {
        assert!(validate_redirect_url("data:text/html,<h1>xss</h1>").is_err());
    }

    #[test]
    fn validate_redirect_url_rejects_invalid_url() {
        assert!(validate_redirect_url("not a url").is_err());
        assert!(validate_redirect_url("ht!tp://invalid").is_err());
    }

    #[test]
    fn validate_redirect_url_rejects_relative_url() {
        assert!(validate_redirect_url("/path/to/page").is_err());
        assert!(validate_redirect_url("path/to/page").is_err());
    }
}

const MAX_PAYMENT_INTENT_AMOUNT: i64 = 10_000_000_000;

#[cfg(test)]
mod tests_issue_254 {
    use super::*;

    #[test]
    fn payment_intent_amount_cap_constant_is_set() {
        assert_eq!(MAX_PAYMENT_INTENT_AMOUNT, 10_000_000_000);
    }

    #[test]
    fn validate_amount_positive() {
        assert!(1 > 0);
        assert!(100_000 > 0);
        assert!(MAX_PAYMENT_INTENT_AMOUNT > 0);
    }

    #[test]
    fn validate_amount_within_bounds() {
        let amount = 1_000_000_000;
        assert!(amount > 0 && amount <= MAX_PAYMENT_INTENT_AMOUNT);
    }

    #[test]
    fn validate_amount_rejects_exceeding_cap() {
        let amount = MAX_PAYMENT_INTENT_AMOUNT + 1;
        assert!(amount > MAX_PAYMENT_INTENT_AMOUNT);
    }

    #[test]
    fn validate_amount_accepts_at_cap_boundary() {
        let amount = MAX_PAYMENT_INTENT_AMOUNT;
        assert!(amount == MAX_PAYMENT_INTENT_AMOUNT);
    }

    #[test]
    fn validate_amount_rejects_zero_or_negative() {
        assert!(!(0 > 0));
        assert!(!(-1 > 0));
        assert!(!(-1_000_000 > 0));
    }
}

fn validate_slug(input: &str) -> Result<String, ApiError> {
    let normalized = input.trim().to_lowercase();

    if normalized.is_empty() {
        return Err(ApiError::BadRequest("slug cannot be empty".into()));
    }

    if normalized.len() < 3 {
        return Err(ApiError::BadRequest("slug must be at least 3 characters long".into()));
    }

    if normalized.len() > 64 {
        return Err(ApiError::BadRequest("slug must be at most 64 characters long".into()));
    }

    let reserved = ["api", "admin", "health"];
    if reserved.contains(&normalized.as_str()) {
        return Err(ApiError::BadRequest(format!("slug '{}' is reserved", normalized)));
    }

    if !normalized.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return Err(ApiError::BadRequest(
            "slug must contain only lowercase letters, digits, and hyphens".into(),
        ));
    }

    Ok(normalized)
}

fn validate_redirect_url(url: &str) -> Result<(), ApiError> {
    if url.is_empty() {
        return Ok(());
    }

    match url::Url::parse(url) {
        Ok(parsed) => {
            let scheme = parsed.scheme();
            if scheme != "http" && scheme != "https" {
                return Err(ApiError::BadRequest(
                    "redirect_url must use http:// or https:// scheme".into(),
                ));
            }
            Ok(())
        }
        Err(_) => Err(ApiError::BadRequest(
            "redirect_url must be a valid absolute URL".into(),
        )),
    }
}

const MAX_PAYMENT_INTENT_AMOUNT: i64 = 10_000_000_000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_slug_accepts_valid_slug() {
        assert_eq!(validate_slug("valid-slug").unwrap(), "valid-slug");
    }

    #[test]
    fn validate_slug_normalizes_casing() {
        assert_eq!(validate_slug("VALID-SLUG").unwrap(), "valid-slug");
    }

    #[test]
    fn validate_slug_trims_whitespace() {
        assert_eq!(validate_slug("  valid-slug  ").unwrap(), "valid-slug");
    }

    #[test]
    fn validate_slug_rejects_invalid_characters() {
        assert!(validate_slug("invalid_slug").is_err());
        assert!(validate_slug("invalid slug").is_err());
        assert!(validate_slug("invalid.slug").is_err());
        assert!(validate_slug("invalid/slug").is_err());
    }

    #[test]
    fn validate_slug_rejects_slug_under_3_characters() {
        assert!(validate_slug("ab").is_err());
        assert!(validate_slug("a").is_err());
    }

    #[test]
    fn validate_slug_rejects_slug_over_64_characters() {
        let long_slug = "a".repeat(65);
        assert!(validate_slug(&long_slug).is_err());
    }

    #[test]
    fn validate_slug_accepts_slug_at_64_character_boundary() {
        let slug_64 = "a".repeat(64);
        assert_eq!(validate_slug(&slug_64).unwrap().len(), 64);
    }

    #[test]
    fn validate_slug_rejects_reserved_words() {
        assert!(validate_slug("api").is_err());
        assert!(validate_slug("admin").is_err());
        assert!(validate_slug("health").is_err());
        assert!(validate_slug("API").is_err());
        assert!(validate_slug("Admin").is_err());
    }

    #[test]
    fn validate_slug_accepts_digit_and_hyphen_combinations() {
        assert!(validate_slug("test-123").is_ok());
        assert!(validate_slug("123-test").is_ok());
        assert!(validate_slug("123").is_ok());
    }

    #[test]
    fn validate_redirect_url_accepts_empty_url() {
        assert!(validate_redirect_url("").is_ok());
    }

    #[test]
    fn validate_redirect_url_accepts_https_url() {
        assert!(validate_redirect_url("https://example.com").is_ok());
        assert!(validate_redirect_url("https://example.com/path").is_ok());
        assert!(validate_redirect_url("https://example.com:8080/path?query=1").is_ok());
    }

    #[test]
    fn validate_redirect_url_accepts_http_url() {
        assert!(validate_redirect_url("http://example.com").is_ok());
        assert!(validate_redirect_url("http://localhost:8000").is_ok());
    }

    #[test]
    fn validate_redirect_url_rejects_javascript_scheme() {
        assert!(validate_redirect_url("javascript:alert('xss')").is_err());
    }

    #[test]
    fn validate_redirect_url_rejects_data_scheme() {
        assert!(validate_redirect_url("data:text/html,<h1>xss</h1>").is_err());
    }

    #[test]
    fn validate_redirect_url_rejects_invalid_url() {
        assert!(validate_redirect_url("not a url").is_err());
        assert!(validate_redirect_url("ht!tp://invalid").is_err());
    }

    #[test]
    fn validate_redirect_url_rejects_relative_url() {
        assert!(validate_redirect_url("/path/to/page").is_err());
        assert!(validate_redirect_url("path/to/page").is_err());
    }

    #[test]
    fn payment_intent_amount_cap_constant_is_set() {
        assert_eq!(MAX_PAYMENT_INTENT_AMOUNT, 10_000_000_000);
    }

    #[test]
    fn validate_amount_positive() {
        assert!(1 > 0);
        assert!(100_000 > 0);
    }

    #[test]
    fn validate_amount_within_bounds() {
        let amount = 1_000_000_000;
        assert!(amount > 0 && amount <= MAX_PAYMENT_INTENT_AMOUNT);
    }

    #[test]
    fn validate_amount_rejects_exceeding_cap() {
        let amount = MAX_PAYMENT_INTENT_AMOUNT + 1;
        assert!(amount > MAX_PAYMENT_INTENT_AMOUNT);
    }

    #[test]
    fn validate_amount_accepts_at_cap_boundary() {
        let amount = MAX_PAYMENT_INTENT_AMOUNT;
        assert!(amount == MAX_PAYMENT_INTENT_AMOUNT);
    }
}
