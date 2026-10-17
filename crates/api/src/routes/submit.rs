//! Non-custodial submit endpoint: relay a client-signed transaction to Horizon.
//!
//! The private key never touches the server — the client builds and signs locally (dashboard or
//! SDK) and Octo validates, submits, and records history. Authorization to *move funds* is the
//! user's own ed25519 signature (checked by the network); the API credential only authorizes use
//! of Octo's relay + bookkeeping.

use crate::auth::{authorize_wallet, authorize_wallet_scope, require_login};
use crate::error::{ApiError, ApiResult, Envelope};
use crate::json::parse_optional;
use crate::state::AppState;
use crate::submit_validation::validate_signed_xdr;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use octo_wallet_core::compute_inner_tx_hash;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Withdrawal-OTP TTL. Matches the signup OTP's 10-minute window.
const WITHDRAW_OTP_TTL_MINUTES: i64 = 10;

/// Stroops (1e-7) as a trimmed decimal string, matching Horizon's own asset precision.
fn format_amount(stroops: i64) -> String {
    let s = format!("{:.7}", stroops as f64 / 10_000_000.0);
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

#[derive(Debug, Default, Deserialize)]
pub struct SubmitSignedRequest {
    /// Base64 XDR of the client-signed v1 `TransactionEnvelope`.
    pub transaction_xdr: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SubmitSignedResponse {
    pub status: String,
    pub stellar_tx_hash: Option<String>,
    /// Human-readable reason when `status == "failed"` (from Horizon result codes).
    pub detail: Option<String>,
}

/// Map common Stellar result codes to human-readable explanations.
fn explain_code(code: &str) -> String {
    match code {
        "op_underfunded" => "Insufficient balance to cover this amount.".into(),
        "op_low_reserve" => {
            "Not enough XLM to satisfy the base reserve (each trustline/subentry reserves 0.5 XLM)."
                .into()
        }
        "op_no_destination" => "The destination account does not exist on this network.".into(),
        "op_no_trust" => {
            "The destination has no trustline for this asset — they must add one first.".into()
        }
        "op_no_issuer" => "The asset issuer does not exist on this network.".into(),
        "op_invalid_limit" => "The trust limit is invalid.".into(),
        "op_line_full" => "The destination's trustline limit would be exceeded.".into(),
        "tx_bad_seq" => {
            "Stale sequence number — refresh signing info and rebuild the transaction.".into()
        }
        "tx_bad_auth" => {
            "Signature verification failed — the transaction was not signed by this wallet's key."
                .into()
        }
        "tx_insufficient_fee" => "The network fee was too low; rebuild with a higher fee.".into(),
        other => format!("Transaction failed ({other})."),
    }
}

/// Result of `relay_signed_transaction`: the response plus the payment destination (for audit
/// logging / withdrawal emails), when the transaction was a Payment/PathPayment.
pub struct RelayOutcome {
    pub response: SubmitSignedResponse,
    pub destination: Option<String>,
    pub amount_stroops: Option<i64>,
    pub asset_code: Option<String>,
}

/// Core relay logic shared by `submit_signed` and the withdrawal OTP `confirm` endpoint: validate,
/// allowlist-check, submit to Horizon, and record history. Callers handle auth and OTP gating.
pub async fn relay_signed_transaction(
    state: &AppState,
    wallet_id: Uuid,
    wallet: &octo_store::Wallet,
    signed_xdr: &str,
) -> ApiResult<RelayOutcome> {
    // Pure validation: v1 envelope, ≥1 signature, source == this wallet, op allowlist.
    let payment = validate_signed_xdr(signed_xdr, &wallet.stellar_account_g)?;

    // Withdrawal allowlist: if the wallet has opted in, a Payment/PathPayment destination must be
    // pre-approved. Checked BEFORE anything touches Horizon, so a blocked send never reaches the
    // network. Off by default (see migration 0013) — enabling this can never retroactively lock a
    // wallet out of an address it already used.
    if let Some(p) = &payment {
        let allowlist_enabled = state
            .store()
            .get_withdrawal_allowlist_config(wallet_id)
            .await
            .map_err(|_| ApiError::Internal)?
            .is_some_and(|c| c.enabled);
        if allowlist_enabled {
            let base_destination = octo_wallet_core::to_base_account(&p.destination)
                .map_err(|_| ApiError::BadRequest("destination is not a valid address".into()))?;
            let ok = state
                .store()
                .is_address_whitelisted(wallet_id, &base_destination)
                .await
                .map_err(|_| ApiError::Internal)?;
            if !ok {
                return Err(ApiError::Forbidden(
                    "destination is not on this wallet's withdrawal allowlist".into(),
                ));
            }
        }
    }

    // Compute the canonical tx hash up-front so the response/record always reference it, even
    // when Horizon submission errors out at the transport layer.
    let precomputed_hash = hex::encode(
        compute_inner_tx_hash(signed_xdr, state.network())
            .map_err(|_| ApiError::BadRequest("transaction_xdr could not be hashed".into()))?,
    );

    let submit = state.horizon().submit_transaction(signed_xdr).await;

    let (status, hash, detail) = match submit {
        Ok(r) if r.successful => ("confirmed", Some(r.hash), None),
        Ok(r) => {
            let reason = r
                .operation_codes
                .iter()
                .find(|c| c.as_str() != "op_success")
                .map(|c| explain_code(c))
                .or_else(|| r.transaction_code.as_deref().map(explain_code));
            ("failed", Some(r.hash), reason)
        }
        Err(ApiError::BadRequest(msg)) => ("failed", Some(precomputed_hash), Some(msg)),
        Err(_) => (
            "failed",
            Some(precomputed_hash),
            Some("Could not reach the Stellar network — try again.".into()),
        ),
    };

    // Record outbound payments in the history the dashboard lists (best-effort). The store call
    // is idempotent per tx hash, so `Ok(None)` (already recorded) is expected on a retry.
    if let Some(p) = &payment {
        if let Err(e) = state
            .store()
            .record_withdrawal_transaction(
                wallet_id,
                &p.asset_code,
                p.asset_issuer.as_deref(),
                p.amount_stroops,
                &wallet.stellar_account_g,
                &p.destination,
                hash.as_deref(),
                status,
            )
            .await
        {
            tracing::warn!(wallet = %wallet_id, error = ?e, "failed to record withdrawal history");
        }
    }

    Ok(RelayOutcome {
        response: SubmitSignedResponse {
            status: status.to_string(),
            stellar_tx_hash: hash,
            detail,
        },
        destination: payment.as_ref().map(|p| p.destination.clone()),
        amount_stroops: payment.as_ref().map(|p| p.amount_stroops),
        asset_code: payment.as_ref().map(|p| p.asset_code.clone()),
    })
}

/// `POST /v1/wallets/:id/submit-signed`
pub async fn submit_signed(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<Envelope<SubmitSignedResponse>>)> {
    authorize_wallet_scope(&headers, &state, wallet_id, "write").await?;
    // For the audit log only: present when the caller used a login JWT (None for API keys).
    let audit_user = crate::auth::authenticate(&headers, &state).await.ok();
    let wallet = state.store().get_wallet(wallet_id).await?;
    if wallet.is_archived() {
        return Err(ApiError::Forbidden("wallet is archived".into()));
    }

    let req: SubmitSignedRequest = parse_optional(&body)?;
    let signed_xdr = req
        .transaction_xdr
        .filter(|x| !x.is_empty())
        .ok_or_else(|| ApiError::BadRequest("transaction_xdr is required".into()))?;

    let outcome = relay_signed_transaction(&state, wallet_id, &wallet, &signed_xdr).await?;

    if let Some(user_id) = audit_user {
        crate::audit::record(
            &state,
            user_id,
            &format!(
                "submitted a signed transaction ({})",
                outcome.response.status
            ),
            crate::audit::category::WALLET,
            outcome.destination.as_deref(),
            &headers,
        )
        .await;
    }

    let (code, json) = Envelope::created(outcome.response);
    Ok((code, json))
}

#[derive(Debug, Default, Deserialize)]
pub struct WithdrawOtpRequest {
    pub transaction_xdr: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct WithdrawConfirmRequest {
    pub transaction_xdr: Option<String>,
    pub code: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WithdrawOtpResponse {
    pub sent: bool,
}

fn require_xdr(x: Option<String>) -> ApiResult<String> {
    x.filter(|x| !x.is_empty())
        .ok_or_else(|| ApiError::BadRequest("transaction_xdr is required".into()))
}

/// `POST /v1/wallets/:id/withdraw/request-otp` — email a code bound to this exact, already-signed
/// transaction. Requires a dashboard login (not an API key) since this gates a sensitive action.
pub async fn withdraw_request_otp(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Envelope<WithdrawOtpResponse>>> {
    let user_id = require_login(&headers, &state).await?;
    let wallet = state.store().get_wallet(wallet_id).await?;
    if wallet.is_archived() {
        return Err(ApiError::Forbidden("wallet is archived".into()));
    }
    if wallet.user_id != Some(user_id) {
        return Err(ApiError::NotFound);
    }
    let user = state
        .store()
        .get_user(user_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    let req: WithdrawOtpRequest = parse_optional(&body)?;
    let signed_xdr = require_xdr(req.transaction_xdr)?;

    // Validate up front so a garbage transaction never gets an OTP issued for it.
    validate_signed_xdr(&signed_xdr, &wallet.stellar_account_g)?;
    let tx_hash = hex::encode(
        compute_inner_tx_hash(&signed_xdr, state.network())
            .map_err(|_| ApiError::BadRequest("transaction_xdr could not be hashed".into()))?,
    );

    let code = octo_email::generate_otp();
    let code_hash = octo_email::hash_otp(&code);
    state
        .store()
        .create_otp(
            user_id,
            "withdrawal",
            &code_hash,
            Some(&tx_hash),
            chrono::Duration::minutes(WITHDRAW_OTP_TTL_MINUTES),
        )
        .await
        .map_err(|_| ApiError::Internal)?;
    state
        .email()
        .send_otp(&user.email, "withdrawal", &code)
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(Envelope::ok(WithdrawOtpResponse { sent: true }))
}

/// `POST /v1/wallets/:id/withdraw/confirm` — verify the OTP (bound to this exact transaction) and,
/// only if it's correct, relay to Horizon. A wrong/expired/reused code never reaches Horizon.
pub async fn withdraw_confirm(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<Envelope<SubmitSignedResponse>>)> {
    let user_id = require_login(&headers, &state).await?;
    let wallet = state.store().get_wallet(wallet_id).await?;
    if wallet.is_archived() {
        return Err(ApiError::Forbidden("wallet is archived".into()));
    }
    if wallet.user_id != Some(user_id) {
        return Err(ApiError::NotFound);
    }
    let user = state
        .store()
        .get_user(user_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    let req: WithdrawConfirmRequest = parse_optional(&body)?;
    let signed_xdr = require_xdr(req.transaction_xdr)?;
    let code = req
        .code
        .filter(|c| !c.is_empty())
        .ok_or_else(|| ApiError::BadRequest("code is required".into()))?;

    let tx_hash = hex::encode(
        compute_inner_tx_hash(&signed_xdr, state.network())
            .map_err(|_| ApiError::BadRequest("transaction_xdr could not be hashed".into()))?,
    );

    let code_hash = octo_email::hash_otp(&code);
    let payment = validate_signed_xdr(&signed_xdr, &wallet.stellar_account_g)?;
    if state
        .store()
        .verify_and_consume_otp(user_id, "withdrawal", &code_hash, Some(&tx_hash))
        .await
        .is_err()
    {
        // Wrong/expired/reused code: never touches Horizon. Tell the user in case it wasn't them.
        if let Some(p) = &payment {
            let html = octo_email::templates::withdrawal_failed_email(
                &format_amount(p.amount_stroops),
                &p.asset_code,
                &p.destination,
                "an incorrect verification code was entered",
            );
            let _ = state
                .email()
                .send(&user.email, "Withdrawal attempt failed", &html)
                .await;
        }
        return Err(ApiError::BadRequest("invalid or expired code".into()));
    }

    let outcome = relay_signed_transaction(&state, wallet_id, &wallet, &signed_xdr).await?;

    crate::audit::record(
        &state,
        user_id,
        &format!("confirmed a withdrawal ({})", outcome.response.status),
        crate::audit::category::WALLET,
        outcome.destination.as_deref(),
        &headers,
    )
    .await;

    let (amount, asset, destination) = (
        outcome.amount_stroops.map(format_amount),
        outcome.asset_code.clone(),
        outcome.destination.clone(),
    );
    if let (Some(amount), Some(asset), Some(destination)) = (amount, asset, destination) {
        let html = if outcome.response.status == "confirmed" {
            octo_email::templates::withdrawal_success_email(
                &amount,
                &asset,
                &destination,
                outcome.response.stellar_tx_hash.as_deref().unwrap_or(""),
            )
        } else {
            octo_email::templates::withdrawal_failed_email(
                &amount,
                &asset,
                &destination,
                outcome
                    .response
                    .detail
                    .as_deref()
                    .unwrap_or("the transaction was rejected"),
            )
        };
        let subject = if outcome.response.status == "confirmed" {
            "Withdrawal successful"
        } else {
            "Withdrawal attempt failed"
        };
        let _ = state.email().send(&user.email, subject, &html).await;
    }

    let (code, json) = Envelope::created(outcome.response);
    Ok((code, json))
}

/// `GET /v1/wallets/:id/signing-info` — what a client needs to build a transaction locally:
/// the account's current sequence number plus network parameters. No Horizon access required
/// client-side.
pub async fn signing_info(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<SigningInfo>>> {
    authorize_wallet(&headers, &state, wallet_id).await?;
    let wallet = state.store().get_wallet(wallet_id).await?;

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

    Ok(Envelope::ok(SigningInfo {
        account: wallet.stellar_account_g,
        sequence,
        network_passphrase: state.network().passphrase().to_string(),
        base_fee_stroops: 100,
    }))
}

#[derive(Debug, Serialize)]
pub struct SigningInfo {
    pub account: String,
    /// The account's current sequence number, as a **string**.
    ///
    /// This is not stylistic. Stellar sequence numbers are `(ledger << 32)`-based and are already
    /// ~1.6e16 on testnet, which is past JavaScript's `Number.MAX_SAFE_INTEGER` (9.007e15). Sent
    /// as a JSON number, `JSON.parse` silently rounds it — e.g. ...466433 becomes ...466432, one
    /// too low — so the client signs with a stale sequence and Horizon rejects the transaction
    /// with `tx_bad_seq`. The first withdrawal after funding happens to land on an even value and
    /// succeeds, which makes this look like an intermittent bug rather than a rounding one.
    ///
    /// Horizon itself returns `sequence` as a string for exactly this reason; we match it.
    #[serde(with = "crate::json::i64_as_string")]
    pub sequence: i64,
    pub network_passphrase: String,
    pub base_fee_stroops: i64,
}

const WITHDRAW_CONFIRM_RATE_LIMIT_THRESHOLD: u32 = 10;
const WITHDRAW_CONFIRM_RATE_LIMIT_WINDOW: std::time::Duration = std::time::Duration::from_secs(3600);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_amount_strips_trailing_zeros() {
        assert_eq!(format_amount(1_000_000), "0.1");
        assert_eq!(format_amount(10_000_000), "1");
        assert_eq!(format_amount(100_000_000), "10");
    }

    #[test]
    fn format_amount_handles_fractional_stroops() {
        assert_eq!(format_amount(1), "0.0000001");
        assert_eq!(format_amount(10), "0.000001");
        assert_eq!(format_amount(100), "0.00001");
    }

    #[test]
    fn format_amount_zero() {
        assert_eq!(format_amount(0), "0");
    }

    #[test]
    fn withdraw_confirm_rate_limit_threshold_is_reasonable() {
        assert!(WITHDRAW_CONFIRM_RATE_LIMIT_THRESHOLD >= 5);
        assert!(WITHDRAW_CONFIRM_RATE_LIMIT_THRESHOLD <= 20);
    }

    #[test]
    fn withdraw_confirm_rate_limit_window_is_one_hour() {
        assert_eq!(WITHDRAW_CONFIRM_RATE_LIMIT_WINDOW, std::time::Duration::from_secs(3600));
    }

    #[test]
    fn withdrawal_otp_ttl_is_ten_minutes() {
        assert_eq!(WITHDRAW_OTP_TTL_MINUTES, 10);
    }

    #[test]
    fn rate_limit_allows_reasonable_retry_count() {
        assert!(WITHDRAW_CONFIRM_RATE_LIMIT_THRESHOLD > 2);
    }

    #[test]
    fn explain_code_returns_human_readable_messages() {
        assert!(!explain_code("op_underfunded").is_empty());
        assert!(!explain_code("op_low_reserve").is_empty());
        assert!(!explain_code("tx_bad_seq").is_empty());
        assert!(!explain_code("unknown_code").contains("unknown_code"));
    }
}
