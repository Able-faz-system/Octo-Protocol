//! Dashboard authentication: signup, login, refresh, logout, and JWT-based auth helpers.
//!
//! # Session lifecycle
//!
//! ```text
//!  login/signup ──▶ issues token T1 (7-day TTL)
//!  POST /refresh   ──▶ revokes T1, issues T2
//!  POST /logout    ──▶ revokes T2
//!  POST /change-password ──▶ revokes every token issued so far, issues T3
//! ```
//!
//! Single-token revocation uses a deny-list in Postgres (migration 0008_token_denylist.sql).
//! Revoking *all* of a user's sessions uses a per-user `session_epoch` (migration
//! 0021_session_epoch.sql): every JWT carries the epoch it was issued under, and a password
//! change bumps it. Every authenticated request checks both after signature + expiry
//! verification, in one query, so a revoked token is rejected even within its original TTL.
//!
//! # Refresh atomicity
//!
//! `refresh` revokes the old token and issues a new one in two sequential Postgres calls.
//! There is a brief window (< one DB round-trip, typically < 5 ms) where both tokens are
//! technically valid. This is acceptable for bearer-token auth over HTTPS — an attacker
//! would need to replay the old token in a sub-5 ms window after the user triggered a refresh,
//! which is not a realistic threat model. A fully window-free design would require distributed
//! locking or opaque session IDs, which is out of scope here.
//!
//! # Concurrent-request race on refresh
//!
//! In-flight requests that carry T1 at the moment T1 is revoked may succeed or fail
//! depending on timing: if `is_token_revoked` runs before the deny-list INSERT commits they
//! succeed; after, they get 401. Clients should treat a mid-session 401 as a signal to
//! re-authenticate. This is the standard deny-list tradeoff and is documented here explicitly.
//!
//! # Security
//! - Passwords are hashed with **argon2id** (PHC string, random salt).
//! - Same error for "no such user" and "wrong password" → no account enumeration.
//! - Session token: HS256 JWT signed with `JWT_SECRET`.
//! - Revoked tokens stored in deny-list, checked on every authenticated request.
#![allow(clippy::too_many_arguments)]

use crate::error::{ApiError, ApiResult, Envelope};
use crate::json::parse_optional;
use crate::state::AppState;
use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::Argon2;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

/// Token lifetime: 7 days.
const TOKEN_TTL_SECS: i64 = 7 * 24 * 60 * 60;

#[derive(Debug, Deserialize, Default)]
pub struct Credentials {
    pub email: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: UserView,
}

/// Returned by signup, and by login when the account isn't yet email-verified — tells the
/// client to show the OTP-entry step instead of a token.
#[derive(Debug, Serialize)]
pub struct VerificationRequiredResponse {
    pub user_id: Uuid,
    pub email_verification_required: bool,
}

#[derive(Debug, Deserialize, Default)]
pub struct VerifyEmailRequest {
    pub user_id: Option<Uuid>,
    pub code: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct RequestPasswordResetRequest {
    pub email: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ConfirmPasswordResetRequest {
    pub email: Option<String>,
    pub code: Option<String>,
    pub new_password: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct RequestEmailChangeRequest {
    pub new_email: Option<String>,
    /// The account's current password — changing the login identifier is a sensitive action.
    pub password: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ConfirmEmailChangeRequest {
    pub new_email: Option<String>,
    pub code: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ResendOtpRequest {
    pub user_id: Option<Uuid>,
}

/// Change-password attempts allowed per user per 15 minutes.
const CHANGE_PASSWORD_ATTEMPTS: u32 = 5;

/// Signup-OTP TTL. Matches the wallet-ownership challenge's 10-minute window.
const OTP_TTL_MINUTES: i64 = 10;

#[derive(Debug, Serialize)]
pub struct UserView {
    pub id: Uuid,
    pub email: String,
    pub username: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ChangePasswordRequest {
    pub current_password: Option<String>,
    pub new_password: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct UpdateUsernameRequest {
    pub username: Option<String>,
}

/// JWT claims.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject: the user id.
    pub sub: String,
    /// Expiry (unix seconds).
    pub exp: i64,
    /// Unique token id. Without it, two tokens issued for the same user within the same second
    /// are byte-identical, so "rotating" a token on refresh would hand back the same string —
    /// and denylisting the old one would revoke the new one too.
    #[serde(default)]
    pub jti: String,
    /// The user's `session_epoch` at issue time. Pre-epoch tokens decode as 0 (the column
    /// default), so they stay valid until the user's first password change.
    #[serde(default)]
    pub epoch: i32,
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

/// Rate-limit an auth attempt by client IP: 10 per minute per IP.
///
/// Blunts credential stuffing and signup spam. Deliberately per-IP rather than per-email — an
/// attacker rotates emails freely, but not source addresses.
fn check_auth_rate_limit(
    state: &AppState,
    headers: &HeaderMap,
    peer: Option<std::net::SocketAddr>,
) -> Result<(), ApiError> {
    let ip = crate::rate_limit::client_ip(headers, peer);
    if state
        .rate_limiter()
        .check(&ip, "auth", crate::rate_limit::AUTH_RATE_LIMIT, crate::rate_limit::AUTH_RATE_WINDOW)
    {
        Ok(())
    } else {
        Err(ApiError::TooManyRequests(
            "too many attempts — wait a minute and try again".into(),
        ))
    }
}

/// Generate, store, and email a one-time code for `purpose`. `bound_to` ties the code to one value
/// (e.g. a new email address) so it can't be redeemed for anything else.
async fn issue_otp(
    state: &AppState,
    user_id: Uuid,
    purpose: &str,
    to: &str,
    bound_to: Option<&str>,
) -> Result<(), ApiError> {
    let code = octo_email::generate_otp();
    let code_hash = octo_email::hash_otp(&code);
    state
        .store()
        .create_otp(
            user_id,
            purpose,
            &code_hash,
            bound_to,
            chrono::Duration::minutes(OTP_TTL_MINUTES),
        )
        .await
        .map_err(|_| ApiError::Internal)?;
    state
        .email()
        .send_otp(to, purpose, &code)
        .await
        .map_err(|_| ApiError::Internal)?;
    Ok(())
}

/// Issue a signup-verification OTP. Shared by `signup`, `resend_otp`, and `login` when the account
/// isn't yet verified.
async fn issue_signup_otp(state: &AppState, user_id: Uuid, email: &str) -> Result<(), ApiError> {
    issue_otp(state, user_id, "signup", email, None).await
}

/// `POST /v1/auth/signup`
pub async fn signup(
    State(state): State<AppState>,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<Envelope<VerificationRequiredResponse>>)> {
    check_auth_rate_limit(&state, &headers, peer.map(|c| c.0))?;
    let creds: Credentials = parse_optional(&body)?;
    let (email, password) = validate(creds)?;

    let hash = hash_password(&password)?;
    let user = state
        .store()
        .create_user(&email, &hash)
        .await
        .map_err(|e| match e {
            octo_store::StoreError::Conflict => {
                ApiError::BadRequest("email already registered".into())
            }
            _ => ApiError::Internal,
        })?;

    crate::audit::record(
        &state,
        user.id,
        "created an account",
        crate::audit::category::AUTH,
        None,
        &headers,
    )
    .await;

    // If the OTP email can't be sent, this account is otherwise unreachable — delete it rather
    // than leaving the email permanently stuck as "already registered" with no way to verify.
    if let Err(e) = issue_signup_otp(&state, user.id, &user.email).await {
        let _ = state.store().delete_unverified_user(user.id).await;
        return Err(e);
    }

    let (code, json) = Envelope::created(VerificationRequiredResponse {
        user_id: user.id,
        email_verification_required: true,
    });
    Ok((code, json))
}

/// `POST /v1/auth/verify-email` — consume a signup OTP and issue the first session token.
pub async fn verify_email(
    State(state): State<AppState>,
    body: Bytes,
) -> ApiResult<Json<Envelope<AuthResponse>>> {
    let req: VerifyEmailRequest = parse_optional(&body)?;
    let user_id = req
        .user_id
        .ok_or_else(|| ApiError::BadRequest("user_id is required".into()))?;
    let code = req
        .code
        .filter(|c| !c.is_empty())
        .ok_or_else(|| ApiError::BadRequest("code is required".into()))?;

    let code_hash = octo_email::hash_otp(&code);
    state
        .store()
        .verify_and_consume_otp(user_id, "signup", &code_hash, None)
        .await
        .map_err(|_| ApiError::BadRequest("invalid or expired code".into()))?;

    let user = state
        .store()
        .get_user(user_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    state
        .store()
        .mark_email_verified(user_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let welcome_html = octo_email::templates::welcome_email(&user.email);
    let _ = state
        .email()
        .send(&user.email, "Welcome to Octo", &welcome_html)
        .await;

    let token = issue_token(state.jwt_secret(), user.id, user.session_epoch)?;
    Ok(Envelope::ok(AuthResponse {
        token,
        user: UserView {
            id: user.id,
            email: user.email,
            username: user.username,
        },
    }))
}

/// `POST /v1/auth/resend-otp` — re-send a signup verification code.
pub async fn resend_otp(
    State(state): State<AppState>,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Envelope<serde_json::Value>>> {
    check_auth_rate_limit(&state, &headers, peer.map(|c| c.0))?;
    let req: ResendOtpRequest = parse_optional(&body)?;
    let user_id = req
        .user_id
        .ok_or_else(|| ApiError::BadRequest("user_id is required".into()))?;

    let ip = crate::rate_limit::client_ip(&headers, peer.map(|c| c.0));
    if !state.rate_limiter().check(
        &format!("otp:{user_id}"),
        "otp_resend",
        crate::rate_limit::OTP_RESEND_USER_LIMIT,
        crate::rate_limit::OTP_RESEND_USER_WINDOW,
    ) {
        return Err(ApiError::TooManyRequests(
            "too many resend attempts — wait a while and try again".into(),
        ));
    }
    // Belt and suspenders: also cap per-IP, so one IP can't hammer many user_ids.
    if !state.rate_limiter().check(
        &ip,
        "otp_resend_ip",
        crate::rate_limit::OTP_RESEND_IP_LIMIT,
        crate::rate_limit::OTP_RESEND_IP_WINDOW,
    ) {
        return Err(ApiError::TooManyRequests(
            "too many resend attempts — wait a while and try again".into(),
        ));
    }

    let user = state
        .store()
        .get_user(user_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    issue_signup_otp(&state, user.id, &user.email).await?;
    Ok(Envelope::ok(serde_json::json!({ "sent": true })))
}

/// `POST /v1/auth/login`
pub async fn login(
    State(state): State<AppState>,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Envelope<serde_json::Value>>> {
    check_auth_rate_limit(&state, &headers, peer.map(|c| c.0))?;
    let creds: Credentials = parse_optional(&body)?;
    let (email, password) = validate(creds)?;

    let user = state
        .store()
        .find_user_by_email(&email)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or_else(|| ApiError::BadRequest("invalid email or password".into()))?;

    verify_password(&password, &user.password_hash)
        .map_err(|_| ApiError::BadRequest("invalid email or password".into()))?;

    // A correct password on an unverified account (pre-existing user, or one who abandoned
    // signup before verifying) re-triggers the same OTP gate signup uses, instead of a token.
    if user.email_verified_at.is_none() {
        issue_signup_otp(&state, user.id, &user.email).await?;
        return Ok(Envelope::ok(
            serde_json::to_value(VerificationRequiredResponse {
                user_id: user.id,
                email_verification_required: true,
            })
            .map_err(|_| ApiError::Internal)?,
        ));
    }

    crate::audit::record(
        &state,
        user.id,
        "signed in",
        crate::audit::category::AUTH,
        None,
        &headers,
    )
    .await;

    let token = issue_token(state.jwt_secret(), user.id, user.session_epoch)?;
    Ok(Envelope::ok(
        serde_json::to_value(AuthResponse {
            token,
            user: UserView {
                id: user.id,
                email: user.email,
                username: user.username,
            },
        })
        .map_err(|_| ApiError::Internal)?,
    ))
}

/// `POST /v1/auth/refresh` — exchange a valid, unexpired token for a freshly-signed one.
///
/// The caller presents their current JWT via `Authorization: Bearer`; the response carries a new
/// token for the same user with a full [`TOKEN_TTL_SECS`] window starting now.
///
/// **This is not a security control.** Refreshing does **not** invalidate the previous token:
/// both the old and the new token remain valid until their natural expiry. That is an intentional
/// scope limit — real revocation (server-side session state / a token denylist) is a separate,
/// larger piece of work.
pub async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<AuthResponse>>> {
    let user_id = authenticate(&headers, &state).await?;
    let user = state
        .store()
        .get_user(user_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    // Rotate, don't just re-issue: deny-list the presented token so a refreshed session leaves
    // exactly one live token. Without this a leaked token stayed valid for its full TTL even
    // after the user refreshed.
    if let Some(old_token) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
    {
        if let Some(claims) = verify_token(state.jwt_secret(), old_token) {
            let expires_at =
                chrono::DateTime::from_timestamp(claims.exp, 0).unwrap_or_else(chrono::Utc::now);
            state
                .store()
                .denylist_token(&hash_token(old_token), user.id, expires_at)
                .await
                .map_err(|_| ApiError::Internal)?;
        }
    }

    crate::audit::record(
        &state,
        user.id,
        "refreshed session token",
        crate::audit::category::AUTH,
        None,
        &headers,
    )
    .await;

    let token = issue_token(state.jwt_secret(), user.id, user.session_epoch)?;
    Ok(Envelope::ok(AuthResponse {
        token,
        user: UserView {
            id: user.id,
            email: user.email,
            username: user.username,
        },
    }))
}

/// `POST /v1/auth/change-password` — re-verify the current password, set a new one, revoke every
/// previously issued session, and return a fresh token (same shape as `refresh`).
pub async fn change_password(
    State(state): State<AppState>,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Envelope<AuthResponse>>> {
    check_auth_rate_limit(&state, &headers, peer.map(|c| c.0))?;
    // API keys are wallet-scoped automation credentials; only a login session may do this.
    let user_id = require_login(&headers, &state).await?;
    // Per-user cap too, so a stolen token can't guess the current password by rotating IPs.
    if !state.rate_limiter().check(
        &user_id.to_string(),
        "change_password",
        CHANGE_PASSWORD_ATTEMPTS,
        std::time::Duration::from_secs(15 * 60),
    ) {
        return Err(ApiError::TooManyRequests(
            "too many attempts — wait a while and try again".into(),
        ));
    }

    let req: ChangePasswordRequest = parse_optional(&body)?;
    let current = req
        .current_password
        .filter(|p| !p.is_empty())
        .ok_or_else(|| ApiError::BadRequest("current_password is required".into()))?;
    let new = req
        .new_password
        .filter(|p| p.len() >= 8)
        .ok_or_else(|| ApiError::BadRequest("new_password must be at least 8 characters".into()))?;
    if new == current {
        return Err(ApiError::BadRequest(
            "new_password must differ from the current password".into(),
        ));
    }

    let user = state
        .store()
        .get_user(user_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::Unauthorized)?;
    verify_password(&current, &user.password_hash)
        .map_err(|_| ApiError::BadRequest("current password is incorrect".into()))?;

    let epoch = state
        .store()
        .change_password(user_id, &hash_password(&new)?)
        .await
        .map_err(|_| ApiError::Internal)?;

    crate::audit::record(
        &state,
        user_id,
        "changed password",
        crate::audit::category::AUTH,
        None,
        &headers,
    )
    .await;

    let token = issue_token(state.jwt_secret(), user_id, epoch)?;

    Ok(Envelope::ok(AuthResponse {
        token,
        user: UserView {
            id: user.id,
            email: user.email,
            username: user.username,
        },
    }))
}

/// `GET /v1/auth/me` — returns the authenticated user (token required).
pub async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<UserView>>> {
    let user_id = authenticate(&headers, &state).await?;
    let user = state
        .store()
        .get_user(user
    Ok(Envelope::ok(AuthResponse {
        token,
        user: UserView {
            id: user.id,
            email: user.email,
            username: user.username,
        },
    }))
}

/// `GET /v1/auth/me` — returns the authenticated user (token required).
pub async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<UserView>>> {
    let user_id = authenticate(&headers, &state).await?;
    let user = state
        .store()
        .get_user(user_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;
    Ok(Envelope::ok(UserView {
        id: user.id,
        email: user.email,
        username: user.username,
    }))
}

/// `PATCH /v1/auth/me` — set the authenticated user's display username.
pub async fn update_username(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Envelope<UserView>>> {
    let user_id = authenticate(&headers, &state).await?;
    let req: UpdateUsernameRequest = parse_optional(&body)?;
    let username = validate_username(req.username)?;

    let user = state
        .store()
        .update_username(user_id, &username)
        .await
        .map_err(|e| match e {
            octo_store::StoreError::Conflict => {
                ApiError::BadRequest("username already taken".into())
            }
            _ => ApiError::Internal,
        })?;

    Ok(Envelope::ok(UserView {
        id: user.id,
        email: user.email,
        username: user.username,
    }))
}

/// Send a password-reset OTP if `email` belongs to a verified account; otherwise do nothing.
async fn send_password_reset_otp(state: &AppState, email: &str) -> Result<(), ApiError> {
    let Some(user) = state
        .store()
        .find_user_by_email(email)
        .await
        .map_err(|_| ApiError::Internal)?
    else {
        return Ok(());
    };
    if user.email_verified_at.is_none() {
        return Ok(());
    }
    // Per-account cap: with the per-code attempt limit it bounds guessing to a few tries an hour.
    if !state.rate_limiter().check(
        &format!("pwreset:{}", user.id),
        "pw_reset_send",
        3,
        std::time::Duration::from_secs(60 * 60),
    ) {
        return Ok(());
    }
    issue_otp(state, user.id, "password_reset", &user.email, None).await
}

/// `POST /v1/auth/request-password-reset` — email a reset code if the account exists.
///
/// The response is identical whether or not the email matches an account. The lookup and send run
/// in the background, so neither the body nor the latency reveals which case it was.
pub async fn request_password_reset(
    State(state): State<AppState>,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Envelope<serde_json::Value>>> {
    check_auth_rate_limit(&state, &headers, peer.map(|c| c.0))?;
    let req: RequestPasswordResetRequest = parse_optional(&body)?;
    let email = normalize_email(req.email)?;

    tokio::spawn(async move {
        if let Err(e) = send_password_reset_otp(&state, &email).await {
            tracing::warn!(error = ?e, "password-reset OTP could not be sent");
        }
    });
    Ok(Envelope::ok(serde_json::json!({ "sent": true })))
}

/// `POST /v1/auth/confirm-password-reset` — verify the emailed code, set the new password, and
/// revoke every existing session.
pub async fn confirm_password_reset(
    State(state): State<AppState>,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Envelope<serde_json::Value>>> {
    check_auth_rate_limit(&state, &headers, peer.map(|c| c.0))?;
    let req: ConfirmPasswordResetRequest = parse_optional(&body)?;
    // Validate the password first so a typo doesn't burn the one-time code.
    let (email, new_password) = validate(Credentials {
        email: req.email,
        password: req.new_password,
    })?;
    let code = req
        .code
        .filter(|c| !c.is_empty())
        .ok_or_else(|| ApiError::BadRequest("code is required".into()))?;

    // One message for every failure: unknown email, wrong code, expired code, reused code.
    let invalid = || ApiError::BadRequest("invalid or expired code".into());
    let user = state
        .store()
        .find_user_by_email(&email)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or_else(invalid)?;
    state
        .store()
        .verify_and_consume_otp(
            user.id,
            "password_reset",
            &octo_email::hash_otp(&code),
            None,
        )
        .await
        .map_err(|_| invalid())?;

    let hash = hash_password(&new_password)?;
    state
        .store()
        .reset_password(user.id, &hash)
        .await
        .map_err(|_| ApiError::Internal)?;

    crate::audit::record(
        &state,
        user.id,
        "reset their password",
        crate::audit::category::AUTH,
        None,
        &headers,
    )
    .await;

    Ok(Envelope::ok(serde_json::json!({ "reset": true })))
}

/// `POST /v1/auth/change-email` — step 1: email an OTP to the *new* address. The email is not
/// changed here; only confirming the code (step 2) applies it.
pub async fn request_email_change(
    State(state): State<AppState>,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Envelope<serde_json::Value>>> {
    check_auth_rate_limit(&state, &headers, peer.map(|c| c.0))?;
    let user_id = require_login(&headers, &state).await?;
    let req: RequestEmailChangeRequest = parse_optional(&body)?;
    let new_email = normalize_email(req.new_email)?;
    let password = req
        .password
        .filter(|p| !p.is_empty())
        .ok_or_else(|| ApiError::BadRequest("password is required".into()))?;

    // Per-account cap: bounds password guessing with a stolen session, and OTP mail to third parties.
    if !state.rate_limiter().check(
        &format!("emailchange:{user_id}"),
        "email_change_request",
        5,
        std::time::Duration::from_secs(60 * 60),
    ) {
        return Err(ApiError::TooManyRequests(
            "too many attempts — wait a while and try again".into(),
        ));
    }

    let user = state
        .store()
        .get_user(user_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::Unauthorized)?;
    verify_password(&password, &user.password_hash)
        .map_err(|_| ApiError::BadRequest("incorrect password".into()))?;

    let taken = || ApiError::BadRequest("email already registered".into());
    if new_email == user.email {
        return Err(taken());
    }
    if state
        .store()
        .find_user_by_email(&new_email)
        .await
        .map_err(|_| ApiError::Internal)?
        .is_some()
    {
        return Err(taken());
    }

    // Bound to the new address: the code can't be redeemed for a different one.
    issue_otp(
        &state,
        user.id,
        "email_change",
        &new_email,
        Some(&new_email),
    )
    .await?;
    Ok(Envelope::ok(serde_json::json!({ "sent": true })))
}

/// `POST /v1/auth/change-email/confirm` — step 2: apply the change once the new address's OTP checks out.
pub async fn confirm_email_change(
    State(state): State<AppState>,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Envelope<UserView>>> {
    check_auth_rate_limit(&state, &headers, peer.map(|c| c.0))?;
    let user_id = require_login(&headers, &state).await?;
    let req: ConfirmEmailChangeRequest = parse_optional(&body)?;
    let new_email = normalize_email(req.new_email)?;
    let code = req
        .code
        .filter(|c| !c.is_empty())
        .ok_or_else(|| ApiError::BadRequest("code is required".into()))?;

    let old_email = state
        .store()
        .get_user(user_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::Unauthorized)?
        .email;

    state
        .store()
        .verify_and_consume_otp(
            user_id,
            "email_change",
            &octo_email::hash_otp(&code),
            Some(&new_email),
        )
        .await
        .map_err(|_| ApiError::BadRequest("invalid or expired code".into()))?;

    // The unique index is the real guard: someone may have registered this address since step 1.
    let user = state
        .store()
        .update_email(user_id, &new_email)
        .await
        .map_err(|e| match e {
            octo_store::StoreError::Conflict => {
                ApiError::BadRequest("email already registered".into())
            }
            _ => ApiError::Internal,
        })?;

    crate::audit::record(
        &state,
        user_id,
        "changed their email",
        crate::audit::category::AUTH,
        Some(&new_email),
        &headers,
    )
    .await;

    let notice = octo_email::templates::email_changed_email(&new_email);
    let _ = state
        .email()
        .send(&old_email, "Your Octo login email was changed", &notice)
        .await;

    Ok(Envelope::ok(UserView {
        id: user.id,
        email: user.email,
        username: user.username,
    }))
}

/// `POST /v1/auth/logout` — invalidate the current session token server-side.
///
/// Inserts the token's SHA-256 hash into the deny-list with an expiry matching the token's own
/// `exp` claim. Subsequent requests carrying the same token will receive `401 Unauthorized` even
/// though the token's signature and expiry are still mathematically valid.
///
/// The deny-list entry is pruned automatically once `expires_at` passes (the token would fail
/// `verify_token`'s own expiry check at that point anyway).
pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<serde_json::Value>>> {
    // Extract and validate the token *before* denylisting it — also gives us the user_id and exp.
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?;

    let claims = verify_token(state.jwt_secret(), token).ok_or(ApiError::Unauthorized)?;
    let user_id = claims
        .sub
        .parse::<Uuid>()
        .map_err(|_| ApiError::Unauthorized)?;

    // Deny-list the token so it cannot be replayed.
    let token_hash = hash_token(token);
    let expires_at =
        chrono::DateTime::from_timestamp(claims.exp, 0).unwrap_or_else(chrono::Utc::now);
    state
        .store()
        .denylist_token(&token_hash, user_id, expires_at)
        .await
        .map_err(|_| ApiError::Internal)?;

    crate::audit::record(
        &state,
        user_id,
        "logged out",
        crate::audit::category::AUTH,
        None,
        &headers,
    )
    .await;

    Ok(Envelope::ok(serde_json::json!({ "message": "logged out" })))
}

// --- helpers ---------------------------------------------------------------

fn normalize_email(email: Option<String>) -> Result<String, ApiError> {
    email
        .map(|e| e.trim().to_lowercase())
        .filter(|e| e.contains('@') && e.len() >= 3)
        .ok_or_else(|| ApiError::BadRequest("a valid email is required".into()))
}

fn validate(creds: Credentials) -> Result<(String, String), ApiError> {
    let email = normalize_email(creds.email)?;
    let password = creds
        .password
        .filter(|p| p.len() >= 8)
        .ok_or_else(|| ApiError::BadRequest("password must be at least 8 characters".into()))?;
    Ok((email, password))
}

/// 3–20 chars, ASCII letters/digits/underscore/hyphen only. Case is preserved for display;
/// uniqueness is enforced case-insensitively by `users_username_unique_idx`.
/// Reserved usernames are blocked case-insensitively to prevent impersonation.
fn validate_username(input: Option<String>) -> Result<String, ApiError> {
    const RESERVED_USERNAMES: &[&str] = &[
        "admin", "root", "support", "official", "octo", "system", "me", "api",
    ];

    let username = input
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty())
        .ok_or_else(|| ApiError::BadRequest("username is required".into()))?;
    if username.len() < 3 || username.len() > 20 {
        return Err(ApiError::BadRequest(
            "username must be 3-20 characters".into(),
        ));
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(ApiError::BadRequest(
            "username may only contain letters, numbers, underscores, and hyphens".into(),
        ));
    }
    if RESERVED_USERNAMES
        .iter()
        .any(|reserved| reserved.eq_ignore_ascii_case(&username))
    {
        return Err(ApiError::BadRequest(
            "this username is not available".into(),
        ));
    }
    Ok(username)
}

/// Validate that JWT_SECRET meets the minimum length requirement.
/// HMAC-SHA256 silently accepts secrets of any length, but a short secret
/// enables trivial token forgery. This enforces a 32-byte minimum at startup.
pub fn validate_jwt_secret(secret: &[u8]) -> Result<(), String> {
    const MIN_LENGTH: usize = 32;
    if secret.len() < MIN_LENGTH {
        return Err(format!(
            "JWT_SECRET must be at least {MIN_LENGTH} bytes, got {}",
            secret.len()
        ));
    }
    Ok(())
}

fn hash_password(password: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| ApiError::Internal)
}

fn verify_password(password: &str, phc: &str) -> Result<(), ()> {
    let parsed = PasswordHash::new(phc).map_err(|_| ())?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| ())
}

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize, Deserialize)]
struct JwtHeader {
    alg: String,
    typ: String,
    kid: String,
}

fn jwt_key_id(secret: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(&Sha256::digest(secret)[..8])
}

fn b64(input: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input)
}

fn b64_decode(input: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .ok()
}

fn issue_token(secret: &[u8], user_id: Uuid, session_epoch: i32) -> Result<String, ApiError> {
    let claims = Claims {
        sub: user_id.to_string(),
        exp: now_secs() + TOKEN_TTL_SECS,
        jti: Uuid::new_v4().to_string(),
        epoch: session_epoch,
    };
    let header = b64(
        &serde_json::to_vec(&JwtHeader {
            alg: "HS256".into(),
            typ: "JWT".into(),
            kid: jwt_key_id(secret),
        })
        .map_err(|_| ApiError::Internal)?,
    );
    let payload = serde_json::to_vec(&claims).map_err(|_| ApiError::Internal)?;
    let signing_input = format!("{header}.{}", b64(&payload));
    let sig = sign_hs256(secret, signing_input.as_bytes());
    Ok(format!("{signing_input}.{sig}"))
}

/// Verify an HS256 JWT and return its claims if the signature is valid and it has not expired.
pub fn verify_token(secret: &[u8], token: &str) -> Option<Claims> {
    let mut parts = token.split('.');
    let header = parts.next()?;
    let payload = parts.next()?;
    let signature = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let header_data: JwtHeader = serde_json::from_slice(&b64_decode(header)?).ok()?;
    if header_data.alg != "HS256" || header_data.typ != "JWT" {
        return None;
    }
    let previous = std::env::var("JWT_SECRET_PREVIOUS").ok();
    let verification_secret = if header_data.kid == jwt_key_id(secret) {
        secret
    } else {
        previous
            .as_deref()
            .map(str::as_bytes)
            .filter(|previous| header_data.kid == jwt_key_id(previous))?
    };
    let signing_input = format!("{header}.{payload}");
    if !verify_hs256(verification_secret, signing_input.as_bytes(), signature) {
        return None;
    }
    let claims: Claims = serde_json::from_slice(&b64_decode(payload)?).ok()?;
    if claims.exp < now_secs() {
        return None;
    }
    Some(claims)
}

pub(crate) fn sign_hs256(secret: &[u8], input: &[u8]) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(input);
    b64(&mac.finalize().into_bytes())
}

pub(crate) fn verify_hs256(secret: &[u8], input: &[u8], signature_b64: &str) -> bool {
    let Some(sig) = b64_decode(signature_b64) else {
        return false;
    };
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(input);
    mac.verify_slice(&sig).is_ok()
}

pub(crate) fn now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// SHA-256 hex of a raw token string — used as the deny-list key.
///
/// This is the same pattern used for API key hashing in `routes/apikeys.rs`.
pub fn hash_token(token: &str) -> String {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    hex::encode(h.finalize())
}

/// Authenticate a request from its headers via the `Authorization: Bearer <jwt>` header.
/// Returns the authenticated user's id, or [`ApiError::Unauthorized`].
///
/// Checks, in order:
/// 1. Presence of the `Authorization: Bearer <token>` header.
/// 2. Valid HS256 signature and unexpired `exp` claim (`verify_token`).
/// 3. Token is **not** in the server-side deny-list (populated by `POST /v1/auth/logout`), and
///    its `epoch` matches the user's current `session_epoch` (bumped by a password change).
///    This adds one database round-trip per authenticated request. The deny-list table is indexed
///    on `(token_hash)` (primary key) so the lookup is a single index probe. In practice the
///    p99 overhead is well under 1 ms on a co-located Postgres instance; an in-memory cache is
///    worth adding only if profiling shows this is a hot path.
///
/// Used directly by protected handlers (rather than a `FromRequestParts` extractor, which trips an
/// async-trait lifetime bug on this toolchain — see notes in the repo).
pub async fn authenticate(
    headers: &axum::http::HeaderMap,
    state: &AppState,
) -> Result<Uuid, ApiError> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?;
    let claims = verify_token(state.jwt_secret(), token).ok_or(ApiError::Unauthorized)?;
    let user_id = claims
        .sub
        .parse::<Uuid>()
        .map_err(|_| ApiError::Unauthorized)?;

    // Reject tokens revoked individually (deny-list) or en masse (stale session epoch).
    let valid = state
        .store()
        .is_session_valid(&hash_token(token), user_id, claims.epoch)
        .await
        .map_err(|_| ApiError::Internal)?;
    if !valid {
        return Err(ApiError::Unauthorized);
    }

    // A stale epoch (password reset) or a deleted user revokes the token.
    let epoch = state
        .store()
        .get_session_epoch(user_id)
        .await
        .map_err(|_| ApiError::Internal)?;
    if epoch != Some(claims.epoch) {
        return Err(ApiError::Unauthorized);
    }

    Ok(user_id)
}

/// Prefix that marks an octo API key (vs a dashboard login JWT).
const API_KEY_PREFIX: &str = "octo_sk_";

/// Extract the raw bearer token (`octo_sk_…` or a JWT), if present.
fn bearer(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
}

/// SHA-256 hex of an API key (matches how keys are stored in `api_keys`).
fn hash_api_key(key: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    hex::encode(h.finalize())
}

fn has_valid_api_key_checksum(key: &str) -> bool {
    let Some((body, supplied)) = key.rsplit_once('_') else {
        return false;
    };
    supplied.len() == 8 && hash_api_key(body).starts_with(supplied)
}

/// Authorize a request to operate on `wallet_id`, accepting **either**:
/// - a dashboard login JWT whose user **owns** the wallet, or
/// - an `octo_sk_…` API key whose wallet **is** `wallet_id` (the key implies its wallet).
///
/// Returns `Ok(())` when authorized, `Unauthorized` if no/invalid credential, `NotFound` if the
/// credential is valid but not for this wallet (so we don't reveal other users' wallets).
pub async fn authorize_wallet(
    headers: &axum::http::HeaderMap,
    state: &AppState,
    wallet_id: Uuid,
) -> Result<(), ApiError> {
    authorize_wallet_scope(headers, state, wallet_id, "read").await
}

pub async fn authorize_wallet_scope(
    headers: &axum::http::HeaderMap,
    state: &AppState,
    wallet_id: Uuid,
    required_scope: &str,
) -> Result<(), ApiError> {
    let token = bearer(headers).ok_or(ApiError::Unauthorized)?;

    if let Some(_key) = token.strip_prefix(API_KEY_PREFIX) {
        if !has_valid_api_key_checksum(token) {
            return Err(ApiError::Unauthorized);
        }
        // API-key path: the key maps to exactly one wallet.
        let key = state
            .store()
            .use_api_key(&hash_api_key(token))
            .await
            .map_err(|_| ApiError::Internal)?
            .ok_or(ApiError::Unauthorized)?;
        if key.wallet_id != wallet_id {
            return Err(ApiError::NotFound);
        }
        if !key.scopes.iter().any(|scope| scope == required_scope) {
            return Err(ApiError::Forbidden("API key lacks the required scope".into()));
        }
        return Ok(());
    }

    // Login-JWT path: the user must own the wallet.
    let user_id = authenticate(headers, state).await?;
    let wallet = state.store().get_wallet(wallet_id).await?;
    if wallet.user_id != Some(user_id) {
        return Err(ApiError::NotFound);
    }
    Ok(())
}

/// Require a **dashboard login** (reject API keys). Returns the authenticated user id.
/// Used for sensitive operations (e.g. withdrawals) that must not be driven by an API key.
pub async fn require_login(
    headers: &axum::http::HeaderMap,
    state: &AppState,
) -> Result<Uuid, ApiError> {
    if let Some(tok) = bearer(headers) {
        if tok.starts_with(API_KEY_PREFIX) {
            // An API key was presented where a login is required.
            return Err(ApiError::Unauthorized);
        }
    }
    authenticate(headers, state).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"unit-test-jwt-secret";

    /// Test-only: build and sign a JWT with an arbitrary `exp`, bypassing `issue_token`'s
    /// "always TOKEN_TTL_SECS from now" policy so expiry can be tested precisely. Signs the
    /// token exactly the way `issue_token` does (same header, same `sign_hs256` call) so this
    /// only varies `exp` — it does not exercise a different code path than production tokens.
    fn issue_token_with_exp(secret: &[u8], user_id: Uuid, exp: i64) -> String {
        let claims = Claims {
            sub: user_id.to_string(),
            exp,
            jti: Uuid::new_v4().to_string(),
            epoch: 0,
        };
        let payload = serde_json::to_vec(&claims).expect("Claims always serialize");
        let header = b64(
            &serde_json::to_vec(&JwtHeader {
                alg: "HS256".into(),
                typ: "JWT".into(),
                kid: jwt_key_id(secret),
            })
            .unwrap(),
        );
        let signing_input = format!("{header}.{}", b64(&payload));
        let sig = sign_hs256(secret, signing_input.as_bytes());
        format!("{signing_input}.{sig}")
    }

    #[test]
    fn expired_token_is_rejected() {
        let user_id = Uuid::new_v4();
        let token = issue_token_with_exp(SECRET, user_id, now_secs() - 1);
        assert!(verify_token(SECRET, &token).is_none());
    }

    #[test]
    fn tampered_signature_byte_is_rejected() {
        let user_id = Uuid::new_v4();
        let token = issue_token(SECRET, user_id, 0).expect("issue_token should succeed");
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have header.payload.signature");

        let sig_bytes = b64_decode(parts[2]).expect("signature segment must be valid base64");
        for i in 0..sig_bytes.len() {
            let mut flipped = sig_bytes.clone();
            flipped[i] ^= 0x01;
            let flipped_b64 = b64(&flipped);
            let tampered = format!("{}.{}.{}", parts[0], parts[1], flipped_b64);
            assert!(
                verify_token(SECRET, &tampered).is_none(),
                "flipping byte {i} of the signature should invalidate the token"
            );
        }

        // Sanity check: the original, untampered token must still verify.
        assert!(verify_token(SECRET, &token).is_some());
    }

    #[test]
    fn tampered_payload_byte_is_rejected() {
        let user_id = Uuid::new_v4();
        let token = issue_token(SECRET, user_id, 0).expect("issue_token should succeed");
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have header.payload.signature");

        let payload_bytes = b64_decode(parts[1]).expect("payload segment must be valid base64");
        for i in 0..payload_bytes.len() {
            let mut flipped = payload_bytes.clone();
            flipped[i] ^= 0x01;
            let flipped_b64 = b64(&flipped);
            // Still syntactically valid URL-safe base64 (no padding, same charset) — just no
            // longer matches the signature that was computed over the original payload.
            let tampered = format!("{}.{}.{}", parts[0], flipped_b64, parts[2]);
            assert!(
                verify_token(SECRET, &tampered).is_none(),
                "flipping byte {i} of the payload should invalidate the token"
            );
        }

        assert!(verify_token(SECRET, &token).is_some());
    }

    #[test]
    fn non_standard_header_segment_is_rejected() {
        let user_id = Uuid::new_v4();
        let token = issue_token(SECRET, user_id, 0).expect("issue_token should succeed");
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have header.payload.signature");

        // `{"alg":"none","typ":"JWT"}` — the classic "alg: none" downgrade attempt. The
        // signature segment is irrelevant here: verify_token must reject on the header check
        // alone, before ever reaching signature verification.
        let none_header = b64(br#"{"alg":"none","typ":"JWT"}"#);
        assert_ne!(none_header, parts[0]);
        let tampered = format!("{}.{}.{}", none_header, parts[1], parts[2]);
        assert!(verify_token(SECRET, &tampered).is_none());

        // Also confirm a header that isn't even valid JSON (garbage bytes) is rejected the
        // same way, and doesn't panic.
        let garbage_header = b64(b"not-a-jwt-header");
        assert_ne!(garbage_header, parts[0]);
        let tampered = format!("{}.{}.{}", garbage_header, parts[1], parts[2]);
        assert!(verify_token(SECRET, &tampered).is_none());

        assert!(verify_token(SECRET, &token).is_some());
    }

    #[test]
    fn validate_jwt_secret_rejects_empty_secret() {
        let result = validate_jwt_secret(&[]);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_lowercase()
            .contains("minimum length"));
    }

    #[test]
    fn validate_jwt_secret_rejects_secret_under_32_bytes() {
        let result = validate_jwt_secret(b"too-short");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_lowercase()
            .contains("minimum length"));

        let result = validate_jwt_secret(b"31-byte-secret-still-too-shor");
        assert!(result.is_err());
    }

    #[test]
    fn validate_jwt_secret_accepts_32_byte_secret() {
        let result = validate_jwt_secret(b"exactly-32-byte-secret-for-hmac");
        assert!(result.is_ok());

        let result = validate_jwt_secret(b"more-than-32-bytes-is-also-fine!!");
        assert!(result.is_ok());
    }

    #[test]
    fn update_username_rejects_reserved_names() {
        let reserved = ["admin", "root", "support", "official", "octo", "system", "me", "api"];
        for name in reserved.iter() {
            let result = validate_username(Some(name.to_string()));
            assert!(
                result.is_err(),
                "validate_username should reject reserved name: {}",
                name
            );
        }
    }

    #[test]
    fn update_username_still_accepts_valid_non_reserved_names() {
        let valid = ["alice", "bob123", "user_name", "test-user"];
        for name in valid.iter() {
            let result = validate_username(Some(name.to_string()));
            assert!(
                result.is_ok(),
                "validate_username should accept valid name: {}",
                name
            );
            assert_eq!(result.unwrap(), *name);
        }
    }

    #[test]
    fn update_username_reserved_check_is_case_insensitive() {
        let result = validate_username(Some("AdMiN".to_string()));
        assert!(result.is_err());

        let result = validate_username(Some("SUPPORT".to_string()));
        assert!(result.is_err());

        let result = validate_username(Some("Root".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn validate_credentials_rejects_short_password() {
        let creds = Credentials {
            email: Some("test@example.com".to_string()),
            password: Some("short".to_string()),
        };
        let result = validate(creds);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .message
            .to_lowercase()
            .contains("password must be"));
    }

    #[test]
    fn validate_credentials_accepts_8_char_password() {
        let creds = Credentials {
            email: Some("test@example.com".to_string()),
            password: Some("12345678".to_string()),
        };
        let result = validate(creds);
        assert!(result.is_ok());
        let (email, password) = result.unwrap();
        assert_eq!(email, "test@example.com");
        assert_eq!(password, "12345678");
    }

    #[test]
    fn validate_credentials_requires_valid_email() {
        let creds = Credentials {
            email: Some("invalid-email".to_string()),
            password: Some("validpassword".to_string()),
        };
        let result = validate(creds);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .message
            .to_lowercase()
            .contains("valid email"));

        let creds = Credentials {
            email: Some("a@b".to_string()),
            password: Some("validpassword".to_string()),
        };
        let result = validate(creds);
        assert!(result.is_ok());
    }

    #[test]
    fn token_includes_unique_jti_to_prevent_collision() {
        let user_id = Uuid::new_v4();
        let token1 = issue_token(SECRET, user_id).expect("issue_token should succeed");
        let token2 = issue_token(SECRET, user_id).expect("issue_token should succeed");

        assert_ne!(token1, token2, "tokens for same user issued in quick succession should differ");

        let claims1 = verify_token(SECRET, &token1).expect("token1 should verify");
        let claims2 = verify_token(SECRET, &token2).expect("token2 should verify");
        assert_ne!(
            claims1.jti, claims2.jti,
            "each token should have a unique jti"
        );
        assert_eq!(
            claims1.sub, claims2.sub,
            "but both should be for the same user"
        );
    }

    #[test]
    fn token_expires_after_ttl() {
        let user_id = Uuid::new_v4();
        let token = issue_token(SECRET, user_id).expect("issue_token should succeed");
        let claims = verify_token(SECRET, &token).expect("token should verify");

        let now = now_secs();
        let ttl_secs = claims.exp - now;

        assert!(ttl_secs > 0, "token should have positive TTL");
        assert!(
            ttl_secs >= 7 * 24 * 60 * 60 - 1 && ttl_secs <= 7 * 24 * 60 * 60 + 1,
            "token TTL should be 7 days (within ±1 second for timing variance)"
        );
    }

    #[test]
    fn hash_token_produces_consistent_output() {
        let token = "test.jwt.token";
        let hash1 = hash_token(token);
        let hash2 = hash_token(token);

        assert_eq!(
            hash1, hash2,
            "hashing the same token should produce the same hash"
        );
        assert_eq!(
            hash1.len(),
            64,
            "SHA-256 hex should be 64 characters"
        );
    }

    #[test]
    fn different_tokens_produce_different_hashes() {
        let token1 = "test.jwt.token1";
        let token2 = "test.jwt.token2";
        let hash1 = hash_token(token1);
        let hash2 = hash_token(token2);

        assert_ne!(
            hash1, hash2,
            "different tokens should produce different hashes"
        );
    }

    #[test]
    fn verify_token_rejects_malformed_tokens() {
        assert!(verify_token(SECRET, "").is_none());
        assert!(verify_token(SECRET, "not.a.token").is_none());
        assert!(verify_token(SECRET, "a.b").is_none());
        assert!(verify_token(SECRET, "a.b.c.d").is_none());
    }

    #[test]
    fn verify_token_rejects_tokens_signed_with_different_secret() {
        let user_id = Uuid::new_v4();
        let token = issue_token(SECRET, user_id).expect("issue_token should succeed");

        let other_secret = b"different-secret-at-least-32-bytes-long!";
        assert!(verify_token(other_secret, &token).is_none());
    }
}
