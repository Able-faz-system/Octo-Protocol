//! Integration tests for the forgot-password flow (request + confirm, OTP-gated).
//!
//! Requires Postgres via `DATABASE_URL`. Skips gracefully if absent.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use octo_api::{build_router, AppState};
use octo_store::Store;
use octo_wallet_core::StellarNetwork;
use std::sync::Once;
use std::time::Duration;
use tower::ServiceExt;

static LOAD_ENV: Once = Once::new();

fn database_url() -> Option<String> {
    LOAD_ENV.call_once(|| {
        let _ = dotenvy::dotenv();
    });
    std::env::var("DATABASE_URL").ok()
}

async fn test_state() -> Option<AppState> {
    let url = database_url()?;
    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");
    Some(
        AppState::new(
            store,
            [42u8; 32],
            StellarNetwork::Testnet,
            "https://horizon-testnet.stellar.org".into(),
            None,
            octo_email::EmailSender::new_captured(),
        )
        .with_jwt_secret(b"test-jwt-secret-at-least-16-bytes".to_vec()),
    )
}

fn unique_email() -> String {
    format!("reset-{}@octo.test", uuid::Uuid::new_v4().simple())
}

fn post_json(uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// Send a request and return `(status, body json)`.
async fn send(app: &axum::Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or_default())
}

async fn request_reset(app: &axum::Router, email: &str) -> (StatusCode, serde_json::Value) {
    send(
        app,
        post_json(
            "/v1/auth/request-password-reset",
            serde_json::json!({ "email": email }),
        ),
    )
    .await
}

async fn confirm_reset(
    app: &axum::Router,
    email: &str,
    code: &str,
    new_password: &str,
) -> (StatusCode, serde_json::Value) {
    send(
        app,
        post_json(
            "/v1/auth/confirm-password-reset",
            serde_json::json!({ "email": email, "code": code, "new_password": new_password }),
        ),
    )
    .await
}

/// The reset OTP is emailed from a background task, so wait for one that differs from `previous`
/// (the signup code, which is also captured for the same address).
async fn new_otp(state: &AppState, email: &str, previous: Option<&str>) -> String {
    for _ in 0..100 {
        if let Some(code) = state.email().last_otp_for(email) {
            if Some(code.as_str()) != previous {
                return code;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no password-reset OTP was emailed");
}

async fn me_status(app: &axum::Router, token: &str) -> StatusCode {
    let req = Request::builder()
        .uri("/v1/auth/me")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    send(app, req).await.0
}

#[tokio::test]
async fn request_password_reset_returns_the_same_response_for_an_existing_and_a_nonexistent_email()
{
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let email = unique_email();
    common::signup_and_verify(&app, &state, &email).await;

    let existing = request_reset(&app, &email).await;
    let missing = request_reset(&app, &unique_email()).await;

    assert_eq!(existing.0, StatusCode::OK);
    assert_eq!(
        existing, missing,
        "status and body must not reveal the account"
    );
}

#[tokio::test]
async fn confirm_password_reset_rejects_a_wrong_or_expired_otp() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let email = unique_email();
    common::signup_and_verify(&app, &state, &email).await;
    let signup_code = state.email().last_otp_for(&email).unwrap();

    request_reset(&app, &email).await;
    let code = new_otp(&state, &email, Some(&signup_code)).await;

    let wrong = if code == "000000" { "000001" } else { "000000" };
    let (status, body) = confirm_reset(&app, &email, wrong, "brand-new-pass1").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "invalid or expired code");

    // Expire the (still-correct) code: it must now be rejected too.
    sqlx::query(
        "UPDATE email_otps SET expires_at = now() - interval '1 minute' \
         WHERE purpose = 'password_reset' AND user_id = (SELECT id FROM users WHERE email = $1)",
    )
    .bind(&email)
    .execute(state.store().pool())
    .await
    .unwrap();
    let (status, body) = confirm_reset(&app, &email, &code, "brand-new-pass1").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "invalid or expired code");
}

#[tokio::test]
async fn confirm_password_reset_succeeds_and_invalidates_prior_sessions() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let email = unique_email();
    let old_token = common::signup_and_verify(&app, &state, &email).await;
    let signup_code = state.email().last_otp_for(&email).unwrap();
    assert_eq!(me_status(&app, &old_token).await, StatusCode::OK);

    request_reset(&app, &email).await;
    let code = new_otp(&state, &email, Some(&signup_code)).await;
    let (status, _) = confirm_reset(&app, &email, &code, "brand-new-pass1").await;
    assert_eq!(status, StatusCode::OK);

    // The pre-reset session is dead, and the code cannot be replayed.
    assert_eq!(me_status(&app, &old_token).await, StatusCode::UNAUTHORIZED);
    let (status, _) = confirm_reset(&app, &email, &code, "another-pass-99").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // The old password no longer works; the new one does and yields a live session.
    let login = |password: &str| {
        post_json(
            "/v1/auth/login",
            serde_json::json!({ "email": email, "password": password }),
        )
    };
    assert_eq!(
        send(&app, login("supersecret123")).await.0,
        StatusCode::BAD_REQUEST
    );
    let (status, body) = send(&app, login("brand-new-pass1")).await;
    assert_eq!(status, StatusCode::OK);
    let new_token = body["data"]["token"].as_str().unwrap();
    assert_eq!(me_status(&app, new_token).await, StatusCode::OK);
}

#[tokio::test]
async fn request_password_reset_is_rate_limited() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state);
    let email = unique_email();

    for _ in 0..10 {
        assert_eq!(request_reset(&app, &email).await.0, StatusCode::OK);
    }
    assert_eq!(
        request_reset(&app, &email).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
}
