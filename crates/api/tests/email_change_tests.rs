//! Integration tests for the OTP-gated email-change flow (request → confirm).
//!
//! Requires Postgres via `DATABASE_URL`. Skips gracefully if absent.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use octo_api::{build_router, AppState};
use octo_store::Store;
use octo_wallet_core::StellarNetwork;
use std::sync::Once;
use tower::ServiceExt;

static LOAD_ENV: Once = Once::new();

const PASSWORD: &str = "supersecret123";

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
    format!("chg-{}@octo.test", uuid::Uuid::new_v4().simple())
}

fn req(method: &str, uri: &str, token: Option<&str>, body: serde_json::Value) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    b.body(Body::from(body.to_string())).unwrap()
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

async fn request_change(
    app: &axum::Router,
    token: &str,
    new_email: &str,
    password: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let body = serde_json::json!({ "new_email": new_email, "password": password });
    send(app, req("POST", "/v1/auth/change-email", Some(token), body)).await
}

async fn confirm_change(
    app: &axum::Router,
    token: &str,
    new_email: &str,
    code: &str,
) -> (StatusCode, serde_json::Value) {
    let body = serde_json::json!({ "new_email": new_email, "code": code });
    send(
        app,
        req("POST", "/v1/auth/change-email/confirm", Some(token), body),
    )
    .await
}

async fn current_email(app: &axum::Router, token: &str) -> String {
    let (_, body) = send(
        app,
        req("GET", "/v1/auth/me", Some(token), serde_json::Value::Null),
    )
    .await;
    body["data"]["email"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn request_email_change_requires_the_current_password() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let email = unique_email();
    let token = common::signup_and_verify(&app, &state, &email).await;
    let new_email = unique_email();

    let (status, _) = request_change(&app, &token, &new_email, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = request_change(&app, &token, &new_email, Some("not-my-password")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "incorrect password");
    assert!(
        state.email().last_otp_for(&new_email).is_none(),
        "no code may be sent without the password"
    );

    // With the password a code goes to the NEW address — and the email is still unchanged.
    let (status, _) = request_change(&app, &token, &new_email, Some(PASSWORD)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(state.email().last_otp_for(&new_email).is_some());
    assert_eq!(current_email(&app, &token).await, email);
}

#[tokio::test]
async fn confirm_email_change_rejects_a_wrong_otp() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let email = unique_email();
    let token = common::signup_and_verify(&app, &state, &email).await;
    let new_email = unique_email();
    request_change(&app, &token, &new_email, Some(PASSWORD)).await;
    let code = state.email().last_otp_for(&new_email).unwrap();

    let wrong = if code == "000000" { "000001" } else { "000000" };
    let (status, body) = confirm_change(&app, &token, &new_email, wrong).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "invalid or expired code");

    // A correct code is bound to the address it was sent to: it can't confirm a different one.
    let other = unique_email();
    let (status, _) = confirm_change(&app, &token, &other, &code).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(current_email(&app, &token).await, email);
}

#[tokio::test]
async fn confirm_email_change_rejects_a_new_email_already_registered_to_another_account() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let email = unique_email();
    let token = common::signup_and_verify(&app, &state, &email).await;

    // Step 1 already refuses an address that is taken.
    let taken = unique_email();
    common::signup_and_verify(&app, &state, &taken).await;
    let (status, body) = request_change(&app, &token, &taken, Some(PASSWORD)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "email already registered");

    // Race: the address is free at step 1 but registered before the code is confirmed.
    let racing = unique_email();
    request_change(&app, &token, &racing, Some(PASSWORD)).await;
    let code = state.email().last_otp_for(&racing).unwrap();
    common::signup_and_verify(&app, &state, &racing).await;
    let (status, body) = confirm_change(&app, &token, &racing, &code).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "email already registered");
    assert_eq!(current_email(&app, &token).await, email);
}

#[tokio::test]
async fn confirm_email_change_updates_the_login_identity_and_audit_logs_it() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let email = unique_email();
    let token = common::signup_and_verify(&app, &state, &email).await;
    let new_email = unique_email();

    request_change(&app, &token, &new_email, Some(PASSWORD)).await;
    let code = state.email().last_otp_for(&new_email).unwrap();
    let (status, body) = confirm_change(&app, &token, &new_email, &code).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["email"], new_email.as_str());
    assert_eq!(current_email(&app, &token).await, new_email);

    // The code is single-use.
    let (status, _) = confirm_change(&app, &token, &new_email, &code).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Login identity moved: the new address signs in, the old one no longer does.
    let login = |e: &str| {
        req(
            "POST",
            "/v1/auth/login",
            None,
            serde_json::json!({ "email": e, "password": PASSWORD }),
        )
    };
    assert_eq!(send(&app, login(&new_email)).await.0, StatusCode::OK);
    assert_eq!(send(&app, login(&email)).await.0, StatusCode::BAD_REQUEST);

    let (_, logs) = send(
        &app,
        req(
            "GET",
            "/v1/audit-logs",
            Some(&token),
            serde_json::Value::Null,
        ),
    )
    .await;
    let logged = logs["data"]
        .as_array()
        .unwrap()
        .iter()
        .any(|l| l["action"] == "changed their email" && l["target"] == new_email.as_str());
    assert!(logged, "email change must be audit-logged: {logs}");
}
