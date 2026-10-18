//! Integration tests for `POST /v1/auth/change-password`.
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

// Matches the password `common::signup_and_verify` signs up with.
const PASSWORD: &str = "supersecret123";

async fn test_state() -> Option<AppState> {
    LOAD_ENV.call_once(|| {
        let _ = dotenvy::dotenv();
    });
    let url = std::env::var("DATABASE_URL").ok()?;
    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");
    Some(AppState::new(
        store,
        [42u8; 32],
        StellarNetwork::Testnet,
        "https://horizon-testnet.stellar.org".into(),
        None,
        octo_email::EmailSender::new_captured(),
    ))
}

async fn setup() -> Option<(axum::Router, AppState, String, String)> {
    let state = test_state().await?;
    let app = build_router(state.clone());
    let email = format!("pw-{}@octo.test", uuid::Uuid::new_v4().simple());
    let token = common::signup_and_verify(&app, &state, &email).await;
    Some((app, state, email, token))
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let b = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&b).unwrap()
}

async fn change_password(
    app: &axum::Router,
    token: &str,
    current: &str,
    new: &str,
) -> axum::response::Response {
    let body = serde_json::json!({ "current_password": current, "new_password": new });
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/change-password")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn me_status(app: &axum::Router, token: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .uri("/v1/auth/me")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

async fn login_status(app: &axum::Router, email: &str, password: &str) -> StatusCode {
    let body = serde_json::json!({ "email": email, "password": password });
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn change_password_requires_the_correct_current_password() {
    let Some((app, _state, _email, token)) = setup().await else {
        return;
    };
    let resp = change_password(&app, &token, "wrong-password", "brand-new-pass").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    // A failed attempt must not revoke the session.
    assert_eq!(me_status(&app, &token).await, StatusCode::OK);

    // A bare session token without the current password is not enough.
    let resp = change_password(&app, &token, "", "brand-new-pass").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // No session at all → 401.
    let resp = change_password(&app, "not-a-token", PASSWORD, "brand-new-pass").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn change_password_invalidates_tokens_issued_before_the_change() {
    let Some((app, _state, email, token1)) = setup().await else {
        return;
    };
    // A second device's session, issued before the change.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "email": email, "password": PASSWORD }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let token2 = body_json(resp).await["data"]["token"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(me_status(&app, &token2).await, StatusCode::OK);

    let resp = change_password(&app, &token1, PASSWORD, "brand-new-pass").await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Both the presenting token and the other device's token are revoked.
    assert_eq!(me_status(&app, &token1).await, StatusCode::UNAUTHORIZED);
    assert_eq!(me_status(&app, &token2).await, StatusCode::UNAUTHORIZED);
    // And the old password no longer logs in.
    assert_eq!(
        login_status(&app, &email, PASSWORD).await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn change_password_issues_a_valid_new_token() {
    let Some((app, _state, email, token)) = setup().await else {
        return;
    };
    let resp = change_password(&app, &token, PASSWORD, "brand-new-pass").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let new_token = json["data"]["token"].as_str().unwrap().to_string();
    assert_eq!(json["data"]["user"]["email"], email.as_str());

    assert_ne!(new_token, token);
    assert_eq!(me_status(&app, &new_token).await, StatusCode::OK);
    assert_eq!(
        login_status(&app, &email, "brand-new-pass").await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn change_password_is_rate_limited() {
    let Some((app, _state, _email, token)) = setup().await else {
        return;
    };
    // The per-user cap (5 / 15 min) holds even if each attempt came from a different IP.
    for i in 0..5 {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/change-password")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .header("x-forwarded-for", format!("10.0.0.{i}"))
                    .body(Body::from(
                        r#"{"current_password":"wrong-password","new_password":"brand-new-pass"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
    let resp = change_password(&app, &token, PASSWORD, "brand-new-pass").await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    // The rate-limited attempt did not change anything.
    assert_eq!(me_status(&app, &token).await, StatusCode::OK);
}
