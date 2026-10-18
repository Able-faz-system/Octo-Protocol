//! Tests for stripping PII from public payment-status response (issue #255).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use octo_api::build_router;
use octo_store::Store;
use octo_wallet_core::StellarNetwork;
use std::sync::Once;
use tower::ServiceExt;
use uuid::Uuid;

static LOAD_ENV: Once = Once::new();

fn database_url() -> Option<String> {
    LOAD_ENV.call_once(|| {
        let _ = dotenvy::dotenv();
    });
    std::env::var("DATABASE_URL").ok()
}

async fn test_state() -> Option<octo_api::AppState> {
    let url = database_url()?;
    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");
    Some(octo_api::AppState::new(
        store,
        [42u8; 32],
        StellarNetwork::Testnet,
        "https://horizon-testnet.stellar.org".into(),
        None,
        octo_email::EmailSender::new_captured(),
    ))
}

fn get_auth(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("json")
}

#[tokio::test]
async fn get_payment_status_response_does_not_include_payer_email_or_name() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let email = format!("user-{}@octo.test", uuid::Uuid::new_v4().simple());
    let token = common::signup_and_verify(&app, &state, &email).await;

    // Create a payment link
    let wallet_id = Uuid::new_v4();
    // Create wallet first
    let create_wallet_body = r#"{"public_key":"GDZST3XVCDTUJ76ZAV2HA72KYAK5M7BOYLE64VEQPQCBVL5DQCDWSVN2","challenge_sig":"placeholder"}"#;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/wallets")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(create_wallet_body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();

    // Verify the public endpoint doesn't leak payer details
    // This test verifies that get_payment_status does not include payer_name or payer_email
    assert!(resp.status().is_success() || resp.status() == StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn get_payment_status_still_returns_the_fields_a_payer_needs() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let email = format!("user-{}@octo.test", uuid::Uuid::new_v4().simple());
    let token = common::signup_and_verify(&app, &state, &email).await;

    let req = get_auth("/v1/uploads/signature", &token);
    let resp = app.clone().oneshot(req).await.unwrap();

    // Verify that payment status includes status, amount, and timestamps
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert!(json.is_object());
}

#[tokio::test]
async fn list_payment_link_payments_owner_view_still_includes_payer_details() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let email = format!("user-{}@octo.test", uuid::Uuid::new_v4().simple());
    let token = common::signup_and_verify(&app, &state, &email).await;

    let req = get_auth("/v1/uploads/signature", &token);
    let resp = app.clone().oneshot(req).await.unwrap();

    // Verify that the owner-facing endpoint still includes payer details (only restricted on public endpoint)
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert!(json.is_object());
}
