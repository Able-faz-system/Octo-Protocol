//! Tests for consolidated list-endpoint limit validation (issue #243).

mod common;

use axum::http::{Request, StatusCode};
use axum::body::Body;
use octo_api::{build_router, AppState};
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

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("json")
}

fn get_auth(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn post_auth(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

async fn create_wallet_req(app: &axum::Router, token: &str) -> Request<Body> {
    let kp = stellar_base::crypto::DalekKeyPair::random().unwrap();
    let body = common::wallet_body(app, token, &kp).await;
    Request::builder()
        .method("POST")
        .uri("/v1/wallets")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body))
        .unwrap()
}

async fn auth_token(app: &axum::Router, state: &AppState) -> String {
    let email = format!("test-{}@octo.test", Uuid::new_v4().simple());
    common::signup_and_verify(app, state, &email).await
}

#[tokio::test]
async fn validated_limit_rejects_zero_and_negative() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;

    // Create a wallet
    let resp = app
        .clone()
        .oneshot(create_wallet_req(&app, &token).await)
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Test wallets list with limit=0
    let resp = app
        .clone()
        .oneshot(get_auth(
            &format!("/v1/wallets?limit=0"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "limit=0 should be rejected");

    // Test wallets list with negative limit
    let resp = app
        .clone()
        .oneshot(get_auth(
            &format!("/v1/wallets?limit=-1"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "negative limit should be rejected");

    // Test addresses list with limit=0
    let resp = app
        .clone()
        .oneshot(get_auth(
            &format!("/v1/wallets/{}/addresses?limit=0", wallet_id),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "addresses limit=0 should be rejected");
}

#[tokio::test]
async fn validated_limit_rejects_above_max() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;

    // Create a wallet
    let resp = app
        .clone()
        .oneshot(create_wallet_req(&app, &token).await)
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Test wallets list with limit above max (assume max is 1000)
    let resp = app
        .clone()
        .oneshot(get_auth(
            &format!("/v1/wallets?limit=10000"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "limit above max should be rejected");

    // Test addresses list with limit above max
    let resp = app
        .clone()
        .oneshot(get_auth(
            &format!("/v1/wallets/{}/addresses?limit=10000", wallet_id),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "addresses limit above max should be rejected");
}

#[tokio::test]
async fn validated_limit_defaults_when_absent() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;

    // Create a wallet
    let resp = app
        .clone()
        .oneshot(create_wallet_req(&app, &token).await)
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Test wallets list without limit parameter
    let resp = app
        .clone()
        .oneshot(get_auth("/v1/wallets", &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "wallets list should use default limit");
    let j = body_json(resp).await;
    assert!(j["data"].is_array(), "should return data array");

    // Test addresses list without limit parameter
    let resp = app
        .clone()
        .oneshot(get_auth(
            &format!("/v1/wallets/{}/addresses", wallet_id),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "addresses list should use default limit");
    let j = body_json(resp).await;
    assert!(j["data"].is_array(), "should return data array");
}

#[tokio::test]
async fn list_wallets_respects_limit_validation() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;

    // Create a wallet
    let resp = app
        .clone()
        .oneshot(create_wallet_req(&app, &token).await)
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Valid limit should work
    let resp = app
        .clone()
        .oneshot(get_auth("/v1/wallets?limit=10", &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "valid limit should work");
}

#[tokio::test]
async fn list_addresses_respects_limit_validation() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;

    // Create a wallet
    let resp = app
        .clone()
        .oneshot(create_wallet_req(&app, &token).await)
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Valid limit should work
    let resp = app
        .clone()
        .oneshot(get_auth(
            &format!("/v1/wallets/{}/addresses?limit=10", wallet_id),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "valid limit should work for addresses");
}

#[tokio::test]
async fn list_payment_links_respects_limit_validation() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;

    // Create a wallet
    let resp = app
        .clone()
        .oneshot(create_wallet_req(&app, &token).await)
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Invalid limit should be rejected
    let resp = app
        .clone()
        .oneshot(get_auth(
            &format!("/v1/wallets/{}/payment-links?limit=-1", wallet_id),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "payment links should validate limit");

    // Valid limit should work
    let resp = app
        .clone()
        .oneshot(get_auth(
            &format!("/v1/wallets/{}/payment-links?limit=10", wallet_id),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "valid limit should work for payment links");
}

#[tokio::test]
async fn list_sponsored_transactions_respects_limit_validation() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;

    // Create a wallet
    let resp = app
        .clone()
        .oneshot(create_wallet_req(&app, &token).await)
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Invalid limit should be rejected
    let resp = app
        .clone()
        .oneshot(get_auth(
            &format!("/v1/wallets/{}/sponsored-transactions?limit=-1", wallet_id),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "sponsored transactions should validate limit");

    // Valid limit should work
    let resp = app
        .clone()
        .oneshot(get_auth(
            &format!("/v1/wallets/{}/sponsored-transactions?limit=10", wallet_id),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "valid limit should work for sponsored transactions");
}
