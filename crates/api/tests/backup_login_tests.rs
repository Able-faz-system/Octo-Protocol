//! Tests for requiring dashboard login to fetch encrypted wallet backup (issue #244).

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

async fn generate_api_key(app: &axum::Router, wallet_id: &str, token: &str) -> String {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&format!("/v1/wallets/{}/api-key", wallet_id))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let j = body_json(resp).await;
    j["data"]["api_key"].as_str().unwrap().to_string()
}

async fn auth_token(app: &axum::Router, state: &AppState) -> String {
    let email = format!("test-{}@octo.test", Uuid::new_v4().simple());
    common::signup_and_verify(app, state, &email).await
}

#[tokio::test]
async fn get_backup_rejects_api_key_even_for_the_owning_wallet() {
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

    // Generate an API key for the wallet
    let api_key = generate_api_key(&app, &wallet_id, &token).await;

    // Try to get backup with the API key - should be rejected
    let resp = app
        .clone()
        .oneshot(get_auth(
            &format!("/v1/wallets/{}/backup", wallet_id),
            &api_key,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "get_backup should reject API key authentication"
    );
}

#[tokio::test]
async fn get_backup_succeeds_with_owner_login_jwt() {
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

    // Get backup with the owner's JWT - should succeed
    let resp = app
        .clone()
        .oneshot(get_auth(
            &format!("/v1/wallets/{}/backup", wallet_id),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "get_backup should succeed with owner JWT"
    );
    let j = body_json(resp).await;
    assert!(j["data"]["encrypted_backup"].is_string(), "should return encrypted_backup");
}

#[tokio::test]
async fn get_backup_rejects_non_owner_login_jwt() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let token1 = auth_token(&app, &state).await;
    let token2 = auth_token(&app, &state).await;

    // Create a wallet for user 1
    let resp = app
        .clone()
        .oneshot(create_wallet_req(&app, &token1).await)
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // User 2 tries to get backup - should be rejected
    let resp = app
        .clone()
        .oneshot(get_auth(
            &format!("/v1/wallets/{}/backup", wallet_id),
            &token2,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "non-owner should not be able to get backup"
    );
}
