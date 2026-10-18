//! Tests for apikeys route error consistency to prevent wallet enumeration (issue #245).

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

fn delete_auth(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
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
async fn apikeys_routes_return_identical_error_shape_for_nonexistent_and_unowned_wallet() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;

    // Use a fake wallet ID that doesn't exist
    let fake_wallet_id = Uuid::new_v4();

    // Test generate_key
    let resp = app
        .clone()
        .oneshot(post_auth(
            &format!("/v1/wallets/{}/api-key", fake_wallet_id),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "generate_key should return 404 for nonexistent wallet"
    );
    let generate_error = body_json(resp).await;

    // Test get_key
    let resp = app
        .clone()
        .oneshot(get_auth(
            &format!("/v1/wallets/{}/api-key", fake_wallet_id),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "get_key should return 404 for nonexistent wallet"
    );
    let get_error = body_json(resp).await;

    // Test delete_key
    let resp = app
        .clone()
        .oneshot(delete_auth(
            &format!("/v1/wallets/{}/api-key", fake_wallet_id),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "delete_key should return 404 for nonexistent wallet"
    );
    let delete_error = body_json(resp).await;

    // All three should have the same error response shape
    assert_eq!(
        generate_error["error"]["code"], get_error["error"]["code"],
        "generate_key and get_key should have same error code"
    );
    assert_eq!(
        generate_error["error"]["code"], delete_error["error"]["code"],
        "delete_key should have same error code as others"
    );
}

#[tokio::test]
async fn apikeys_routes_succeed_for_the_true_owner() {
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

    // generate_key should succeed for owner
    let resp = app
        .clone()
        .oneshot(post_auth(
            &format!("/v1/wallets/{}/api-key", wallet_id),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "generate_key should succeed for owner");

    // get_key should succeed for owner
    let resp = app
        .clone()
        .oneshot(get_auth(
            &format!("/v1/wallets/{}/api-key", wallet_id),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "get_key should succeed for owner");

    // delete_key should succeed for owner
    let resp = app
        .clone()
        .oneshot(delete_auth(
            &format!("/v1/wallets/{}/api-key", wallet_id),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "delete_key should succeed for owner");
}

#[tokio::test]
async fn apikeys_nonexistent_and_unowned_wallet_return_same_error() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let token1 = auth_token(&app, &state).await;
    let token2 = auth_token(&app, &state).await;

    // Create a wallet owned by user 1
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

    // User 2 tries to access the wallet - should get 404
    let resp = app
        .clone()
        .oneshot(get_auth(
            &format!("/v1/wallets/{}/api-key", wallet_id),
            &token2,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "unowned wallet should return 404, not 403"
    );

    // Trying to generate a key for unowned wallet should also be 404
    let resp = app
        .clone()
        .oneshot(post_auth(
            &format!("/v1/wallets/{}/api-key", wallet_id),
            &token2,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "generate_key for unowned wallet should be 404");
}
