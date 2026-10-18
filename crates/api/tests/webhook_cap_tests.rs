//! Tests for webhook endpoint capping per wallet (issue #246).

mod common;

use axum::http::{Request, StatusCode};
use axum::body::Body;
use octo_api::{build_router, AppState};
use octo_store::Store;
use octo_wallet_core::StellarNetwork;
use std::sync::Once;
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

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("json")
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

fn post_json_auth(uri: &str, token: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
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
    let email = format!("test-{}@octo.test", uuid::Uuid::new_v4().simple());
    common::signup_and_verify(app, state, &email).await
}

#[tokio::test]
async fn create_webhook_succeeds_up_to_the_cap() {
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

    // Create webhooks up to the cap (assume cap is 10)
    for i in 0..10 {
        let webhook_body = serde_json::json!({
            "endpoint": format!("https://webhook.test/{}", i),
            "events": ["deposit"]
        }).to_string();
        let resp = app
            .clone()
            .oneshot(post_json_auth(
                &format!("/v1/wallets/{}/webhooks", wallet_id),
                &token,
                &webhook_body,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED, "webhook {} should succeed", i);
    }
}

#[tokio::test]
async fn create_webhook_rejects_once_the_per_wallet_cap_is_reached() {
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

    // Create webhooks up to the cap (assume cap is 10)
    for i in 0..10 {
        let webhook_body = serde_json::json!({
            "endpoint": format!("https://webhook.test/{}", i),
            "events": ["deposit"]
        }).to_string();
        let resp = app
            .clone()
            .oneshot(post_json_auth(
                &format!("/v1/wallets/{}/webhooks", wallet_id),
                &token,
                &webhook_body,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    // The 11th webhook should be rejected with 400 BadRequest
    let webhook_body = serde_json::json!({
        "endpoint": "https://webhook.test/over-cap",
        "events": ["deposit"]
    }).to_string();
    let resp = app
        .clone()
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{}/webhooks", wallet_id),
            &token,
            &webhook_body,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "webhook cap should be enforced");
    let j = body_json(resp).await;
    assert!(
        j["error"]["message"]
            .as_str()
            .unwrap()
            .contains("webhook endpoint limit"),
        "error message should mention webhook endpoint limit"
    );
}

#[tokio::test]
async fn delete_webhook_frees_a_slot_under_the_cap() {
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

    // Create 10 webhooks (at cap)
    let mut webhook_ids = vec![];
    for i in 0..10 {
        let webhook_body = serde_json::json!({
            "endpoint": format!("https://webhook.test/{}", i),
            "events": ["deposit"]
        }).to_string();
        let resp = app
            .clone()
            .oneshot(post_json_auth(
                &format!("/v1/wallets/{}/webhooks", wallet_id),
                &token,
                &webhook_body,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let webhook_id = body_json(resp).await["data"]["id"]
            .as_str()
            .unwrap()
            .to_string();
        webhook_ids.push(webhook_id);
    }

    // Verify cap is reached
    let webhook_body = serde_json::json!({
        "endpoint": "https://webhook.test/over-cap",
        "events": ["deposit"]
    }).to_string();
    let resp = app
        .clone()
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{}/webhooks", wallet_id),
            &token,
            &webhook_body,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "cap should be reached");

    // Delete the first webhook
    let resp = app
        .clone()
        .oneshot(delete_auth(
            &format!("/v1/wallets/{}/webhooks/{}", wallet_id, webhook_ids[0]),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "deletion should succeed");

    // Now we should be able to create one more webhook
    let webhook_body = serde_json::json!({
        "endpoint": "https://webhook.test/new-after-delete",
        "events": ["deposit"]
    }).to_string();
    let resp = app
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{}/webhooks", wallet_id),
            &token,
            &webhook_body,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "new webhook should succeed after deletion");
}
