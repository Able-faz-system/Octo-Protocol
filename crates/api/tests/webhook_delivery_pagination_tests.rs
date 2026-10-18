//! Tests for issue #247: Add pagination to webhook deliveries

mod common;

use axum::http::StatusCode;
use axum::{body::Body, http::Request};
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
    let master_key = [42u8; 32];
    Some(AppState::new(
        store,
        master_key,
        StellarNetwork::Testnet,
        "https://horizon-testnet.stellar.org".into(),
        None,
        octo_email::EmailSender::new_captured(),
    ))
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

fn post_json_auth(uri: &str, body: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn auth_token(app: &axum::Router, state: &AppState) -> String {
    let email = format!("u-{}@octo.test", uuid::Uuid::new_v4().simple());
    common::signup_and_verify(app, state, &email).await
}

async fn create_wallet_for(app: &axum::Router, token: &str) -> String {
    let kp = stellar_base::crypto::DalekKeyPair::random().unwrap();
    let body = common::wallet_body(app, token, &kp).await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/wallets")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn list_deliveries_paginates_with_a_cursor() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL to run integration tests");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let wallet_id = create_wallet_for(&app, &token).await;

    // Create a webhook endpoint.
    let resp = app
        .clone()
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/webhooks"),
            r#"{"url":"https://example.com/webhook"}"#,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let endpoint_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Manually insert some webhook deliveries into the database for testing pagination.
    for i in 0..5 {
        sqlx::query(
            "INSERT INTO webhook_deliveries (id, endpoint_id, event_type, payload, status, attempts, created_at, updated_at)
             VALUES ($1, $2::uuid, 'test_event', '{}', 'success', 1, NOW() - INTERVAL '1 minute' * $3, NOW())"
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&endpoint_id)
        .bind(i)
        .execute(state.store().pool())
        .await
        .expect("insert delivery");
    }

    // Fetch deliveries with limit=2.
    let resp = app
        .clone()
        .oneshot(get_auth(
            &format!("/v1/wallets/{wallet_id}/webhooks/{endpoint_id}/deliveries?limit=2"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let deliveries = json["data"].as_array().unwrap();
    assert_eq!(deliveries.len(), 2, "should return 2 items per page");

    let next_cursor = &json["next_cursor"];
    assert!(!next_cursor.is_null(), "should have a next_cursor when more results exist");
}

#[tokio::test]
async fn list_deliveries_next_cursor_is_null_on_the_last_page() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL to run integration tests");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let wallet_id = create_wallet_for(&app, &token).await;

    // Create a webhook endpoint.
    let resp = app
        .clone()
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/webhooks"),
            r#"{"url":"https://example.com/webhook"}"#,
            &token,
        ))
        .await
        .unwrap();
    let endpoint_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Insert 2 deliveries.
    for i in 0..2 {
        sqlx::query(
            "INSERT INTO webhook_deliveries (id, endpoint_id, event_type, payload, status, attempts, created_at, updated_at)
             VALUES ($1, $2::uuid, 'test_event', '{}', 'success', 1, NOW() - INTERVAL '1 minute' * $3, NOW())"
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&endpoint_id)
        .bind(i)
        .execute(state.store().pool())
        .await
        .expect("insert delivery");
    }

    // Fetch with limit=10 (larger than the number of items).
    let resp = app
        .clone()
        .oneshot(get_auth(
            &format!("/v1/wallets/{wallet_id}/webhooks/{endpoint_id}/deliveries?limit=10"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let deliveries = json["data"].as_array().unwrap();
    assert_eq!(deliveries.len(), 2, "should return all 2 items");

    let next_cursor = &json["next_cursor"];
    assert!(
        next_cursor.is_null(),
        "should have null next_cursor on the last page"
    );
}

#[tokio::test]
async fn list_deliveries_rejects_an_out_of_range_limit() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL to run integration tests");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let wallet_id = create_wallet_for(&app, &token).await;

    // Create a webhook endpoint.
    let resp = app
        .clone()
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/webhooks"),
            r#"{"url":"https://example.com/webhook"}"#,
            &token,
        ))
        .await
        .unwrap();
    let endpoint_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Reject limit=0.
    let resp = app
        .clone()
        .oneshot(get_auth(
            &format!("/v1/wallets/{wallet_id}/webhooks/{endpoint_id}/deliveries?limit=0"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Reject limit > 200.
    let resp = app
        .clone()
        .oneshot(get_auth(
            &format!("/v1/wallets/{wallet_id}/webhooks/{endpoint_id}/deliveries?limit=201"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Accept limit=1.
    let resp = app
        .clone()
        .oneshot(get_auth(
            &format!("/v1/wallets/{wallet_id}/webhooks/{endpoint_id}/deliveries?limit=1"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
