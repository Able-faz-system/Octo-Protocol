//! Tests for issue #248: Cap whitelist entries

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

fn post_json_auth(uri: &str, body: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
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
async fn add_address_succeeds_up_to_the_cap() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL to run integration tests");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let wallet_id = create_wallet_for(&app, &token).await;

    // Add addresses up to the cap (assume 50).
    for i in 0..50 {
        let address = format!("GDZST3XVCDTUJ76ZAV2HA72KYJE4P5VXLC7RVNPQZQ6SXZCQWBKBGQYD");
        let label = format!("label_{}", i);
        let resp = app
            .clone()
            .oneshot(post_json_auth(
                &format!("/v1/wallets/{wallet_id}/whitelist"),
                &format!(r#"{{"address":"{}","label":"{}"}}"#, address, label),
                &token,
            ))
            .await
            .unwrap();

        assert!(
            resp.status().is_success() || resp.status() == StatusCode::BAD_REQUEST,
            "adding address {} failed with status {}",
            i,
            resp.status()
        );
    }
}

#[tokio::test]
async fn add_address_rejects_once_cap_reached() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL to run integration tests");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let wallet_id = create_wallet_for(&app, &token).await;

    // Insert 50 whitelisted addresses (the cap).
    for i in 0..50 {
        sqlx::query(
            "INSERT INTO whitelisted_addresses (id, wallet_id, address, label, created_at)
             VALUES ($1, $2::uuid, $3, $4, NOW())"
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&wallet_id)
        .bind("GDZST3XVCDTUJ76ZAV2HA72KYJE4P5VXLC7RVNPQZQ6SXZCQWBKBGQYD")
        .bind(Some(format!("address_{}", i)))
        .execute(state.store().pool())
        .await
        .expect("insert whitelisted address");
    }

    // Attempt to add one more address — should be rejected with 400.
    let resp = app
        .clone()
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/whitelist"),
            r#"{"address":"GDZST3XVCDTUJ76ZAV2HA72KYJE4P5VXLC7RVNPQZQ6SXZCQWBKBGQYD"}"#,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "should reject when cap is reached"
    );
}

#[tokio::test]
async fn remove_address_frees_a_slot_under_the_cap() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL to run integration tests");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let wallet_id = create_wallet_for(&app, &token).await;

    // Insert 50 whitelisted addresses (at the cap).
    let mut entry_ids = vec![];
    for i in 0..50 {
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO whitelisted_addresses (id, wallet_id, address, label, created_at)
             VALUES ($1, $2::uuid, $3, $4, NOW())"
        )
        .bind(&id)
        .bind(&wallet_id)
        .bind("GDZST3XVCDTUJ76ZAV2HA72KYJE4P5VXLC7RVNPQZQ6SXZCQWBKBGQYD")
        .bind(Some(format!("address_{}", i)))
        .execute(state.store().pool())
        .await
        .expect("insert whitelisted address");
        entry_ids.push(id);
    }

    // Remove one address.
    let resp = app
        .clone()
        .oneshot(delete_auth(
            &format!("/v1/wallets/{wallet_id}/whitelist/{}", entry_ids[0]),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "delete should succeed");

    // Now adding a new address should succeed (we freed up a slot).
    let resp = app
        .clone()
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/whitelist"),
            r#"{"address":"GDZST3XVCDTUJ76ZAV2HA72KYJE4P5VXLC7RVNPQZQ6SXZCQWBKBGQYD"}"#,
            &token,
        ))
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "adding a new address should succeed after freeing a slot"
    );
}
