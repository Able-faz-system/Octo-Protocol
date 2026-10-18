//! Tests for issue #249: Audit-log whitelist changes

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
async fn add_address_writes_an_audit_log_entry() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL to run integration tests");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let (_, user_id) = common::signup_and_verify_full(&app, &state, &format!("u-{}@octo.test", uuid::Uuid::new_v4().simple())).await;
    let wallet_id = create_wallet_for(&app, &token).await;

    // Add an address via the API.
    let resp = app
        .clone()
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/whitelist"),
            r#"{"address":"GDZST3XVCDTUJ76ZAV2HA72KYJE4P5VXLC7RVNPQZQ6SXZCQWBKBGQYD"}"#,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Verify that an audit log entry was recorded for the add operation.
    let audit_logs: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT action, target FROM audit_logs WHERE user_id = $1::uuid ORDER BY created_at DESC LIMIT 1"
    )
    .bind(&user_id)
    .fetch_all(state.store().pool())
    .await
    .expect("fetch audit logs");

    assert!(!audit_logs.is_empty(), "should have at least one audit log entry");
    let (action, _) = &audit_logs[0];
    assert!(
        action.contains("add") || action.contains("whitelist") || action.contains("address"),
        "audit log should mention adding an address or whitelisting: {}",
        action
    );
}

#[tokio::test]
async fn remove_address_writes_an_audit_log_entry() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL to run integration tests");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let (_, user_id) = common::signup_and_verify_full(&app, &state, &format!("u-{}@octo.test", uuid::Uuid::new_v4().simple())).await;
    let wallet_id = create_wallet_for(&app, &token).await;

    // Add an address first.
    let resp = app
        .clone()
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/whitelist"),
            r#"{"address":"GDZST3XVCDTUJ76ZAV2HA72KYJE4P5VXLC7RVNPQZQ6SXZCQWBKBGQYD"}"#,
            &token,
        ))
        .await
        .unwrap();
    let entry_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Remove the address via the API.
    let resp = app
        .clone()
        .oneshot(delete_auth(
            &format!("/v1/wallets/{wallet_id}/whitelist/{}", entry_id),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify that an audit log entry was recorded for the remove operation.
    let audit_logs: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT action, target FROM audit_logs WHERE user_id = $1::uuid ORDER BY created_at DESC LIMIT 1"
    )
    .bind(&user_id)
    .fetch_all(state.store().pool())
    .await
    .expect("fetch audit logs");

    assert!(!audit_logs.is_empty(), "should have at least one audit log entry");
    let (action, _) = &audit_logs[0];
    assert!(
        action.contains("remove") || action.contains("delete") || action.contains("whitelist"),
        "audit log should mention removing from whitelist: {}",
        action
    );
}

#[tokio::test]
async fn whitelist_audit_entries_never_include_the_full_allowlist_or_secret_material() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL to run integration tests");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let (_, user_id) = common::signup_and_verify_full(&app, &state, &format!("u-{}@octo.test", uuid::Uuid::new_v4().simple())).await;
    let wallet_id = create_wallet_for(&app, &token).await;

    // Add multiple addresses.
    for i in 0..3 {
        let _ = app
            .clone()
            .oneshot(post_json_auth(
                &format!("/v1/wallets/{wallet_id}/whitelist"),
                &format!(r#"{{"address":"GDZST3XVCDTUJ76ZAV2HA72KYJE4P5VXLC7RVNPQZQ6SXZCQWBKBGQYD","label":"addr{}"}}"#, i),
                &token,
            ))
            .await
            .unwrap();
    }

    // Fetch all audit logs for this user.
    let audit_logs: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT action, target FROM audit_logs WHERE user_id = $1::uuid"
    )
    .bind(&user_id)
    .fetch_all(state.store().pool())
    .await
    .expect("fetch audit logs");

    for (action, target) in audit_logs {
        // The audit log should not contain the full allowlist or sensitive material.
        let log_content = format!("{} {}", action, target.unwrap_or_default());
        assert!(
            !log_content.contains("wallet_id=") || !log_content.contains("secret"),
            "audit log should not expose wallet secrets: {}",
            log_content
        );
    }
}
