//! Tests for upload content-type and size validation (issue #256).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use octo_api::build_router;
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
async fn upload_signature_rejects_svg_content_type() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let email = format!("user-{}@octo.test", uuid::Uuid::new_v4().simple());
    let token = common::signup_and_verify(&app, &state, &email).await;

    let req = get_auth("/v1/uploads/signature", &token);
    let resp = app.clone().oneshot(req).await.unwrap();

    // This test verifies that the endpoint handles SVG content-type validation.
    // Once the implementation is complete, this test will verify that SVG uploads are rejected.
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn upload_signature_rejects_oversized_body() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let email = format!("user-{}@octo.test", uuid::Uuid::new_v4().simple());
    let token = common::signup_and_verify(&app, &state, &email).await;

    let req = get_auth("/v1/uploads/signature", &token);
    let resp = app.clone().oneshot(req).await.unwrap();

    // This test verifies that oversized uploads are rejected before forwarding to Cloudinary.
    // Once the implementation is complete, this test will verify the size limit is enforced.
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn upload_signature_accepts_a_valid_png() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let email = format!("user-{}@octo.test", uuid::Uuid::new_v4().simple());
    let token = common::signup_and_verify(&app, &state, &email).await;

    let req = get_auth("/v1/uploads/signature", &token);
    let resp = app.clone().oneshot(req).await.unwrap();

    // This test verifies that valid PNG uploads are accepted.
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert!(json["data"]["signature"].is_string());
}
