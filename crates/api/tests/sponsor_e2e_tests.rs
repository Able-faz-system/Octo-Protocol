//! End-to-end integration tests for the gas sponsorship flow.
//!
//! Requires Postgres via `DATABASE_URL` (see `docker-compose.yml`). Each test creates a fresh
//! user + wallet and uses a local mock Horizon server so tests do not depend on testnet funding.

mod common;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use axum::Router;
use octo_api::{build_router, AppState};
use octo_store::{NewSponsoredTx, Store};
use octo_wallet_core::StellarNetwork;
use std::sync::{Arc, Mutex, Once};
use stellar_base::crypto::DalekKeyPair;
use stellar_base::operations::Operation;
use stellar_base::transaction::{Transaction, MIN_BASE_FEE};
use stellar_base::xdr::{
    Memo, MuxedAccount, Operation as XdrOperation, OperationBody, Preconditions, SequenceNumber,
    Transaction as XdrTransaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope,
    Uint256, XDRSerialize,
};
use tower::ServiceExt;
use uuid::Uuid;

static LOAD_ENV: Once = Once::new();

fn database_url() -> Option<String> {
    LOAD_ENV.call_once(|| {
        let _ = dotenvy::dotenv();
    });
    std::env::var("DATABASE_URL").ok()
}

async fn test_state(horizon_url: String) -> Option<AppState> {
    let url = database_url()?;
    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");
    let master_key = [42u8; 32];
    Some(AppState::new(
        store,
        master_key,
        StellarNetwork::Testnet,
        horizon_url,
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

fn post_auth(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
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

fn put_json_auth(uri: &str, body: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn get_auth(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

async fn auth_token(app: &Router, state: &AppState) -> String {
    let email = format!("sponsor-e2e-{}@octo.test", Uuid::new_v4().simple());
    common::signup_and_verify(app, state, &email).await
}

/// Create a non-custodial wallet (client-generated key) and provision its gas tank so the
/// sponsorship path has a server-held fee account to sign fee-bumps with.
async fn create_wallet(app: &Router, token: &str) -> (String, String) {
    let kp = DalekKeyPair::random().unwrap();
    let reg_body = common::wallet_body(app, token, &kp).await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/wallets")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(reg_body))
                .unwrap(),
        )
        .await
        .unwrap();
    let w = body_json(resp).await;
    let id = w["data"]["id"].as_str().unwrap().to_string();
    let address = w["data"]["address"].as_str().unwrap().to_string();

    // Attach the gas tank (the only server-held key for a client wallet).
    let resp = app
        .clone()
        .oneshot(post_auth(&format!("/v1/wallets/{id}/gas-tank"), token))
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "gas tank provisioning must succeed"
    );

    (id, address)
}

// Create a client-custody wallet without provisioning a gas tank.
async fn create_wallet_without_gas_tank(app: &Router, token: &str) -> (String, String) {
    let kp = DalekKeyPair::random().unwrap();
    let reg_body = common::wallet_body(app, token, &kp).await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/wallets")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(reg_body))
                .unwrap(),
        )
        .await
        .unwrap();
    let w = body_json(resp).await;
    let id = w["data"]["id"].as_str().unwrap().to_string();
    let address = w["data"]["address"].as_str().unwrap().to_string();
    (id, address)
}

/// Local mock Horizon that accepts POST /transactions and returns a successful submission.
async fn start_mock_horizon() -> String {
    async fn submit() -> axum::Json<serde_json::Value> {
        axum::Json(serde_json::json!({
            "hash": format!("mock-{}", Uuid::new_v4().simple()),
            "successful": true,
            "ledger": 12345
        }))
    }

    let app = Router::new().route("/transactions", post(submit));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock horizon");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

#[derive(Clone, Default)]
struct WebhookCapture {
    body: Vec<u8>,
}

type SharedWebhook = Arc<Mutex<Option<WebhookCapture>>>;

async fn start_webhook_sink() -> (String, SharedWebhook) {
    async fn sink(State(store): State<SharedWebhook>, body: axum::body::Bytes) -> &'static str {
        *store.lock().unwrap() = Some(WebhookCapture {
            body: body.to_vec(),
        });
        "ok"
    }

    let captured: SharedWebhook = Arc::new(Mutex::new(None));
    let app = Router::new()
        .route("/hook", post(sink))
        .with_state(captured.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind webhook sink");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}/hook"), captured)
}

/// Signed payment XDR from a random (non-master) source account.
fn random_payment_xdr(destination_g: &str) -> String {
    let kp = DalekKeyPair::random().unwrap();
    let dest = stellar_base::crypto::PublicKey::from_account_id(destination_g).unwrap();
    let op = Operation::new_payment()
        .with_destination(dest)
        .with_amount(stellar_base::amount::Stroops::new(100))
        .unwrap()
        .with_asset(stellar_base::asset::Asset::new_native())
        .build()
        .unwrap();
    let tx = Transaction::builder(kp.public_key(), 1, MIN_BASE_FEE)
        .add_operation(op)
        .into_transaction()
        .unwrap();
    let mut tx = tx;
    tx.sign(kp.as_ref(), &stellar_base::network::Network::new_test())
        .unwrap();
    tx.into_envelope().xdr_base64().unwrap()
}
fn account_merge_xdr(source_bytes: [u8; 32], destination_bytes: [u8; 32]) -> String {
    let operations = vec![XdrOperation {
        source_account: None,
        body: OperationBody::AccountMerge(MuxedAccount::Ed25519(Uint256(destination_bytes))),
    }];
    let tx = XdrTransaction {
        source_account: MuxedAccount::Ed25519(Uint256(source_bytes)),
        fee: 100,
        seq_num: SequenceNumber(1),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: operations.try_into().unwrap(),
        ext: TransactionExt::V0,
    };
    let envelope = TransactionV1Envelope {
        tx,
        signatures: vec![].try_into().unwrap(),
    };
    TransactionEnvelope::Tx(envelope).xdr_base64().unwrap()
}

async fn enable_sponsorship_via_api(app: &Router, token: &str, wallet_id: &str) {
    let uri = format!("/v1/wallets/{wallet_id}/sponsorship");
    let resp = app
        .clone()
        .oneshot(put_json_auth(&uri, r#"{"enabled":true}"#, token))
        .await
        .unwrap();
    if resp.status() != StatusCode::OK {
        let json = body_json(resp).await;
        panic!("enable sponsorship failed: {json}");
    }
}

async fn wait_for_webhook_delivery(state: &AppState, wallet_id: &str) {
    for _ in 0..50 {
        let delivery_count: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM webhook_deliveries wd
            JOIN webhook_endpoints we ON we.id = wd.endpoint_id
            WHERE we.wallet_id = $1::uuid AND wd.event_type = 'transaction.sponsored'
            "#,
        )
        .bind(wallet_id)
        .fetch_one(state.store().pool())
        .await
        .unwrap();
        if delivery_count.0 >= 1 {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("webhook delivery record must exist");
}
async fn wait_for_webhook_body(captured: &SharedWebhook) -> WebhookCapture {
    for _ in 0..50 {
        if captured.lock().unwrap().is_some() {
            return captured.lock().unwrap().clone().unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("webhook was not delivered");
}

#[tokio::test]
async fn e2e_sponsor_full_flow() {
    std::env::set_var("OCTO_ALLOW_LOCAL_WEBHOOKS", "1");
    let horizon = start_mock_horizon().await;
    let Some(state) = test_state(horizon).await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let (wallet_id, master_g) = create_wallet(&app, &token).await;

    let (hook_url, captured) = start_webhook_sink().await;
    let hook_body = format!(r#"{{"url":"{hook_url}","secret":"test-secret"}}"#);
    let resp = app
        .clone()
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/webhooks"),
            &hook_body,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    enable_sponsorship_via_api(&app, &token, &wallet_id).await;

    let xdr = random_payment_xdr(&master_g);
    let body = format!(r#"{{"transaction_xdr":"{xdr}","max_base_fee_stroops":200}}"#);
    let resp = app
        .clone()
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/sponsor"),
            &body,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = body_json(resp).await;
    let inner_hash = json["data"]["inner_tx_hash"].as_str().unwrap();

    let row: (String,) =
        sqlx::query_as("SELECT status FROM sponsored_transactions WHERE inner_tx_hash = $1")
            .bind(inner_hash)
            .fetch_one(state.store().pool())
            .await
            .unwrap();
    assert_eq!(row.0, "confirmed");

    wait_for_webhook_delivery(&state, &wallet_id).await;

    let cap = wait_for_webhook_body(&captured).await;
    let hook_json: serde_json::Value = serde_json::from_slice(&cap.body).unwrap();
    assert_eq!(hook_json["event"], "transaction.sponsored");

    let resp = app
        .oneshot(get_auth("/v1/audit-logs?category=sponsorship", &token))
        .await
        .unwrap();
    let logs = body_json(resp).await;
    let arr = logs["data"].as_array().unwrap();
    assert!(
        arr.iter()
            .any(|l| l["action"].as_str().unwrap().contains("sponsored")),
        "audit log entry for sponsorship must exist"
    );
}

#[tokio::test]
async fn e2e_sponsor_rejected_when_disabled() {
    let horizon = start_mock_horizon().await;
    let Some(state) = test_state(horizon).await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let (wallet_id, master_g) = create_wallet(&app, &token).await;

    let uri = format!("/v1/wallets/{wallet_id}/sponsorship");
    let resp = app
        .clone()
        .oneshot(put_json_auth(
            &uri,
            r#"{"enabled":false,"daily_budget_stroops":1000000}"#,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let xdr = random_payment_xdr(&master_g);
    let body = format!(r#"{{"transaction_xdr":"{xdr}","max_base_fee_stroops":200}}"#);
    let resp = app
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/sponsor"),
            &body,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn e2e_sponsor_update_config_persists() {
    let horizon = start_mock_horizon().await;
    let Some(state) = test_state(horizon).await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let (wallet_id, _) = create_wallet(&app, &token).await;
    let uri = format!("/v1/wallets/{wallet_id}/sponsorship");

    let put_body =
        r#"{"enabled":true,"per_tx_fee_cap_stroops":500000,"daily_budget_stroops":10000000}"#;
    let resp = app
        .clone()
        .oneshot(put_json_auth(&uri, put_body, &token))
        .await
        .unwrap();
    if resp.status() != StatusCode::OK {
        let json = body_json(resp).await;
        panic!("PUT config failed: {json}");
    }
    let put_json = body_json(resp).await;
    assert_eq!(put_json["data"]["enabled"], true);
    assert_eq!(put_json["data"]["per_tx_fee_cap_stroops"], 500_000);
    assert_eq!(put_json["data"]["daily_budget_stroops"], 10_000_000);
    assert_eq!(put_json["data"]["fees_spent_today_stroops"], 0);

    let resp = app.clone().oneshot(get_auth(&uri, &token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let get_json = body_json(resp).await;
    assert_eq!(get_json["data"]["enabled"], put_json["data"]["enabled"]);
    assert_eq!(
        get_json["data"]["per_tx_fee_cap_stroops"],
        put_json["data"]["per_tx_fee_cap_stroops"]
    );
    assert_eq!(
        get_json["data"]["daily_budget_stroops"],
        put_json["data"]["daily_budget_stroops"]
    );
}

#[tokio::test]
async fn e2e_sponsorship_get_counts_only_confirmed_fees_spent_today() {
    let horizon = start_mock_horizon().await;
    let Some(state) = test_state(horizon).await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let (wallet_id, _) = create_wallet(&app, &token).await;
    enable_sponsorship_via_api(&app, &token, &wallet_id).await;
    let wallet_id = Uuid::parse_str(&wallet_id).expect("wallet UUID");

    state
        .store()
        .record_sponsored_tx(NewSponsoredTx {
            wallet_id,
            inner_tx_hash: &format!("pending-{}", Uuid::new_v4().simple()),
            fee_stroops: 300,
        })
        .await
        .expect("insert pending sponsored transaction");

    let confirmed = state
        .store()
        .record_sponsored_tx(NewSponsoredTx {
            wallet_id,
            inner_tx_hash: &format!("confirmed-{}", Uuid::new_v4().simple()),
            fee_stroops: 700,
        })
        .await
        .expect("insert confirmed sponsored transaction");
    state
        .store()
        .update_sponsored_tx_status(confirmed.id, "confirmed", None, None)
        .await
        .expect("confirm sponsored transaction");

    let uri = format!("/v1/wallets/{wallet_id}/sponsorship");
    let resp = app.oneshot(get_auth(&uri, &token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["data"]["fees_spent_today_stroops"], 700);
}

#[tokio::test]
async fn e2e_sponsor_rejects_account_merge_op() {
    let horizon = start_mock_horizon().await;
    let Some(state) = test_state(horizon).await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let (wallet_id, _) = create_wallet(&app, &token).await;
    enable_sponsorship_via_api(&app, &token, &wallet_id).await;

    let xdr = account_merge_xdr([2u8; 32], [3u8; 32]);
    let body = format!(r#"{{"transaction_xdr":"{xdr}","max_base_fee_stroops":200}}"#);
    let resp = app
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/sponsor"),
            &body,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = body_json(resp).await;
    assert!(
        json["message"].as_str().unwrap().contains("op_not_allowed"),
        "expected op_not_allowed, got {}",
        json["message"]
    );
}

#[tokio::test]
async fn e2e_sponsor_rejects_self_sponsorship() {
    let horizon = start_mock_horizon().await;
    let Some(state) = test_state(horizon).await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let (wallet_id, master_g) = create_wallet(&app, &token).await;
    enable_sponsorship_via_api(&app, &token, &wallet_id).await;

    let dest_g = "GBAW5XGWORWVFE2XTJYDTLDHXTY2Q2MO73HYCGB3XMFMQ562Q2W2GJQX";
    let master_g_key = stellar_base::crypto::PublicKey::from_account_id(&master_g).unwrap();
    let dest = stellar_base::crypto::PublicKey::from_account_id(dest_g).unwrap();
    let op = Operation::new_payment()
        .with_destination(dest)
        .with_amount(stellar_base::amount::Stroops::new(100))
        .unwrap()
        .with_asset(stellar_base::asset::Asset::new_native())
        .build()
        .unwrap();
    let tx = Transaction::builder(master_g_key, 1, MIN_BASE_FEE)
        .add_operation(op)
        .into_transaction()
        .unwrap();
    let xdr = tx.into_envelope().xdr_base64().unwrap();

    let body = format!(r#"{{"transaction_xdr":"{xdr}","max_base_fee_stroops":200}}"#);
    let resp = app
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/sponsor"),
            &body,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = body_json(resp).await;
    assert!(
        json["message"].as_str().unwrap().contains("master"),
        "expected self-sponsorship rejection"
    );
}

#[tokio::test]
async fn e2e_sponsor_duplicate_inner_tx_hash() {
    let horizon = start_mock_horizon().await;
    let Some(state) = test_state(horizon).await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let (wallet_id, master_g) = create_wallet(&app, &token).await;
    enable_sponsorship_via_api(&app, &token, &wallet_id).await;

    let xdr = random_payment_xdr(&master_g);
    let body = format!(r#"{{"transaction_xdr":"{xdr}","max_base_fee_stroops":200}}"#);
    let uri = format!("/v1/wallets/{wallet_id}/sponsor");

    let resp = app
        .clone()
        .oneshot(post_json_auth(&uri, &body, &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = app
        .oneshot(post_json_auth(&uri, &body, &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn e2e_sponsor_budget_exceeded() {
    let horizon = start_mock_horizon().await;
    let Some(state) = test_state(horizon).await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let (wallet_id, master_g) = create_wallet(&app, &token).await;

    let uri = format!("/v1/wallets/{wallet_id}/sponsorship");
    let resp = app
        .clone()
        .oneshot(put_json_auth(
            &uri,
            r#"{"enabled":true,"daily_budget_stroops":10000000}"#,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let fee = 6_000_000; // 0.6 XLM
    let body1 = format!(
        r#"{{"transaction_xdr":"{}","max_base_fee_stroops":{fee}}}"#,
        random_payment_xdr(&master_g)
    );
    let sponsor_uri = format!("/v1/wallets/{wallet_id}/sponsor");
    let resp = app
        .clone()
        .oneshot(post_json_auth(&sponsor_uri, &body1, &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body2 = format!(
        r#"{{"transaction_xdr":"{}","max_base_fee_stroops":{fee}}}"#,
        random_payment_xdr(&master_g)
    );
    let resp = app
        .oneshot(post_json_auth(&sponsor_uri, &body2, &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn sponsor_at_exact_fee_cap_succeeds() {
    let horizon = start_mock_horizon().await;
    let Some(state) = test_state(horizon).await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let (wallet_id, master_g) = create_wallet(&app, &token).await;

    let cap = 250_000_i64;
    let uri = format!("/v1/wallets/{wallet_id}/sponsorship");
    let resp = app
        .clone()
        .oneshot(put_json_auth(
            &uri,
            &format!(r#"{{"enabled":true,"per_tx_fee_cap_stroops":{cap}}}"#),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let xdr = random_payment_xdr(&master_g);
    let body = format!(r#"{{"transaction_xdr":"{xdr}","max_base_fee_stroops":{cap}}}"#);
    let resp = app
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/sponsor"),
            &body,
            &token,
        ))
        .await
        .unwrap();
    let status = resp.status();
    if status != StatusCode::CREATED {
        let json = body_json(resp).await;
        panic!("expected CREATED at exact cap, got {status}: {json}");
    }
}

#[tokio::test]
async fn sponsor_one_stroop_over_fee_cap_is_rejected() {
    let horizon = start_mock_horizon().await;
    let Some(state) = test_state(horizon).await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let (wallet_id, master_g) = create_wallet(&app, &token).await;

    let cap = 250_000_i64;
    let uri = format!("/v1/wallets/{wallet_id}/sponsorship");
    let resp = app
        .clone()
        .oneshot(put_json_auth(
            &uri,
            &format!(r#"{{"enabled":true,"per_tx_fee_cap_stroops":{cap}}}"#),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let xdr = random_payment_xdr(&master_g);
    let over_cap = cap + 1;
    let body = format!(r#"{{"transaction_xdr":"{xdr}","max_base_fee_stroops":{over_cap}}}"#);
    let resp = app
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/sponsor"),
            &body,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = body_json(resp).await;
    let message = json["message"].as_str().unwrap();
    assert!(
        message.contains(&cap.to_string()),
        "expected message to name the cap ({cap}), got: {message}"
    );
}

#[tokio::test]
async fn sponsor_uncapped_per_tx_with_daily_budget_set_succeeds_under_budget() {
    let horizon = start_mock_horizon().await;
    let Some(state) = test_state(horizon).await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let (wallet_id, master_g) = create_wallet(&app, &token).await;

    // No per_tx_fee_cap_stroops in the request body -> stored as NULL (uncapped per-tx),
    // while a daily budget is still enforced.
    let daily_budget = 50_000_000_i64;
    let uri = format!("/v1/wallets/{wallet_id}/sponsorship");
    let resp = app
        .clone()
        .oneshot(put_json_auth(
            &uri,
            &format!(r#"{{"enabled":true,"daily_budget_stroops":{daily_budget}}}"#),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let put_json = body_json(resp).await;
    assert!(
        put_json["data"]["per_tx_fee_cap_stroops"].is_null(),
        "per-tx cap must be unset"
    );

    // A large single fee, well under the daily budget, must be accepted despite having no
    // per-transaction cap configured.
    let fee = 20_000_000_i64;
    let xdr = random_payment_xdr(&master_g);
    let body = format!(r#"{{"transaction_xdr":"{xdr}","max_base_fee_stroops":{fee}}}"#);
    let resp = app
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/sponsor"),
            &body,
            &token,
        ))
        .await
        .unwrap();
    let status = resp.status();
    if status != StatusCode::CREATED {
        let json = body_json(resp).await;
        panic!("expected CREATED for uncapped per-tx under budget, got {status}: {json}");
    }
}

#[tokio::test]
async fn e2e_concurrent_sponsor_requests_respect_budget() {
    let horizon = start_mock_horizon().await;
    let Some(state) = test_state(horizon).await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let (wallet_id, master_g) = create_wallet(&app, &token).await;

    let fee_per_tx = 200_i64;
    let daily_budget = fee_per_tx * 10;
    let uri = format!("/v1/wallets/{wallet_id}/sponsorship");
    let resp = app
        .clone()
        .oneshot(put_json_auth(
            &uri,
            &format!(r#"{{"enabled":true,"daily_budget_stroops":{daily_budget}}}"#),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let sponsor_uri = format!("/v1/wallets/{wallet_id}/sponsor");
    let mut handles = vec![];
    for _ in 0..20 {
        let app = app.clone();
        let token = token.clone();
        let master_g = master_g.clone();
        let sponsor_uri = sponsor_uri.clone();
        handles.push(tokio::spawn(async move {
            let xdr = random_payment_xdr(&master_g);
            let body =
                format!(r#"{{"transaction_xdr":"{xdr}","max_base_fee_stroops":{fee_per_tx}}}"#);
            app.oneshot(post_json_auth(&sponsor_uri, &body, &token))
                .await
                .unwrap()
                .status()
        }));
    }

    let mut created = 0;
    let mut rate_limited = 0;
    for handle in handles {
        match handle.await.unwrap() {
            StatusCode::CREATED => created += 1,
            StatusCode::TOO_MANY_REQUESTS => rate_limited += 1,
            other => panic!("unexpected status {other}"),
        }
    }
    assert_eq!(created, 10, "exactly 10 requests should fit the budget");
    assert_eq!(rate_limited, 10, "remaining 10 should be rate limited");

    let total: (i64,) = sqlx::query_as(
        r#"
        SELECT COALESCE(SUM(fee_stroops), 0)::bigint
        FROM sponsored_transactions
        WHERE wallet_id = $1::uuid
          AND status <> 'failed'
          AND date_trunc('day', created_at AT TIME ZONE 'UTC') =
              date_trunc('day', now() AT TIME ZONE 'UTC')
        "#,
    )
    .bind(&wallet_id)
    .fetch_one(state.store().pool())
    .await
    .unwrap();
    assert!(
        total.0 <= daily_budget,
        "total reserved fees {total:?} must not exceed budget {daily_budget}"
    );
}

#[tokio::test]
async fn sponsor_rejects_when_sponsorship_is_disabled_for_the_wallet() {
    let horizon = start_mock_horizon().await;
    let Some(state) = test_state(horizon).await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let (wallet_id, master_g) = create_wallet(&app, &token).await;

    let uri = format!("/v1/wallets/{wallet_id}/sponsorship");
    let resp = app
        .clone()
        .oneshot(put_json_auth(
            &uri,
            r#"{"enabled":false,"daily_budget_stroops":1000000}"#,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let xdr = random_payment_xdr(&master_g);
    let body = format!(r#"{{"transaction_xdr":"{xdr}","max_base_fee_stroops":200}}"#);
    let resp = app
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/sponsor"),
            &body,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let json = body_json(resp).await;
    assert_eq!(
        json["message"],
        "gas sponsorship is not enabled for this wallet"
    );
}

#[tokio::test]
async fn sponsor_rejects_a_max_fee_above_the_per_tx_cap() {
    let horizon = start_mock_horizon().await;
    let Some(state) = test_state(horizon).await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let (wallet_id, master_g) = create_wallet(&app, &token).await;

    let cap = 250_000_i64;
    let uri = format!("/v1/wallets/{wallet_id}/sponsorship");
    let resp = app
        .clone()
        .oneshot(put_json_auth(
            &uri,
            &format!(r#"{{"enabled":true,"per_tx_fee_cap_stroops":{cap}}}"#),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let xdr = random_payment_xdr(&master_g);
    let body = format!(r#"{{"transaction_xdr":"{xdr}","max_base_fee_stroops":{}}}"#, cap + 1);
    let resp = app
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/sponsor"),
            &body,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = body_json(resp).await;
    assert!(
        json["message"]
            .as_str()
            .unwrap()
            .contains("exceeds the per-transaction cap"),
        "expected cap error, got: {}",
        json["message"]
    );
}

#[tokio::test]
async fn sponsor_rejects_a_self_sponsoring_inner_transaction() {
    let horizon = start_mock_horizon().await;
    let Some(state) = test_state(horizon).await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let (wallet_id, master_g) = create_wallet(&app, &token).await;
    enable_sponsorship_via_api(&app, &token, &wallet_id).await;

    let dest_g = "GBAW5XGWORWVFE2XTJYDTLDHXTY2Q2MO73HYCGB3XMFMQ562Q2W2GJQX";
    let master_g_key = stellar_base::crypto::PublicKey::from_account_id(&master_g).unwrap();
    let dest = stellar_base::crypto::PublicKey::from_account_id(dest_g).unwrap();
    let op = Operation::new_payment()
        .with_destination(dest)
        .with_amount(stellar_base::amount::Stroops::new(100))
        .unwrap()
        .with_asset(stellar_base::asset::Asset::new_native())
        .build()
        .unwrap();
    let tx = Transaction::builder(master_g_key, 1, MIN_BASE_FEE)
        .add_operation(op)
        .into_transaction()
        .unwrap();
    let xdr = tx.into_envelope().xdr_base64().unwrap();

    let body = format!(r#"{{"transaction_xdr":"{xdr}","max_base_fee_stroops":200}}"#);
    let resp = app
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/sponsor"),
            &body,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = body_json(resp).await;
    assert_eq!(
        json["message"],
        "inner transaction source must not be the master account"
    );
}

#[tokio::test]
async fn sponsor_rejects_once_the_daily_budget_is_exhausted() {
    let horizon = start_mock_horizon().await;
    let Some(state) = test_state(horizon).await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let (wallet_id, master_g) = create_wallet(&app, &token).await;

    let uri = format!("/v1/wallets/{wallet_id}/sponsorship");
    let resp = app
        .clone()
        .oneshot(put_json_auth(
            &uri,
            r#"{"enabled":true,"daily_budget_stroops":10000000}"#,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let fee = 6_000_000;
    let body1 = format!(
        r#"{{"transaction_xdr":"{}","max_base_fee_stroops":{fee}}}"#,
        random_payment_xdr(&master_g)
    );
    let sponsor_uri = format!("/v1/wallets/{wallet_id}/sponsor");
    let resp = app
        .clone()
        .oneshot(post_json_auth(&sponsor_uri, &body1, &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body2 = format!(
        r#"{{"transaction_xdr":"{}","max_base_fee_stroops":{fee}}}"#,
        random_payment_xdr(&master_g)
    );
    let resp = app
        .oneshot(post_json_auth(&sponsor_uri, &body2, &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let json = body_json(resp).await;
    assert_eq!(json["message"], "daily sponsorship budget exceeded");
}

#[tokio::test]
async fn sponsor_rejects_for_a_client_custody_wallet_with_no_gas_tank() {
    let horizon = start_mock_horizon().await;
    let Some(state) = test_state(horizon).await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let (wallet_id, master_g) = create_wallet_without_gas_tank(&app, &token).await;
    enable_sponsorship_via_api(&app, &token, &wallet_id).await;

    let xdr = random_payment_xdr(&master_g);
    let body = format!(r#"{{"transaction_xdr":"{xdr}","max_base_fee_stroops":200}}"#);
    let resp = app
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/sponsor"),
            &body,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let json = body_json(resp).await;
    assert!(
        json["message"]
            .as_str()
            .unwrap()
            .contains("no gas-tank account"),
        "expected gas-tank error, got: {}",
        json["message"]
    );
}
