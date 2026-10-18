//! `WebhookSender::dispatch` against a local sink: retry classification and the diagnostic
//! fields written to the delivery log. Requires Postgres via `DATABASE_URL` (skipped otherwise).

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use octo_resilience::RetryPolicy;
use octo_store::{NewWallet, Store, WebhookDelivery};
use octo_webhooks::{Event, WebhookSender, RESPONSE_SNIPPET_MAX_BYTES};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Once};
use uuid::Uuid;

static LOAD_ENV: Once = Once::new();

fn database_url() -> Option<String> {
    LOAD_ENV.call_once(|| {
        let _ = dotenvy::dotenv();
    });
    std::env::var("DATABASE_URL").ok()
}

/// Per-call responses: the sink answers with `script[n]` on its n-th hit (last entry repeats).
#[derive(Clone)]
struct Sink {
    hits: Arc<AtomicU32>,
    script: Arc<Vec<(StatusCode, String)>>,
}

async fn sink(State(s): State<Sink>) -> (StatusCode, String) {
    let n = s.hits.fetch_add(1, Ordering::SeqCst) as usize;
    s.script[n.min(s.script.len() - 1)].clone()
}

struct Harness {
    store: Store,
    sender: WebhookSender,
    wallet_id: Uuid,
    endpoint_id: Uuid,
    hits: Arc<AtomicU32>,
}

/// Spin up a sink with `script`, a wallet, and an endpoint pointing at the sink.
async fn harness(script: Vec<(StatusCode, String)>) -> Option<Harness> {
    let url = database_url()?;
    std::env::set_var("OCTO_ALLOW_LOCAL_WEBHOOKS", "1");
    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");

    let hits = Arc::new(AtomicU32::new(0));
    let app = Router::new().route("/hook", post(sink)).with_state(Sink {
        hits: hits.clone(),
        script: Arc::new(script),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let wallet = store
        .create_wallet(NewWallet {
            network: "testnet",
            stellar_account_g: &format!("GWEBHOOKDISPATCH-{}", Uuid::new_v4().simple()),
            sealed_ciphertext: b"ct",
            sealed_nonce: b"n",
            sealed_salt: b"s",
            sealed_scheme: 1,
            label: None,
            user_id: None,
            description: None,
        })
        .await
        .unwrap();
    let ep = store
        .create_webhook_endpoint(wallet.id, &format!("http://{addr}/hook"), "dispatch-secret")
        .await
        .unwrap();

    // Millisecond backoff keeps the retry tests fast.
    let sender = WebhookSender::new(store.clone()).with_retry_policy(RetryPolicy {
        max_attempts: 3,
        base_delay_ms: 10,
        max_delay_ms: 20,
        ..RetryPolicy::default()
    });
    Some(Harness {
        store,
        sender,
        wallet_id: wallet.id,
        endpoint_id: ep.id,
        hits,
    })
}

fn event() -> Event {
    Event {
        event_type: "deposit.created".into(),
        data: serde_json::json!({ "amount": "1.0000000" }),
    }
}

async fn only_delivery(h: &Harness) -> WebhookDelivery {
    let mut rows = h.store.list_webhook_deliveries(h.endpoint_id, 10).await.unwrap();
    assert_eq!(rows.len(), 1, "exactly one log row per dispatch");
    rows.remove(0)
}

#[tokio::test]
async fn dispatch_retries_a_5xx_response_and_eventually_succeeds() {
    let Some(h) = harness(vec![
        (StatusCode::SERVICE_UNAVAILABLE, "deploying".into()),
        (StatusCode::BAD_GATEWAY, "deploying".into()),
        (StatusCode::OK, "ok".into()),
    ])
    .await
    else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    assert_eq!(h.sender.dispatch(h.wallet_id, &event()).await, 1);
    assert_eq!(h.hits.load(Ordering::SeqCst), 3);
    let d = only_delivery(&h).await;
    assert_eq!(d.status, "delivered");
    assert_eq!(d.attempts, 3);
    assert_eq!(d.response_code, Some(200));
    assert_eq!(d.response_body_snippet.as_deref(), Some("ok"));
}

#[tokio::test]
async fn dispatch_does_not_retry_a_4xx_response() {
    let Some(h) = harness(vec![(StatusCode::BAD_REQUEST, "bad payload".into())]).await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    assert_eq!(h.sender.dispatch(h.wallet_id, &event()).await, 0);
    assert_eq!(h.hits.load(Ordering::SeqCst), 1);
    let d = only_delivery(&h).await;
    assert_eq!(d.status, "failed");
    assert_eq!(d.attempts, 1);
    assert_eq!(d.response_code, Some(400));
}

#[tokio::test]
async fn dispatch_gives_up_after_the_configured_attempt_count_and_logs_failure() {
    let Some(h) = harness(vec![(StatusCode::INTERNAL_SERVER_ERROR, "boom".into())]).await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    assert_eq!(h.sender.dispatch(h.wallet_id, &event()).await, 0);
    assert_eq!(h.hits.load(Ordering::SeqCst), 3);
    let d = only_delivery(&h).await;
    assert_eq!(d.status, "failed");
    assert_eq!(d.attempts, 3);
}

#[tokio::test]
async fn dispatch_records_the_response_status_on_failure() {
    let Some(h) = harness(vec![(StatusCode::UNPROCESSABLE_ENTITY, "missing field `id`".into())])
        .await
    else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    h.sender.dispatch(h.wallet_id, &event()).await;
    let d = only_delivery(&h).await;
    assert_eq!(d.status, "failed");
    assert_eq!(d.response_code, Some(422));
    assert_eq!(d.response_body_snippet.as_deref(), Some("missing field `id`"));
}

#[tokio::test]
async fn dispatch_truncates_an_oversized_response_body_before_storing_it() {
    let huge = "E".repeat(64 * 1024);
    let Some(h) = harness(vec![(StatusCode::BAD_REQUEST, huge)]).await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    h.sender.dispatch(h.wallet_id, &event()).await;
    let snippet = only_delivery(&h).await.response_body_snippet.unwrap();
    assert_eq!(snippet.len(), RESPONSE_SNIPPET_MAX_BYTES);
    assert!(snippet.chars().all(|c| c == 'E'));
}

#[tokio::test]
async fn dispatch_never_stores_an_echoed_secret_in_the_snippet() {
    let Some(h) = harness(vec![(StatusCode::BAD_REQUEST, "you sent dispatch-secret".into())])
        .await
    else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    h.sender.dispatch(h.wallet_id, &event()).await;
    let snippet = only_delivery(&h).await.response_body_snippet.unwrap();
    assert!(!snippet.contains("dispatch-secret"));
}
