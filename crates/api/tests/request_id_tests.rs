//! Tests for per-request id propagation through middleware, response headers, and tracing spans.

use axum::body::Body;
use axum::http::header::HeaderName;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::Router;
use octo_api::{build_router, request_id_middleware, AppState, REQUEST_ID_HEADER};
use octo_store::Store;
use octo_wallet_core::StellarNetwork;
use std::sync::{Arc, Mutex, Once};
use tower::ServiceExt;
use tracing_subscriber::fmt::MakeWriter;
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
    let store = Store::connect(&url).await.ok()?;
    let _ = store.migrate().await;
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

async fn test_router() -> Router {
    if let Some(state) = test_state().await {
        build_router(state)
    } else {
        // Fallback router with identical middleware layer when database is unavailable.
        Router::new()
            .route("/health", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(request_id_middleware))
    }
}

#[derive(Clone)]
struct BufferWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for BufferWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for BufferWriter {
    type Writer = BufferWriter;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn every_response_carries_an_x_request_id_header() {
    let app = test_router().await;
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.expect("execute request");
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify response carries X-Request-Id header.
    let header_val = resp
        .headers()
        .get(&REQUEST_ID_HEADER)
        .expect("X-Request-Id header present in response")
        .to_str()
        .expect("header is valid ASCII");

    // Verify generated request id is a valid UUIDv4.
    let parsed = Uuid::parse_str(header_val);
    assert!(parsed.is_ok(), "generated request id must be a valid UUID");
    assert_eq!(parsed.unwrap().get_version_num(), 4);
}

#[tokio::test]
async fn a_caller_supplied_x_request_id_is_echoed_back_unchanged() {
    let app = test_router().await;
    let custom_id = "client-trace-777-custom-id";
    let req = Request::builder()
        .uri("/health")
        .header(HeaderName::from_static("x-request-id"), custom_id)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.expect("execute request");
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify caller-supplied request ID is preserved exactly.
    let header_val = resp
        .headers()
        .get(&REQUEST_ID_HEADER)
        .expect("X-Request-Id header present in response")
        .to_str()
        .expect("header is valid ASCII");
    assert_eq!(header_val, custom_id);
}

#[tokio::test]
async fn log_output_for_a_request_consistently_carries_the_same_request_id_across_nested_spans() {
    let log_buffer = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(BufferWriter(log_buffer.clone()))
        .with_ansi(false)
        .finish();

    // Register test subscriber for the current thread during test execution.
    let _guard = tracing::subscriber::set_default(subscriber);

    // Handler with a nested child span to test span inheritance.
    async fn nested_handler() -> &'static str {
        let child_span = tracing::info_span!("horizon_dispatch", operation = "poll_status");
        let _enter = child_span.enter();
        tracing::info!("nested horizon call completed");
        "ok"
    }

    let app = Router::new()
        .route("/trace-test", get(nested_handler))
        .layer(axum::middleware::from_fn(request_id_middleware));

    let custom_id = "trace-correlation-id-9988";
    let req = Request::builder()
        .uri("/trace-test")
        .header(HeaderName::from_static("x-request-id"), custom_id)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.expect("execute request");
    assert_eq!(resp.status(), StatusCode::OK);

    // Extract captured logs and assert request id is threaded through nested spans.
    let logs = String::from_utf8(log_buffer.lock().unwrap().clone()).expect("valid utf8 logs");
    assert!(
        logs.contains(custom_id),
        "log output must contain the request id: {}",
        logs
    );
    assert!(
        logs.contains("nested horizon call completed"),
        "log output must contain nested span event: {}",
        logs
    );
}
