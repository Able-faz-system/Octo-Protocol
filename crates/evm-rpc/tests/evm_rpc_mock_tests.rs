//! Mock-server tests for the EVM JSON-RPC client.
//!
//! These tests exercise the resilience posture, JSON-RPC error handling,
//! submit-asymmetry rule, hex parsing edge cases, response-size cap, and the
//! chain-id mismatch guard.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::post;
use axum::Router;
use serde_json::{json, Value};
use tokio::net::TcpListener;

use octo_evm_rpc::{
    CallKind, EvmRpcClient, EvmRpcError, RetryPolicy, RpcConfig,
};

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

/// A programmable mock JSON-RPC server.
struct MockServer {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
    _handle: tokio::task::JoinHandle<()>,
}

impl MockServer {
    async fn start<F>(handler: F) -> Self
    where
        F: Fn(usize, Value) -> MockResponse + Send + Sync + 'static,
    {
        let hits = Arc::new(AtomicUsize::new(0));
        let state = (hits.clone(), Arc::new(handler));

        let app = Router::new()
            .route(
                "/",
                post(
                    |State((hits, handler)): State<(
                        Arc<AtomicUsize>,
                        Arc<dyn Fn(usize, Value) -> MockResponse + Send + Sync>,
                    )>,
                     body: String| async move {
                        let n = hits.fetch_add(1, Ordering::SeqCst);
                        let parsed: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
                        let resp = handler(n, parsed);
                        resp.into_response()
                    },
                ),
            )
            .with_state(state);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        MockServer {
            addr,
            hits,
            _handle: handle,
        }
    }

    fn url(&self) -> String {
        format!("http://{}/", self.addr)
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

/// A canned response from the mock server.
struct MockResponse {
    status: StatusCode,
    body: Vec<u8>,
    headers: Vec<(String, String)>,
}

impl MockResponse {
    fn json(status: StatusCode, value: Value) -> Self {
        MockResponse {
            status,
            body: serde_json::to_vec(&value).unwrap(),
            headers: vec![("content-type".into(), "application/json".into())],
        }
    }

    fn ok(value: Value) -> Self {
        Self::json(StatusCode::OK, value)
    }

    fn rpc_result(id: u64, result: Value) -> Self {
        Self::ok(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
    }

    fn rpc_error(id: u64, code: i64, message: &str) -> Self {
        Self::ok(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": code, "message": message }
        }))
    }

    fn status(status: StatusCode) -> Self {
        MockResponse {
            status,
            body: b"server error".to_vec(),
            headers: vec![],
        }
    }

    fn raw(status: StatusCode, body: Vec<u8>) -> Self {
        MockResponse {
            status,
            body,
            headers: vec![("content-type".into(), "application/json".into())],
        }
    }

    fn into_response(self) -> Response {
        let mut builder = Response::builder().status(self.status);
        for (k, v) in self.headers {
            builder = builder.header(k, v);
        }
        builder.body(Body::from(self.body)).unwrap()
    }
}

fn test_config(url: String) -> RpcConfig {
    RpcConfig {
        url,
        chain_id: 1,
        request_timeout: Duration::from_secs(5),
        max_response_bytes: 1024 * 1024,
        retry: RetryPolicy {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(50),
            ..Default::default()
        },
        failure_threshold: 3,
        circuit_reset_timeout: Duration::from_millis(200),
    }
}

// ---------------------------------------------------------------------------
// JSON-RPC error handling
// ---------------------------------------------------------------------------

/// HTTP 200 with a JSON-RPC `error` member must be treated as an error, not
/// success. A status-only client would read this as a successful call.
#[tokio::test]
async fn http_200_with_jsonrpc_error_is_an_error() {
    let server = MockServer::start(|_n, _req| {
        MockResponse::rpc_error(1, -32000, "execution reverted")
    })
    .await;

    let client = EvmRpcClient::new(test_config(server.url())).unwrap();
    let err = client.eth_block_number().await.unwrap_err();

    match err {
        EvmRpcError::JsonRpc { code, message } => {
            assert_eq!(code, -32000);
            assert_eq!(message, "execution reverted");
        }
        other => panic!("expected JsonRpc error, got {other:?}"),
    }
}

/// A revert with `data` should be surfaced as `Revert { data }`.
#[tokio::test]
async fn jsonrpc_revert_with_data_is_typed() {
    let server = MockServer::start(|_n, _req| {
        MockResponse::ok(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": 3,
                "message": "execution reverted",
                "data": "0x08c379a0"
            }
        }))
    })
    .await;

    let client = EvmRpcClient::new(test_config(server.url())).unwrap();
    let err = client
        .eth_call(
            json!({"to": "0x0000000000000000000000000000000000000001", "data": "0x"}),
            "latest",
        )
        .await
        .unwrap_err();

    match err {
        EvmRpcError::Revert { data } => {
            assert_eq!(data.as_deref(), Some("0x08c379a0"));
        }
        other => panic!("expected Revert error, got {other:?}"),
    }
}

/// A transport failure (5xx) is distinct from a protocol error.
#[tokio::test]
async fn transport_failure_is_typed() {
    let server = MockServer::start(|_n, _req| MockResponse::status(StatusCode::BAD_GATEWAY)).await;

    let mut cfg = test_config(server.url());
    cfg.retry.max_attempts = 1;
    let client = EvmRpcClient::new(cfg).unwrap();

    let err = client.eth_block_number().await.unwrap_err();
    assert!(
        matches!(err, EvmRpcError::Transport { .. }),
        "expected Transport error, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Retry / backoff / circuit breaker
// ---------------------------------------------------------------------------

/// Reads retry on 5xx and eventually succeed.
#[tokio::test]
async fn reads_retry_on_5xx_and_succeed() {
    let server = MockServer::start(|n, _req| {
        if n < 2 {
            MockResponse::status(StatusCode::INTERNAL_SERVER_ERROR)
        } else {
            MockResponse::rpc_result(1, json!("0x10"))
        }
    })
    .await;

    let client = EvmRpcClient::new(test_config(server.url())).unwrap();
    let block = client.eth_block_number().await.unwrap();

    assert_eq!(block, 16u64.into());
    assert_eq!(server.hits(), 3, "expected two failures then a success");
}

/// The circuit opens after `failure_threshold` consecutive failures and
/// short-circuits subsequent calls with `CircuitOpen`.
#[tokio::test]
async fn circuit_opens_after_failure_threshold() {
    let server = MockServer::start(|_n, _req| {
        MockResponse::status(StatusCode::INTERNAL_SERVER_ERROR)
    })
    .await;

    let mut cfg = test_config(server.url());
    cfg.retry.max_attempts = 1;
    cfg.failure_threshold = 3;
    let client = EvmRpcClient::new(cfg).unwrap();

    // Drive the circuit to the threshold.
    for _ in 0..3 {
        let _ = client.eth_block_number().await;
    }

    let err = client.eth_block_number().await.unwrap_err();
    assert!(
        matches!(err, EvmRpcError::CircuitOpen),
        "expected CircuitOpen, got {err:?}"
    );

    // The circuit should have prevented further hits to the server.
    assert_eq!(
        server.hits(),
        3,
        "circuit should short-circuit after threshold"
    );
}

// ---------------------------------------------------------------------------
// Submit asymmetry (AD-5)
// ---------------------------------------------------------------------------

/// `eth_sendRawTransaction` must be called exactly once on failure — no
/// transparent retry. This preserves the submit-asymmetry rule.
#[tokio::test]
async fn send_raw_transaction_is_not_retried() {
    let server = MockServer::start(|_n, _req| {
        MockResponse::status(StatusCode::INTERNAL_SERVER_ERROR)
    })
    .await;

    let client = EvmRpcClient::new(test_config(server.url())).unwrap();
    let err = client
        .eth_send_raw_transaction("0xdeadbeef")
        .await
        .unwrap_err();

    assert!(
        matches!(err, EvmRpcError::Transport { .. }),
        "expected Transport error, got {err:?}"
    );
    assert_eq!(
        server.hits(),
        1,
        "eth_sendRawTransaction must be called exactly once on failure"
    );
}

/// Even a JSON-RPC error on submit must not be retried.
#[tokio::test]
async fn send_raw_transaction_jsonrpc_error_is_not_retried() {
    let server = MockServer::start(|_n, _req| {
        MockResponse::rpc_error(1, -32000, "nonce too low")
    })
    .await;

    let client = EvmRpcClient::new(test_config(server.url())).unwrap();
    let err = client
        .eth_send_raw_transaction("0xdeadbeef")
        .await
        .unwrap_err();

    assert!(matches!(err, EvmRpcError::JsonRpc { .. }));
    assert_eq!(server.hits(), 1, "submit must not be retried");
}

// ---------------------------------------------------------------------------
// Hex parsing edge cases
// ---------------------------------------------------------------------------

#[tokio::test]
async fn hex_parsing_zero() {
    let server = MockServer::start(|_n, _req| MockResponse::rpc_result(1, json!("0x0"))).await;
    let client = EvmRpcClient::new(test_config(server.url())).unwrap();
    let block = client.eth_block_number().await.unwrap();
    assert_eq!(block, 0u64.into());
}

#[tokio::test]
async fn hex_parsing_above_u64_max() {
    // 2^64 = 0x10000000000000000, which exceeds u64::MAX.
    let server = MockServer::start(|_n, _req| {
        MockResponse::rpc_result(1, json!("0x10000000000000000"))
    })
    .await;
    let client = EvmRpcClient::new(test_config(server.url())).unwrap();
    let block = client.eth_block_number().await.unwrap();

    let expected = num_bigint::BigUint::from(1u8) << 64u32;
    assert_eq!(block, expected.into());
}

#[tokio::test]
async fn hex_parsing_malformed_input_is_error() {
    let server = MockServer::start(|_n, _req| MockResponse::rpc_result(1, json!("0xzz"))).await;
    let client = EvmRpcClient::new(test_config(server.url())).unwrap();
    let err = client.eth_block_number().await.unwrap_err();
    assert!(
        matches!(err, EvmRpcError::JsonRpc { .. } | EvmRpcError::Transport { .. }),
        "expected parse failure to surface as an error, got {err:?}"
    );
}

/// A response body exceeding the size cap must be rejected, not buffered.
#[tokio::test]
async fn response_body_exceeding_size_cap_is_rejected() {
    let server = MockServer::start(|_n, _req| {
        // Build a body larger than the configured cap.
        let big = "a".repeat(2 * 1024 * 1024);
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": big
        }))
        .unwrap();
        MockResponse::raw(StatusCode::OK, body)
    })
    .await;

    let mut cfg = test_config(server.url());
    cfg.max_response_bytes = 1024 * 1024; // 1 MiB cap
    cfg.retry.max_attempts = 1;
    let client = EvmRpcClient::new(cfg).unwrap();

    let err = client.eth_block_number().await.unwrap_err();
    assert!(
        matches!(err, EvmRpcError::Transport { .. }),
        "expected oversized body to be rejected, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Chain-id guard
// ---------------------------------------------------------------------------

/// The startup chain-id assertion must reject a mismatched RPC.
#[tokio::test]
async fn chain_id_mismatch_rejects_at_startup() {
    let server = MockServer::start(|_n, _req| {
        // Server reports chain id 137 (Polygon) but config expects 1.
        MockResponse::rpc_result(1, json!("0x89"))
    })
    .await;

    let mut cfg = test_config(server.url());
    cfg.chain_id = 1;
    let client = EvmRpcClient::new(cfg).unwrap();

    let err = client.assert_chain_id().await.unwrap_err();
    assert!(
        matches!(err, EvmRpcError::ChainIdMismatch { .. }),
        "expected ChainIdMismatch, got {err:?}"
    );
}

/// A matching chain id passes the guard.
#[tokio::test]
async fn chain_id_match_passes_guard() {
    let server = MockServer::start(|_n, _req| MockResponse::rpc_result(1, json!("0x1"))).await;

    let mut cfg = test_config(server.url());
    cfg.chain_id = 1;
    let client = EvmRpcClient::new(cfg).unwrap();

    client.assert_chain_id().await.unwrap();
}

// ---------------------------------------------------------------------------
// Range-too-large detection
// ---------------------------------------------------------------------------

/// A provider that rejects an oversized `eth_getLogs` range must surface a
/// typed `RangeTooLarge` so callers can bisect.
#[tokio::test]
async fn get_logs_range_too_large_is_typed() {
    let server = MockServer::start(|_n, _req| {
        MockResponse::rpc_error(1, -32005, "query returned more than 10000 results")
    })
    .await;

    let client = EvmRpcClient::new(test_config(server.url())).unwrap();
    let err = client
        .eth_get_logs(json!({
            "fromBlock": "0x0",
            "toBlock": "0x100000",
            "address": "0x0000000000000000000000000000000000000001"
        }))
        .await
        .unwrap_err();

    assert!(
        matches!(err, EvmRpcError::RangeTooLarge { .. }),
        "expected RangeTooLarge, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

/// A 429 with `Retry-After` surfaces as `RateLimited { retry_after }`.
#[tokio::test]
async fn rate_limited_is_typed() {
    let server = MockServer::start(|_n, _req| {
        let mut resp = MockResponse::status(StatusCode::TOO_MANY_REQUESTS);
        resp.headers
            .push(("retry-after".into(), "2".into()));
        resp
    })
    .await;

    let mut cfg = test_config(server.url());
    cfg.retry.max_attempts = 1;
    let client = EvmRpcClient::new(cfg).unwrap();

    let err = client.eth_block_number().await.unwrap_err();
    match err {
        EvmRpcError::RateLimited { retry_after } => {
            assert_eq!(retry_after, Some(Duration::from_secs(2)));
        }
        other => panic!("expected RateLimited, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// CallKind sanity
// ---------------------------------------------------------------------------

/// Reads are retryable; submits are not.
#[test]
fn call_kind_retryability() {
    assert!(CallKind::Read.is_retryable());
    assert!(!CallKind::Submit.is_retryable());
}