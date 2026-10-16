//! Typed JSON-RPC 2.0 client for EVM chains.
//!
//! This module implements the client described in #218. It is deliberately
//! small: no full EVM SDK, just the methods this epic needs, over the
//! workspace `reqwest` (rustls-tls, no OpenSSL).
//!
//! ## Submit-asymmetry (AD-5)
//!
//! Reads (`eth_call`, `eth_getLogs`, `eth_blockNumber`,
//! `eth_getTransactionReceipt`, ...) are `CallKind::Read` and go through
//! `octo-resilience` retry + circuit breaker. `eth_sendRawTransaction` is
//! **never** transparently retried: a retried submit can double-spend if the
//! first attempt actually landed but the response was lost. The same reasoning
//! is documented at the top of `crates/ingest/src/horizon.rs` for Stellar
//! submits. The submit path is therefore excluded from the resilience wrapper
//! at the call site below.
//!
//! ## JSON-RPC error handling
//!
//! A JSON-RPC error is HTTP 200 with an `error` member. A client that only
//! checks HTTP status treats every failure as success. We handle the error
//! object explicitly and distinguish:
//!
//! * [`EvmRpcError::Transport`] — network/TLS/HTTP failure.
//! * [`EvmRpcError::JsonRpc`] — protocol error (`error` member present).
//! * [`EvmRpcError::Revert`] — execution revert (code `3`, revert data).
//! * [`EvmRpcError::RangeTooLarge`] — provider-specific `eth_getLogs` cap.
//! * [`EvmRpcError::RateLimited`] — 429 / provider rate-limit response.
//! * [`EvmRpcError::CircuitOpen`] — circuit breaker tripped.
//!
//! ## Security
//!
//! RPC URLs contain API keys. We never log the URL (see #216). Response bodies
//! are capped at [`MAX_RESPONSE_BODY_BYTES`] so a malicious or compromised RPC
//! returning a multi-GB response cannot OOM the worker.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use octo_resilience::{CallKind, CircuitBreaker, RetryPolicy};
use primitive_types::U256;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use tracing::{debug, warn};

/// Maximum response body size we will buffer. A malicious or compromised RPC
/// returning a multi-GB response must not OOM the worker.
pub const MAX_RESPONSE_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Default per-request timeout.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// JSON-RPC error code for execution revert (EIP-1474 / geth convention).
const JSONRPC_REVERT_CODE: i64 = 3;

/// JSON-RPC error code for "requested block range too large" as returned by
/// several providers (Alchemy, Infura, QuickNode) when `eth_getLogs` exceeds
/// their cap.
const JSONRPC_RANGE_TOO_LARGE_CODE: i64 = -32005;

/// JSON-RPC error code for "limit exceeded" (Infura uses this for range caps).
const JSONRPC_LIMIT_EXCEEDED_CODE: i64 = -32005;

/// Typed errors surfaced by the client.
#[derive(Debug, Error)]
pub enum EvmRpcError {
    /// Network, TLS, or HTTP-level failure. Retryable for reads.
    #[error("transport error: {0}")]
    Transport(String),

    /// JSON-RPC protocol error: HTTP 200 with an `error` member.
    #[error("json-rpc error {code}: {message}")]
    JsonRpc { code: i64, message: String },

    /// Execution revert. `data` is the raw revert data if the provider
    /// supplied it (encoding is inconsistent across providers).
    #[error("execution revert: {data}")]
    Revert { data: String },

    /// Provider rejected the `eth_getLogs` block range as too large.
    /// #221 uses this to adaptively bisect.
    #[error("block range too large: {message}")]
    RangeTooLarge { message: String },

    /// Rate limited. `retry_after` is the provider hint if present.
    #[error("rate limited (retry_after={retry_after:?})")]
    RateLimited { retry_after: Option<Duration> },

    /// Circuit breaker is open; the call was not attempted.
    #[error("circuit open")]
    CircuitOpen,

    /// Response body exceeded [`MAX_RESPONSE_BODY_BYTES`].
    #[error("response body exceeded {limit} bytes")]
    ResponseTooLarge { limit: usize },

    /// Hex parsing failure (malformed quantity, non-`0x` prefix, overflow).
    #[error("invalid hex quantity: {0}")]
    InvalidHex(String),

    /// Chain-id mismatch at startup. A misconfigured RPC pointing at the wrong
    /// chain is a fund-loss bug.
    #[error("chain id mismatch: expected {expected}, got {actual}")]
    ChainIdMismatch { expected: String, actual: String },
}

impl EvmRpcError {
    /// Whether this error is worth retrying for a read call.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            EvmRpcError::Transport(_) | EvmRpcError::RateLimited { .. }
        )
    }
}

/// A JSON-RPC request envelope.
#[derive(Debug, Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'a str,
    id: u64,
    method: &'a str,
    params: Value,
}

/// A JSON-RPC response envelope. `result` and `error` are mutually exclusive
/// per spec; we model both as optional and validate.
#[derive(Debug, Deserialize)]
struct RpcResponse {
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<RpcErrorObject>,
}

#[derive(Debug, Deserialize)]
struct RpcErrorObject {
    code: i64,
    message: String,
    #[serde(default)]
    data: Option<Value>,
}

/// A log entry as returned by `eth_getLogs`.
#[derive(Debug, Clone, Deserialize)]
pub struct Log {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    #[serde(rename = "logIndex")]
    pub log_index: String,
    #[serde(rename = "removed", default)]
    pub removed: bool,
}

/// A block header as returned by `eth_getBlockByNumber`.
#[derive(Debug, Clone, Deserialize)]
pub struct Block {
    pub number: String,
    pub hash: String,
    #[serde(rename = "parentHash")]
    pub parent_hash: String,
    pub timestamp: String,
}

/// A transaction receipt as returned by `eth_getTransactionReceipt`.
#[derive(Debug, Clone, Deserialize)]
pub struct TransactionReceipt {
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    #[serde(rename = "blockNumber")]
    pub block_number: Option<String>,
    #[serde(rename = "status", default)]
    pub status: Option<String>,
    #[serde(rename = "logs", default)]
    pub logs: Vec<Log>,
}

/// A fee-history entry as returned by `eth_feeHistory`.
#[derive(Debug, Clone, Deserialize)]
pub struct FeeHistory {
    #[serde(rename = "oldestBlock")]
    pub oldest_block: String,
    #[serde(rename = "baseFeePerGas")]
    pub base_fee_per_gas: Vec<String>,
    #[serde(rename = "gasUsedRatio")]
    pub gas_used_ratio: Vec<f64>,
    #[serde(rename = "reward", default)]
    pub reward: Option<Vec<Vec<String>>>,
}

/// Filter for `eth_getLogs`.
#[derive(Debug, Clone, Serialize)]
pub struct LogFilter {
    #[serde(rename = "fromBlock")]
    pub from_block: String,
    #[serde(rename = "toBlock")]
    pub to_block: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topics: Option<Vec<Value>>,
}

/// Transaction call object for `eth_call` / `eth_estimateGas`.
#[derive(Debug, Clone, Serialize, Default)]
pub struct CallRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "gasPrice")]
    pub gas_price: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

/// The typed EVM JSON-RPC client.
///
/// Construct one per configured chain. The URL is held privately and never
/// logged.
#[derive(Clone)]
pub struct EvmRpcClient {
    http: Client,
    /// RPC endpoint. Contains an API key — never log this.
    url: String,
    retry: RetryPolicy,
    breaker: Arc<CircuitBreaker>,
    next_id: Arc<std::sync::atomic::AtomicU64>,
}

impl fmt::Debug for EvmRpcClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately omit `url`: it contains an API key (#216).
        f.debug_struct("EvmRpcClient")
            .field("url", &"<redacted>")
            .finish()
    }
}

impl EvmRpcClient {
    /// Build a new client.
    ///
    /// `url` contains an API key and is never logged.
    pub fn new(
        url: impl Into<String>,
        retry: RetryPolicy,
        breaker: Arc<CircuitBreaker>,
    ) -> Result<Self, EvmRpcError> {
        let http = Client::builder()
            .timeout(DEFAULT_REQUEST_TIMEOUT)
            .build()
            .map_err(|e| EvmRpcError::Transport(e.to_string()))?;
        Ok(Self {
            http,
            url: url.into(),
            retry,
            breaker,
            next_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        })
    }

    /// Build a client with a caller-supplied `reqwest::Client` (for tests).
    pub fn with_http(
        http: Client,
        url: impl Into<String>,
        retry: RetryPolicy,
        breaker: Arc<CircuitBreaker>,
    ) -> Self {
        Self {
            http,
            url: url.into(),
            retry,
            breaker,
            next_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        }
    }

    fn next_id(&self) -> u64 {
        self.next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Perform a single JSON-RPC call without resilience wrapping.
    ///
    /// This is the raw transport path. Callers that need retry/circuit-breaker
    /// semantics should use [`Self::call_read`] instead.
    async fn call_once(&self, method: &str, params: Value) -> Result<Value, EvmRpcError> {
        let id = self.next_id();
        let req = RpcRequest {
            jsonrpc: "2.0",
            id,
            method,
            params,
        };

        // NOTE: never log `self.url` — it contains an API key (#216).
        let resp = self
            .http
            .post(&self.url)
            .json(&req)
            .send()
            .await
            .map_err(|e| EvmRpcError::Transport(e.to_string()))?;

        let status = resp.status();

        // Rate-limit handling: 429 (and some providers use 503 with a
        // Retry-After header).
        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = parse_retry_after(resp.headers());
            return Err(EvmRpcError::RateLimited { retry_after });
        }

        // Read the body with a hard cap. `content_length` is advisory; we
        // enforce the cap while streaming.
        let body = read_body_capped(resp, MAX_RESPONSE_BODY_BYTES).await?;

        if !status.is_success() {
            // Non-2xx with a body: treat as transport failure, but preserve
            // any JSON-RPC error object if present.
            if let Ok(parsed) = serde_json::from_slice::<RpcResponse>(&body) {
                if let Some(err) = parsed.error {
                    return Err(map_rpc_error(err));
                }
            }
            return Err(EvmRpcError::Transport(format!(
                "http status {status}"
            )));
        }

        // HTTP 200. A JSON-RPC error is HTTP 200 with an `error` member —
        // status-only checking would read every failure as success.
        let parsed: RpcResponse = serde_json::from_slice(&body)
            .map_err(|e| EvmRpcError::Transport(format!("invalid json-rpc response: {e}")))?;

        if let Some(err) = parsed.error {
            return Err(map_rpc_error(err));
        }

        parsed
            .result
            .ok_or_else(|| EvmRpcError::Transport("json-rpc response missing result".into()))
    }

    /// Perform a read call through the resilience layer.
    ///
    /// Reads are `CallKind::Read` and retryable. The submit path
    /// (`eth_sendRawTransaction`) deliberately does **not** use this method —
    /// see the module docs and [`Self::send_raw_transaction`].
    async fn call_read(&self, method: &str, params: Value) -> Result<Value, EvmRpcError> {
        // Circuit breaker gate.
        if !self.breaker.allow(CallKind::Read) {
            return Err(EvmRpcError::CircuitOpen);
        }

        let mut attempt = 0u32;
        loop {
            match self.call_once(method, params.clone()).await {
                Ok(v) => {
                    self.breaker.record_success(CallKind::Read);
                    return Ok(v);
                }
                Err(e) => {
                    if !e.is_retryable() {
                        // Protocol errors and reverts are not transport
                        // failures; do not trip the breaker on them.
                        return Err(e);
                    }
                    self.breaker.record_failure(CallKind::Read);
                    attempt += 1;
                    if attempt > self.retry.max_attempts {
                        return Err(e);
                    }
                    let backoff = self.retry.backoff_for(attempt);
                    debug!(attempt, method, "retrying evm rpc read");
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }

    // ---------------------------------------------------------------------
    // Typed wrappers
    // ---------------------------------------------------------------------

    /// `eth_chainId` — returns the chain id as `U256`.
    pub async fn chain_id(&self) -> Result<U256, EvmRpcError> {
        let v = self.call_read("eth_chainId", json!([])).await?;
        parse_u256_value(&v)
    }

    /// `eth_blockNumber` — returns the latest block number as `U256`.
    pub async fn block_number(&self) -> Result<U256, EvmRpcError> {
        let v = self.call_read("eth_blockNumber", json!([])).await?;
        parse_u256_value(&v)
    }

    /// `eth_getBlockByNumber`.
    ///
    /// `full_tx` controls whether full transaction objects are returned.
    pub async fn get_block_by_number(
        &self,
        block: &str,
        full_tx: bool,
    ) -> Result<Option<Block>, EvmRpcError> {
        let v = self
            .call_read("eth_getBlockByNumber", json!([block, full_tx]))
            .await?;
        if v.is_null() {
            return Ok(None);
        }
        serde_json::from_value(v)
            .map(Some)
            .map_err(|e| EvmRpcError::Transport(format!("invalid block: {e}")))
    }

    /// `eth_getLogs`.
    ///
    /// Surfaces [`EvmRpcError::RangeTooLarge`] when the provider rejects the
    /// block range (Alchemy 2k, Infura 10k, others unbounded) so #221 can
    /// adaptively bisect.
    pub async fn get_logs(&self, filter: &LogFilter) -> Result<Vec<Log>, EvmRpcError> {
        let v = self
            .call_read("eth_getLogs", json!([filter]))
            .await?;
        serde_json::from_value(v)
            .map_err(|e| EvmRpcError::Transport(format!("invalid logs: {e}")))
    }

    /// `eth_getTransactionReceipt`.
    pub async fn get_transaction_receipt(
        &self,
        tx_hash: &str,
    ) -> Result<Option<TransactionReceipt>, EvmRpcError> {
        let v = self
            .call_read("eth_getTransactionReceipt", json!([tx_hash]))
            .await?;
        if v.is_null() {
            return Ok(None);
        }
        serde_json::from_value(v)
            .map(Some)
            .map_err(|e| EvmRpcError::Transport(format!("invalid receipt: {e}")))
    }

    /// `eth_getTransactionCount` — returns the nonce as `U256`.
    pub async fn get_transaction_count(
        &self,
        address: &str,
        block: &str,
    ) -> Result<U256, EvmRpcError> {
        let v = self
            .call_read("eth_getTransactionCount", json!([address, block]))
            .await?;
        parse_u256_value(&v)
    }

    /// `eth_call` — returns the raw return data as a hex string.
    pub async fn call(&self, req: &CallRequest, block: &str) -> Result<String, EvmRpcError> {
        let v = self
            .call_read("eth_call", json!([req, block]))
            .await?;
        v.as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| EvmRpcError::Transport("eth_call result not a string".into()))
    }

    /// `eth_estimateGas` — returns the estimate as `U256`.
    pub async fn estimate_gas(&self, req: &CallRequest) -> Result<U256, EvmRpcError> {
        let v = self.call_read("eth_estimateGas", json!([req])).await?;
        parse_u256_value(&v)
    }

    /// `eth_feeHistory`.
    pub async fn fee_history(
        &self,
        block_count: &str,
        newest_block: &str,
        reward_percentiles: &[f64],
    ) -> Result<FeeHistory, EvmRpcError> {
        let v = self
            .call_read(
                "eth_feeHistory",
                json!([block_count, newest_block, reward_percentiles]),
            )
            .await?;
        serde_json::from_value(v)
            .map_err(|e| EvmRpcError::Transport(format!("invalid fee history: {e}")))
    }

    /// `eth_sendRawTransaction`.
    ///
    /// **Submit-asymmetry (AD-5):** this method is deliberately **not**
    /// wrapped in retry or circuit-breaker logic. A transparently retried
    /// submit can double-spend if the first attempt actually landed but the
    /// response was lost. The caller is responsible for any idempotency
    /// (e.g. nonce management) and for deciding whether to resubmit.
    ///
    /// Returns the transaction hash on success.
    pub async fn send_raw_transaction(&self, raw_tx: &str) -> Result<String, EvmRpcError> {
        // NOTE: no `call_read` here — see the doc comment above and the
        // module-level submit-asymmetry note.
        let v = self
            .call_once("eth_sendRawTransaction", json!([raw_tx]))
            .await?;
        v.as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| EvmRpcError::Transport("sendRawTransaction result not a string".into()))
    }

    /// Startup assertion: verify that `eth_chainId` matches the configured
    /// CAIP-2 chain id.
    ///
    /// A misconfigured RPC pointing at the wrong chain is a fund-loss bug.
    /// `expected_caip2` is the full CAIP-2 string, e.g. `eip155:1`.
    pub async fn assert_chain_id(&self, expected_caip2: &str) -> Result<(), EvmRpcError> {
        let expected = parse_caip2_chain_id(expected_caip2)?;
        let actual = self.chain_id().await?;
        if actual != expected {
            return Err(EvmRpcError::ChainIdMismatch {
                expected: expected_caip2.to_string(),
                actual: format!("eip155:{actual}"),
            });
        }
        Ok(())
    }
}

/// Parse a CAIP-2 chain id string (`eip155:<n>`) into a `U256`.
fn parse_caip2_chain_id(caip2: &str) -> Result<U256, EvmRpcError> {
    let (namespace, reference) = caip2
        .split_once(':')
        .ok_or_else(|| EvmRpcError::InvalidHex(format!("invalid caip-2 id: {caip2}")))?;
    if namespace != "eip155" {
        return Err(EvmRpcError::InvalidHex(format!(
            "unsupported caip-2 namespace: {namespace}"
        )));
    }
    U256::from_dec_str(reference)
        .map_err(|_| EvmRpcError::InvalidHex(format!("invalid caip-2 reference: {reference}")))
}

/// Map a JSON-RPC error object to a typed error.
fn map_rpc_error(err: RpcErrorObject) -> EvmRpcError {
    // Execution revert: code 3, with revert data in `data`.
    if err.code == JSONRPC_REVERT_CODE {
        let data = err
            .data
            .as_ref()
            .map(|d| match d {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .unwrap_or_default();
        return EvmRpcError::Revert { data };
    }

    // Range-too-large: providers use -32005 (and sometimes a message-only
    // signal). Detect both the code and the message text.
    if err.code == JSONRPC_RANGE_TOO_LARGE_CODE
        || err.code == JSONRPC_LIMIT_EXCEEDED_CODE
        || is_range_too_large_message(&err.message)
    {
        return EvmRpcError::RangeTooLarge {
            message: err.message,
        };
    }

    EvmRpcError::JsonRpc {
        code: err.code,
        message: err.message,
    }
}

/// Heuristic: some providers signal range caps only via the message text.
fn is_range_too_large_message(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("range") && (m.contains("too large") || m.contains("exceed"))
        || m.contains("block range")
        || m.contains("query returned more than")
        || m.contains("limit exceeded")
}

/// Parse a `Retry-After` header into a `Duration`.
fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let v = headers.get(reqwest::header::RETRY_AFTER)?;
    let s = v.to_str().ok()?;
    // Retry-After is either delta-seconds or an HTTP-date. We support the
    // common delta-seconds form; anything else is ignored.
    s.trim().parse::<u64>().ok().map(Duration::from_secs)
}

/// Read a response body with a hard size cap.
async fn read_body_capped(
    resp: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, EvmRpcError> {
    // Fast-path rejection on an honest Content-Length.
    if let Some(len) = resp.content_length() {
        if len as usize > limit {
            return Err(EvmRpcError::ResponseTooLarge { limit });
        }
    }

    let mut body = Vec::new();
    let mut stream = resp;
    while let Some(chunk) = stream
        .chunk()
        .await
        .map_err(|e| EvmRpcError::Transport(e.to_string()))?
    {
        if body.len() + chunk.len() > limit {
            return Err(EvmRpcError::ResponseTooLarge { limit });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Parse a JSON value that should be a `0x`-prefixed hex quantity into `U256`.
///
/// All EVM quantities are hex-encoded strings (`0x`-prefixed, minimal-length).
/// We never parse into `u64` or `f64`.
pub fn parse_u256_value(v: &Value) -> Result<U256, EvmRpcError> {
    match v {
        Value::String(s) => parse_u256_hex(s),
        other => Err(EvmRpcError::InvalidHex(format!(
            "expected hex string, got {other}"
        ))),
    }
}

/// Parse a `0x`-prefixed hex quantity string into `U256`.
///
/// Accepts `0x0` (minimal-length zero) and values above `u64::MAX`. Rejects
/// malformed input (missing `0x`, non-hex digits, empty).
pub fn parse_u256_hex(s: &str) -> Result<U256, EvmRpcError> {
    let stripped = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .ok_or_else(|| EvmRpcError::InvalidHex(format!("missing 0x prefix: {s}")))?;
    if stripped.is_empty() {
        return Err(EvmRpcError::InvalidHex("empty hex quantity".into()));
    }
    // `U256::from_str_radix` accepts leading zeros; EVM quantities are
    // minimal-length but we are lenient on input.
    U256::from_str_radix(stripped, 16)
        .map_err(|_| EvmRpcError::InvalidHex(format!("invalid hex quantity: {s}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_zero() {
        assert_eq!(parse_u256_hex("0x0").unwrap(), U256::zero());
    }

    #[test]
    fn parse_above_u64_max() {
        // 2^64 = 0x10000000000000000
        let v = parse_u256_hex("0x10000000000000000").unwrap();
        assert_eq!(v, U256::from(1u64) << 64);
    }

    #[test]
    fn parse_malformed() {
        assert!(parse_u256_hex("1234").is_err());
        assert!(parse_u256_hex("0x").is_err());
        assert!(parse_u256_hex("0xzz").is_err());
    }

    #[test]
    fn caip2_parsing() {
        assert_eq!(parse_caip2_chain_id("eip155:1").unwrap(), U256::one());
        assert!(parse_caip2_chain_id("solana:1").is_err());
        assert!(parse_caip2_chain_id("eip155").is_err());
    }

    #[test]
    fn range_too_large_detection() {
        let err = map_rpc_error(RpcErrorObject {
            code: -32005,
            message: "query returned more than 10000 results".into(),
            data: None,
        });
        assert!(matches!(err, EvmRpcError::RangeTooLarge { .. }));
    }

    #[test]
    fn revert_detection() {
        let err = map_rpc_error(RpcErrorObject {
            code: 3,
            message: "execution reverted".into(),
            data: Some(Value::String("0xdeadbeef".into())),
        });
        match err {
            EvmRpcError::Revert { data } => assert_eq!(data, "0xdeadbeef"),
            other => panic!("expected revert, got {other:?}"),
        }
    }
}