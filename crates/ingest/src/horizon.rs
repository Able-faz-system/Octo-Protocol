//! Horizon payments client for the ingest worker.
//!
//! Polls an account's `/payments` endpoint (with `join=transactions` so we get the memo) using a
//! saved paging-token cursor. Cursor polling — rather than the SSE stream — keeps the worker
//! simple, restart-safe, and trivially horizontally scalable (one worker per account); the cursor
//! is the durable resume point.
//!
//! # Resilience
//!
//! `payments_after` is a **read-only** call and is therefore wrapped with retry-with-backoff and
//! a circuit breaker from [`octo_resilience`]. Transient Horizon failures (connection errors,
//! timeouts, 5xx) are retried up to `max_attempts` times with exponential backoff. After
//! `failure_threshold` consecutive failures the circuit opens, short-circuiting further calls
//! until the cool-down elapses.
//!
//! There is no equivalent of `submit_transaction` in this crate, so the submit-asymmetry rule
//! does not apply here.

use octo_resilience::{execute, CallKind, CircuitBreaker, ResilienceError, RetryPolicy};
use serde::{Deserialize, Serialize};

/// Errors talking to Horizon.
#[derive(Debug, thiserror::Error)]
pub enum HorizonError {
    #[error("horizon request failed")]
    Request,
    #[error("horizon returned an unexpected response")]
    Decode,
    #[error("horizon circuit breaker open")]
    CircuitOpen,
}

/// One payment record from Horizon (the fields octo needs).
///
/// `Serialize` is derived so tests can round-trip these through a mock Horizon server that
/// returns Horizon-shaped JSON; production only ever deserializes them.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PaymentRecord {
    /// The operation TOID — globally unique; used as the idempotent dedup key.
    pub id: String,
    /// Cursor token for resuming after this record.
    pub paging_token: String,
    /// `"payment"` or `"create_account"` etc. We only credit `payment` (and createAccount).
    #[serde(rename = "type")]
    pub kind: String,
    pub transaction_hash: Option<String>,
    #[serde(default)]
    pub transaction_successful: bool,
    pub from: Option<String>,
    /// Destination base account (`G...`).
    pub to: Option<String>,
    /// Present when the payment was sent to a muxed (`M...`) address.
    #[serde(default)]
    pub to_muxed: Option<String>,
    /// The muxed id (customer id) when `to_muxed` is set. Horizon returns it as a string.
    #[serde(default)]
    pub to_muxed_id: Option<String>,
    pub asset_type: Option<String>,
    #[serde(default)]
    pub asset_code: Option<String>,
    #[serde(default)]
    pub asset_issuer: Option<String>,
    /// Decimal amount string, e.g. "10.0000000".
    pub amount: Option<String>,
    /// createAccount uses `starting_balance` instead of `amount`.
    #[serde(default)]
    pub starting_balance: Option<String>,
    /// Joined parent transaction (for memo + ledger).
    #[serde(default)]
    pub transaction: Option<TransactionRecord>,
}

/// The joined transaction fields we use.
///
/// `Serialize` is derived for the same test-only reason as [`PaymentRecord`].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TransactionRecord {
    #[serde(default)]
    pub memo_type: Option<String>,
    #[serde(default)]
    pub memo: Option<String>,
    #[serde(default)]
    pub ledger: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct Embedded {
    records: Vec<PaymentRecord>,
}

#[derive(Debug, Deserialize)]
struct PaymentsPage {
    _embedded: Embedded,
}

/// A thin Horizon payments client with retry-with-backoff and circuit-breaker protection.
///
/// Clones share the same circuit-breaker state (via `Arc` inside [`CircuitBreaker`]).
#[derive(Clone)]
pub struct HorizonPayments {
    http: reqwest::Client,
    base_url: String,
    circuit: CircuitBreaker,
    retry: RetryPolicy,
}

impl HorizonPayments {
    /// Create a new client with default resilience settings.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::with_resilience(
            base_url,
            RetryPolicy::default(),
            CircuitBreaker::new(5, std::time::Duration::from_secs(30)),
        )
    }

    /// Create a client with explicit resilience configuration.
    /// Used by `bin/server` (to wire env-var config) and tests (to inject tight thresholds).
    pub fn with_resilience(
        base_url: impl Into<String>,
        retry: RetryPolicy,
        circuit: CircuitBreaker,
    ) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.into(),
            circuit,
            retry,
        }
    }

    /// Fetch up to `limit` payments for `account_g`, oldest-first, starting after `cursor`.
    ///
    /// Oldest-first (`order=asc`) so we process and advance the cursor monotonically. Transient
    /// failures are retried with exponential backoff; the circuit breaker opens after repeated
    /// failures so the ingest loop doesn't pile up independent timeouts.
    #[tracing::instrument(
        name = "horizon_payments_after",
        skip(self),
        fields(
            call_type = "payments_after",
            account_g = %account_g,
            cursor = ?cursor,
            limit = limit,
            outcome = tracing::field::Empty
        )
    )]
    pub async fn payments_after(
        &self,
        account_g: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Vec<PaymentRecord>, HorizonError> {
        let span = tracing::Span::current();
        let mut url = format!(
            "{}/accounts/{}/payments?order=asc&limit={}&join=transactions",
            self.base_url.trim_end_matches('/'),
            account_g,
            limit
        );
        if let Some(c) = cursor {
            url.push_str("&cursor=");
            url.push_str(c);
        }

        let http = self.http.clone();
        let result = execute(&self.circuit, &self.retry, CallKind::ReadOnly, || {
            let url = url.clone();
            let http = http.clone();
            async move {
                let resp = http
                    .get(&url)
                    .send()
                    .await
                    .map_err(|_| IngestFetchError::Transport)?;

                // 404 means the account does not exist on-chain yet — not a retriable error.
                if resp.status() == reqwest::StatusCode::NOT_FOUND {
                    return Ok(Vec::new());
                }
                if resp.status().is_server_error() {
                    return Err(IngestFetchError::Transport); // retriable
                }
                if !resp.status().is_success() {
                    return Err(IngestFetchError::Permanent);
                }
                let page: PaymentsPage = resp.json().await.map_err(|_| IngestFetchError::Decode)?;
                Ok(page._embedded.records)
            }
        })
        .await;

        match &result {
            Ok(_) => span.record("outcome", "success"),
            Err(ResilienceError::Circuit) => span.record("outcome", "circuit_open"),
            Err(ResilienceError::Exhausted(IngestFetchError::Decode)) => {
                span.record("outcome", "decode_error")
            }
            Err(ResilienceError::Exhausted(_)) => span.record("outcome", "failure"),
        };

        match result {
            Ok(records) => Ok(records),
            Err(ResilienceError::Circuit) => Err(HorizonError::CircuitOpen),
            Err(ResilienceError::Exhausted(IngestFetchError::Decode)) => Err(HorizonError::Decode),
            Err(ResilienceError::Exhausted(_)) => Err(HorizonError::Request),
        }
    }
}

// ---------------------------------------------------------------------------
// Internal error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum IngestFetchError {
    Transport,
    Decode,
    Permanent,
}

impl octo_resilience::Retriable for IngestFetchError {
    fn is_retriable(&self) -> bool {
        // Only transport failures are transient. A decode failure or a permanent status will
        // repeat identically on a retry, and retrying them would also count toward opening the
        // circuit breaker.
        matches!(self, IngestFetchError::Transport)
    }
}

impl std::fmt::Display for IngestFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport => write!(f, "transport error"),
            Self::Decode => write!(f, "decode error"),
            Self::Permanent => write!(f, "permanent error"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::layer::SubscriberExt;

    // Asserts that horizon_payments_after emits its distinct named tracing span.
    #[tokio::test]
    async fn horizon_payments_after_emits_tracing_span() {
        let recorded_spans = Arc::new(Mutex::new(Vec::<String>::new()));
        let spans_clone = recorded_spans.clone();

        struct SpanRecorder(Arc<Mutex<Vec<String>>>);
        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SpanRecorder {
            fn on_new_span(
                &self,
                attrs: &tracing::span::Attributes<'_>,
                _id: &tracing::span::Id,
                _ctx: tracing_subscriber::layer::Context<'_, S>,
            ) {
                self.0.lock().unwrap().push(attrs.metadata().name().to_string());
            }
        }

        let subscriber = tracing_subscriber::registry().with(SpanRecorder(spans_clone));
        let _guard = tracing::subscriber::set_default(subscriber);

        let client = HorizonPayments::new("http://127.0.0.1:1");
        let _ = client.payments_after("GABCDEFGHIJKLMNOPQRSTUVWXYZ", None, 10).await;

        let spans = recorded_spans.lock().unwrap().clone();
        assert!(spans.contains(&"horizon_payments_after".to_string()));
    }
}
