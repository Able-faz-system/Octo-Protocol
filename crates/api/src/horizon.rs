//! Minimal Horizon + friendbot client used by the API for funding and balance reads.
//!
//! # Resilience
//!
//! Read-only calls (`balances`, `account_sequence`) are wrapped with:
//! - **Retry-with-exponential-backoff** via [`octo_resilience::RetryPolicy`] — transient
//!   connection errors, timeouts, and 5xx responses are retried up to `max_attempts` times.
//! - **Circuit breaker** via [`octo_resilience::CircuitBreaker`] — after `failure_threshold`
//!   consecutive failures the circuit opens and calls return immediately with an internal error,
//!   preventing every concurrent request from queuing up its own timeout against an already-
//!   struggling Horizon instance.
//!
//! `submit_transaction` is deliberately excluded from automatic retry. See
//! [`octo_resilience`]'s module documentation for the full rationale; the short version is:
//! a network timeout on submission does NOT mean the transaction was rejected — it may have
//! already landed on-chain. Retrying would risk a double-submission. The caller must instead
//! query the ledger by hash to determine what actually happened.
//!
//! `friendbot_fund` runs with a separate small retry pass (friendbot is idempotent on testnet —
//! re-funding an already-funded account is a no-op).

use crate::error::ApiError;
use octo_resilience::{execute, CallKind, CircuitBreaker, ResilienceError, RetryPolicy};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Timeout for balance/sequence reads and friendbot funding — these are simple GETs against a
/// Horizon-like endpoint and should be fast; a hung connection here must not block a request
/// handler indefinitely.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
/// Signed-transaction submission may legitimately take longer than a simple read (Horizon can hold
/// the connection while the tx is validated/applied), so it gets a longer per-request override
/// instead of raising the client's default for every call.
const SUBMIT_TIMEOUT: Duration = Duration::from_secs(30);

/// A single balance line from a Horizon account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Balance {
    /// Decimal string, e.g. "100.0000000".
    pub balance: String,
    /// "native" for XLM, else "credit_alphanum4" / "credit_alphanum12".
    pub asset_type: String,
    #[serde(default)]
    pub asset_code: Option<String>,
    #[serde(default)]
    pub asset_issuer: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AccountResponse {
    balances: Vec<Balance>,
    /// Account sequence number (Horizon returns it as a string).
    #[serde(default)]
    sequence: String,
    #[serde(default)]
    subentry_count: i64,
    #[serde(default)]
    num_sponsoring: i64,
    #[serde(default)]
    num_sponsored: i64,
}

/// Everything the withdrawal pre-flight checks need about the source account, fetched in a
/// single Horizon call (balances + sequence + reserve inputs).
#[derive(Debug, Clone)]
pub struct AccountInfo {
    pub balances: Vec<Balance>,
    pub sequence: i64,
    /// Number of subentries (trustlines, offers, data entries, signers) — drives the minimum
    /// reserve requirement alongside the 2 base entries every account carries.
    pub subentry_count: i64,
    pub num_sponsoring: i64,
    pub num_sponsored: i64,
}

/// The Stellar protocol's base reserve, in stroops. This is a network-wide ledger parameter that
/// has been stable at 0.5 XLM since the 2019 fee/reserve protocol upgrade; we hardcode it rather
/// than fetch `/ledgers` on every withdrawal (an extra Horizon round trip) since a live change
/// would be a rare, widely-announced network event.
pub const BASE_RESERVE_STROOPS: i64 = 5_000_000;

impl AccountInfo {
    /// Minimum native XLM balance this account must maintain, per the standard reserve formula:
    /// `base_reserve * (2 + subentry_count + num_sponsoring - num_sponsored)`.
    pub fn min_reserve_stroops(&self) -> i64 {
        let entries = 2 + self.subentry_count + self.num_sponsoring - self.num_sponsored;
        BASE_RESERVE_STROOPS * entries.max(0)
    }

    pub fn native_balance_stroops(&self) -> i64 {
        self.balances
            .iter()
            .find(|b| b.asset_type == "native")
            .and_then(|b| parse_amount_stroops(&b.balance))
            .unwrap_or(0)
    }

    /// Balance of a specific credit asset, or `None` if there is no trustline for it.
    pub fn asset_balance_stroops(&self, code: &str, issuer: &str) -> Option<i64> {
        self.balances
            .iter()
            .find(|b| {
                b.asset_code.as_deref() == Some(code) && b.asset_issuer.as_deref() == Some(issuer)
            })
            .and_then(|b| parse_amount_stroops(&b.balance))
    }
}

/// Whether `balances` (as returned for some account) includes a trustline for the given credit
/// asset. Pulled out of the withdrawal route so the matching rule is unit-testable without a
/// live Horizon call.
pub fn has_trustline(balances: &[Balance], code: &str, issuer: &str) -> bool {
    balances
        .iter()
        .any(|b| b.asset_code.as_deref() == Some(code) && b.asset_issuer.as_deref() == Some(issuer))
}

/// Parse a Horizon decimal amount string (e.g. `"100.0000000"`) into integer stroops without
/// going through floating point (avoids rounding error near balance/reserve boundaries).
fn parse_amount_stroops(s: &str) -> Option<i64> {
    let (whole, frac) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    let whole: i64 = whole.parse().ok()?;
    let mut frac = frac.to_string();
    while frac.len() < 7 {
        frac.push('0');
    }
    frac.truncate(7);
    let frac: i64 = frac.parse().ok()?;
    Some(whole * 10_000_000 + frac)
}

/// The result of submitting a transaction to Horizon.
#[derive(Debug, Clone)]
pub struct SubmitResult {
    pub hash: String,
    pub successful: bool,
    pub ledger: Option<i64>,
    /// Horizon result codes when the tx failed, e.g. `("tx_failed", ["op_low_reserve"])`.
    /// Empty on success or when Horizon didn't return them.
    pub transaction_code: Option<String>,
    pub operation_codes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SubmitResponse {
    #[serde(default)]
    hash: String,
    #[serde(default)]
    successful: bool,
    #[serde(default)]
    ledger: Option<i64>,
    #[serde(default)]
    extras: Option<SubmitExtras>,
}

#[derive(Debug, Default, Deserialize)]
struct SubmitExtras {
    #[serde(default)]
    result_codes: Option<ResultCodes>,
}

#[derive(Debug, Default, Deserialize)]
struct ResultCodes {
    #[serde(default)]
    transaction: Option<String>,
    #[serde(default)]
    operations: Vec<String>,
}

/// A thin Horizon client with retry/backoff and circuit-breaker protection.
///
/// The circuit breaker and retry policy are shared across all calls through this client instance
/// so failures on any call type count toward opening the circuit.
///
/// # Cloning
///
/// [`Horizon`] is `Clone`; clones share the **same** circuit-breaker state (via `Arc` inside
/// [`CircuitBreaker`]) so all clones participate in the same failure window.
#[derive(Clone)]
pub struct Horizon {
    http: reqwest::Client,
    base_url: String,
    circuit: CircuitBreaker,
    retry: RetryPolicy,
}

impl Horizon {
    /// Create a new client with default resilience settings.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::with_resilience(
            base_url,
            RetryPolicy::default(),
            CircuitBreaker::new(5, std::time::Duration::from_secs(30)),
        )
    }

    /// Create a client with explicit resilience configuration.
    /// Used by `bin/server` (to wire env-var config) and by tests (to inject tight thresholds).
    pub fn with_resilience(
        base_url: impl Into<String>,
        retry: RetryPolicy,
        circuit: CircuitBreaker,
    ) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(DEFAULT_TIMEOUT)
                .build()
                .unwrap_or_default(),
            base_url: base_url.into(),
            circuit,
            retry,
        }
    }

    /// Fetch an account's balances. Retried on transient failures (transport errors, 5xx).
    /// Returns `NotFound` if the account does not exist on-chain yet.
    #[tracing::instrument(
        name = "horizon_balances",
        skip(self),
        fields(call_type = "balances", account_g = %account_g, outcome = tracing::field::Empty)
    )]
    pub async fn balances(&self, account_g: &str) -> Result<Vec<Balance>, ApiError> {
        let span = tracing::Span::current();
        let url = format!(
            "{}/accounts/{}",
            self.base_url.trim_end_matches('/'),
            account_g
        );
        let http = self.http.clone();
        let result = execute(&self.circuit, &self.retry, CallKind::ReadOnly, || {
            let url = url.clone();
            let http = http.clone();
            async move {
                let resp = http
                    .get(&url)
                    .send()
                    .await
                    .map_err(|_| FetchError::Transport)?;

                if resp.status() == reqwest::StatusCode::NOT_FOUND {
                    return Err(FetchError::NotFound);
                }
                if resp.status().is_server_error() {
                    return Err(FetchError::Transport); // retriable
                }
                if !resp.status().is_success() {
                    return Err(FetchError::Permanent);
                }
                let account: AccountResponse =
                    resp.json().await.map_err(|_| FetchError::Permanent)?;
                Ok(account.balances)
            }
        })
        .await;

        match &result {
            Ok(_) => span.record("outcome", "success"),
            Err(ResilienceError::Circuit) => span.record("outcome", "circuit_open"),
            Err(ResilienceError::Exhausted(FetchError::NotFound)) => {
                span.record("outcome", "not_found")
            }
            Err(ResilienceError::Exhausted(_)) => span.record("outcome", "failure"),
        };

        map_result(result)
    }

    /// Fetch an account's current sequence number. Retried on transient failures.
    /// Returns `NotFound` if the account doesn't exist.
    #[tracing::instrument(
        name = "horizon_account_sequence",
        skip(self),
        fields(call_type = "account_sequence", account_g = %account_g, outcome = tracing::field::Empty)
    )]
    pub async fn account_sequence(&self, account_g: &str) -> Result<i64, ApiError> {
        let span = tracing::Span::current();
        let res = self.account_info(account_g).await.map(|a| a.sequence);
        match &res {
            Ok(_) => span.record("outcome", "success"),
            Err(ApiError::NotFound) => span.record("outcome", "not_found"),
            Err(_) => span.record("outcome", "failure"),
        };
        res
    }

    /// Fetch balances, sequence, and reserve inputs for an account in a single Horizon call.
    /// `NotFound` if the account does not exist on-chain yet.
    #[tracing::instrument(
        name = "horizon_account_info",
        skip(self),
        fields(call_type = "account_info", account_g = %account_g, outcome = tracing::field::Empty)
    )]
    pub async fn account_info(&self, account_g: &str) -> Result<AccountInfo, ApiError> {
        // This is a read-only call, so it goes through the same retry + circuit-breaker path as
        // `balances`. (It previously issued a bare, unwrapped GET, so a transient 5xx from
        // Horizon failed immediately instead of being retried.)
        let span = tracing::Span::current();
        let url = format!(
            "{}/accounts/{}",
            self.base_url.trim_end_matches('/'),
            account_g
        );
        let http = self.http.clone();

        let result = execute(&self.circuit, &self.retry, CallKind::ReadOnly, || {
            let url = url.clone();
            let http = http.clone();
            async move {
                let resp = http
                    .get(&url)
                    .send()
                    .await
                    .map_err(|_| FetchError::Transport)?;

                if resp.status() == reqwest::StatusCode::NOT_FOUND {
                    return Err(FetchError::NotFound);
                }
                if resp.status().is_server_error() {
                    return Err(FetchError::Transport); // retriable
                }
                if !resp.status().is_success() {
                    return Err(FetchError::Permanent);
                }

                let account: AccountResponse =
                    resp.json().await.map_err(|_| FetchError::Permanent)?;
                let sequence = account
                    .sequence
                    .parse::<i64>()
                    .map_err(|_| FetchError::Permanent)?;
                Ok(AccountInfo {
                    balances: account.balances,
                    sequence,
                    subentry_count: account.subentry_count,
                    num_sponsoring: account.num_sponsoring,
                    num_sponsored: account.num_sponsored,
                })
            }
        })
        .await;

        match &result {
            Ok(_) => span.record("outcome", "success"),
            Err(ResilienceError::Circuit) => span.record("outcome", "circuit_open"),
            Err(ResilienceError::Exhausted(FetchError::NotFound)) => {
                span.record("outcome", "not_found")
            }
            Err(ResilienceError::Exhausted(_)) => span.record("outcome", "failure"),
        };

        match result {
            Ok(info) => Ok(info),
            Err(ResilienceError::Circuit) => Err(ApiError::Internal),
            Err(ResilienceError::Exhausted(FetchError::NotFound)) => Err(ApiError::NotFound),
            Err(ResilienceError::Exhausted(_)) => Err(ApiError::Internal),
        }
    }

    /// Submit a signed transaction (base64 XDR envelope) to Horizon.
    ///
    /// **Not retried** — see the module-level documentation and [`octo_resilience`] for the full
    /// rationale. TL;DR: a transport timeout does not mean the tx was rejected; it may have
    /// already landed on-chain, so a retry risks double-submission. The circuit breaker still
    /// applies: if Horizon is clearly down we fail fast rather than queuing up timeouts.
    ///
    /// Returns the result even when the transaction failed on-chain (`successful == false`) so the
    /// caller can record the failure; only transport/HTTP errors return `Err`.
    #[tracing::instrument(
        name = "horizon_submit_transaction",
        skip(self, envelope_xdr),
        fields(call_type = "submit", outcome = tracing::field::Empty)
    )]
    pub async fn submit_transaction(&self, envelope_xdr: &str) -> Result<SubmitResult, ApiError> {
        // NOTE: an eager, unwrapped POST used to sit here ahead of the resilience-wrapped call
        // below. It fired a *duplicate* submission on every call and referenced `http`/`xdr`
        // locals that were never bound (so this did not compile). Removed — the single submit
        // now happens inside `execute`, with SUBMIT_TIMEOUT applied to that request.
        let span = tracing::Span::current();
        let url = format!("{}/transactions", self.base_url.trim_end_matches('/'));
        let http = self.http.clone();
        let xdr = envelope_xdr.to_string();

        let result = execute(&self.circuit, &self.retry, CallKind::Submit, || {
            let url = url.clone();
            let http = http.clone();
            let xdr = xdr.clone();
            async move {
                let resp = http
                    .post(&url)
                    .form(&[("tx", &xdr)])
                    .timeout(SUBMIT_TIMEOUT)
                    .send()
                    .await
                    .map_err(|_| FetchError::Transport)?;

                // Horizon returns 400 with a problem document when the tx is rejected (e.g. bad
                // seq, no reserve). Parse it either way so we can surface the specific result
                // codes — with client-signed transactions the caller needs to know *why* it
                // failed in order to correct and re-sign.
                let status = resp.status();
                let body: SubmitResponse = match resp.json().await {
                    Ok(b) => b,
                    Err(_) => {
                        if status.is_success() {
                            return Err(FetchError::Transport);
                        }
                        return Err(FetchError::TxRejected);
                    }
                };
                let (transaction_code, operation_codes) = body
                    .extras
                    .and_then(|e| e.result_codes)
                    .map(|rc| (rc.transaction, rc.operations))
                    .unwrap_or((None, Vec::new()));
                Ok(SubmitResult {
                    hash: body.hash,
                    successful: body.successful,
                    ledger: body.ledger,
                    transaction_code,
                    operation_codes,
                })
            }
        })
        .await;

        match &result {
            Ok(r) => {
                if r.successful {
                    span.record("outcome", "success");
                } else {
                    span.record("outcome", "tx_failed");
                }
            }
            Err(ResilienceError::Circuit) => span.record("outcome", "circuit_open"),
            Err(ResilienceError::Exhausted(FetchError::TxRejected)) => {
                span.record("outcome", "rejected")
            }
            Err(ResilienceError::Exhausted(_)) => span.record("outcome", "failure"),
        };

        match result {
            Ok(r) => Ok(r),
            Err(ResilienceError::Circuit) => Err(ApiError::Internal),
            Err(ResilienceError::Exhausted(FetchError::TxRejected)) => Err(ApiError::BadRequest(
                "transaction rejected by network".into(),
            )),
            Err(ResilienceError::Exhausted(_)) => Err(ApiError::Internal),
        }
    }

    // Probe Horizon root endpoint to verify node reachability.
    pub async fn check_reachability(&self) -> Result<(), String> {
        let url = self.base_url.trim_end_matches('/');
        let resp = self
            .http
            .get(url)
            .timeout(Duration::from_secs(3))
            .send()
            .await
            .map_err(|e| format!("horizon unreachable: {e}"))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("horizon returned HTTP {}", resp.status()))
        }
    }
}

// ---------------------------------------------------------------------------
// Internal fetch-error type
// ---------------------------------------------------------------------------

/// Errors from inside retry closures. `Transport` = transient (retriable on read-only calls);
/// others are permanent.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FetchError {
    /// Network error, timeout, or 5xx — transient.
    Transport,
    /// Horizon returned 404 — account not found. Permanent.
    NotFound,
    /// Any other non-success status. Permanent.
    Permanent,
    /// `POST /transactions` returned no parseable hash — tx rejected. Permanent.
    TxRejected,
}

impl octo_resilience::Retriable for FetchError {
    fn is_retriable(&self) -> bool {
        // Only transport-level failures (network error, timeout, 5xx) are worth another attempt.
        // 404 / other 4xx / a rejected tx are settled answers — retrying them would also let a
        // few of them trip the circuit breaker and mask the real error.
        matches!(self, FetchError::Transport)
    }
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport => write!(f, "transport error"),
            Self::NotFound => write!(f, "account not found"),
            Self::Permanent => write!(f, "permanent error"),
            Self::TxRejected => write!(f, "transaction rejected"),
        }
    }
}

/// Map a resilience `Result` (read-only calls) to an `ApiError`.
fn map_result<T>(r: Result<T, ResilienceError<FetchError>>) -> Result<T, ApiError> {
    match r {
        Ok(v) => Ok(v),
        Err(ResilienceError::Circuit) => Err(ApiError::Internal),
        Err(ResilienceError::Exhausted(FetchError::NotFound)) => Err(ApiError::NotFound),
        Err(ResilienceError::Exhausted(_)) => Err(ApiError::Internal),
    }
}

// ---------------------------------------------------------------------------
// Friendbot
// ---------------------------------------------------------------------------

/// Fund a testnet account via friendbot. Best-effort; a single retry is safe because friendbot
/// is idempotent (re-funding an already-funded account is a no-op on testnet).
#[tracing::instrument(
    name = "horizon_friendbot_fund",
    skip(friendbot_url),
    fields(call_type = "friendbot", account_g = %account_g, outcome = tracing::field::Empty)
)]
pub async fn friendbot_fund(friendbot_url: &str, account_g: &str) -> Result<(), ApiError> {
    let span = tracing::Span::current();
    let res = friendbot_fund_with_timeout(friendbot_url, account_g, DEFAULT_TIMEOUT).await;
    match &res {
        Ok(_) => span.record("outcome", "success"),
        Err(_) => span.record("outcome", "failure"),
    };
    res
}

async fn friendbot_fund_with_timeout(
    friendbot_url: &str,
    account_g: &str,
    timeout: Duration,
) -> Result<(), ApiError> {
    let url = format!(
        "{}/?addr={}",
        friendbot_url.trim_end_matches('/'),
        account_g
    );
    let resp = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .unwrap_or_default()
        .get(&url)
        .send()
        .await
        .map_err(|_| ApiError::Internal)?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(ApiError::Internal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Binds an ephemeral listener that accepts a connection and then holds it open forever
    /// without reading or writing, so callers get no response and only the client's own timeout
    /// ends the request. Returns the base URL to hit.
    async fn hanging_server() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((_socket, _)) = listener.accept().await {
                std::future::pending::<()>().await;
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn horizon_client_times_out_and_maps_to_internal_error() {
        let base_url = hanging_server().await;
        let horizon = Horizon {
            http: reqwest::Client::builder()
                .timeout(Duration::from_millis(200))
                .build()
                .unwrap(),
            base_url,
            // This test exercises the transport timeout, so keep resilience out of the way:
            // a single attempt and a breaker that won't trip within the test.
            retry: RetryPolicy {
                max_attempts: 1,
                ..Default::default()
            },
            circuit: CircuitBreaker::new(u32::MAX, Duration::from_secs(60)),
        };

        let result = horizon.balances("GABCDEFGHIJKLMNOPQRSTUVWXYZ").await;
        assert!(matches!(result, Err(ApiError::Internal)));
    }

    #[tokio::test]
    async fn friendbot_fund_times_out_and_returns_an_error() {
        let base_url = hanging_server().await;

        let result = friendbot_fund_with_timeout(
            &base_url,
            "GABCDEFGHIJKLMNOPQRSTUVWXYZ",
            Duration::from_millis(200),
        )
        .await;

        assert!(matches!(result, Err(ApiError::Internal)));
    }

    // Asserts that every Horizon call type emits its distinct named tracing span.
    #[tokio::test]
    async fn horizon_calls_emit_named_tracing_spans() {
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::layer::SubscriberExt;

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

        let base_url = hanging_server().await;
        let horizon = Horizon {
            http: reqwest::Client::builder()
                .timeout(Duration::from_millis(50))
                .build()
                .unwrap(),
            base_url: base_url.clone(),
            retry: RetryPolicy {
                max_attempts: 1,
                ..Default::default()
            },
            circuit: CircuitBreaker::new(u32::MAX, Duration::from_secs(60)),
        };

        let _ = horizon.balances("GABCDEFGHIJKLMNOPQRSTUVWXYZ").await;
        let _ = horizon.account_sequence("GABCDEFGHIJKLMNOPQRSTUVWXYZ").await;
        let _ = horizon.submit_transaction("AAAA").await;
        let _ = friendbot_fund("http://127.0.0.1:1", "GABCDEFGHIJKLMNOPQRSTUVWXYZ").await;

        let spans = recorded_spans.lock().unwrap().clone();
        assert!(spans.contains(&"horizon_balances".to_string()));
        assert!(spans.contains(&"horizon_account_sequence".to_string()));
        assert!(spans.contains(&"horizon_account_info".to_string()));
        assert!(spans.contains(&"horizon_submit_transaction".to_string()));
        assert!(spans.contains(&"horizon_friendbot_fund".to_string()));
    }
}
