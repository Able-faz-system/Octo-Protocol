//! Shared resilience primitives for Horizon HTTP calls.
//!
//! # Components
//!
//! - [`RetryPolicy`]: exponential backoff with jitter for transient failures. Used exclusively on
//!   **read-only** Horizon calls (balances, account sequence, payments). Never applied to
//!   `submit_transaction` — see the "Submit asymmetry" section below.
//!
//! - [`CircuitBreaker`]: after `failure_threshold` consecutive failures the circuit **opens**,
//!   short-circuiting further calls with [`CircuitError::Open`] for `reset_timeout` seconds.
//!   After the cool-down the circuit moves to **half-open**: exactly one probe call is attempted
//!   (concurrent callers still see `Open`); success closes it, failure re-opens it.
//!
//! # Submit asymmetry — why submit_transaction is never retried
//!
//! Horizon's `POST /transactions` is **not idempotent** from the client's perspective:
//!
//! 1. Horizon receives the XDR and broadcasts it to the network.
//! 2. The network accepts it and closes the ledger.
//! 3. **Before** Horizon can send back `200 OK`, the client's TCP connection times out (or the
//!    Horizon node restarts, crashes, etc.).
//! 4. The client sees an error — but the transaction has already landed on-chain.
//!
//! If the client retries, it submits the same transaction a second time. For a payment this is
//! catastrophic: the second submission will either:
//!   - succeed (double-spend), because the sequence number was bumped by the first, or more
//!     commonly
//!   - fail with `tx_bad_seq` — but by then the caller has already wasted time retrying and the
//!     caller-level error-handling is confused about whether the payment landed.
//!
//! The correct response to a transport error on `submit_transaction` is to **query the ledger**
//! by hash to determine whether the transaction actually landed, and act accordingly. That query
//! path lives in the caller (API route / withdrawal handler) and is outside this crate's scope.
//!
//! The circuit breaker **does** apply to submission (it counts failures and opens when Horizon is
//! clearly down), but the retry policy explicitly does not.
#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tracing::warn;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Policy controlling retry behaviour for **read-only** Horizon calls.
///
/// # Defaults
/// - `max_attempts`: 3 (initial attempt + 2 retries)
/// - `base_delay_ms`: 200 ms
/// - `max_delay_ms`: 5 000 ms
/// - `multiplier`: 2.0 (doubles each attempt)
/// - `jitter_factor`: 0.2 (±20 % random jitter to avoid thundering herd)
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Total number of attempts (including the first). Must be ≥ 1.
    pub max_attempts: u32,
    /// Initial delay before the first retry, in milliseconds.
    pub base_delay_ms: u64,
    /// Upper bound on the delay, in milliseconds.
    pub max_delay_ms: u64,
    /// Backoff multiplier applied to the delay on each retry.
    pub multiplier: f64,
    /// Jitter fraction — a random value in `[0, jitter_factor)` of the current delay is added
    /// (or subtracted) so concurrent requests don't all retry at the same moment.
    pub jitter_factor: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay_ms: 200,
            max_delay_ms: 5_000,
            multiplier: 2.0,
            jitter_factor: 0.2,
        }
    }
}

impl RetryPolicy {
    /// Compute the delay before attempt number `attempt` (0-indexed: attempt 0 = first retry).
    ///
    /// Invariant: never panics and never exceeds `max_delay_ms`, whatever `attempt` is passed.
    pub fn delay_for(&self, attempt: u32) -> Duration {
        let base = self.base_delay_ms as f64;
        let max = self.max_delay_ms as f64;
        // Saturate rather than wrap: `attempt as i32` turned huge attempts into negative powers.
        let exponent = i32::try_from(attempt).unwrap_or(i32::MAX);
        // A zero base stays zero instead of becoming 0 × ∞ = NaN once the power overflows.
        let exp = if base == 0.0 {
            0.0
        } else {
            base * self.multiplier.powi(exponent)
        };
        // Clamp before any further arithmetic; a NaN (bad multiplier) backs off fully.
        let capped = if exp.is_nan() { max } else { exp.clamp(0.0, max) };
        // Simple pseudo-jitter: use the attempt index as a cheap entropy source.
        // In production this is fine — the goal is just to spread bursts out, not
        // to be cryptographically random.
        let jitter_range = capped * self.jitter_factor;
        let jitter = if attempt % 2 == 0 {
            jitter_range * 0.5
        } else {
            jitter_range * -0.5
        };
        // Jitter must not push past the documented upper bound either.
        let ms = (capped + jitter).clamp(0.0, max) as u64;
        Duration::from_millis(ms)
    }
}

// ---------------------------------------------------------------------------
// Circuit breaker state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum CbState {
    Closed,
    Open { opened_at: Instant },
    /// A single probe is in flight; it was claimed at `probe_started`.
    HalfOpen { probe_started: Instant },
}

/// Shared, thread-safe circuit-breaker state.
#[derive(Debug)]
struct CbInner {
    state: CbState,
    consecutive_failures: u32,
}

/// A circuit breaker that wraps concurrent Horizon calls.
///
/// # State machine
///
/// ```text
///  Closed ──[failure_threshold failures]──▶ Open
///    ▲                                         │
///    │                                    [reset_timeout]
///    │                                         │
///    └──[success]── HalfOpen ◀────────────────┘
///                     │
///               [next failure]
///                     │
///                     ▼
///                   Open (re-opens)
/// ```
///
/// In the **Closed** state every call passes through. In the **Open** state every call returns
/// [`CircuitError::Open`] immediately — no network request is made. After `reset_timeout` the
/// breaker becomes **HalfOpen** and allows one probe call through; success → Closed, failure →
/// Open again.
#[derive(Clone, Debug)]
pub struct CircuitBreaker {
    inner: Arc<Mutex<CbInner>>,
    /// How many consecutive failures before opening.
    pub failure_threshold: u32,
    /// How long the circuit stays open before allowing a probe.
    pub reset_timeout: Duration,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, reset_timeout: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(CbInner {
                state: CbState::Closed,
                consecutive_failures: 0,
            })),
            failure_threshold,
            reset_timeout,
        }
    }

    /// Check whether a call may proceed. Returns `Err(CircuitError::Open)` when the circuit is
    /// open and the cool-down has not elapsed yet.
    ///
    /// Single-probe guarantee: once the cool-down elapses, exactly one caller claims the probe
    /// slot — the Open → HalfOpen transition and the claim happen under one lock. Every other
    /// caller gets `CircuitError::Open` until that probe reports via `on_success`/`on_failure`.
    /// A probe that never reports (cancelled future, non-retriable error) frees the slot after
    /// another `reset_timeout`, so a lost probe cannot wedge the breaker half-open forever.
    pub fn check(&self) -> Result<(), CircuitError> {
        let mut inner = self.inner.lock().unwrap();
        let since = match inner.state {
            CbState::Closed => return Ok(()),
            CbState::Open { opened_at } => opened_at,
            CbState::HalfOpen { probe_started } => probe_started,
        };
        if since.elapsed() >= self.reset_timeout {
            inner.state = CbState::HalfOpen {
                probe_started: Instant::now(),
            };
            Ok(())
        } else {
            Err(CircuitError::Open)
        }
    }

    /// Record a successful call. Resets the failure counter and closes the circuit.
    pub fn on_success(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.consecutive_failures = 0;
        inner.state = CbState::Closed;
    }

    /// Record a failed call. Increments the consecutive failure counter and potentially opens the
    /// circuit.
    pub fn on_failure(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.consecutive_failures += 1;
        if inner.consecutive_failures >= self.failure_threshold {
            inner.state = CbState::Open {
                opened_at: Instant::now(),
            };
            warn!(
                failures = inner.consecutive_failures,
                "circuit breaker opened"
            );
        }
    }

    /// Returns `true` when the circuit is currently open (refusing calls).
    #[cfg(test)]
    pub fn is_open(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        matches!(inner.state, CbState::Open { .. })
    }

    /// Returns `true` when the circuit is closed (normal operation).
    #[cfg(test)]
    pub fn is_closed(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.state == CbState::Closed
    }
}

/// Errors produced by the circuit breaker / retry wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitError {
    /// The circuit is open — call was short-circuited without hitting the network.
    Open,
}

// ---------------------------------------------------------------------------
// Combined retry + circuit-breaker executor
// ---------------------------------------------------------------------------

/// The category of a call — controls whether the retry policy is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallKind {
    /// A read-only, idempotent call. Eligible for retry-with-backoff.
    ReadOnly,
    /// A non-idempotent call (e.g. `submit_transaction`). Only the circuit breaker is applied;
    /// the retry policy is **not** applied even on transient failures, because a successful
    /// submission that resulted in a client-visible timeout must not be re-submitted.
    Submit,
}

/// Whether a given error is worth retrying.
///
/// Without this, `execute` would retry *every* failure — including permanent ones like a 404.
/// That both wastes attempts and, worse, lets a handful of legitimate "not found" responses trip
/// the circuit breaker, so the caller sees `Circuit` instead of the real error.
///
/// Error types passed to [`execute`] implement this to say which failures are transient.
pub trait Retriable {
    /// `true` if this error is transient and the call may be retried.
    fn is_retriable(&self) -> bool;
}

// Convenience impls for error types used directly in tests.
impl Retriable for &str {
    fn is_retriable(&self) -> bool {
        true
    }
}

impl Retriable for () {
    fn is_retriable(&self) -> bool {
        true
    }
}

/// Execute `f` with retry-and-circuit-breaker protection.
///
/// - If `kind == CallKind::Submit`, `f` is attempted at most **once** regardless of the retry
///   policy (the circuit breaker still applies).
/// - If `kind == CallKind::ReadOnly`, `f` is retried up to `policy.max_attempts` times with
///   exponential backoff, stopping early on an error that reports itself non-retriable.
///
/// The closure receives no arguments and must return `Ok(T)` on success or `Err(E)` on failure.
///
/// Returns:
/// - `Ok(T)` — the call succeeded.
/// - `Err(ResilienceError::Circuit)` — the circuit was open (no network call made).
/// - `Err(ResilienceError::Exhausted(e))` — all attempts failed; `e` is the last error.
// NOTE: no `F` type parameter here — the closure is taken as `impl FnMut() -> Fut`, so a
// declared-but-unused `F` would be uninferable and every call site would fail with E0282.
pub async fn execute<Fut, T, E>(
    circuit: &CircuitBreaker,
    policy: &RetryPolicy,
    kind: CallKind,
    mut f: impl FnMut() -> Fut,
) -> Result<T, ResilienceError<E>>
where
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Debug + Retriable,
{
    circuit.check().map_err(|_| ResilienceError::Circuit)?;

    let max_attempts = if kind == CallKind::Submit {
        1
    } else {
        policy.max_attempts.max(1)
    };

    let mut last_err: Option<E> = None;
    for attempt in 0..max_attempts {
        match f().await {
            Ok(val) => {
                circuit.on_success();
                return Ok(val);
            }
            Err(e) => {
                // A permanent error (e.g. Horizon 404) is the *answer*, not a fault: retrying it
                // wastes attempts and would let a few of them trip the breaker, masking the real
                // error behind `Circuit`. Return it immediately without counting a failure.
                if !e.is_retriable() {
                    return Err(ResilienceError::Exhausted(e));
                }
                circuit.on_failure();
                // Re-check: if this failure just opened the circuit, stop retrying.
                if circuit.check().is_err() {
                    return Err(ResilienceError::Circuit);
                }
                last_err = Some(e);
                if attempt + 1 < max_attempts {
                    let delay = policy.delay_for(attempt);
                    sleep(delay).await;
                }
            }
        }
    }
    Err(ResilienceError::Exhausted(last_err.unwrap()))
}

/// Errors returned by [`execute`].
#[derive(Debug)]
pub enum ResilienceError<E> {
    /// The circuit breaker was open — the call was not attempted.
    Circuit,
    /// All retry attempts were exhausted; this is the last observed error.
    Exhausted(E),
}

impl<E: std::fmt::Display> std::fmt::Display for ResilienceError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Circuit => write!(f, "circuit breaker open"),
            Self::Exhausted(e) => write!(f, "all attempts exhausted: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Config struct (for use by bin/server)
// ---------------------------------------------------------------------------

/// Resilience configuration for Horizon calls, read from environment variables.
#[derive(Debug, Clone)]
pub struct ResilienceConfig {
    /// Maximum number of attempts for read-only calls (including the initial attempt).
    pub max_attempts: u32,
    /// Base backoff delay in milliseconds.
    pub base_delay_ms: u64,
    /// Maximum backoff delay in milliseconds.
    pub max_delay_ms: u64,
    /// Number of consecutive failures before the circuit opens.
    pub cb_failure_threshold: u32,
    /// How many seconds the circuit stays open before allowing a probe.
    pub cb_reset_timeout_secs: u64,
}

impl Default for ResilienceConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay_ms: 200,
            max_delay_ms: 5_000,
            cb_failure_threshold: 5,
            cb_reset_timeout_secs: 30,
        }
    }
}

impl ResilienceConfig {
    /// Read configuration from environment variables, falling back to defaults.
    ///
    /// | Variable | Default | Description |
    /// |---|---|---|
    /// | `HORIZON_MAX_ATTEMPTS` | 3 | Retry attempts for read-only calls |
    /// | `HORIZON_BASE_DELAY_MS` | 200 | Base backoff delay (ms) |
    /// | `HORIZON_MAX_DELAY_MS` | 5000 | Max backoff delay (ms) |
    /// | `HORIZON_CB_FAILURE_THRESHOLD` | 5 | Consecutive failures before circuit opens |
    /// | `HORIZON_CB_RESET_TIMEOUT_SECS` | 30 | Seconds before circuit allows a probe |
    pub fn from_env() -> Self {
        fn parse<T: std::str::FromStr>(key: &str, default: T) -> T {
            std::env::var(key)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        }
        Self {
            max_attempts: parse("HORIZON_MAX_ATTEMPTS", 3),
            base_delay_ms: parse("HORIZON_BASE_DELAY_MS", 200),
            max_delay_ms: parse("HORIZON_MAX_DELAY_MS", 5_000),
            cb_failure_threshold: parse("HORIZON_CB_FAILURE_THRESHOLD", 5),
            cb_reset_timeout_secs: parse("HORIZON_CB_RESET_TIMEOUT_SECS", 30),
        }
    }

    /// Build a [`RetryPolicy`] from this config.
    pub fn retry_policy(&self) -> RetryPolicy {
        RetryPolicy {
            max_attempts: self.max_attempts,
            base_delay_ms: self.base_delay_ms,
            max_delay_ms: self.max_delay_ms,
            ..Default::default()
        }
    }

    /// Build a [`CircuitBreaker`] from this config.
    pub fn circuit_breaker(&self) -> CircuitBreaker {
        CircuitBreaker::new(
            self.cb_failure_threshold,
            Duration::from_secs(self.cb_reset_timeout_secs),
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    // --- RetryPolicy ---------------------------------------------------------

    #[test]
    fn delay_grows_with_multiplier() {
        let p = RetryPolicy {
            base_delay_ms: 100,
            multiplier: 2.0,
            max_delay_ms: 10_000,
            jitter_factor: 0.0,
            ..Default::default()
        };
        // attempt 0 → 100 ms, attempt 1 → 200 ms, attempt 2 → 400 ms
        assert_eq!(p.delay_for(0), Duration::from_millis(100));
        assert_eq!(p.delay_for(1), Duration::from_millis(200));
        assert_eq!(p.delay_for(2), Duration::from_millis(400));
    }

    #[test]
    fn delay_is_capped_at_max() {
        let p = RetryPolicy {
            base_delay_ms: 1_000,
            multiplier: 100.0,
            max_delay_ms: 2_000,
            jitter_factor: 0.0,
            ..Default::default()
        };
        assert_eq!(p.delay_for(5), Duration::from_millis(2_000));
    }

    // --- CircuitBreaker ------------------------------------------------------

    #[test]
    fn circuit_opens_after_threshold() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(60));
        assert!(cb.is_closed());
        cb.on_failure();
        cb.on_failure();
        assert!(cb.is_closed(), "not yet at threshold");
        cb.on_failure();
        assert!(cb.is_open(), "should open at threshold");
        assert_eq!(cb.check(), Err(CircuitError::Open));
    }

    #[test]
    fn circuit_resets_on_success() {
        let cb = CircuitBreaker::new(2, Duration::from_secs(60));
        cb.on_failure();
        cb.on_failure();
        assert!(cb.is_open());
        // Manually force to half-open by pretending the timeout elapsed.
        {
            let mut inner = cb.inner.lock().unwrap();
            inner.state = CbState::HalfOpen {
                probe_started: Instant::now(),
            };
        }
        cb.on_success();
        assert!(cb.is_closed());
    }

    // --- execute: ReadOnly retries ------------------------------------------

    #[tokio::test]
    async fn read_only_call_retries_on_failure_then_succeeds() {
        let call_count = Arc::new(AtomicU32::new(0));
        let cb = CircuitBreaker::new(10, Duration::from_secs(60)); // high threshold
        let policy = RetryPolicy {
            max_attempts: 3,
            base_delay_ms: 0, // no delay in tests
            max_delay_ms: 0,
            ..Default::default()
        };

        let cc = call_count.clone();
        let result = execute(&cb, &policy, CallKind::ReadOnly, || {
            let cc = cc.clone();
            async move {
                let n = cc.fetch_add(1, Ordering::SeqCst) + 1;
                if n < 3 {
                    Err("transient error")
                } else {
                    Ok("success")
                }
            }
        })
        .await;

        assert_eq!(result.unwrap(), "success");
        assert_eq!(call_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn read_only_call_exhausts_retries() {
        let call_count = Arc::new(AtomicU32::new(0));
        let cb = CircuitBreaker::new(100, Duration::from_secs(60));
        let policy = RetryPolicy {
            max_attempts: 3,
            base_delay_ms: 0,
            max_delay_ms: 0,
            ..Default::default()
        };

        let cc = call_count.clone();
        let result: Result<&str, _> = execute(&cb, &policy, CallKind::ReadOnly, || {
            let cc = cc.clone();
            async move {
                cc.fetch_add(1, Ordering::SeqCst);
                Err("always fails")
            }
        })
        .await;

        assert!(matches!(result, Err(ResilienceError::Exhausted(_))));
        assert_eq!(call_count.load(Ordering::SeqCst), 3);
    }

    // --- execute: Submit is NOT retried -------------------------------------

    #[tokio::test]
    async fn submit_call_is_never_retried_even_on_error() {
        // This test guards the double-submission-risk asymmetry explicitly.
        // A Submit call must be attempted exactly once regardless of errors.
        let call_count = Arc::new(AtomicU32::new(0));
        let cb = CircuitBreaker::new(100, Duration::from_secs(60));
        let policy = RetryPolicy {
            max_attempts: 5, // high — must be ignored for Submit
            base_delay_ms: 0,
            max_delay_ms: 0,
            ..Default::default()
        };

        let cc = call_count.clone();
        let result: Result<&str, _> = execute(&cb, &policy, CallKind::Submit, || {
            let cc = cc.clone();
            async move {
                cc.fetch_add(1, Ordering::SeqCst);
                Err("timeout")
            }
        })
        .await;

        assert!(matches!(result, Err(ResilienceError::Exhausted(_))));
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "submit_transaction must never be retried; double-submission risk"
        );
    }

    // --- execute: circuit breaker short-circuits ----------------------------

    #[tokio::test]
    async fn open_circuit_short_circuits_without_calling_f() {
        let call_count = Arc::new(AtomicU32::new(0));
        // Threshold of 1 so the first failure opens it.
        let cb = CircuitBreaker::new(1, Duration::from_secs(60));
        let policy = RetryPolicy {
            max_attempts: 1,
            base_delay_ms: 0,
            max_delay_ms: 0,
            ..Default::default()
        };

        // First call: fails and opens the circuit.
        let cc = call_count.clone();
        let _ = execute(&cb, &policy, CallKind::ReadOnly, || {
            let cc = cc.clone();
            async move {
                cc.fetch_add(1, Ordering::SeqCst);
                Err::<(), _>("fail")
            }
        })
        .await;

        assert!(cb.is_open());
        let count_before = call_count.load(Ordering::SeqCst);

        // Second call: circuit is open — f must not be invoked.
        let cc2 = call_count.clone();
        let result: Result<(), _> = execute(&cb, &policy, CallKind::ReadOnly, || {
            let cc2 = cc2.clone();
            async move {
                cc2.fetch_add(1, Ordering::SeqCst);
                Err("should not be called")
            }
        })
        .await;

        assert!(matches!(result, Err(ResilienceError::Circuit)));
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            count_before,
            "no network call should be made when circuit is open"
        );
    }

    // --- execute: circuit closes after cool-down ----------------------------

    #[tokio::test]
    async fn circuit_closes_after_cooldown_and_successful_probe() {
        let cb = CircuitBreaker::new(1, Duration::from_millis(50));
        let policy = RetryPolicy {
            max_attempts: 1,
            base_delay_ms: 0,
            max_delay_ms: 0,
            ..Default::default()
        };

        // Open the circuit.
        let _ = execute::<_, (), _>(&cb, &policy, CallKind::ReadOnly, || async {
            Err("open it")
        })
        .await;
        assert!(cb.is_open());

        // Wait for the cool-down.
        sleep(Duration::from_millis(100)).await;

        // Next call should be allowed through as a probe.
        let result = execute(&cb, &policy, CallKind::ReadOnly, || async {
            Ok::<_, &str>(42)
        })
        .await;
        assert_eq!(result.unwrap(), 42);
        assert!(cb.is_closed());
    }
}
