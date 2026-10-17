//! Per-key fixed-window rate limiting for public and auth endpoints.
//!
//! Counters live behind a [`RateLimitStore`]: [`MemoryRateLimitStore`] is per-process (tests,
//! single-instance dev), while [`PostgresRateLimitStore`] is shared by every replica and survives
//! restarts — with N in-memory replicas the effective limit would be N times higher. Handlers call
//! [`RateLimiter::check`] explicitly, the same way auth is enforced per-handler here — there is
//! no tower middleware layer to configure or bypass.

use axum::http::HeaderMap;
use octo_store::{Store, StoreError};
use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Cap on tracked (key, class) buckets before expired entries are swept.
const SWEEP_THRESHOLD: usize = 10_000;

// Rate limit thresholds and fixed windows for API endpoints.
pub const AUTH_RATE_LIMIT: u32 = 10;
pub const AUTH_RATE_WINDOW: Duration = Duration::from_secs(60);
pub const OTP_RESEND_USER_LIMIT: u32 = 3;
pub const OTP_RESEND_USER_WINDOW: Duration = Duration::from_secs(3600);
pub const OTP_RESEND_IP_LIMIT: u32 = 10;
pub const OTP_RESEND_IP_WINDOW: Duration = Duration::from_secs(3600);
pub const PAY_READ_LIMIT: u32 = 60;
pub const PAY_READ_WINDOW: Duration = Duration::from_secs(60);
pub const PAY_INTENT_LIMIT: u32 = 5;
pub const PAY_INTENT_WINDOW: Duration = Duration::from_secs(60);
pub const PAY_STATUS_LIMIT: u32 = 60;
pub const PAY_STATUS_WINDOW: Duration = Duration::from_secs(60);
pub const PAY_SIGNING_INFO_LIMIT: u32 = 60;
pub const PAY_SIGNING_INFO_WINDOW: Duration = Duration::from_secs(60);
pub const PAY_SUBMIT_LIMIT: u32 = 20;
pub const PAY_SUBMIT_WINDOW: Duration = Duration::from_secs(60);

/// Boxed future so [`RateLimitStore`] stays object-safe without an `async-trait` dependency.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A backend that counts hits per `(key, class)` fixed window.
pub trait RateLimitStore: Send + Sync {
    /// Record one hit and return the hits in the current window, this one included.
    fn hit<'a>(
        &'a self,
        key: &'a str,
        class: &'static str,
        window: Duration,
    ) -> BoxFuture<'a, Result<u64, StoreError>>;

    /// Drop expired windows; returns how many were removed.
    fn prune(&self) -> BoxFuture<'_, Result<u64, StoreError>>;
}

/// Bucket key: the limited subject (IP, `otp:{user}`, ...) plus the endpoint class.
type BucketKey = (String, &'static str);
/// Bucket value: when the current fixed window ends, and hits so far within it.
type Bucket = (Instant, u64);

/// Per-process counters. Limits multiply with replica count and reset on restart.
#[derive(Clone, Default)]
pub struct MemoryRateLimitStore {
    buckets: Arc<Mutex<HashMap<BucketKey, Bucket>>>,
}

impl MemoryRateLimitStore {
    /// Synchronous hit counter shared by the trait impl and the [`RateLimiter`] fallback path.
    fn count(&self, key: &str, class: &'static str, window: Duration) -> u64 {
        let now = Instant::now();
        // A panic elsewhere must not disable rate limiting, so recover from poisoning.
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());

        if buckets.len() > SWEEP_THRESHOLD {
            buckets.retain(|_, (expires, _)| *expires > now);
        }

        let entry = buckets
            .entry((key.to_string(), class))
            .or_insert((now + window, 0));
        if now >= entry.0 {
            *entry = (now + window, 0);
        }
        entry.1 = entry.1.saturating_add(1);
        entry.1
    }

    fn prune_expired(&self) -> u64 {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let before = buckets.len();
        buckets.retain(|_, (expires, _)| *expires > now);
        (before - buckets.len()) as u64
    }
}

impl RateLimitStore for MemoryRateLimitStore {
    fn hit<'a>(
        &'a self,
        key: &'a str,
        class: &'static str,
        window: Duration,
    ) -> BoxFuture<'a, Result<u64, StoreError>> {
        Box::pin(std::future::ready(Ok(self.count(key, class, window))))
    }

    fn prune(&self) -> BoxFuture<'_, Result<u64, StoreError>> {
        Box::pin(std::future::ready(Ok(self.prune_expired())))
    }
}

/// Counters in the `rate_limit_buckets` table, shared by every instance on the database.
#[derive(Clone)]
pub struct PostgresRateLimitStore {
    store: Store,
}

impl PostgresRateLimitStore {
    pub fn new(store: Store) -> Self {
        Self { store }
    }
}

impl RateLimitStore for PostgresRateLimitStore {
    fn hit<'a>(
        &'a self,
        key: &'a str,
        class: &'static str,
        window: Duration,
    ) -> BoxFuture<'a, Result<u64, StoreError>> {
        Box::pin(async move {
            let hits = self.store.rate_limit_hit(key, class, window).await?;
            Ok(u64::try_from(hits).unwrap_or(0))
        })
    }

    fn prune(&self) -> BoxFuture<'_, Result<u64, StoreError>> {
        Box::pin(self.store.prune_rate_limit_buckets())
    }
}

/// Which [`RateLimitStore`] the server uses, selected by `RATE_LIMIT_BACKEND`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitBackend {
    Memory,
    Postgres,
}

impl RateLimitBackend {
    /// Accepts `memory` or `postgres` (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "memory" => Some(Self::Memory),
            "postgres" => Some(Self::Postgres),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Postgres => "postgres",
        }
    }
}

/// The limiter handlers call; cheap to clone.
#[derive(Clone)]
pub struct RateLimiter {
    backend: Arc<dyn RateLimitStore>,
    /// Used only when `backend` errors: a database blip degrades to per-process limits rather
    /// than disabling limits (fail-open) or rejecting every request (fail-closed).
    fallback: MemoryRateLimitStore,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::memory()
    }
}

impl RateLimiter {
    /// Per-process limiter (tests and single-instance dev).
    pub fn memory() -> Self {
        Self::with_backend(Arc::new(MemoryRateLimitStore::default()))
    }

    /// Limiter shared across replicas through Postgres.
    pub fn postgres(store: Store) -> Self {
        Self::with_backend(Arc::new(PostgresRateLimitStore::new(store)))
    }

    pub fn with_backend(backend: Arc<dyn RateLimitStore>) -> Self {
        Self {
            backend,
            fallback: MemoryRateLimitStore::default(),
        }
    }

    /// Build the limiter for a configured backend.
    pub fn for_backend(backend: RateLimitBackend, store: Store) -> Self {
        match backend {
            RateLimitBackend::Memory => Self::memory(),
            RateLimitBackend::Postgres => Self::postgres(store),
        }
    }

    /// Record a hit for `(key, class)`; false when the fixed window's limit is exceeded.
    pub async fn check(&self, key: &str, class: &'static str, limit: u32, window: Duration) -> bool {
        let hits = match self.backend.hit(key, class, window).await {
            Ok(hits) => hits,
            Err(e) => {
                tracing::warn!(error = ?e, class, "rate-limit backend failed; using per-process fallback");
                self.fallback.count(key, class, window)
            }
        };
        hits <= u64::from(limit)
    }

    /// Prune expired windows in the backend and the fallback. Run periodically.
    pub async fn prune(&self) -> Result<u64, StoreError> {
        self.fallback.prune_expired();
        self.backend.prune().await
    }
}

/// Best-effort client IP: first hop of `X-Forwarded-For` (set by a fronting proxy), else the
/// socket peer address, else a shared fallback key (still rate-limited, just collectively).
///
/// The forwarded hop is only used when it parses as an IP, and is re-serialised canonically, so
/// junk or oversized headers cannot mint unbounded rate-limit keys (or rows, with Postgres).
pub fn client_ip(headers: &HeaderMap, peer: Option<std::net::SocketAddr>) -> String {
    let forwarded = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|xff| xff.split(',').next())
        .and_then(|first| first.trim().parse::<IpAddr>().ok());
    if let Some(ip) = forwarded {
        return ip.to_string();
    }
    match peer {
        Some(addr) => addr.ip().to_string(),
        None => "unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allows_up_to_limit_then_rejects() {
        let rl = RateLimiter::default();
        let window = Duration::from_secs(60);
        for _ in 0..5 {
            assert!(rl.check("1.2.3.4", "test", 5, window).await);
        }
        assert!(!rl.check("1.2.3.4", "test", 5, window).await);
        // A different IP has its own bucket.
        assert!(rl.check("5.6.7.8", "test", 5, window).await);
        // A different class on the same IP has its own bucket too.
        assert!(rl.check("1.2.3.4", "other", 5, window).await);
    }

    #[tokio::test]
    async fn window_resets_after_expiry() {
        let rl = RateLimiter::default();
        let window = Duration::from_millis(30);
        assert!(rl.check("1.2.3.4", "test", 1, window).await);
        assert!(!rl.check("1.2.3.4", "test", 1, window).await);
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(rl.check("1.2.3.4", "test", 1, window).await);
    }

    #[test]
    fn client_ip_prefers_forwarded_header() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "9.9.9.9, 10.0.0.1".parse().unwrap());
        assert_eq!(client_ip(&headers, None), "9.9.9.9");

        let empty = HeaderMap::new();
        let peer = "127.0.0.1:5000".parse().ok();
        assert_eq!(client_ip(&empty, peer), "127.0.0.1");
        assert_eq!(client_ip(&empty, None), "unknown");
    }
}
