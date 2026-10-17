//! Connection-pool tuning, read from the environment at startup.

use std::time::Duration;

/// Pool sizing and per-connection timeouts for [`crate::Store::connect_with`].
///
/// | Variable | Default | Meaning |
/// |---|---|---|
/// | `DB_MAX_CONNECTIONS` | 10 | Pool size shared by the API and ingest in one process |
/// | `DB_ACQUIRE_TIMEOUT_SECS` | 30 | Max wait for a free pooled connection |
/// | `DB_IDLE_TIMEOUT_SECS` | 600 | Idle connections above the minimum are closed after this |
/// | `DB_STATEMENT_TIMEOUT_SECS` | 30 | Server-side cap per statement; `0` disables it |
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreConfig {
    pub max_connections: u32,
    pub acquire_timeout: Duration,
    pub idle_timeout: Duration,
    /// Zero means no statement timeout (Postgres semantics).
    pub statement_timeout: Duration,
}

/// Upper bound on `DB_MAX_CONNECTIONS`; Postgres' own default `max_connections` is 100.
const MAX_POOL_SIZE: u32 = 1_000;

/// An env var held a value outside its accepted range.
#[derive(Debug, thiserror::Error)]
#[error("{var} must be {expected} (got {value:?})")]
pub struct StoreConfigError {
    pub var: &'static str,
    pub expected: &'static str,
    pub value: String,
}

impl Default for StoreConfig {
    /// Pool values match sqlx's defaults and the previously hardcoded `max_connections(10)`.
    fn default() -> Self {
        Self {
            max_connections: 10,
            acquire_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(600),
            statement_timeout: Duration::from_secs(30),
        }
    }
}

impl StoreConfig {
    /// Read the `DB_*` variables; unset falls back to [`StoreConfig::default`], invalid fails.
    pub fn from_env() -> Result<Self, StoreConfigError> {
        let d = Self::default();
        Ok(Self {
            max_connections: parse_env(
                "DB_MAX_CONNECTIONS",
                d.max_connections,
                "an integer between 1 and 1000",
                |n: &u32| (1..=MAX_POOL_SIZE).contains(n),
            )?,
            acquire_timeout: secs_env(
                "DB_ACQUIRE_TIMEOUT_SECS",
                d.acquire_timeout,
                "a whole number of seconds >= 1",
                |s| *s >= 1,
            )?,
            idle_timeout: secs_env(
                "DB_IDLE_TIMEOUT_SECS",
                d.idle_timeout,
                "a whole number of seconds >= 1",
                |s| *s >= 1,
            )?,
            statement_timeout: secs_env(
                "DB_STATEMENT_TIMEOUT_SECS",
                d.statement_timeout,
                "a whole number of seconds (0 disables)",
                |_| true,
            )?,
        })
    }
}

/// Parse a duration-in-seconds env var with a range check.
fn secs_env(
    var: &'static str,
    default: Duration,
    expected: &'static str,
    valid: impl Fn(&u64) -> bool,
) -> Result<Duration, StoreConfigError> {
    parse_env(var, default.as_secs(), expected, valid).map(Duration::from_secs)
}

/// Read `var`, returning `default` when unset and an error when unparsable or out of range.
fn parse_env<T: std::str::FromStr>(
    var: &'static str,
    default: T,
    expected: &'static str,
    valid: impl Fn(&T) -> bool,
) -> Result<T, StoreConfigError> {
    let Ok(raw) = std::env::var(var) else {
        return Ok(default);
    };
    match raw.trim().parse::<T>() {
        Ok(v) if valid(&v) => Ok(v),
        _ => Err(StoreConfigError {
            var,
            expected,
            value: raw,
        }),
    }
}
