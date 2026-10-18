//! octo service entry point.
//!
// Loads config from env, connects & migrates the DB, then runs both the REST API (axum)
// and the deposit ingest supervisor (polls Horizon for all wallets) in one process.
// Can be split for scale — ingest cursor makes the worker restart-safe and rerunnable.
//
// `octo-server verify-audit-chain [--user <uuid>]` instead verifies the audit hash chain and
// exits non-zero if any chain is broken (needs only DATABASE_URL and AUDIT_CHAIN_KEY).
#![forbid(unsafe_code)]

mod mainnet_guard;

use anyhow::{Context, Result};
use octo_api::rate_limit::{RateLimitBackend, RateLimiter};
use octo_api::{build_router, AppState};
use octo_email::EmailSender;
use octo_ingest::Supervisor;
use octo_resilience::ResilienceConfig;
use octo_store::{AuditChainKey, AuditChainStatus, Store, StoreConfig};
use octo_wallet_core::StellarNetwork;
use octo_webhooks::WebhookSender;
use std::future::IntoFuture;
use std::fmt;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

fn main() -> Result<()> {
    // Load .env if present (no-op in production where env is set directly).
    let _ = dotenvy::dotenv();
    init_tracing();

    // Migrator-role entry point: needs only DATABASE_URL, never the app's secrets.
    if std::env::args().nth(1).as_deref() == Some("--migrate-only") {
        let url = std::env::var("DATABASE_URL").context("DATABASE_URL is required")?;
        return runtime()?.block_on(async {
            let store = Store::connect(&url).await.context("connect to database")?;
            store.migrate().await.context("run migrations")?;
            tracing::info!("migrations applied; exiting (--migrate-only)");
            Ok(())
        });
    }

    // Config (and so every secret) is read and scrubbed from the environment *before* the runtime
    // starts any threads: removing env vars is only sound while nothing else can be reading them.
    if std::env::args().nth(1).as_deref() == Some("verify-audit-chain") {
        let cfg = VerifyConfig::from_env()?;
        return runtime()?.block_on(verify_audit_chain(cfg));
    }
    let cfg = Config::from_env()?;
    // Fail closed before touching the DB; exit directly so the operator sees exactly one fatal line.
    if let Err(e) = cfg.ensure_safe_for_network() {
        tracing::error!(network = cfg.network.as_str(), "{e}");
        std::process::exit(1);
    }
    runtime()?.block_on(serve(cfg))
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")
}

async fn serve(cfg: Config) -> Result<()> {
    tracing::info!(network = cfg.network.as_str(), bind = %cfg.bind_addr, "starting octo-server");

    // Database.
    let db = &cfg.store;
    tracing::info!(
        max_connections = db.max_connections,
        acquire_timeout_secs = db.acquire_timeout.as_secs(),
        idle_timeout_secs = db.idle_timeout.as_secs(),
        statement_timeout_secs = db.statement_timeout.as_secs(),
        "database pool config"
    );
    if db.statement_timeout.is_zero() {
        tracing::warn!("DB_STATEMENT_TIMEOUT_SECS=0: statements may run unbounded");
    }
    let store = Store::connect_with(&cfg.database_url, db)
        .await
        .context("connect to database")?;
    // A least-privilege runtime role can't run DDL; migrations then run separately as the
    // migrator role (see docs/postgres-roles.md).
    if cfg.run_migrations {
        store.migrate().await.context("run migrations")?;
        tracing::info!("database connected and migrated");
    } else {
        tracing::info!("database connected (RUN_MIGRATIONS=false, skipping migrations)");
    }

    // Resilience config (shared between API Horizon client and ingest HorizonPayments client).
    let resilience = cfg.resilience.clone();
    tracing::info!(
        max_attempts = resilience.max_attempts,
        base_delay_ms = resilience.base_delay_ms,
        max_delay_ms = resilience.max_delay_ms,
        cb_failure_threshold = resilience.cb_failure_threshold,
        cb_reset_timeout_secs = resilience.cb_reset_timeout_secs,
        "horizon resilience config"
    );

    // Shared state (includes the API's Horizon client wired with resilience).
    let email = EmailSender::new(cfg.resend_api_key.clone(), cfg.email_from_address.clone());
    let mut state = AppState::new_with_resilience(
        store.clone(),
        cfg.master_key,
        cfg.network,
        cfg.horizon_url.clone(),
        cfg.friendbot_url.clone(),
        cfg.public_app_url.clone(),
        email,
        resilience.retry_policy(),
        resilience.circuit_breaker(),
    )
    .with_jwt_secret(cfg.jwt_secret.clone())
    .with_audit_chain_key(cfg.audit_chain_key.clone())
    .with_public_api_url(cfg.public_api_url.as_deref())
    .map_err(anyhow::Error::msg)?;
    // MASTER_KEY_NEXT, when set, activates zero-downtime key rotation: already-migrated rows
    // (by sealed_scheme) sign with this key; un-migrated rows still use `master_key`. Without
    // this call the parsed env var was read into config and then never used anywhere.
    if let Some(next) = cfg.master_key_next {
        state = state.with_master_key_next(next);
    }
    // Fail at boot, not at first signature, on a broken RNG or a key that can't open our data.
    octo_api::self_test::run(&state)
        .await
        .map_err(|e| anyhow::anyhow!("startup crypto self-test failed: {e}"))?;
    tracing::info!("startup crypto self-test passed");
    // Postgres-backed limits hold across replicas and restarts; memory is per-process only.
    let rate_limiter = RateLimiter::for_backend(cfg.rate_limit_backend, store.clone());
    state = state.with_rate_limiter(rate_limiter.clone());
    tracing::info!(backend = cfg.rate_limit_backend.as_str(), "rate limiter configured");

    // Ingest supervisor (background task) — uses its own HorizonPayments client with the same
    // resilience config (separate circuit-breaker instance so ingest and API failures are counted
    // independently).
    let ingest_retry = cfg.resilience.retry_policy();
    let ingest_circuit = cfg.resilience.circuit_breaker();
    let supervisor = Supervisor::new_with_resilience(
        store.clone(),
        cfg.horizon_url.clone(),
        WebhookSender::new(store.clone()),
        cfg.network.as_str(),
        ingest_retry,
        ingest_circuit,
    )
    .with_lock_retry(cfg.ingest_lock_retry);
    // Cancelled on SIGTERM/SIGINT; both the ingest loop and the HTTP server drain on it.
    let shutdown = CancellationToken::new();
    let ingest = tokio::spawn(supervisor.run_until_cancelled(
        Duration::from_secs(cfg.ingest_interval_secs),
        cfg.ingest_page_limit,
        shutdown.clone(),
    ));
    tracing::info!(
        interval_secs = cfg.ingest_interval_secs,
        lock_retry_secs = cfg.ingest_lock_retry.as_secs(),
        "deposit ingest supervisor started (ingests only while holding the leader lock)"
    );

    // Prune expired rate-limit windows so the shared table stays bounded.
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            match rate_limiter.prune().await {
                Ok(count) if count > 0 => tracing::debug!(count, "pruned expired rate-limit windows"),
                Ok(_) => {}
                Err(e) => tracing::warn!(error = ?e, "failed to prune rate-limit windows"),
            }
        }
    });

    // Periodic background sweep to reconcile sponsorships stuck pending after a crash.
    let sweep_store = store.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            match sweep_store
                .reconcile_stale_pending_sponsorships(Duration::from_secs(300))
                .await
            {
                Ok(count) => {
                    if count > 0 {
                        tracing::info!(count, "reconciled stale pending sponsored transactions");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = ?e, "failed to reconcile stale pending sponsorships");
                }
            }
        }
    });

    // Hourly prune of expired deny-list entries and sessions, so neither table grows unbounded.
    let purge_store = store.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60 * 60));
        loop {
            interval.tick().await;
            if let Err(e) = purge_store.purge_expired_tokens().await {
                tracing::warn!(error = ?e, "failed to purge expired deny-list tokens");
            }
            if let Err(e) = purge_store.purge_expired_sessions().await {
                tracing::warn!(error = ?e, "failed to purge expired sessions");
            }
        }
    });

    // REST API.
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr)
        .await
        .with_context(|| format!("bind {}", cfg.bind_addr))?;
    tracing::info!(addr = %cfg.bind_addr, "API listening");
    // Graceful shutdown stops accepting new connections and lets in-flight requests finish.
    // `into_make_service_with_connect_info` is what makes the peer address available to the
    // rate limiter's `ConnectInfo` extractor; without it every caller looks like one client.
    let mut server = tokio::spawn(
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown.clone().cancelled_owned())
        .into_future(),
    );

    // A server that dies on its own (not via a signal) is a hard failure, not a shutdown.
    tokio::select! {
        res = &mut server => {
            shutdown.cancel();
            return res.context("API task panicked")?.context("serve API");
        }
        signal = shutdown_signal() => {
            tracing::info!(signal, "shutdown signal received");
        }
    }

    shutdown.cancel();
    tracing::info!(
        timeout_secs = cfg.shutdown_drain_timeout.as_secs(),
        "draining in-flight HTTP requests and the current ingest tick"
    );
    let ingest_abort = ingest.abort_handle();
    let server_abort = server.abort_handle();
    let drain = async { tokio::join!(server, ingest) };
    match tokio::time::timeout(cfg.shutdown_drain_timeout, drain).await {
        Ok((http, ingest)) => {
            let http = http
                .context("API task panicked")
                .and_then(|r| r.context("serve API"));
            if let Err(e) = http {
                tracing::error!(error = ?e, "API server errored while draining");
            }
            if let Err(e) = ingest {
                tracing::error!(error = ?e, "ingest supervisor task panicked while draining");
            }
            tracing::info!("drained");
        }
        Err(_) => {
            // Deposit inserts are deduplicated, so a page cut short here re-runs safely.
            tracing::warn!(
                timeout_secs = cfg.shutdown_drain_timeout.as_secs(),
                "drain timeout elapsed; forcing exit"
            );
            ingest_abort.abort();
            server_abort.abort();
        }
    }
    tracing::info!("exiting");
    Ok(())
}

/// Resolve on SIGTERM (what Kubernetes/ECS send on a rolling deploy) or SIGINT (Ctrl-C).
async fn shutdown_signal() -> &'static str {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!(error = ?e, "failed to listen for SIGINT");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                tracing::error!(error = ?e, "failed to listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => "SIGINT",
        () = terminate => "SIGTERM",
    }
}

/// `verify-audit-chain`: check every user's chain (or one, with `--user <uuid>`).
async fn verify_audit_chain(cfg: VerifyConfig) -> Result<()> {
    let store = Store::connect(&cfg.database_url)
        .await
        .context("connect to database")?;
    let reports = match cfg.user {
        Some(user_id) => vec![store.verify_audit_chain(&cfg.audit_chain_key, user_id).await?],
        None => store.verify_all_audit_chains(&cfg.audit_chain_key).await?,
    };
    let mut broken = 0usize;
    for r in &reports {
        if let AuditChainStatus::Broken { seq, reason } = &r.status {
            broken += 1;
            tracing::error!(user_id = %r.user_id, seq = ?seq, reason, "audit chain broken");
        }
    }
    let rows: u64 = reports.iter().map(|r| r.rows_verified).sum();
    let unchained = reports
        .iter()
        .filter(|r| r.status == AuditChainStatus::Unchained)
        .count();
    tracing::info!(
        users = reports.len(),
        rows_verified = rows,
        unchained_users = unchained,
        broken,
        "audit chain verification finished"
    );
    if broken > 0 {
        anyhow::bail!("{broken} of {} audit chains failed verification", reports.len());
    }
    Ok(())
}

/// Read a base64 32-byte key from `name` into zeroizing memory and remove it from the process
/// environment. `None` when unset.
///
/// Limitation: this scrubs only our copies. The kernel's `/proc/<pid>/environ` snapshot and
/// libc's original environment strings are not ours to wipe — see docs/threat-model.md.
fn take_key_from_env(name: &str) -> Result<Option<Zeroizing<[u8; 32]>>> {
    let raw = match std::env::var(name) {
        Ok(v) => Zeroizing::new(v),
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => anyhow::bail!("{name} must be valid UTF-8"),
    };
    std::env::remove_var(name);
    AppState::decode_master_key(&raw)
        .map(Some)
        .map_err(|_| anyhow::anyhow!("{name} must be base64-encoded 32 bytes"))
}

/// `AUDIT_CHAIN_KEY`, required: an audit chain without a secret key proves nothing.
fn audit_chain_key_from_env() -> Result<AuditChainKey> {
    take_key_from_env("AUDIT_CHAIN_KEY")?
        .map(AuditChainKey::new)
        .context("AUDIT_CHAIN_KEY is required (base64 32 bytes; signs the audit hash chain)")
}

/// Configuration for `verify-audit-chain`.
struct VerifyConfig {
    database_url: String,
    audit_chain_key: AuditChainKey,
    user: Option<Uuid>,
}

impl VerifyConfig {
    fn from_env() -> Result<VerifyConfig> {
        let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL is required")?;
        let audit_chain_key = audit_chain_key_from_env()?;
        let user = std::env::args()
            .skip_while(|a| a != "--user")
            .nth(1)
            .map(|v| v.parse::<Uuid>().context("--user must be a UUID"))
            .transpose()?;
        Ok(VerifyConfig {
            database_url,
            audit_chain_key,
            user,
        })
    }
}

fn init_tracing() {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info,octo=debug".to_string());
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .init();
}

/// Server configuration, read from environment variables.
struct Config {
    database_url: String,
    /// Pool size and timeouts (`DB_MAX_CONNECTIONS`, `DB_ACQUIRE_TIMEOUT_SECS`,
    /// `DB_IDLE_TIMEOUT_SECS`, `DB_STATEMENT_TIMEOUT_SECS`); see [`StoreConfig`].
    store: StoreConfig,
    /// `RATE_LIMIT_BACKEND`: `postgres` (default, shared across replicas) or `memory`.
    rate_limit_backend: RateLimitBackend,
    network: StellarNetwork,
    horizon_url: String,
    friendbot_url: Option<String>,
    /// Base URL of the hosted checkout frontend (e.g. `https://app.octo.dev`), used to build the
    /// `url` field on payment-link responses. Defaults to the local frontend dev server.
    public_app_url: String,
    /// Public base URL of this API, for blocking direct self-referential webhook endpoints.
    public_api_url: Option<String>,
    resend_api_key: String,
    email_from_address: String,
    master_key: Zeroizing<[u8; 32]>,
    /// Optional next master key for zero-downtime rotation. Present only during the rotation
    /// window while `octo-migrate-keys` is backfilling. When set, the server uses this key as
    /// the primary signing key (for already-migrated rows) and falls back to `master_key` for
    /// rows not yet re-sealed. See `docs/key-rotation.md` for the full runbook.
    master_key_next: Option<Zeroizing<[u8; 32]>>,
    jwt_secret: Vec<u8>,
    /// HMAC key for the tamper-evident audit chain. Must stay stable across deploys.
    audit_chain_key: AuditChainKey,
    bind_addr: String,
    ingest_interval_secs: u64,
    ingest_page_limit: u32,
    /// `INGEST_LOCK_RETRY_SECS`, default 5: how often a standby retries the ingest leader lock,
    /// which bounds failover time once the leader's session ends.
    ingest_lock_retry: Duration,
    /// Upper bound on the graceful-shutdown drain (in-flight HTTP requests + the current ingest
    /// tick) before the process force-exits. `SHUTDOWN_DRAIN_TIMEOUT_SECS`, default 25 — keep it
    /// below the orchestrator's kill deadline (Kubernetes `terminationGracePeriodSeconds`: 30).
    shutdown_drain_timeout: Duration,
    /// `RUN_MIGRATIONS`, default true. Set false when the server connects as a runtime role that
    /// lacks DDL rights and migrations are applied separately by the migrator role.
    run_migrations: bool,
    /// Resilience settings for all Horizon clients (API + ingest).
    ///
    /// | Variable | Default | Description |
    /// |---|---|---|
    /// | `HORIZON_MAX_ATTEMPTS` | 3 | Retry attempts for read-only calls |
    /// | `HORIZON_BASE_DELAY_MS` | 200 | Base backoff delay (ms) |
    /// | `HORIZON_MAX_DELAY_MS` | 5000 | Max backoff delay (ms) |
    /// | `HORIZON_CB_FAILURE_THRESHOLD` | 5 | Consecutive failures before circuit opens |
    /// | `HORIZON_CB_RESET_TIMEOUT_SECS` | 30 | Seconds before circuit allows a probe |
    resilience: ResilienceConfig,
}

impl fmt::Debug for Config {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Config")
            .field("database_url", &"[REDACTED]")
            .field("network", &self.network)
            .field("horizon_url", &self.horizon_url)
            .field("friendbot_url", &self.friendbot_url)
            .field("public_app_url", &self.public_app_url)
            .field("public_api_url", &self.public_api_url)
            .field("resend_api_key", &"[REDACTED]")
            .field("email_from_address", &self.email_from_address)
            .field("master_key", &"[REDACTED]")
            .field("master_key_next", &self.master_key_next.as_ref().map(|_| "[REDACTED]"))
            .field("jwt_secret", &"[REDACTED]")
            .field("bind_addr", &self.bind_addr)
            .field("ingest_interval_secs", &self.ingest_interval_secs)
            .field("ingest_page_limit", &self.ingest_page_limit)
            .field("shutdown_drain_timeout", &self.shutdown_drain_timeout)
            .field("resilience", &self.resilience)
            .finish()
    }
}

impl Config {
    /// Reject placeholder/low-entropy secrets and plaintext URLs when running on mainnet.
    fn ensure_safe_for_network(&self) -> Result<(), mainnet_guard::UnsafeMainnetConfig> {
        mainnet_guard::check(
            self.network,
            &mainnet_guard::MainnetCheck {
                jwt_secret: &self.jwt_secret,
                master_key: &self.master_key,
                master_key_next: self.master_key_next.as_ref(),
                resend_api_key: &self.resend_api_key,
                horizon_url: &self.horizon_url,
                public_app_url: &self.public_app_url,
                public_api_url: self.public_api_url.as_deref(),
            },
        )
    }

    fn from_env() -> Result<Config> {
        let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL is required")?;
        let store = StoreConfig::from_env()?;

        let rate_limit_backend = match std::env::var("RATE_LIMIT_BACKEND") {
            Ok(raw) => RateLimitBackend::parse(&raw).with_context(|| {
                format!("RATE_LIMIT_BACKEND must be `postgres` or `memory` (got {raw:?})")
            })?,
            Err(_) => RateLimitBackend::Postgres,
        };

        let network_str = std::env::var("NETWORK").unwrap_or_else(|_| "testnet".to_string());
        // Accepted values: "mainnet" | "public", "testnet" | "test", "standalone".
        let network = StellarNetwork::parse(&network_str)
            .with_context(|| format!("invalid NETWORK: {network_str}"))?;

        let horizon_url = std::env::var("HORIZON_URL")
            .unwrap_or_else(|_| "https://horizon-testnet.stellar.org".to_string());
        let friendbot_url = std::env::var("FRIENDBOT_URL").ok();

        let public_app_url = std::env::var("PUBLIC_APP_URL")
            .unwrap_or_else(|_| "http://localhost:3000".to_string())
            .trim_end_matches('/')
            .to_string();
        let public_api_url = std::env::var("PUBLIC_API_URL")
            .ok()
            .filter(|url| !url.trim().is_empty());

        let resend_api_key =
            std::env::var("RESEND_API_KEY").context("RESEND_API_KEY is required")?;
        let email_from_address =
            std::env::var("EMAIL_FROM_ADDRESS").context("EMAIL_FROM_ADDRESS is required")?;

        let master_key = take_key_from_env("MASTER_KEY")?.context("MASTER_KEY is required")?;
        // During key rotation, MASTER_KEY_NEXT lets the server sign with the new key (if present)
        // and fall back to the old key for unmigrated rows. Both must remain secure at all times.
        let master_key_next = take_key_from_env("MASTER_KEY_NEXT")?;
        let audit_chain_key = audit_chain_key_from_env()?;

        let jwt_secret = std::env::var("JWT_SECRET")
            .context("JWT_SECRET is required (used to sign dashboard auth tokens)")?
            .into_bytes();
        if jwt_secret.len() < 16 {
            anyhow::bail!("JWT_SECRET must be at least 16 bytes");
        }

        let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());

        let ingest_interval_secs = std::env::var("INGEST_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5);
        let ingest_page_limit = std::env::var("INGEST_PAGE_LIMIT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(50);

        let ingest_lock_retry = match std::env::var("INGEST_LOCK_RETRY_SECS") {
            Ok(raw) => match raw.trim().parse::<u64>() {
                Ok(secs) if secs >= 1 => Duration::from_secs(secs),
                _ => anyhow::bail!("INGEST_LOCK_RETRY_SECS must be a whole number >= 1 (got {raw:?})"),
            },
            Err(_) => Supervisor::DEFAULT_LOCK_RETRY,
        };

        let shutdown_drain_timeout = Duration::from_secs(
            std::env::var("SHUTDOWN_DRAIN_TIMEOUT_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(25),
        );

        let run_migrations = match std::env::var("RUN_MIGRATIONS").ok().as_deref() {
            None | Some("true") | Some("1") => true,
            Some("false") | Some("0") => false,
            Some(other) => anyhow::bail!("RUN_MIGRATIONS must be true or false, got {other:?}"),
        };

        let resilience = ResilienceConfig::from_env();

        Ok(Config {
            database_url,
            store,
            rate_limit_backend,
            network,
            horizon_url,
            friendbot_url,
            public_app_url,
            public_api_url,
            resend_api_key,
            email_from_address,
            master_key,
            master_key_next,
            jwt_secret,
            audit_chain_key,
            bind_addr,
            ingest_interval_secs,
            ingest_page_limit,
            ingest_lock_retry,
            shutdown_drain_timeout,
            run_migrations,
            resilience,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_startup_fails_loudly_on_an_unrecognized_configured_network_rather_than_defaulting() {
        std::env::set_var("DATABASE_URL", "postgres://localhost/test");
        std::env::set_var("NETWORK", "invalid_network_name");
        assert!(Config::from_env().is_err());
    }
}
