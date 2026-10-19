//! Postgres persistence for octo (sqlx).
//!
//! Tables: `wallets`, `addresses`, `transactions`, `withdrawals`, `webhook_endpoints`,
//! `webhook_deliveries`, `ingest_cursor` — see `migrations/0001_init.sql`.
//!
//! Security-relevant guarantees implemented here (see `docs/threat-model.md`):
//! - All queries are parameterized (no string-built SQL) → no SQL injection.
//! - [`Store::allocate_address`] increments the per-wallet muxed-id counter **atomically** inside a
//!   transaction, so concurrent address creation can't collide or reuse an id.
//! - [`Store::record_deposit`] is **idempotent** on the immutable `(tx_hash, operation_index)`
//!   unique index, so a replayed/reorged Horizon event cannot double-credit.
//! - [`Store::create_withdrawal`] is idempotent on `(wallet_id, idempotency_key)`.
#![forbid(unsafe_code)]

mod audit_chain;
mod config;
mod error;
mod models;

pub use audit_chain::{AuditChainKey, AuditChainReport, AuditChainStatus, AUDIT_CHAIN_KEY_LEN};
pub use config::{StoreConfig, StoreConfigError};
pub use error::StoreError;
pub use models::{
    Address, ApiKey, AuditLog, DenylistedToken, EmailOtp, GasSponsorshipConfig,
    IdempotencyClaim, NewDeposit,
    NewPaymentLink, NewSponsoredTx, PaymentLink, PaymentLinkPayment, PaymentLinkUpdate, Session,
    SponsoredTransaction, Transaction, TransactionFilter, User, Wallet, WebhookDelivery, WebhookEndpoint,
    WhitelistedAddress, Withdrawal, WithdrawalAllowlistConfig,
};

use sqlx::postgres::{PgPool, PgPoolOptions};
use uuid::Uuid;

/// How long a stored idempotency key (and its replayable response) lives.
pub const IDEMPOTENCY_KEY_TTL_SECS: i64 = 24 * 60 * 60;

/// Embedded migrations, applied by [`Store::migrate`].
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// A handle to the database (cloneable; wraps a connection pool).
#[derive(Clone)]
pub struct Store {
    pool: PgPool,
}

/// Parameters for creating a server-custody wallet (legacy wallets and gas-tank fee accounts —
/// the only rows that carry a server-held sealed seed).
pub struct NewWallet<'a> {
    pub network: &'a str,
    pub stellar_account_g: &'a str,
    pub sealed_ciphertext: &'a [u8],
    pub sealed_nonce: &'a [u8],
    pub sealed_salt: &'a [u8],
    /// Scheme version tag for the sealed seed. Use `octo_crypto::SCHEME_V1`.
    pub sealed_scheme: i16,
    pub label: Option<&'a str>,
    pub user_id: Option<Uuid>,
    pub description: Option<&'a str>,
}

/// Parameters for creating a non-custodial (client-custody) wallet: the client generated the
/// keypair and sends only the public account plus an opaque password-encrypted backup blob the
/// server cannot decrypt.
pub struct NewClientWallet<'a> {
    pub network: &'a str,
    pub stellar_account_g: &'a str,
    pub encrypted_backup: Option<&'a str>,
    pub label: Option<&'a str>,
    pub user_id: Option<Uuid>,
    pub description: Option<&'a str>,
}

/// Parameters for creating a withdrawal intent.
pub struct NewWithdrawal<'a> {
    pub wallet_id: Uuid,
    pub idempotency_key: &'a str,
    pub destination_account: &'a str,
    pub asset_code: &'a str,
    pub asset_issuer: Option<&'a str>,
    pub amount_stroops: i64,
    pub memo_id: Option<i64>,
}

impl Store {
    /// Connect to Postgres at `database_url` with [`StoreConfig::default`].
    pub async fn connect(database_url: &str) -> Result<Self, StoreError> {
        Self::connect_with(database_url, &StoreConfig::default()).await
    }

    /// Connect with explicit pool sizing and timeouts (see [`StoreConfig::from_env`]).
    pub async fn connect_with(database_url: &str, cfg: &StoreConfig) -> Result<Self, StoreError> {
        let statement_timeout_ms = cfg.statement_timeout.as_millis().to_string();
        let pool = PgPoolOptions::new()
            .max_connections(cfg.max_connections)
            .acquire_timeout(cfg.acquire_timeout)
            .idle_timeout(cfg.idle_timeout)
            // Session-level, so it applies to every statement on every pooled connection.
            .after_connect(move |conn, _meta| {
                let ms = statement_timeout_ms.clone();
                Box::pin(async move {
                    sqlx::query("SELECT set_config('statement_timeout', $1, false)")
                        .bind(ms)
                        .execute(conn)
                        .await?;
                    Ok(())
                })
            })
            .connect(database_url)
            .await?;
        Ok(Self { pool })
    }

    /// Build a store from an existing pool (useful in tests).
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Apply all pending migrations.
    ///
    /// Runs on a connection detached from the pool with `statement_timeout` disabled, so a slow
    /// index build is not killed by the request-path timeout and the override never leaks back.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        let mut conn = self.pool.acquire().await?.detach();
        sqlx::query("SET statement_timeout = 0")
            .execute(&mut conn)
            .await?;
        let result = MIGRATOR.run(&mut conn).await;
        let _ = sqlx::Connection::close(conn).await;
        result?;
        Ok(())
    }

    /// Borrow the underlying pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    // --- users ------------------------------------------------------------

    /// Create a user. `email` should already be lowercased by the caller. Returns
    /// [`StoreError::Conflict`] if the email is already registered.
    pub async fn create_user(&self, email: &str, password_hash: &str) -> Result<User, StoreError> {
        sqlx::query_as::<_, User>(
            "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING *",
        )
        .bind(email)
        .bind(password_hash)
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::from_sqlx_conflict)
    }

    /// Set a user's display username. Returns [`StoreError::Conflict`] if another user already
    /// has it (compared case-insensitively, per the `users_username_unique_idx` index).
    pub async fn update_username(&self, user_id: Uuid, username: &str) -> Result<User, StoreError> {
        sqlx::query_as::<_, User>(
            "UPDATE users SET username = $2, updated_at = now() WHERE id = $1 RETURNING *",
        )
        .bind(user_id)
        .bind(username)
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::from_sqlx_conflict)
    }

    /// Delete a user outright. Only safe pre-verification — used to roll back a signup whose
    /// OTP email never went out, so the email isn't stuck as "already registered" forever.
    pub async fn delete_unverified_user(&self, user_id: Uuid) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM users WHERE id = $1 AND email_verified_at IS NULL")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Look up a user by email (caller lowercases).
    pub async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, StoreError> {
        let row = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
            .bind(email)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row)
    }

    /// Fetch a user by id.
    pub async fn get_user(&self, id: Uuid) -> Result<Option<User>, StoreError> {
        let row = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row)
    }

    /// Return the active per-email authentication lock, if any.
    pub async fn auth_locked_until(
        &self,
        email: &str,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>, StoreError> {
        Ok(sqlx::query_scalar(
            "SELECT locked_until FROM auth_lockouts WHERE email = lower($1) AND locked_until > now()",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?
        .flatten())
    }

    /// Record a failed login. Five failures in fifteen minutes trigger an exponentially longer lock.
    pub async fn record_auth_failure(&self, email: &str) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            INSERT INTO auth_lockouts (email, failed_attempts) VALUES (lower($1), 1)
            ON CONFLICT (email) DO UPDATE SET
                failed_attempts = CASE WHEN auth_lockouts.window_started < now() - interval '15 minutes' THEN 1 ELSE auth_lockouts.failed_attempts + 1 END,
                window_started = CASE WHEN auth_lockouts.window_started < now() - interval '15 minutes' THEN now() ELSE auth_lockouts.window_started END,
                lockout_count = CASE WHEN auth_lockouts.failed_attempts + 1 >= 5 THEN auth_lockouts.lockout_count + 1 ELSE auth_lockouts.lockout_count END,
                locked_until = CASE WHEN auth_lockouts.failed_attempts + 1 >= 5 THEN now() + make_interval(secs => 60 * (1 << LEAST(auth_lockouts.lockout_count, 6))) ELSE auth_lockouts.locked_until END,
                updated_at = now()
            "#,
        )
        .bind(email)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Clear failed-attempt state after successful authentication or an administrative unlock.
    pub async fn reset_auth_failures(&self, email: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM auth_lockouts WHERE email = lower($1)")
            .bind(email)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Mark a user's email as verified.
    pub async fn mark_email_verified(&self, user_id: Uuid) -> Result<(), StoreError> {
        sqlx::query("UPDATE users SET email_verified_at = now() WHERE id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Replace a user's password hash, bump `session_epoch` (revoking every issued token) and
    /// revoke every session row except `keep_session`. Returns the new epoch for the caller's
    /// replacement token.
    pub async fn change_password(
        &self,
        user_id: Uuid,
        new_password_hash: &str,
        keep_session: Option<Uuid>,
    ) -> Result<i32, StoreError> {
        let mut tx = self.pool.begin().await?;
        let epoch: i32 = sqlx::query_scalar(
            r#"
            UPDATE users
            SET password_hash = $2, session_epoch = session_epoch + 1, updated_at = now()
            WHERE id = $1
            RETURNING session_epoch
            "#,
        )
        .bind(user_id)
        .bind(new_password_hash)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StoreError::NotFound)?;
        revoke_sessions_except(&mut tx, user_id, keep_session).await?;
        tx.commit().await?;
        Ok(epoch)
    }

    /// Set a new password after a verified reset and revoke **every** session (no token is issued
    /// by the reset flow, so nothing is kept).
    pub async fn reset_password(
        &self,
        user_id: Uuid,
        new_password_hash: &str,
    ) -> Result<(), StoreError> {
        self.change_password(user_id, new_password_hash, None)
            .await
            .map(|_| ())
    }

    /// Change a user's login email (caller lowercases). Returns [`StoreError::Conflict`] if the
    /// address is already registered.
    pub async fn update_email(&self, user_id: Uuid, email: &str) -> Result<User, StoreError> {
        sqlx::query_as::<_, User>(
            "UPDATE users SET email = $2, updated_at = now() WHERE id = $1 RETURNING *",
        )
        .bind(user_id)
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::from_sqlx_conflict)?
        .ok_or(StoreError::NotFound)
    }

    // --- email OTP ----------------------------------------------------------

    /// Issue a fresh OTP row. Callers hash the code themselves before calling this.
    pub async fn create_otp(
        &self,
        user_id: Uuid,
        purpose: &str,
        code_hash: &str,
        tx_hash_bound: Option<&str>,
        ttl: chrono::Duration,
    ) -> Result<Uuid, StoreError> {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO email_otps (user_id, purpose, code_hash, tx_hash_bound, expires_at)
             VALUES ($1, $2, $3, $4, now() + $5) RETURNING id",
        )
        .bind(user_id)
        .bind(purpose)
        .bind(code_hash)
        .bind(tx_hash_bound)
        .bind(ttl)
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    /// Verify an already-hashed code against the most recent OTP for `(user_id, purpose)` and
    /// consume it. Every attempt is counted atomically *before* the comparison, so concurrent
    /// guesses can't all slip under the attempt cap, and the consume is conditional, so one code
    /// can't be redeemed twice. Callers should surface a generic "invalid or expired code" either
    /// way, so guessing can't distinguish "wrong code" from "no such code exists".
    pub async fn verify_and_consume_otp(
        &self,
        user_id: Uuid,
        purpose: &str,
        code_hash: &str,
        tx_hash_bound: Option<&str>,
    ) -> Result<(), StoreError> {
        const MAX_ATTEMPTS: i16 = 5;

        // Claim one attempt on the latest live code; no row back means none is redeemable.
        let claimed: Option<(Uuid, String, Option<String>)> = sqlx::query_as(
            r#"
            UPDATE email_otps SET attempts = attempts + 1
            WHERE id = (
                SELECT id FROM email_otps WHERE user_id = $1 AND purpose = $2
                ORDER BY created_at DESC LIMIT 1
            )
              AND consumed_at IS NULL AND attempts < $3 AND expires_at > now()
            RETURNING id, code_hash, tx_hash_bound
            "#,
        )
        .bind(user_id)
        .bind(purpose)
        .bind(MAX_ATTEMPTS)
        .fetch_optional(&self.pool)
        .await?;
        let (otp_id, stored_hash, bound) = claimed.ok_or(StoreError::InvalidOtp)?;

        let hash_ok: bool =
            subtle::ConstantTimeEq::ct_eq(stored_hash.as_bytes(), code_hash.as_bytes()).into();
        if !hash_ok || bound.as_deref() != tx_hash_bound {
            return Err(StoreError::InvalidOtp);
        }

        let consumed = sqlx::query(
            "UPDATE email_otps SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL",
        )
        .bind(otp_id)
        .execute(&self.pool)
        .await?;
        if consumed.rows_affected() != 1 {
            return Err(StoreError::InvalidOtp);
        }
        Ok(())
    }

    // --- audit logs -------------------------------------------------------

    /// List a user's audit logs (most recent first), optionally filtered by `category` and a
    /// case-insensitive `search` over the action/target. Capped at `limit` rows.
    pub async fn list_audit_logs(
        &self,
        user_id: Uuid,
        category: Option<&str>,
        search: Option<&str>,
        limit: i64,
    ) -> Result<Vec<AuditLog>, StoreError> {
        // Build with optional filters; `$2`/`$3` are NULL when not provided.
        let rows = sqlx::query_as::<_, AuditLog>(
            r#"
            SELECT * FROM audit_logs
            WHERE user_id = $1
              AND ($2::text IS NULL OR category = $2)
              AND ($3::text IS NULL OR action ILIKE '%' || $3 || '%'
                                    OR coalesce(target, '') ILIKE '%' || $3 || '%')
            ORDER BY created_at DESC
            LIMIT $4
            "#,
        )
        .bind(user_id)
        .bind(category)
        .bind(search)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    // --- api keys ---------------------------------------------------------

    /// Create or replace the wallet's API key (regenerate). Stores only the hash + display prefix.
    pub async fn upsert_api_key(
        &self,
        wallet_id: Uuid,
        prefix: &str,
        key_hash: &str,
        scopes: &[String],
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<ApiKey, StoreError> {
        sqlx::query_as::<_, ApiKey>(
            r#"
            INSERT INTO api_keys (wallet_id, prefix, key_hash, scopes, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (wallet_id)
            DO UPDATE SET prefix = EXCLUDED.prefix, key_hash = EXCLUDED.key_hash,
                          scopes = EXCLUDED.scopes, expires_at = EXCLUDED.expires_at,
                          last_used_at = NULL, created_at = now()
            RETURNING *
            "#,
        )
        .bind(wallet_id)
        .bind(prefix)
        .bind(key_hash)
        .bind(scopes)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::Database)
    }

    pub async fn create_api_key(
        &self,
        wallet_id: Uuid,
        prefix: &str,
        key_hash: &str,
        scopes: &[String],
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<ApiKey, StoreError> {
        sqlx::query_as::<_, ApiKey>(
            "INSERT INTO api_keys (wallet_id, prefix, key_hash, scopes, expires_at) \
             VALUES ($1, $2, $3, $4, $5) RETURNING *",
        )
        .bind(wallet_id)
        .bind(prefix)
        .bind(key_hash)
        .bind(scopes)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::Database)
    }

    /// Get the wallet's API key metadata (prefix only — never the secret), if one exists.
    pub async fn get_api_key(&self, wallet_id: Uuid) -> Result<Option<ApiKey>, StoreError> {
        let row = sqlx::query_as::<_, ApiKey>("SELECT * FROM api_keys WHERE wallet_id = $1")
            .bind(wallet_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row)
    }

    /// Validate an unexpired API key and atomically record its latest use.
    pub async fn use_api_key(&self, key_hash: &str) -> Result<Option<ApiKey>, StoreError> {
        let row = sqlx::query_as::<_, ApiKey>(
            "UPDATE api_keys SET last_used_at = now() WHERE key_hash = $1 \
             AND (expires_at IS NULL OR expires_at > now()) RETURNING *",
        )
        .bind(key_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn rehash_password(&self, user_id: Uuid, password_hash: &str) -> Result<(), StoreError> {
        sqlx::query("UPDATE users SET password_hash = $2 WHERE id = $1")
            .bind(user_id)
            .bind(password_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Delete (revoke) the API key for a wallet. Returns `Ok(())` even if no key existed.
    pub async fn delete_api_key(&self, wallet_id: Uuid) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM api_keys WHERE wallet_id = $1")
            .bind(wallet_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // --- wallets ----------------------------------------------------------

    /// Create a master wallet. Fails with [`StoreError::Conflict`] if the account already exists.
    pub async fn create_wallet(&self, new: NewWallet<'_>) -> Result<Wallet, StoreError> {
        sqlx::query_as::<_, Wallet>(
            r#"
            INSERT INTO wallets
                (network, stellar_account_g, sealed_ciphertext, sealed_nonce, sealed_salt,
                 sealed_scheme, label, user_id, description, custody)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'server')
            RETURNING *
            "#,
        )
        .bind(new.network)
        .bind(new.stellar_account_g)
        .bind(new.sealed_ciphertext)
        .bind(new.sealed_nonce)
        .bind(new.sealed_salt)
        .bind(new.sealed_scheme)
        .bind(new.label)
        .bind(new.user_id)
        .bind(new.description)
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::from_sqlx_conflict)
    }

    /// Attach a gas-tank fee account to a client-custody wallet: stores the tank's sealed seed
    /// and public account. The tank only ever holds fee float — never customer funds.
    ///
    /// `sealed_scheme` must be written alongside the seed: the `wallets_gas_tank_has_seed` CHECK
    /// requires it, and key rotation (`bin/migrate-keys`) needs the tag to know how to open it.
    pub async fn set_gas_tank(
        &self,
        wallet_id: Uuid,
        gas_tank_account_g: &str,
        sealed_ciphertext: &[u8],
        sealed_nonce: &[u8],
        sealed_salt: &[u8],
        sealed_scheme: i16,
    ) -> Result<Wallet, StoreError> {
        sqlx::query_as::<_, Wallet>(
            r#"
            UPDATE wallets
            SET gas_tank_account_g = $2, sealed_ciphertext = $3, sealed_nonce = $4,
                sealed_salt = $5, sealed_scheme = $6, updated_at = now()
            WHERE id = $1 AND custody = 'client' AND gas_tank_account_g IS NULL
            RETURNING *
            "#,
        )
        .bind(wallet_id)
        .bind(gas_tank_account_g)
        .bind(sealed_ciphertext)
        .bind(sealed_nonce)
        .bind(sealed_salt)
        .bind(sealed_scheme)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StoreError::Conflict) // already has a tank, or not a client wallet
    }

    /// Create a non-custodial wallet: no seed is stored; the server can never sign for it.
    pub async fn create_client_wallet(
        &self,
        new: NewClientWallet<'_>,
    ) -> Result<Wallet, StoreError> {
        sqlx::query_as::<_, Wallet>(
            r#"
            INSERT INTO wallets
                (network, stellar_account_g, label, user_id, description, custody,
                 encrypted_backup)
            VALUES ($1, $2, $3, $4, $5, 'client', $6)
            RETURNING *
            "#,
        )
        .bind(new.network)
        .bind(new.stellar_account_g)
        .bind(new.label)
        .bind(new.user_id)
        .bind(new.description)
        .bind(new.encrypted_backup)
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::from_sqlx_conflict)
    }

    /// List a user's wallets (most recent first), with optional cursor-based pagination.
    ///
    /// Fetching `limit + 1` rows lets the caller detect whether a next page exists without a
    /// separate COUNT query — the same pattern used by `list_sponsored_transactions`.
    pub async fn list_wallets_for_user(
        &self,
        user_id: Uuid,
        limit: i64,
        before_id: Option<Uuid>,
    ) -> Result<Vec<Wallet>, StoreError> {
        let rows = sqlx::query_as::<_, Wallet>(
            r#"
            SELECT * FROM wallets
            WHERE user_id = $1
              AND ($2::uuid IS NULL OR (created_at, id) < (
                  SELECT created_at, id FROM wallets WHERE id = $2
              ))
            ORDER BY created_at DESC, id DESC
            LIMIT $3
            "#,
        )
        .bind(user_id)
        .bind(before_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Paginated version of [`list_wallets_for_user`]: returns at most `limit` rows, newest first.
    /// Pass the last page's final wallet id as `before_id` to fetch the next page.
    pub async fn list_wallets_for_user_page(
        &self,
        user_id: Uuid,
        limit: i64,
        before_id: Option<Uuid>,
    ) -> Result<Vec<Wallet>, StoreError> {
        let rows = sqlx::query_as::<_, Wallet>(
            r#"
            SELECT * FROM wallets
            WHERE user_id = $1
              AND ($2::uuid IS NULL OR (created_at, id) < (
                    SELECT created_at, id FROM wallets WHERE id = $2
                  ))
            ORDER BY created_at DESC, id DESC
            LIMIT $3
            "#,
        )
        .bind(user_id)
        .bind(before_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// List all wallets (used by the ingest supervisor to fan out poll loops).
    pub async fn list_wallets(&self) -> Result<Vec<Wallet>, StoreError> {
        let rows = sqlx::query_as::<_, Wallet>("SELECT * FROM wallets ORDER BY created_at")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows)
    }

    /// Wallets on `network` that are due for an ingest poll, given activity-based backoff.
    ///
    /// A dev/production database accumulates wallets that never see another deposit. Polling all
    /// of them on the same short cycle spends the concurrency budget on dead accounts and delays
    /// the ones that are actually transacting. Idleness is measured by `ingest_cursor.updated_at`,
    /// which is only bumped when a record is actually processed:
    ///
    /// - active (last activity < `active_after_secs`): every tick
    /// - idle: at most once per `idle_interval_secs`
    /// - dormant (last activity older than `dormant_after_secs`): at most once per
    ///   `dormant_interval_secs`
    ///
    /// A wallet with no cursor row has never been polled, so it is always due.
    ///
    /// Unbounded; prefer [`Store::wallets_due_for_poll_page`] when the wallet count can be large.
    pub async fn wallets_due_for_poll(
        &self,
        network: &str,
        active_after_secs: i64,
        idle_interval_secs: i64,
        dormant_after_secs: i64,
        dormant_interval_secs: i64,
    ) -> Result<Vec<Wallet>, StoreError> {
        // `LIMIT NULL` is "no limit" in Postgres, so this is the paged query's full result.
        self.wallets_due_for_poll_page(
            network,
            active_after_secs,
            idle_interval_secs,
            dormant_after_secs,
            dormant_interval_secs,
            None,
            None,
        )
        .await
    }

    /// One keyset page of [`Store::wallets_due_for_poll`], ordered by `id`, with the exact same
    /// backoff filter. Pass the last row's id as `after_id` for the next page; `limit = None`
    /// returns everything. Paging on the unique primary key means no wallet is skipped or
    /// returned twice across page boundaries within one pass.
    #[allow(clippy::too_many_arguments)]
    pub async fn wallets_due_for_poll_page(
        &self,
        network: &str,
        active_after_secs: i64,
        idle_interval_secs: i64,
        dormant_after_secs: i64,
        dormant_interval_secs: i64,
        limit: Option<i64>,
        after_id: Option<Uuid>,
    ) -> Result<Vec<Wallet>, StoreError> {
        let rows = sqlx::query_as::<_, Wallet>(
            r#"
            SELECT w.* FROM wallets w
            LEFT JOIN ingest_cursor c ON c.wallet_id = w.id
            WHERE w.network = $1
              -- Paused wallets are never polled; their cursor waits untouched for a resume.
              AND w.ingest_paused = false
              AND ($6::uuid IS NULL OR w.id > $6)
              -- Never polled, or never saw activity => always due.
              AND (
                c.last_polled_at IS NULL
                OR c.updated_at IS NULL
                OR c.last_polled_at < now() - make_interval(secs =>
                     CASE
                       -- Active: no extra wait, poll every tick.
                       WHEN c.updated_at > now() - make_interval(secs => $2) THEN 0
                       -- Dormant: longest wait between polls.
                       WHEN c.updated_at <= now() - make_interval(secs => $4) THEN $5
                       -- Idle: in between.
                       ELSE $3
                     END)
              )
            ORDER BY w.id
            LIMIT $7
            "#,
        )
        .bind(network)
        .bind(active_after_secs as f64)
        .bind(idle_interval_secs as f64)
        .bind(dormant_after_secs as f64)
        .bind(dormant_interval_secs as f64)
        .bind(after_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Record that a wallet was polled (whether or not anything new arrived).
    ///
    /// Distinct from [`Store::set_cursor`], which only advances on real activity — the backoff
    /// tiers need both "when did we last see money" and "when did we last look".
    pub async fn mark_polled(&self, wallet_id: Uuid) -> Result<(), StoreError> {
        // `updated_at` is deliberately backdated to the epoch on INSERT: it means "last time this
        // wallet saw activity", and merely looking at a wallet is not activity. Letting it take
        // its `DEFAULT now()` would mark every never-used wallet as freshly active and the
        // backoff tiers would never engage. `set_cursor` is the only writer that advances it.
        sqlx::query(
            r#"
            INSERT INTO ingest_cursor (wallet_id, last_polled_at, updated_at)
            VALUES ($1, now(), 'epoch')
            ON CONFLICT (wallet_id) DO UPDATE SET last_polled_at = now()
            "#,
        )
        .bind(wallet_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Pause or resume ingestion for a wallet, returning the updated row.
    ///
    /// Only the flag changes — `ingest_cursor` is deliberately left alone so a resume picks up
    /// from the saved paging token with no gap. `ingest_paused_at` keeps the first pause time
    /// on a repeated pause and is cleared on resume.
    pub async fn set_ingest_paused(
        &self,
        wallet_id: Uuid,
        paused: bool,
    ) -> Result<Wallet, StoreError> {
        sqlx::query_as::<_, Wallet>(
            r#"
            UPDATE wallets SET
                ingest_paused = $2,
                ingest_paused_at = CASE
                    WHEN $2 THEN COALESCE(ingest_paused_at, now())
                    ELSE NULL
                END,
                updated_at = now()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(wallet_id)
        .bind(paused)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StoreError::NotFound)
    }

    /// Fetch a wallet by id.
    pub async fn get_wallet(&self, id: Uuid) -> Result<Wallet, StoreError> {
        sqlx::query_as::<_, Wallet>("SELECT * FROM wallets WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(StoreError::NotFound)
    }

    /// The newest wallet on `network` that carries a server-sealed seed, if any.
    ///
    /// Used by the startup self-test to prove the configured master key opens real data.
    pub async fn latest_sealed_wallet(&self, network: &str) -> Result<Option<Wallet>, StoreError> {
        Ok(sqlx::query_as::<_, Wallet>(
            "SELECT * FROM wallets WHERE network = $1 AND sealed_ciphertext IS NOT NULL
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(network)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Atomically swap the sealed seed material for a single wallet after a reseal/key-rotation.
    ///
    /// The caller (typically `bin/migrate-keys`) opens the old seed with the old master key,
    /// re-seals it with the new master key via `octo_crypto::reseal`, and then calls this method
    /// to persist the result. The `expected_scheme` guard ensures idempotency: if the row was
    /// already migrated (e.g. by a concurrent runner) the update is silently skipped rather than
    /// overwriting a newer record.
    ///
    /// # Atomicity Guarantee
    ///
    /// This method executes a single SQL `UPDATE` statement. Its atomicity guarantee (ensuring
    /// that a failure mid-write never leaves a wallet row half-migrated or partially updated) relies
    /// entirely on PostgreSQL's native single-statement atomicity semantics. No application-level
    /// transaction wrapper is used; Postgres guarantees that a statement either succeeds completely
    /// or rolls back its effect on the row entirely.
    ///
    /// Returns `true` if the row was updated, `false` if it was already on the target scheme.
    pub async fn reseal_wallet(
        &self,
        wallet_id: Uuid,
        new_ciphertext: &[u8],
        new_nonce: &[u8],
        new_salt: &[u8],
        new_scheme: i16,
        expected_old_scheme: i16,
    ) -> Result<bool, StoreError> {
        // Only update the row if it still carries the old scheme — this is the idempotency guard.
        // A concurrent runner that already migrated this wallet will have set sealed_scheme to
        // `new_scheme`, so the WHERE clause won't match and no double-reseal can occur.
        let result = sqlx::query(
            r#"
            UPDATE wallets
            SET sealed_ciphertext = $2,
                sealed_nonce       = $3,
                sealed_salt        = $4,
                sealed_scheme      = $5,
                updated_at         = now()
            WHERE id = $1
              AND sealed_scheme = $6
            "#,
        )
        .bind(wallet_id)
        .bind(new_ciphertext)
        .bind(new_nonce)
        .bind(new_salt)
        .bind(new_scheme)
        .bind(expected_old_scheme)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Fetch a page of wallets whose `sealed_scheme` does not equal `target_scheme`, for the
    /// migration backfill job. Returns at most `batch_size` rows ordered by `id` (stable for
    /// resumable cursored iteration). Pass the last returned wallet's `id` as `after_id` on
    /// subsequent calls to page through the full table without re-scanning already-migrated rows.
    pub async fn list_wallets_needing_reseal(
        &self,
        target_scheme: i16,
        batch_size: i64,
        after_id: Option<Uuid>,
    ) -> Result<Vec<Wallet>, StoreError> {
        let rows = sqlx::query_as::<_, Wallet>(
            r#"
            SELECT * FROM wallets
            WHERE sealed_scheme <> $1
              AND ($2::uuid IS NULL OR id > $2)
            ORDER BY id
            LIMIT $3
            "#,
        )
        .bind(target_scheme)
        .bind(after_id)
        .bind(batch_size)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    // --- addresses --------------------------------------------------------

    /// Atomically allocate the next muxed id for `wallet_id` and insert the address row.
    ///
    /// The counter bump and the insert happen in one transaction with a row lock, so two
    /// concurrent callers always get distinct, gap-free-enough ids and never collide.
    pub async fn allocate_address(
        &self,
        wallet_id: Uuid,
        muxed_address_for: impl FnOnce(i64) -> Result<String, ()>,
        customer_ref: Option<&str>,
        metadata: serde_json::Value,
    ) -> Result<Address, StoreError> {
        let mut tx = self.pool.begin().await?;

        // Lock the wallet row and read+bump the counter.
        let next_id: i64 =
            sqlx::query_scalar("SELECT next_muxed_id FROM wallets WHERE id = $1 FOR UPDATE")
                .bind(wallet_id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(StoreError::NotFound)?;

        sqlx::query("UPDATE wallets SET next_muxed_id = next_muxed_id + 1, updated_at = now() WHERE id = $1")
            .bind(wallet_id)
            .execute(&mut *tx)
            .await?;

        // Derive the muxed address for this id via the caller-provided closure (wallet-core).
        let muxed_address = muxed_address_for(next_id).map_err(|_| StoreError::NotFound)?;

        let address = sqlx::query_as::<_, Address>(
            r#"
            INSERT INTO addresses (wallet_id, muxed_id, muxed_address, customer_ref, metadata)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(wallet_id)
        .bind(next_id)
        .bind(&muxed_address)
        .bind(customer_ref)
        .bind(metadata)
        .fetch_one(&mut *tx)
        .await
        .map_err(StoreError::from_sqlx_conflict)?;

        tx.commit().await?;
        Ok(address)
    }

    /// List addresses for a wallet (most recent first), with optional cursor-based pagination.
    pub async fn list_addresses(
        &self,
        wallet_id: Uuid,
        limit: i64,
        before_id: Option<Uuid>,
    ) -> Result<Vec<Address>, StoreError> {
        let rows = sqlx::query_as::<_, Address>(
            r#"
            SELECT * FROM addresses
            WHERE wallet_id = $1
              AND ($2::uuid IS NULL OR (created_at, id) < (
                  SELECT created_at, id FROM addresses WHERE id = $2
              ))
            ORDER BY created_at DESC, id DESC
            LIMIT $3
            "#,
        )
        .bind(wallet_id)
        .bind(before_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Paginated version of [`list_addresses`]: returns at most `limit` rows, newest first.
    /// Pass the last page's final address id as `before_id` to fetch the next page.
    pub async fn list_addresses_page(
        &self,
        wallet_id: Uuid,
        limit: i64,
        before_id: Option<Uuid>,
    ) -> Result<Vec<Address>, StoreError> {
        let rows = sqlx::query_as::<_, Address>(
            r#"
            SELECT * FROM addresses
            WHERE wallet_id = $1
              AND ($2::uuid IS NULL OR (created_at, id) < (
                    SELECT created_at, id FROM addresses WHERE id = $2
                  ))
            ORDER BY created_at DESC, id DESC
            LIMIT $3
            "#,
        )
        .bind(wallet_id)
        .bind(before_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Fetch an address by id.
    pub async fn get_address(&self, id: Uuid) -> Result<Option<Address>, StoreError> {
        let row = sqlx::query_as::<_, Address>("SELECT * FROM addresses WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row)
    }

    /// Find the address for a given `(wallet_id, muxed_id)`, if any.
    pub async fn address_by_muxed_id(
        &self,
        wallet_id: Uuid,
        muxed_id: i64,
    ) -> Result<Option<Address>, StoreError> {
        let row = sqlx::query_as::<_, Address>(
            "SELECT * FROM addresses WHERE wallet_id = $1 AND muxed_id = $2",
        )
        .bind(wallet_id)
        .bind(muxed_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    // --- transactions (deposits) ------------------------------------------

    /// Idempotently record a confirmed deposit.
    ///
    /// Returns `Ok(Some(tx))` on first insert and `Ok(None)` if this exact on-chain operation was
    /// already recorded (the `(tx_hash, operation_index)` unique index fired) — so replays and
    /// reorged re-deliveries never double-credit.
    pub async fn record_deposit(&self, d: &NewDeposit) -> Result<Option<Transaction>, StoreError> {
        let result = sqlx::query_as::<_, Transaction>(
            r#"
            INSERT INTO transactions
                (wallet_id, address_id, direction, asset_code, asset_issuer, amount_stroops,
                 source_account, destination_account, stellar_tx_hash, operation_index,
                 horizon_op_id, ledger, memo_id, status)
            VALUES ($1, $2, 'deposit', $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'confirmed')
            RETURNING *
            "#,
        )
        .bind(d.wallet_id)
        .bind(d.address_id)
        .bind(&d.asset_code)
        .bind(&d.asset_issuer)
        .bind(d.amount_stroops)
        .bind(&d.source_account)
        .bind(&d.destination_account)
        .bind(&d.stellar_tx_hash)
        .bind(d.operation_index)
        .bind(&d.horizon_op_id)
        .bind(d.ledger)
        .bind(d.memo_id)
        .fetch_one(&self.pool)
        .await;

        match result {
            Ok(tx) => Ok(Some(tx)),
            Err(e) => match StoreError::from_sqlx_conflict(e) {
                StoreError::Conflict => Ok(None), // already recorded — benign
                other => Err(other),
            },
        }
    }

    /// List transactions for a wallet (most recent first), with optional cursor-based pagination.
    pub async fn list_transactions(
        &self,
        wallet_id: Uuid,
        limit: i64,
        before_id: Option<Uuid>,
    ) -> Result<Vec<Transaction>, StoreError> {
        let rows = sqlx::query_as::<_, Transaction>(
            r#"
            SELECT * FROM transactions
            WHERE wallet_id = $1
              AND ($2::uuid IS NULL OR (created_at, id) < (
                  SELECT created_at, id FROM transactions WHERE id = $2
              ))
            ORDER BY created_at DESC, id DESC
            LIMIT $3
            "#,
        )
        .bind(wallet_id)
        .bind(before_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Link a quarantined deposit to an address without ever replacing an existing attribution.
    pub async fn attribute_quarantined_deposit(
        &self,
        transaction_id: Uuid,
        address_id: Uuid,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE transactions SET address_id = $2 WHERE id = $1 AND address_id IS NULL",
        )
        .bind(transaction_id)
        .bind(address_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Return only deposits awaiting attribution for a wallet, newest first.
    pub async fn list_quarantined_transactions(
        &self,
        wallet_id: Uuid,
    ) -> Result<Vec<Transaction>, StoreError> {
        Ok(sqlx::query_as::<_, Transaction>(
            "SELECT * FROM transactions WHERE wallet_id = $1 AND direction = 'deposit' AND address_id IS NULL ORDER BY created_at DESC, id DESC",
        )
        .bind(wallet_id)
        .fetch_all(&self.pool)
        .await?)
    }

    /// Filtered, keyset-paginated transaction history: at most `limit` rows, newest first.
    ///
    /// Pass the last page's final transaction id as `before_id` to fetch the next page. The cursor
    /// is resolved within this wallet only, and ordering is the total order `(created_at, id)`, so
    /// pages stay stable under any filter combination — filters only narrow the set. Served by
    /// `idx_tx_wallet_created` / `idx_tx_wallet_asset_created` (migration 0033).
    pub async fn list_transactions_page(
        &self,
        wallet_id: Uuid,
        filter: &TransactionFilter,
        limit: i64,
        before_id: Option<Uuid>,
    ) -> Result<Vec<Transaction>, StoreError> {
        let rows = sqlx::query_as::<_, Transaction>(
            r#"
            SELECT * FROM transactions
            WHERE wallet_id = $1
              AND ($2::uuid IS NULL OR (created_at, id) < (
                    SELECT created_at, id FROM transactions WHERE id = $2 AND wallet_id = $1
                  ))
              AND ($3::text IS NULL OR direction = $3)
              AND ($4::text IS NULL OR status = $4)
              AND ($5::text IS NULL OR asset_code = $5)
              AND ($6::text IS NULL OR asset_issuer = $6)
              AND ($7::timestamptz IS NULL OR created_at >= $7)
              AND ($8::timestamptz IS NULL OR created_at < $8)
            ORDER BY created_at DESC, id DESC
            LIMIT $9
            "#,
        )
        .bind(wallet_id)
        .bind(before_id)
        .bind(filter.direction.as_deref())
        .bind(filter.status.as_deref())
        .bind(filter.asset_code.as_deref())
        .bind(filter.asset_issuer.as_deref())
        .bind(filter.from)
        .bind(filter.to)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Fetch a single transaction by id.
    pub async fn get_transaction(&self, id: Uuid) -> Result<Option<Transaction>, StoreError> {
        let row = sqlx::query_as::<_, Transaction>("SELECT * FROM transactions WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row)
    }

    // --- withdrawals ------------------------------------------------------

    /// Cheap existence check on `(wallet_id, idempotency_key)`, used to short-circuit a retried
    /// request with a 409 **before** running any pre-flight Horizon checks — a key that has
    /// already been consumed doesn't need its request re-validated against the chain.
    pub async fn withdrawal_exists(
        &self,
        wallet_id: Uuid,
        idempotency_key: &str,
    ) -> Result<bool, StoreError> {
        let found: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM withdrawals WHERE wallet_id = $1 AND idempotency_key = $2",
        )
        .bind(wallet_id)
        .bind(idempotency_key)
        .fetch_optional(&self.pool)
        .await?;
        Ok(found.is_some())
    }

    /// Create a withdrawal intent. Idempotent on `(wallet_id, idempotency_key)`: a retried request
    /// with the same key returns [`StoreError::Conflict`] instead of creating a second payout.
    /// Record a confirmed/failed outbound transfer in the `transactions` history (the table the
    /// dashboard lists). Withdrawals previously lived only in `withdrawals`, which is why they
    /// never showed up in "recent transactions".
    #[allow(clippy::too_many_arguments)]
    pub async fn record_withdrawal_transaction(
        &self,
        wallet_id: Uuid,
        asset_code: &str,
        asset_issuer: Option<&str>,
        amount_stroops: i64,
        source_account: &str,
        destination_account: &str,
        stellar_tx_hash: Option<&str>,
        status: &str,
    ) -> Result<Transaction, StoreError> {
        let row = sqlx::query_as::<_, Transaction>(
            r#"
            INSERT INTO transactions
                (wallet_id, direction, asset_code, asset_issuer, amount_stroops,
                 source_account, destination_account, stellar_tx_hash, status)
            VALUES ($1, 'withdrawal', $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            "#,
        )
        .bind(wallet_id)
        .bind(asset_code)
        .bind(asset_issuer)
        .bind(amount_stroops)
        .bind(source_account)
        .bind(destination_account)
        .bind(stellar_tx_hash)
        .bind(status)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn create_withdrawal(
        &self,
        new: NewWithdrawal<'_>,
    ) -> Result<Withdrawal, StoreError> {
        sqlx::query_as::<_, Withdrawal>(
            r#"
            INSERT INTO withdrawals
                (wallet_id, idempotency_key, destination_account, asset_code, asset_issuer,
                 amount_stroops, memo_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(new.wallet_id)
        .bind(new.idempotency_key)
        .bind(new.destination_account)
        .bind(new.asset_code)
        .bind(new.asset_issuer)
        .bind(new.amount_stroops)
        .bind(new.memo_id)
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::from_sqlx_conflict)
    }

    /// Update a withdrawal's status (and optional tx hash) after submission.
    pub async fn update_withdrawal_status(
        &self,
        id: Uuid,
        status: &str,
        stellar_tx_hash: Option<&str>,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE withdrawals SET status = $2, stellar_tx_hash = $3, updated_at = now() WHERE id = $1",
        )
        .bind(id)
        .bind(status)
        .bind(stellar_tx_hash)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // --- sponsored transactions -------------------------------------------

    /// List sponsored transactions for a wallet (most recent first), with
    /// optional status filter and cursor-based pagination.
    pub async fn list_sponsored_transactions(
        &self,
        wallet_id: Uuid,
        limit: i64,
        status_filter: Option<&str>,
        before_id: Option<Uuid>,
    ) -> Result<Vec<SponsoredTransaction>, StoreError> {
        let rows = sqlx::query_as::<_, SponsoredTransaction>(
            r#"
            SELECT * FROM sponsored_transactions
            WHERE wallet_id = $1
              AND ($2::text IS NULL OR status = $2)
              AND ($3::uuid IS NULL OR (created_at, id) < (SELECT created_at, id FROM sponsored_transactions WHERE id = $3))
            ORDER BY created_at DESC, id DESC
            LIMIT $4
            "#,
        )
        .bind(wallet_id)
        .bind(status_filter)
        .bind(before_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    // --- gas sponsorship config -------------------------------------------

    /// Fetch a wallet's sponsorship config, or `None` if none has been saved.
    pub async fn get_gas_sponsorship_config(
        &self,
        wallet_id: Uuid,
    ) -> Result<Option<GasSponsorshipConfig>, StoreError> {
        let row = sqlx::query_as::<_, GasSponsorshipConfig>(
            "SELECT * FROM gas_sponsorship_configs WHERE wallet_id = $1",
        )
        .bind(wallet_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Create or replace a wallet's sponsorship config.
    pub async fn upsert_gas_sponsorship_config(
        &self,
        wallet_id: Uuid,
        enabled: bool,
        per_tx_fee_cap_stroops: Option<i64>,
        daily_budget_stroops: Option<i64>,
    ) -> Result<GasSponsorshipConfig, StoreError> {
        sqlx::query_as::<_, GasSponsorshipConfig>(
            r#"
            INSERT INTO gas_sponsorship_configs
                (wallet_id, enabled, per_tx_fee_cap_stroops, daily_budget_stroops)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (wallet_id) DO UPDATE SET
                enabled = EXCLUDED.enabled,
                per_tx_fee_cap_stroops = EXCLUDED.per_tx_fee_cap_stroops,
                daily_budget_stroops = EXCLUDED.daily_budget_stroops,
                updated_at = now()
            RETURNING *
            "#,
        )
        .bind(wallet_id)
        .bind(enabled)
        .bind(per_tx_fee_cap_stroops)
        .bind(daily_budget_stroops)
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::Database)
    }

    /// Sum of sponsored fees reserved (pending + confirmed) for a wallet so far today (UTC).
    /// Used to enforce the rolling daily budget and to report `spent_today`.
    pub async fn sum_sponsored_fees_reserved_today(
        &self,
        wallet_id: Uuid,
    ) -> Result<i64, StoreError> {
        let total: Option<i64> = sqlx::query_scalar(
            r#"
            SELECT COALESCE(SUM(fee_stroops), 0)::bigint
            FROM sponsored_transactions
            WHERE wallet_id = $1
              AND status IN ('pending', 'confirmed')
              AND created_at >= date_trunc('day', now() AT TIME ZONE 'UTC')
            "#,
        )
        .bind(wallet_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(total.unwrap_or(0))
    }

    // --- withdrawal allowlist ----------------------------------------------

    /// Fetch a wallet's withdrawal-allowlist config, if one has ever been set. `None` means the
    /// wallet has never touched this feature — treat that the same as `enabled = false`.
    pub async fn get_withdrawal_allowlist_config(
        &self,
        wallet_id: Uuid,
    ) -> Result<Option<WithdrawalAllowlistConfig>, StoreError> {
        let row = sqlx::query_as::<_, WithdrawalAllowlistConfig>(
            "SELECT * FROM withdrawal_allowlist_configs WHERE wallet_id = $1",
        )
        .bind(wallet_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Create or replace a wallet's withdrawal-allowlist toggle.
    pub async fn upsert_withdrawal_allowlist_config(
        &self,
        wallet_id: Uuid,
        enabled: bool,
    ) -> Result<WithdrawalAllowlistConfig, StoreError> {
        sqlx::query_as::<_, WithdrawalAllowlistConfig>(
            r#"
            INSERT INTO withdrawal_allowlist_configs (wallet_id, enabled)
            VALUES ($1, $2)
            ON CONFLICT (wallet_id) DO UPDATE SET
                enabled = EXCLUDED.enabled,
                updated_at = now()
            RETURNING *
            "#,
        )
        .bind(wallet_id)
        .bind(enabled)
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::Database)
    }

    /// Add an address to a wallet's withdrawal allowlist. `Conflict` if already present.
    pub async fn add_whitelisted_address(
        &self,
        wallet_id: Uuid,
        address: &str,
        label: Option<&str>,
    ) -> Result<WhitelistedAddress, StoreError> {
        sqlx::query_as::<_, WhitelistedAddress>(
            r#"
            INSERT INTO whitelisted_addresses (wallet_id, address, label)
            VALUES ($1, $2, $3)
            RETURNING *
            "#,
        )
        .bind(wallet_id)
        .bind(address)
        .bind(label)
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::from_sqlx_conflict)
    }

    /// List a wallet's whitelisted addresses, newest first.
    pub async fn list_whitelisted_addresses(
        &self,
        wallet_id: Uuid,
    ) -> Result<Vec<WhitelistedAddress>, StoreError> {
        let rows = sqlx::query_as::<_, WhitelistedAddress>(
            "SELECT * FROM whitelisted_addresses WHERE wallet_id = $1 ORDER BY created_at DESC",
        )
        .bind(wallet_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Remove a whitelisted address. `NotFound` if it doesn't belong to `wallet_id`.
    pub async fn remove_whitelisted_address(
        &self,
        wallet_id: Uuid,
        entry_id: Uuid,
    ) -> Result<(), StoreError> {
        let result =
            sqlx::query("DELETE FROM whitelisted_addresses WHERE id = $1 AND wallet_id = $2")
                .bind(entry_id)
                .bind(wallet_id)
                .execute(&self.pool)
                .await?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// `true` if `address` (already normalized to its base `G...` form by the caller) is on
    /// `wallet_id`'s allowlist. Pure existence check — callers first check whether the allowlist
    /// is even `enabled` via [`Store::get_withdrawal_allowlist_config`].
    pub async fn is_address_whitelisted(
        &self,
        wallet_id: Uuid,
        address: &str,
    ) -> Result<bool, StoreError> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM whitelisted_addresses WHERE wallet_id = $1 AND address = $2)",
        )
        .bind(wallet_id)
        .bind(address)
        .fetch_one(&self.pool)
        .await?;
        Ok(exists)
    }

    // --- per-address received totals ---------------------------------------

    /// Lifetime total (in stroops) of confirmed deposits credited to one generated address.
    /// This is historical bookkeeping, not a live on-chain balance — deposits to any address
    /// land in the wallet's single master account (that's the point of muxed addresses; there is
    /// nothing to sweep), so this number will not match a per-address Horizon balance query.
    pub async fn sum_deposits_for_address(&self, address_id: Uuid) -> Result<i64, StoreError> {
        let total: Option<i64> = sqlx::query_scalar(
            r#"
            SELECT COALESCE(SUM(amount_stroops), 0)::bigint
            FROM transactions
            WHERE address_id = $1 AND direction = 'deposit' AND status = 'confirmed'
            "#,
        )
        .bind(address_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(total.unwrap_or(0))
    }

    /// Batched version of [`Store::sum_deposits_for_address`] for an address list page: returns
    /// `(address_id, total_stroops)` pairs in one round trip instead of N.
    pub async fn sum_deposits_for_addresses(
        &self,
        address_ids: &[Uuid],
    ) -> Result<Vec<(Uuid, i64)>, StoreError> {
        if address_ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows: Vec<(Uuid, i64)> = sqlx::query_as(
            r#"
            SELECT address_id, COALESCE(SUM(amount_stroops), 0)::bigint AS total
            FROM transactions
            WHERE address_id = ANY($1) AND direction = 'deposit' AND status = 'confirmed'
            GROUP BY address_id
            "#,
        )
        .bind(address_ids)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    // --- payment links -------------------------------------------------------

    /// Create a payment link backed by an already-allocated deposit address.
    pub async fn create_payment_link(
        &self,
        link: NewPaymentLink<'_>,
    ) -> Result<PaymentLink, StoreError> {
        let row = sqlx::query_as::<_, PaymentLink>(
            r#"
            INSERT INTO payment_links
                (wallet_id, address_id, slug, name, description, image_url, redirect_url, amount_usdc_stroops)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            "#,
        )
        .bind(link.wallet_id)
        .bind(link.address_id)
        .bind(link.slug)
        .bind(link.name)
        .bind(link.description)
        .bind(link.image_url)
        .bind(link.redirect_url)
        .bind(link.amount_usdc_stroops)
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::from_sqlx_conflict)?;
        Ok(row)
    }

    /// Fetch a payment link owned by `wallet_id` (scoped so one merchant can't read another's).
    pub async fn get_payment_link(
        &self,
        wallet_id: Uuid,
        id: Uuid,
    ) -> Result<PaymentLink, StoreError> {
        sqlx::query_as::<_, PaymentLink>(
            "SELECT * FROM payment_links WHERE id = $1 AND wallet_id = $2",
        )
        .bind(id)
        .bind(wallet_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StoreError::NotFound)
    }

    /// Public lookup by slug — no wallet scoping, this is the pay-page entry point.
    pub async fn get_payment_link_by_slug(&self, slug: &str) -> Result<PaymentLink, StoreError> {
        sqlx::query_as::<_, PaymentLink>("SELECT * FROM payment_links WHERE slug = $1")
            .bind(slug)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(StoreError::NotFound)
    }

    /// Unscoped lookup by id — for internal (non-owner-facing) callers that already know which
    /// row they want, e.g. the expiry sweep resolving a payment's link to build its webhook.
    pub async fn get_payment_link_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<PaymentLink>, StoreError> {
        let row = sqlx::query_as::<_, PaymentLink>("SELECT * FROM payment_links WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row)
    }

    /// The payment link whose dedicated deposit address is `address_id`, if any.
    pub async fn get_payment_link_by_address(
        &self,
        address_id: Uuid,
    ) -> Result<Option<PaymentLink>, StoreError> {
        let row =
            sqlx::query_as::<_, PaymentLink>("SELECT * FROM payment_links WHERE address_id = $1")
                .bind(address_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row)
    }

    pub async fn list_payment_links(
        &self,
        wallet_id: Uuid,
        limit: i64,
        before_id: Option<Uuid>,
    ) -> Result<Vec<PaymentLink>, StoreError> {
        let rows = sqlx::query_as::<_, PaymentLink>(
            r#"
            SELECT * FROM payment_links
            WHERE wallet_id = $1
              AND ($2::uuid IS NULL OR (created_at, id) < (
                  SELECT created_at, id FROM payment_links WHERE id = $2
              ))
            ORDER BY created_at DESC, id DESC
            LIMIT $3
            "#,
        )
        .bind(wallet_id)
        .bind(before_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn set_payment_link_active(
        &self,
        wallet_id: Uuid,
        id: Uuid,
        active: bool,
    ) -> Result<PaymentLink, StoreError> {
        sqlx::query_as::<_, PaymentLink>(
            r#"
            UPDATE payment_links SET active = $1, updated_at = now()
            WHERE id = $2 AND wallet_id = $3
            RETURNING *
            "#,
        )
        .bind(active)
        .bind(id)
        .bind(wallet_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StoreError::NotFound)
    }

    /// Apply owner edits to a payment link that has not been paid (#455).
    ///
    /// A link is locked once any payment against it is in flight or has landed (`pending`,
    /// `confirmed`, `underpaid`, `overpaid`): a payer was quoted the current terms. The check runs
    /// inside the UPDATE so a payment confirming concurrently can't slip between check and write.
    /// Returns `NotFound` for a missing or foreign link and `Conflict` for a locked one.
    pub async fn update_unpaid_payment_link(
        &self,
        wallet_id: Uuid,
        id: Uuid,
        update: PaymentLinkUpdate<'_>,
    ) -> Result<PaymentLink, StoreError> {
        let updated = sqlx::query_as::<_, PaymentLink>(
            r#"
            UPDATE payment_links SET
                description = CASE WHEN $3 THEN $4 ELSE description END,
                redirect_url = CASE WHEN $5 THEN $6 ELSE redirect_url END,
                amount_usdc_stroops = CASE WHEN $7 THEN $8 ELSE amount_usdc_stroops END,
                updated_at = now()
            WHERE id = $1 AND wallet_id = $2
              AND NOT EXISTS (
                  SELECT 1 FROM payment_link_payments p
                  WHERE p.payment_link_id = payment_links.id
                    AND p.status IN ('pending', 'confirmed', 'underpaid', 'overpaid')
              )
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(wallet_id)
        .bind(update.description.is_some())
        .bind(update.description.flatten())
        .bind(update.redirect_url.is_some())
        .bind(update.redirect_url.flatten())
        .bind(update.amount_usdc_stroops.is_some())
        .bind(update.amount_usdc_stroops.flatten())
        .fetch_optional(&self.pool)
        .await?;

        match updated {
            Some(link) => Ok(link),
            // No row: either it isn't this wallet's link, or it exists but is locked.
            None => {
                self.get_payment_link(wallet_id, id).await?;
                Err(StoreError::Conflict)
            }
        }
    }

    /// Record a payer's intent to pay (the "Continue" step, before any on-chain payment lands).
    pub async fn record_payment_link_intent(
        &self,
        payment_link_id: Uuid,
        payer_name: Option<&str>,
        payer_email: Option<&str>,
        amount_usdc_stroops: i64,
        address_id: Option<Uuid>,
    ) -> Result<PaymentLinkPayment, StoreError> {
        let row = sqlx::query_as::<_, PaymentLinkPayment>(
            r#"
            INSERT INTO payment_link_payments
                (payment_link_id, payer_name, payer_email, amount_usdc_stroops, address_id)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(payment_link_id)
        .bind(payer_name)
        .bind(payer_email)
        .bind(amount_usdc_stroops)
        .bind(address_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    /// The pending intent owning `address_id`, if any — ingest's exact deposit match.
    pub async fn pending_payment_by_address(
        &self,
        address_id: Uuid,
    ) -> Result<Option<PaymentLinkPayment>, StoreError> {
        let row = sqlx::query_as::<_, PaymentLinkPayment>(
            r#"
            SELECT * FROM payment_link_payments
            WHERE address_id = $1 AND status = 'pending'
            ORDER BY created_at ASC
            LIMIT 1
            "#,
        )
        .bind(address_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn get_payment_link_payment(
        &self,
        payment_link_id: Uuid,
        id: Uuid,
    ) -> Result<PaymentLinkPayment, StoreError> {
        sqlx::query_as::<_, PaymentLinkPayment>(
            "SELECT * FROM payment_link_payments WHERE id = $1 AND payment_link_id = $2",
        )
        .bind(id)
        .bind(payment_link_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StoreError::NotFound)
    }

    /// The oldest still-pending payment on a link — ingest matches deposits against this one.
    pub async fn oldest_pending_payment_link_payment(
        &self,
        payment_link_id: Uuid,
    ) -> Result<Option<PaymentLinkPayment>, StoreError> {
        let row = sqlx::query_as::<_, PaymentLinkPayment>(
            r#"
            SELECT * FROM payment_link_payments
            WHERE payment_link_id = $1 AND status = 'pending'
            ORDER BY created_at ASC
            LIMIT 1
            "#,
        )
        .bind(payment_link_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn confirm_payment_link_payment(
        &self,
        id: Uuid,
        transaction_id: Uuid,
    ) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            UPDATE payment_link_payments
            SET status = 'confirmed', transaction_id = $1
            WHERE id = $2
            "#,
        )
        .bind(transaction_id)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Record a deposit that landed on this payment's address but for the wrong amount.
    /// `status` must be `"underpaid"` or `"overpaid"` — the transaction is still linked (so the
    /// merchant/payer can see what actually arrived) but the payment is deliberately NOT marked
    /// `confirmed`.
    pub async fn mark_payment_link_payment_mismatched(
        &self,
        id: Uuid,
        transaction_id: Uuid,
        status: &str,
    ) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            UPDATE payment_link_payments
            SET status = $1, transaction_id = $2
            WHERE id = $3
            "#,
        )
        .bind(status)
        .bind(transaction_id)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Mark payments still `pending` past a 1-hour deadline as `expired`, returning the rows that
    /// were flipped so the caller can fire one webhook per expiry without a second query.
    pub async fn expire_stale_payment_link_payments(
        &self,
    ) -> Result<Vec<PaymentLinkPayment>, StoreError> {
        let rows = sqlx::query_as::<_, PaymentLinkPayment>(
            r#"
            UPDATE payment_link_payments
            SET status = 'expired'
            WHERE status = 'pending' AND created_at < now() - interval '1 hour'
            RETURNING *
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Payments recorded against a link (newest first), with cursor pagination.
    ///
    /// Includes pending intents, not just confirmed ones — a merchant wants to see that someone
    /// started paying, and pending rows are how an abandoned checkout shows up.
    pub async fn list_payment_link_payments(
        &self,
        payment_link_id: Uuid,
        limit: i64,
        before_id: Option<Uuid>,
    ) -> Result<Vec<PaymentLinkPayment>, StoreError> {
        let rows = sqlx::query_as::<_, PaymentLinkPayment>(
            r#"
            SELECT * FROM payment_link_payments
            WHERE payment_link_id = $1
              AND ($2::uuid IS NULL OR (created_at, id) < (
                  SELECT created_at, id FROM payment_link_payments WHERE id = $2
              ))
            ORDER BY created_at DESC, id DESC
            LIMIT $3
            "#,
        )
        .bind(payment_link_id)
        .bind(before_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Lifetime total (in USDC stroops) confirmed on a payment link.
    pub async fn sum_payment_link_collected(
        &self,
        payment_link_id: Uuid,
    ) -> Result<i64, StoreError> {
        let total: Option<i64> = sqlx::query_scalar(
            r#"
            SELECT COALESCE(SUM(amount_usdc_stroops), 0)::bigint
            FROM payment_link_payments
            WHERE payment_link_id = $1 AND status = 'confirmed'
            "#,
        )
        .bind(payment_link_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(total.unwrap_or(0))
    }

    /// Batched version of [`Store::sum_payment_link_collected`] for a link list page.
    pub async fn sum_payment_link_collected_batch(
        &self,
        payment_link_ids: &[Uuid],
    ) -> Result<Vec<(Uuid, i64)>, StoreError> {
        if payment_link_ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows: Vec<(Uuid, i64)> = sqlx::query_as(
            r#"
            SELECT payment_link_id, COALESCE(SUM(amount_usdc_stroops), 0)::bigint AS total
            FROM payment_link_payments
            WHERE payment_link_id = ANY($1) AND status = 'confirmed'
            GROUP BY payment_link_id
            "#,
        )
        .bind(payment_link_ids)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Atomically reserve budget and record a sponsored transaction.
    ///
    /// Inserts a `pending` row **only if** doing so keeps today's reserved fees within
    /// `daily_budget_stroops` (a `NULL` budget means unlimited). The check and insert happen in one
    /// statement (a conditional CTE), so concurrent sponsorships can't oversubscribe the budget.
    /// Returns `StoreError::BudgetExceeded` if the budget would be exceeded, or
    /// `StoreError::Conflict` if this `inner_tx_hash` was already sponsored (double-submit).
    pub async fn try_reserve_sponsored_transaction(
        &self,
        wallet_id: Uuid,
        inner_tx_hash: &str,
        fee_stroops: i64,
        daily_budget_stroops: Option<i64>,
    ) -> Result<SponsoredTransaction, StoreError> {
        // The read-then-insert below must be serialized per wallet. A bare conditional CTE is NOT
        // enough: under READ COMMITTED every concurrent transaction computes `spent` from a
        // snapshot taken before the others' inserts are visible, so N requests can each see the
        // same total and all pass the budget guard (observed: 11 reservations against a 10-slot
        // budget under 20 concurrent requests).
        //
        // A transaction-scoped advisory lock keyed on the wallet id makes the check-and-insert
        // mutually exclusive for that wallet, while leaving other wallets fully parallel. The
        // lock is released automatically when the transaction commits or rolls back.
        let mut tx = self.pool.begin().await?;

        // Fold the wallet UUID into a stable i64 lock key.
        let lock_key = {
            let b = wallet_id.as_bytes();
            i64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
                ^ i64::from_be_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]])
        };
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(lock_key)
            .execute(&mut *tx)
            .await?;

        let result = sqlx::query_as::<_, SponsoredTransaction>(
            r#"
            WITH spent AS (
                SELECT COALESCE(SUM(fee_stroops), 0)::bigint AS total
                FROM sponsored_transactions
                WHERE wallet_id = $1
                  AND status IN ('pending', 'confirmed')
                  AND created_at >= date_trunc('day', now() AT TIME ZONE 'UTC')
            )
            INSERT INTO sponsored_transactions (wallet_id, inner_tx_hash, fee_stroops, status)
            SELECT $1, $2, $3, 'pending'
            FROM spent
            WHERE $4::bigint IS NULL OR spent.total + $3 <= $4
            RETURNING *
            "#,
        )
        .bind(wallet_id)
        .bind(inner_tx_hash)
        .bind(fee_stroops)
        .bind(daily_budget_stroops)
        .fetch_optional(&mut *tx)
        .await;

        // Commit before returning so the reservation (and the lock release) are durable.
        if result.is_ok() {
            tx.commit().await?;
        }

        match result {
            // A row means the insert (and budget check) succeeded.
            Ok(Some(row)) => Ok(row),
            // No row means the WHERE budget guard rejected the insert.
            Ok(None) => Err(StoreError::BudgetExceeded),
            // Unique violation on inner_tx_hash => already sponsored.
            Err(e) => Err(StoreError::from_sqlx_conflict(e)),
        }
    }

    /// Update a sponsored transaction's outcome after submission.
    pub async fn finalize_sponsored_transaction(
        &self,
        id: Uuid,
        status: &str,
        fee_bump_tx_hash: Option<&str>,
        error: Option<&str>,
    ) -> Result<(), StoreError> {
        self.update_sponsored_tx_status(id, status, fee_bump_tx_hash, error)
            .await
    }

    /// Insert a sponsored transaction as `pending` (no budget check — see
    /// [`Store::try_reserve_sponsored_transaction`] for the atomic budget-aware insert).
    /// Fails with [`StoreError::Conflict`] if this `inner_tx_hash` was already recorded.
    pub async fn record_sponsored_tx(
        &self,
        new: NewSponsoredTx<'_>,
    ) -> Result<SponsoredTransaction, StoreError> {
        sqlx::query_as::<_, SponsoredTransaction>(
            r#"
            INSERT INTO sponsored_transactions (wallet_id, inner_tx_hash, fee_stroops, status)
            VALUES ($1, $2, $3, 'pending')
            RETURNING *
            "#,
        )
        .bind(new.wallet_id)
        .bind(new.inner_tx_hash)
        .bind(new.fee_stroops)
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::from_sqlx_conflict)
    }

    /// Update a sponsored transaction's status, fee-bump hash, and error.
    pub async fn update_sponsored_tx_status(
        &self,
        id: Uuid,
        status: &str,
        fee_bump_tx_hash: Option<&str>,
        error: Option<&str>,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE sponsored_transactions SET status = $2, fee_bump_tx_hash = $3, error = $4 WHERE id = $1",
        )
        .bind(id)
        .bind(status)
        .bind(fee_bump_tx_hash)
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Sum of **confirmed** sponsored fees for a wallet so far today (UTC) — i.e. actually spent.
    /// (Pending rows are excluded; for budget *reservation* use
    /// [`Store::sum_sponsored_fees_reserved_today`].)
    pub async fn sum_sponsored_fees_today(&self, wallet_id: Uuid) -> Result<i64, StoreError> {
        let total: Option<i64> = sqlx::query_scalar(
            r#"
            SELECT COALESCE(SUM(fee_stroops), 0)::bigint
            FROM sponsored_transactions
            WHERE wallet_id = $1
              AND status = 'confirmed'
              AND created_at >= date_trunc('day', now() AT TIME ZONE 'UTC')
            "#,
        )
        .bind(wallet_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(total.unwrap_or(0))
    }

    // --- token deny-list -------------------------------------------------

    /// Add a token to the deny-list so it cannot be replayed after logout.
    ///
    /// `token_hash` must be the **SHA-256 hex** of the raw JWT (never the token itself).
    /// `expires_at` should mirror the token's own `exp` claim so that rows can be pruned once
    /// they are past their natural expiry and cannot match any valid token anyway.
    ///
    /// Inserting the same hash twice is harmless (ON CONFLICT DO NOTHING).
    pub async fn denylist_token(
        &self,
        token_hash: &str,
        user_id: Uuid,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            INSERT INTO token_denylist (token_hash, user_id, expires_at)
            VALUES ($1, $2, $3)
            ON CONFLICT (token_hash) DO NOTHING
            "#,
        )
        .bind(token_hash)
        .bind(user_id)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Returns `true` if the token hash is present in the deny-list **and** has not yet expired.
    ///
    /// Expired rows are logically irrelevant (the token itself would fail `verify_token`'s expiry
    /// check), but this query skips them so a slow pruning job doesn't affect correctness.
    pub async fn is_token_denylisted(&self, token_hash: &str) -> Result<bool, StoreError> {
        let found: Option<bool> = sqlx::query_scalar(
            "SELECT true FROM token_denylist WHERE token_hash = $1 AND expires_at > now() LIMIT 1",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(found.is_some())
    }

    // --- ingest leader lock ------------------------------------------------

    /// Try once to become the ingest leader for `network`; `None` means another instance holds it.
    ///
    /// Uses a session-level `pg_try_advisory_lock`, so the lock is tied to one connection. On
    /// success that connection is detached from the pool (see [`IngestLeaderLock`]); on failure
    /// it goes straight back, holding nothing.
    pub async fn try_acquire_ingest_leader(
        &self,
        network: &str,
    ) -> Result<Option<IngestLeaderLock>, StoreError> {
        let mut conn = self.pool.acquire().await?;
        let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1, hashtext($2))")
            .bind(INGEST_LOCK_CLASS)
            .bind(network)
            .fetch_one(&mut *conn)
            .await?;
        Ok(acquired.then(|| IngestLeaderLock {
            conn: conn.detach(),
            network: network.to_string(),
        }))
    }

    // --- ingest cursor ----------------------------------------------------

    /// Read the saved Horizon paging token for a wallet, if any.
    pub async fn get_cursor(&self, wallet_id: Uuid) -> Result<Option<String>, StoreError> {
        let token: Option<String> =
            sqlx::query_scalar("SELECT paging_token FROM ingest_cursor WHERE wallet_id = $1")
                .bind(wallet_id)
                .fetch_optional(&self.pool)
                .await?
                .flatten();
        Ok(token)
    }

    /// Upsert the Horizon paging token for a wallet (durable resume point).
    pub async fn set_cursor(&self, wallet_id: Uuid, paging_token: &str) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            INSERT INTO ingest_cursor (wallet_id, paging_token, updated_at)
            VALUES ($1, $2, now())
            ON CONFLICT (wallet_id)
            DO UPDATE SET paging_token = EXCLUDED.paging_token, updated_at = now()
            "#,
        )
        .bind(wallet_id)
        .bind(paging_token)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // --- webhooks ---------------------------------------------------------

    /// Register a webhook endpoint for a wallet.
    pub async fn create_webhook_endpoint(
        &self,
        wallet_id: Uuid,
        url: &str,
        secret: &str,
    ) -> Result<WebhookEndpoint, StoreError> {
        sqlx::query_as::<_, WebhookEndpoint>(
            r#"
            INSERT INTO webhook_endpoints (wallet_id, url, secret)
            VALUES ($1, $2, $3)
            RETURNING *
            "#,
        )
        .bind(wallet_id)
        .bind(url)
        .bind(secret)
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::from_sqlx_conflict)
    }

    /// List the active webhook endpoints for a wallet (active and not soft-deleted).
    pub async fn active_webhook_endpoints(
        &self,
        wallet_id: Uuid,
    ) -> Result<Vec<WebhookEndpoint>, StoreError> {
        let rows = sqlx::query_as::<_, WebhookEndpoint>(
            "SELECT * FROM webhook_endpoints WHERE wallet_id = $1 AND active = true AND deleted_at IS NULL",
        )
        .bind(wallet_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Soft delete a webhook endpoint by setting its deleted_at timestamp and deactivating it.
    pub async fn delete_webhook(&self, id: Uuid) -> Result<(), StoreError> {
        sqlx::query("UPDATE webhook_endpoints SET deleted_at = now(), active = false WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Soft delete a webhook endpoint (alias for delete_webhook).
    pub async fn delete_webhook_endpoint(&self, id: Uuid) -> Result<(), StoreError> {
        self.delete_webhook(id).await
    }

    /// List webhook endpoints for a wallet, optionally including soft-deleted ones.
    pub async fn list_webhooks(
        &self,
        wallet_id: Uuid,
        include_deleted: bool,
    ) -> Result<Vec<WebhookEndpoint>, StoreError> {
        let query = if include_deleted {
            "SELECT * FROM webhook_endpoints WHERE wallet_id = $1 ORDER BY created_at ASC"
        } else {
            "SELECT * FROM webhook_endpoints WHERE wallet_id = $1 AND deleted_at IS NULL ORDER BY created_at ASC"
        };
        let rows = sqlx::query_as::<_, WebhookEndpoint>(query)
            .bind(wallet_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows)
    }

    /// List webhook endpoints for a wallet (alias for list_webhooks).
    pub async fn list_webhook_endpoints(
        &self,
        wallet_id: Uuid,
        include_deleted: bool,
    ) -> Result<Vec<WebhookEndpoint>, StoreError> {
        self.list_webhooks(wallet_id, include_deleted).await
    }

    /// Deactivate a webhook endpoint by setting its active status to false.
    pub async fn deactivate_webhook_endpoint(&self, id: Uuid) -> Result<(), StoreError> {
        sqlx::query("UPDATE webhook_endpoints SET active = false WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Fetch a single webhook endpoint by id. `NotFound` if it does not exist.
    ///
    /// Callers must still check `wallet_id` before returning data, so that an endpoint belonging
    /// to another wallet is reported as 404 rather than 403 (no existence leak).
    pub async fn get_webhook_endpoint(&self, id: Uuid) -> Result<WebhookEndpoint, StoreError> {
        sqlx::query_as::<_, WebhookEndpoint>("SELECT * FROM webhook_endpoints WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(StoreError::NotFound)
    }

    /// An endpoint's delivery history, newest first, capped at `limit` rows.
    pub async fn list_webhook_deliveries(
        &self,
        endpoint_id: Uuid,
        limit: i64,
    ) -> Result<Vec<WebhookDelivery>, StoreError> {
        let rows = sqlx::query_as::<_, WebhookDelivery>(
            r#"
            SELECT * FROM webhook_deliveries
            WHERE endpoint_id = $1
            ORDER BY created_at DESC, id DESC
            LIMIT $2
            "#,
        )
        .bind(endpoint_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// An endpoint's delivery history filtered to one `status` (e.g. `dead`), newest first.
    pub async fn list_webhook_deliveries_with_status(
        &self,
        endpoint_id: Uuid,
        status: &str,
        limit: i64,
    ) -> Result<Vec<WebhookDelivery>, StoreError> {
        let rows = sqlx::query_as::<_, WebhookDelivery>(
            r#"
            SELECT * FROM webhook_deliveries
            WHERE endpoint_id = $1 AND status = $2
            ORDER BY created_at DESC, id DESC
            LIMIT $3
            "#,
        )
        .bind(endpoint_id)
        .bind(status)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Fetch one delivery scoped to its endpoint, so a delivery id can't be used across endpoints.
    pub async fn get_webhook_delivery(
        &self,
        endpoint_id: Uuid,
        id: Uuid,
    ) -> Result<WebhookDelivery, StoreError> {
        sqlx::query_as::<_, WebhookDelivery>(
            "SELECT * FROM webhook_deliveries WHERE id = $1 AND endpoint_id = $2",
        )
        .bind(id)
        .bind(endpoint_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StoreError::NotFound)
    }

    /// Track an endpoint's dead-delivery streak and deactivate it at `auto_disable_after` (#458).
    ///
    /// A delivered event resets the streak. Returns true only on the call that disabled it.
    pub async fn record_webhook_endpoint_outcome(
        &self,
        endpoint_id: Uuid,
        dead: bool,
        auto_disable_after: Option<i32>,
    ) -> Result<bool, StoreError> {
        if !dead {
            sqlx::query(
                "UPDATE webhook_endpoints SET consecutive_dead_deliveries = 0 \
                 WHERE id = $1 AND consecutive_dead_deliveries <> 0",
            )
            .bind(endpoint_id)
            .execute(&self.pool)
            .await?;
            return Ok(false);
        }

        // SET expressions read pre-update values, so `consecutive_dead_deliveries + 1` is the new streak.
        let disabled: Option<bool> = sqlx::query_scalar(
            r#"
            WITH hit AS (
                SELECT id, active AS was_active,
                       ($2::int IS NOT NULL AND consecutive_dead_deliveries + 1 >= $2) AS trips
                FROM webhook_endpoints WHERE id = $1 FOR UPDATE
            )
            UPDATE webhook_endpoints e SET
                consecutive_dead_deliveries = e.consecutive_dead_deliveries + 1,
                active = CASE WHEN hit.trips THEN false ELSE e.active END,
                auto_disabled_at = CASE WHEN hit.trips AND hit.was_active THEN now()
                                        ELSE e.auto_disabled_at END
            FROM hit WHERE e.id = hit.id
            RETURNING (hit.trips AND hit.was_active)
            "#,
        )
        .bind(endpoint_id)
        .bind(auto_disable_after)
        .fetch_optional(&self.pool)
        .await?;
        Ok(disabled.unwrap_or(false))
    }

    /// Record a webhook delivery attempt (audit log). Returns the delivery id.
    pub async fn log_webhook_delivery(
        &self,
        endpoint_id: Uuid,
        event_type: &str,
        payload: &serde_json::Value,
        status: &str,
        attempts: i32,
        response_code: Option<i32>,
    ) -> Result<Uuid, StoreError> {
        let id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO webhook_deliveries
                (endpoint_id, event_type, payload, status, attempts, response_code)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
            "#,
        )
        .bind(endpoint_id)
        .bind(event_type)
        .bind(payload)
        .bind(status)
        .bind(attempts)
        .bind(response_code)
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    // --- sessions -----------------------------------------------------------

    /// Open a login session. Its id goes into the JWT's `sid` claim.
    pub async fn create_session(
        &self,
        user_id: Uuid,
        user_agent_hash: Option<&str>,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Session, StoreError> {
        let row = sqlx::query_as::<_, Session>(
            "INSERT INTO sessions (user_id, user_agent_hash, expires_at)
             VALUES ($1, $2, $3) RETURNING *",
        )
        .bind(user_id)
        .bind(user_agent_hash)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    /// Push a live session's expiry out to `expires_at` (token refresh). Returns `false` when the
    /// session is not the user's, is revoked, or has already expired.
    pub async fn extend_session(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, StoreError> {
        let res = sqlx::query(
            "UPDATE sessions SET expires_at = $3, last_seen_at = now()
             WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL AND expires_at > now()",
        )
        .bind(session_id)
        .bind(user_id)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() == 1)
    }

    /// One-round-trip check run on every authenticated request: the user still exists at
    /// `session_epoch`, the token hash is not deny-listed, and (for tokens that carry one) the
    /// session is live. Also bumps the session's `last_seen_at`, at most once a minute.
    pub async fn is_session_valid(
        &self,
        token_hash: &str,
        user_id: Uuid,
        session_epoch: i32,
        session_id: Option<Uuid>,
    ) -> Result<bool, StoreError> {
        let valid: bool = sqlx::query_scalar(
            r#"
            WITH touched AS (
                UPDATE sessions SET last_seen_at = now()
                WHERE id = $4 AND user_id = $2 AND revoked_at IS NULL
                  AND last_seen_at < now() - interval '60 seconds'
                RETURNING 1
            )
            SELECT EXISTS (SELECT 1 FROM users WHERE id = $2 AND session_epoch = $3)
               AND NOT EXISTS (
                   SELECT 1 FROM token_denylist WHERE token_hash = $1 AND expires_at > now()
               )
               AND ($4::uuid IS NULL OR EXISTS (
                   SELECT 1 FROM sessions
                   WHERE id = $4 AND user_id = $2 AND revoked_at IS NULL AND expires_at > now()
               ))
            "#,
        )
        .bind(token_hash)
        .bind(user_id)
        .bind(session_epoch)
        .bind(session_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(valid)
    }

    /// A user's live (unrevoked, unexpired) sessions, most recently used first. Capped at 100.
    pub async fn list_active_sessions(&self, user_id: Uuid) -> Result<Vec<Session>, StoreError> {
        let rows = sqlx::query_as::<_, Session>(
            "SELECT * FROM sessions
             WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()
             ORDER BY last_seen_at DESC, id
             LIMIT 100",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Revoke one of the user's sessions. Scoped by `user_id`, so another user's session id
    /// matches nothing; returns `false` in that case (and when already revoked).
    pub async fn revoke_session(
        &self,
        user_id: Uuid,
        session_id: Uuid,
    ) -> Result<bool, StoreError> {
        let res = sqlx::query(
            "UPDATE sessions SET revoked_at = now()
             WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
        )
        .bind(session_id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() == 1)
    }

    /// Revoke every session except `keep` (all of them when `None`), and bump `session_epoch` so
    /// tokens that predate session tracking (no `sid`) die too. Returns
    /// `(new_epoch, sessions_revoked)`; the caller must re-issue its token under the new epoch.
    pub async fn revoke_other_sessions(
        &self,
        user_id: Uuid,
        keep: Option<Uuid>,
    ) -> Result<(i32, u64), StoreError> {
        let mut tx = self.pool.begin().await?;
        let epoch: i32 = sqlx::query_scalar(
            "UPDATE users SET session_epoch = session_epoch + 1, updated_at = now()
             WHERE id = $1 RETURNING session_epoch",
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StoreError::NotFound)?;
        let revoked = revoke_sessions_except(&mut tx, user_id, keep).await?;
        tx.commit().await?;
        Ok((epoch, revoked))
    }

    /// Delete sessions that expired more than a day ago (kept briefly for incident review).
    pub async fn purge_expired_sessions(&self) -> Result<u64, StoreError> {
        let res = sqlx::query("DELETE FROM sessions WHERE expires_at < now() - interval '1 day'")
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }

    // --- idempotency keys -------------------------------------------------

    /// Claim `key` for one `scope` of `wallet_id` before running a non-idempotent create.
    ///
    /// The insert is atomic, so two concurrent requests with one key can't both win the claim.
    /// An expired row is taken over as a fresh claim. Otherwise the existing row decides: a
    /// different `request_hash` is a [`IdempotencyClaim::Mismatch`], a stored response is a
    /// [`IdempotencyClaim::Replay`], and no response yet is [`IdempotencyClaim::InProgress`].
    pub async fn claim_idempotency_key(
        &self,
        wallet_id: Uuid,
        scope: &str,
        key: &str,
        request_hash: &str,
    ) -> Result<IdempotencyClaim, StoreError> {
        let claimed: Option<i32> = sqlx::query_scalar(
            r#"
            INSERT INTO idempotency_keys (wallet_id, scope, key, request_hash, expires_at)
            VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))
            ON CONFLICT (wallet_id, scope, key) DO UPDATE SET
                request_hash = EXCLUDED.request_hash,
                status_code = NULL,
                response = NULL,
                created_at = now(),
                expires_at = EXCLUDED.expires_at
            WHERE idempotency_keys.expires_at <= now()
            RETURNING 1
            "#,
        )
        .bind(wallet_id)
        .bind(scope)
        .bind(key)
        .bind(request_hash)
        .bind(IDEMPOTENCY_KEY_TTL_SECS as f64)
        .fetch_optional(&self.pool)
        .await?;
        if claimed.is_some() {
            return Ok(IdempotencyClaim::Claimed);
        }

        let (stored_hash, status_code, response): (String, Option<i16>, Option<serde_json::Value>) =
            sqlx::query_as(
                "SELECT request_hash, status_code, response FROM idempotency_keys
                 WHERE wallet_id = $1 AND scope = $2 AND key = $3",
            )
            .bind(wallet_id)
            .bind(scope)
            .bind(key)
            .fetch_one(&self.pool)
            .await?;
        Ok(if stored_hash != request_hash {
            IdempotencyClaim::Mismatch
        } else {
            match (status_code, response) {
                (Some(code), Some(response)) => IdempotencyClaim::Replay {
                    status_code: u16::try_from(code).unwrap_or(500),
                    response,
                },
                _ => IdempotencyClaim::InProgress,
            }
        })
    }

    /// Store the finished response for a claimed key so later retries replay it.
    pub async fn complete_idempotency_key(
        &self,
        wallet_id: Uuid,
        scope: &str,
        key: &str,
        status_code: u16,
        response: &serde_json::Value,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE idempotency_keys SET status_code = $4, response = $5
             WHERE wallet_id = $1 AND scope = $2 AND key = $3 AND response IS NULL",
        )
        .bind(wallet_id)
        .bind(scope)
        .bind(key)
        .bind(i16::try_from(status_code).unwrap_or(500))
        .bind(response)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Release an unfinished claim after the operation failed, so the client can retry the key.
    pub async fn release_idempotency_key(
        &self,
        wallet_id: Uuid,
        scope: &str,
        key: &str,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "DELETE FROM idempotency_keys
             WHERE wallet_id = $1 AND scope = $2 AND key = $3 AND response IS NULL",
        )
        .bind(wallet_id)
        .bind(scope)
        .bind(key)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Delete expired idempotency keys; called by the hourly maintenance loop.
    pub async fn purge_expired_idempotency_keys(&self) -> Result<u64, StoreError> {
        let res = sqlx::query("DELETE FROM idempotency_keys WHERE expires_at <= now()")
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }

    // --- token deny-list --------------------------------------------------

    /// Revoke a JWT by inserting it into the deny-list.
    ///
    /// `expires_at` should match the token's `exp` claim (converted from Unix seconds). Duplicate
    /// revocations (same token) are silently ignored via `ON CONFLICT DO NOTHING`.
    pub async fn revoke_token(
        &self,
        token: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            INSERT INTO token_denylist (token, expires_at)
            VALUES ($1, $2)
            ON CONFLICT (token) DO NOTHING
            "#,
        )
        .bind(token)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Return `true` if the token has been revoked (is in the deny-list).
    pub async fn is_token_revoked(&self, token: &str) -> Result<bool, StoreError> {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM token_denylist WHERE token = $1)")
                .bind(token)
                .fetch_one(&self.pool)
                .await?;
        Ok(exists)
    }

    /// Delete expired deny-list entries (those whose `expires_at` is in the past).
    ///
    /// Intended to be called periodically (e.g. once per hour in a background task) to prevent
    /// unbounded table growth. Safe to skip — expired tokens are rejected by `verify_token()`
    /// regardless of the deny-list.
    pub async fn purge_expired_tokens(&self) -> Result<u64, StoreError> {
        let result = sqlx::query("DELETE FROM token_denylist WHERE expires_at < now()")
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    // --- rate limiting ------------------------------------------------------

    /// Count one hit against the fixed window for `(key, class)` and return the hits so far.
    ///
    /// A single `INSERT .. ON CONFLICT DO UPDATE` is atomic under concurrency (the conflicting
    /// row is locked), so replicas sharing this database share one counter. An expired window is
    /// restarted in place. Uses the database clock, so replica clock skew cannot stretch windows.
    pub async fn rate_limit_hit(
        &self,
        key: &str,
        class: &str,
        window: std::time::Duration,
    ) -> Result<i64, StoreError> {
        let hits: i64 = sqlx::query_scalar(
            r#"
            INSERT INTO rate_limit_buckets (key, class, hits, expires_at)
            VALUES ($1, $2, 1, now() + make_interval(secs => $3))
            ON CONFLICT (key, class) DO UPDATE SET
                hits = CASE WHEN rate_limit_buckets.expires_at <= now() THEN 1
                            ELSE rate_limit_buckets.hits + 1 END,
                expires_at = CASE WHEN rate_limit_buckets.expires_at <= now()
                                  THEN EXCLUDED.expires_at
                                  ELSE rate_limit_buckets.expires_at END
            RETURNING hits
            "#,
        )
        .bind(key)
        .bind(class)
        .bind(window.as_secs_f64())
        .fetch_one(&self.pool)
        .await?;
        Ok(hits)
    }

    /// Delete expired rate-limit windows. Returns the number of rows removed.
    pub async fn prune_rate_limit_buckets(&self) -> Result<u64, StoreError> {
        let result = sqlx::query("DELETE FROM rate_limit_buckets WHERE expires_at < now()")
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

/// Advisory-lock class id for ingest leadership (ASCII "OCTI"); the network is the second key.
const INGEST_LOCK_CLASS: i32 = 0x4F43_5449;

/// A held session-level advisory lock electing this process as ingest leader for one network.
///
/// The lock lives on a dedicated connection detached from the pool: left in the pool, unrelated
/// queries would share it and it could never be released deliberately. Postgres frees the lock
/// when this connection ends, so a crashed or partitioned leader releases it with no cleanup.
pub struct IngestLeaderLock {
    conn: sqlx::PgConnection,
    network: String,
}

impl IngestLeaderLock {
    /// Whether this session still holds the lock (false if the connection died or it was freed).
    pub async fn still_held(&mut self) -> bool {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND granted
               AND pid = pg_backend_pid() AND classid = $1::oid AND objid = hashtext($2)::oid)",
        )
        .bind(INGEST_LOCK_CLASS)
        .bind(&self.network)
        .fetch_one(&mut self.conn)
        .await
        .unwrap_or(false)
    }

    /// Unlock and close the connection so a standby can take over on its next retry.
    pub async fn release(mut self) {
        let _ = sqlx::query("SELECT pg_advisory_unlock($1, hashtext($2))")
            .bind(INGEST_LOCK_CLASS)
            .bind(&self.network)
            .execute(&mut self.conn)
            .await;
        let _ = sqlx::Connection::close(self.conn).await;
    }
}

/// Revoke all of a user's live sessions except `keep`, inside the caller's transaction.
async fn revoke_sessions_except(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    keep: Option<Uuid>,
) -> Result<u64, StoreError> {
    let res = sqlx::query(
        "UPDATE sessions SET revoked_at = now()
         WHERE user_id = $1 AND revoked_at IS NULL AND ($2::uuid IS NULL OR id <> $2)",
    )
    .bind(user_id)
    .bind(keep)
    .execute(&mut **tx)
    .await?;
    Ok(res.rows_affected())
}
