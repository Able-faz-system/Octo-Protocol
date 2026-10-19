//! Typed row models mirroring the schema in `migrations/0001_init.sql`.
//!
//! Amounts are `i64` stroops throughout (never floating point). Sealed-seed bytes are stored as
//! `Vec<u8>` and only ever decrypted inside `octo-wallet-core`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A master wallet.
///
/// Custody models (see `migrations/0008_client_custody.sql`):
/// - `custody == "client"`: non-custodial — the USER's private key exists only client-side and
///   the server can never sign for `stellar_account_g`. If `sealed_*` are set on such a row,
///   they hold the seed of the separate **gas-tank** fee account (`gas_tank_account_g`), which
///   only ever carries fee float for sponsorship. `encrypted_backup` is an opaque
///   client-encrypted blob the server cannot decrypt.
/// - `custody == "server"`: legacy — the sealed seed is the user account's own seed.
#[derive(Debug, Clone, FromRow)]
pub struct Wallet {
    pub id: Uuid,
    pub network: String,
    pub stellar_account_g: String,
    pub sealed_ciphertext: Option<Vec<u8>>,
    pub sealed_nonce: Option<Vec<u8>>,
    pub sealed_salt: Option<Vec<u8>>,
    /// Scheme version tag for the sealed seed (see `octo_crypto::SCHEME_V1`). `None` on
    /// client-custody rows that carry no sealed seed at all.
    pub sealed_scheme: Option<i16>,
    pub next_muxed_id: i64,
    pub label: Option<String>,
    pub user_id: Option<Uuid>,
    pub description: Option<String>,
    pub custody: String,
    pub encrypted_backup: Option<String>,
    pub gas_tank_account_g: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub archived_at: Option<DateTime<Utc>>,
    /// When true the ingest supervisor skips this wallet; its cursor is left untouched.
    pub ingest_paused: bool,
    pub ingest_paused_at: Option<DateTime<Utc>>,
}

impl Wallet {
    /// True when the private key lives only client-side (server cannot sign).
    pub fn is_client_custody(&self) -> bool {
        self.custody == "client"
    }

    /// True when the wallet has been archived.
    pub fn is_archived(&self) -> bool {
        self.archived_at.is_some()
    }
}

/// A per-customer deposit address (off-chain row).
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Address {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub muxed_id: i64,
    pub muxed_address: String,
    pub customer_ref: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// A deposit or withdrawal ledger entry.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Transaction {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub address_id: Option<Uuid>,
    pub direction: String,
    pub asset_code: String,
    pub asset_issuer: Option<String>,
    pub amount_stroops: i64,
    pub source_account: Option<String>,
    pub destination_account: Option<String>,
    pub stellar_tx_hash: Option<String>,
    pub operation_index: Option<i32>,
    pub horizon_op_id: Option<String>,
    pub ledger: Option<i64>,
    pub memo_id: Option<i64>,
    pub status: String,
    pub reference: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// Optional filters for listing/exporting a wallet's transactions. `None` means "any".
///
/// Callers validate values before building this; the store only binds them as parameters.
#[derive(Debug, Clone, Default)]
pub struct TransactionFilter {
    /// `deposit` | `withdrawal`.
    pub direction: Option<String>,
    /// `pending` | `confirmed` | `failed`.
    pub status: Option<String>,
    /// `native` for XLM, otherwise a credit asset code.
    pub asset_code: Option<String>,
    /// Restricts a credit asset to one issuer; ignored when `asset_code` is `native`.
    pub asset_issuer: Option<String>,
    /// Inclusive lower bound on `created_at`.
    pub from: Option<DateTime<Utc>>,
    /// Exclusive upper bound on `created_at`.
    pub to: Option<DateTime<Utc>>,
}

/// A withdrawal (payout) intent.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Withdrawal {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub idempotency_key: String,
    pub destination_account: String,
    pub asset_code: String,
    pub asset_issuer: Option<String>,
    pub amount_stroops: i64,
    pub memo_id: Option<i64>,
    pub status: String,
    pub stellar_tx_hash: Option<String>,
    pub error: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A dashboard user.
#[derive(Debug, Clone, FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    /// Optional display name, set by the user. Null until they choose one.
    pub username: Option<String>,
    /// argon2id PHC hash — never returned to clients.
    pub password_hash: String,
    /// Null until the signup/login OTP is verified.
    pub email_verified_at: Option<DateTime<Utc>>,
    /// Bumped to revoke every live session token at once (e.g. on password reset).
    pub session_epoch: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A registered webhook endpoint.
#[derive(Debug, Clone, FromRow)]
pub struct WebhookEndpoint {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub url: String,
    pub secret: String,
    pub active: bool,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    /// Dead deliveries in a row; any successful delivery resets it to 0.
    pub consecutive_dead_deliveries: i32,
    /// Set when the endpoint was deactivated for hitting the dead-delivery threshold.
    pub auto_disabled_at: Option<DateTime<Utc>>,
}

/// A single webhook delivery attempt (append-only log).
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct WebhookDelivery {
    pub id: Uuid,
    pub endpoint_id: Uuid,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub status: String,
    pub attempts: i32,
    pub response_code: Option<i32>,
    /// Truncated (≤ 1 KiB) response body from the last attempt; `None` if no response arrived.
    pub response_body_snippet: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Recent delivery health rollup for a webhook endpoint.
#[derive(Debug, Clone, Default, Serialize, Deserialize, sqlx::FromRow)]
pub struct WebhookDeliveryHealth {
    pub recent_failure_count: i64,
    pub last_successful_delivery_at: Option<DateTime<Utc>>,
}

/// An audit-log entry (append-only record of account activity).
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct AuditLog {
    pub id: Uuid,
    pub user_id: Uuid,
    pub action: String,
    pub category: String,
    pub target: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// A dashboard login session (migration 0027). The JWT's `sid` claim names one of these.
#[derive(Debug, Clone, FromRow)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    /// SHA-256 hex of the User-Agent header at sign-in; never the raw header.
    pub user_agent_hash: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// A per-wallet API key (only the hash + display prefix are stored).
#[derive(Debug, Clone, FromRow)]
pub struct ApiKey {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub prefix: String,
    pub key_hash: String,
    pub created_at: DateTime<Utc>,
    pub scopes: Vec<String>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// A sponsored (fee-bump) transaction record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct SponsoredTransaction {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub inner_tx_hash: String,
    /// Hash of the outer fee-bump tx; `None` until/unless submission succeeds.
    pub fee_bump_tx_hash: Option<String>,
    pub fee_stroops: i64,
    pub status: String,
    /// Horizon error detail on failure; ops-only, never returned to callers.
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// A row in the token deny-list (JWT revocation record).
///
/// Only the SHA-256 hash of the token is stored — never the raw token itself.
#[derive(Debug, Clone, FromRow)]
pub struct DenylistedToken {
    /// SHA-256 hex of the raw JWT.
    pub token_hash: String,
    /// Mirrors the token's `exp` claim; used for safe pruning.
    pub expires_at: DateTime<Utc>,
    /// The user who revoked the token.
    pub user_id: Uuid,
    pub created_at: DateTime<Utc>,
}

/// A new sponsored transaction to record (inserted as `pending`).
#[derive(Debug, Clone)]
pub struct NewSponsoredTx<'a> {
    pub wallet_id: Uuid,
    pub inner_tx_hash: &'a str,
    pub fee_stroops: i64,
}

/// The gas-sponsorship config for a wallet (one row per wallet).
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GasSponsorshipConfig {
    pub wallet_id: Uuid,
    pub enabled: bool,
    /// Max fee (stroops) the sponsor pays per transaction; `None` = no cap.
    pub per_tx_fee_cap_stroops: Option<i64>,
    /// Rolling UTC-day budget (stroops). `None` = unlimited; `Some(0)` = sponsorship fully
    /// disabled for the day (every reservation is refused). Negative values are rejected at the
    /// API and, defensively, treated like `Some(0)` by the store (fail closed).
    pub daily_budget_stroops: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// The withdrawal-allowlist config for a wallet (one row per wallet).
///
/// `enabled = false` by default: a wallet must opt in before the allowlist is enforced, so
/// turning this feature on can never retroactively lock a wallet out of an address it already
/// used.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct WithdrawalAllowlistConfig {
    pub wallet_id: Uuid,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// An approved withdrawal destination for a wallet.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct WhitelistedAddress {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub address: String,
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// A new deposit to record (input to the idempotent insert).
#[derive(Debug, Clone)]
pub struct NewDeposit {
    pub wallet_id: Uuid,
    pub address_id: Option<Uuid>,
    pub asset_code: String,
    pub asset_issuer: Option<String>,
    pub amount_stroops: i64,
    pub source_account: Option<String>,
    pub destination_account: Option<String>,
    pub stellar_tx_hash: String,
    pub operation_index: i32,
    /// Horizon operation id (TOID) — the unique dedup key for this deposit.
    pub horizon_op_id: String,
    pub ledger: Option<i64>,
    pub memo_id: Option<i64>,
}

/// A shareable payment link, backed by a dedicated deposit address.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct PaymentLink {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub address_id: Uuid,
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
    pub image_url: Option<String>,
    pub redirect_url: Option<String>,
    pub amount_usdc_stroops: Option<i64>,
    pub active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Input to create a new payment link.
#[derive(Debug, Clone)]
pub struct NewPaymentLink<'a> {
    pub wallet_id: Uuid,
    pub address_id: Uuid,
    pub slug: &'a str,
    pub name: &'a str,
    pub description: Option<&'a str>,
    pub image_url: Option<&'a str>,
    pub redirect_url: Option<&'a str>,
    pub amount_usdc_stroops: Option<i64>,
}

/// Owner edits to a payment link. Outer `None` leaves a field unchanged; `Some(None)` clears it.
#[derive(Debug, Clone, Default)]
pub struct PaymentLinkUpdate<'a> {
    pub description: Option<Option<&'a str>>,
    pub redirect_url: Option<Option<&'a str>>,
    pub amount_usdc_stroops: Option<Option<i64>>,
}

/// One payment attempt against a payment link.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct PaymentLinkPayment {
    pub id: Uuid,
    pub payment_link_id: Uuid,
    pub transaction_id: Option<Uuid>,
    /// Dedicated muxed deposit address for this intent — how ingest matches a landing deposit to
    /// exactly one payment. `None` on rows created before migration 0015.
    pub address_id: Option<Uuid>,
    pub payer_name: Option<String>,
    pub payer_email: Option<String>,
    pub amount_usdc_stroops: i64,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

/// Result of claiming an idempotency key before running a create (#453).
#[derive(Debug, Clone, PartialEq)]
pub enum IdempotencyClaim {
    /// First use (or the previous use expired): the caller runs the operation, then completes.
    Claimed,
    /// A finished request with the same body: replay this response instead of re-running.
    Replay {
        status_code: u16,
        response: serde_json::Value,
    },
    /// The key was already used with a different request body.
    Mismatch,
    /// The first request with this key has not finished yet.
    InProgress,
}

/// A one-time email code, for signup verification or withdrawal confirmation.
#[derive(Debug, Clone, FromRow)]
pub struct EmailOtp {
    pub id: Uuid,
    pub user_id: Uuid,
    pub purpose: String,
    pub code_hash: String,
    /// Withdrawal OTPs bind to the exact transaction hash they gate; null for signup.
    pub tx_hash_bound: Option<String>,
    pub attempts: i16,
    pub consumed_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}
