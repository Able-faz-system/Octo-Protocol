//! Wallet endpoints: create a master wallet, fetch one, list with pagination.

use crate::auth::{authenticate, authorize_wallet};
use crate::error::{ApiError, ApiResult, Envelope};
use crate::json::parse_optional;
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use octo_store::NewClientWallet;
use octo_wallet_core::is_valid_account;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Shared pagination query parameters used by list_wallets and list_addresses.
/// Mirrors `SponsoredTxnQuery`'s limit/before convention.
#[derive(Debug, Default, Deserialize)]
pub struct ListParams {
    /// Maximum rows to return (default 50, max 200).
    pub limit: Option<i64>,
    /// Cursor: return rows created before this id (exclusive).
    pub before: Option<Uuid>,
    /// Whether to include archived wallets in the listing (default false).
    #[serde(default)]
    pub include_archived: Option<bool>,
}

/// Query parameters for `list_transactions`: supports pagination and direction filter.
#[derive(Debug, Default, Deserialize)]
pub struct TransactionListParams {
    /// Maximum rows to return (default 50, max 200).
    pub limit: Option<i64>,
    /// Cursor: return rows created before this id (exclusive).
    pub before: Option<Uuid>,
    /// Filter by direction: deposit | withdrawal.
    pub direction: Option<String>,
}

/// Body for wallet creation. Non-custodial: the client generates the keypair and sends only the
/// public account — the private key and mnemonic never reach the server.
#[derive(Debug, Default, Deserialize)]
pub struct CreateWalletRequest {
    /// The client-derived Stellar account (`G...`).
    pub public_key: Option<String>,
    /// Opaque client-encrypted seed backup (encrypted under a password-derived key in the
    /// browser/SDK; the server stores it verbatim and cannot decrypt it).
    #[serde(default)]
    pub encrypted_backup: Option<String>,
    /// Optional human label / name for the wallet.
    #[serde(default)]
    pub label: Option<String>,
    /// Optional longer description.
    #[serde(default)]
    pub description: Option<String>,
    /// Server-issued ownership challenge (from `GET /v1/wallets/challenge`).
    #[serde(default)]
    pub challenge: Option<String>,
    /// Base64 ed25519 signature over the challenge bytes, made with `public_key`'s secret key.
    #[serde(default)]
    pub signature: Option<String>,
}

/// How long an issued ownership challenge stays redeemable.
const CHALLENGE_TTL_SECS: i64 = 600;

fn challenge_hmac_input(user_id: Uuid, ts: i64, nonce: &str, network_passphrase: &str) -> String {
    format!("wallet-challenge:v2:{network_passphrase}:{user_id}:{ts}:{nonce}")
}

fn issue_challenge(
    secret: &[u8],
    user_id: Uuid,
    ts: i64,
    nonce: &str,
    network_passphrase: &str,
) -> String {
    let mac = crate::auth::sign_hs256(
        secret,
        challenge_hmac_input(user_id, ts, nonce, network_passphrase).as_bytes(),
    );
    format!("v2.{ts}.{nonce}.{network_passphrase}.{mac}")
}

/// `GET /v1/wallets/challenge` — issue a short-lived ownership challenge for wallet creation.
///
/// The client must sign the returned string with the keypair it intends to register, proving it
/// controls the private key. The challenge is bound to both the requesting user and the configured
/// network passphrase, preventing cross-account and cross-network replay.
pub async fn wallet_challenge(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<ChallengeResponse>>> {
    let user_id = authenticate(&headers, &state).await?;
    let ts = crate::auth::now_secs();
    let nonce = Uuid::new_v4().simple().to_string();
    let challenge = issue_challenge(
        state.jwt_secret(),
        user_id,
        ts,
        &nonce,
        state.network().passphrase(),
    );
    Ok(Envelope::ok(ChallengeResponse {
        challenge,
    }))
}

#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    pub challenge: String,
}

/// Verify a challenge + signature pair for `public_key`, bound to `user_id`.
fn verify_ownership(
    state: &AppState,
    user_id: Uuid,
    public_key: &str,
    challenge: &str,
    signature: &str,
) -> Result<(), ApiError> {
    verify_ownership_for_network(
        state.jwt_secret(),
        user_id,
        state.network().passphrase(),
        challenge,
        signature,
        crate::auth::now_secs(),
    )
}

fn verify_ownership_for_network(
    secret: &[u8],
    user_id: Uuid,
    expected_network_passphrase: &str,
    challenge: &str,
    signature: &str,
    now: i64,
) -> Result<(), ApiError> {
    let bad = || ApiError::BadRequest("invalid or expired ownership challenge".into());

    let mut parts = challenge.splitn(5, '.');
    let version = parts.next().ok_or_else(bad)?;
    let ts: i64 = parts.next().and_then(|p| p.parse().ok()).ok_or_else(bad)?;
    let nonce = parts.next().ok_or_else(bad)?;
    let network_passphrase = parts.next().ok_or_else(bad)?;
    let mac = parts.next().ok_or_else(bad)?;

    if version != "v2" || network_passphrase != expected_network_passphrase {
        return Err(bad());
    }

    let age = now.checked_sub(ts).ok_or_else(bad)?;
    if !(0..=CHALLENGE_TTL_SECS).contains(&age) {
        return Err(bad());
    }
    if !crate::auth::verify_hs256(
        secret,
        challenge_hmac_input(user_id, ts, nonce, network_passphrase).as_bytes(),
        mac,
    ) {
        return Err(bad());
    }

    octo_wallet_core::verify_account_signature(public_key, challenge.as_bytes(), signature).map_err(
        |_| {
            ApiError::BadRequest(
                "signature does not prove ownership of public_key — sign the challenge with the \
                 account's own secret key"
                    .into(),
            )
        },
    )
}

#[cfg(test)]
mod challenge_tests {
    use super::*;
    use base64::Engine as _;
    use octo_wallet_core::StellarNetwork;

    #[test]
    fn ownership_signature_is_bound_to_the_network_passphrase() {
        let secret = b"test challenge secret";
        let user_id = Uuid::new_v4();
        let now = crate::auth::now_secs();
        let nonce = Uuid::new_v4().simple().to_string();
        let network_a = StellarNetwork::Testnet.passphrase();
        let challenge = issue_challenge(secret, user_id, now, &nonce, network_a);
        let keypair = stellar_base::crypto::DalekKeyPair::random().unwrap();
        let signature = base64::engine::general_purpose::STANDARD
            .encode(keypair.sign(challenge.as_bytes()).to_vec());

        assert!(verify_ownership_for_network(
            secret, user_id, network_a, &challenge, &signature, now
        )
        .is_ok());
        assert!(verify_ownership_for_network(
            secret,
            user_id,
            StellarNetwork::Public.passphrase(),
            &challenge,
            &signature,
            now,
        )
        .is_err());
    }
}

/// What we return after creating a wallet. No secret material — the key was generated client-side
/// and the recovery mnemonic was shown there; the server never saw either.
#[derive(Debug, Serialize)]
pub struct CreateWalletResponse {
    pub id: Uuid,
    pub network: String,
    pub address: String,
    pub custody: String,
    /// Whether the account was funded on-chain (testnet friendbot). False on mainnet.
    pub funded: bool,
}

/// Public wallet view (no secrets).
#[derive(Debug, Serialize)]
pub struct WalletView {
    pub id: Uuid,
    pub network: String,
    pub address: String,
    pub custody: String,
    pub label: Option<String>,
    pub description: Option<String>,
    pub archived_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Paginated list response for wallets.
#[derive(Debug, Serialize)]
pub struct WalletListResponse {
    pub data: Vec<WalletView>,
    /// UUID of the last row in this page, or null if there are no more rows.
    pub next_cursor: Option<Uuid>,
}

/// Paginated list response for transactions.
#[derive(Debug, Serialize)]
pub struct TransactionListResponse {
    pub data: Vec<octo_store::Transaction>,
    /// UUID of the last row in this page, or null if there are no more rows.
    pub next_cursor: Option<Uuid>,
}

/// Validate a `limit` query param using the same bounds as `SponsoredTxnQuery`:
/// default 50, min 1, max 200.
pub fn validated_limit(limit: Option<i64>) -> Result<i64, ApiError> {
    let l = limit.unwrap_or(50);
    if l > 200 {
        return Err(ApiError::BadRequest("limit must not exceed 200".into()));
    }
    if l < 1 {
        return Err(ApiError::BadRequest("limit must be at least 1".into()));
    }
    Ok(l)
}

/// `POST /v1/wallets` — create a master wallet for the authenticated user.
///
/// Ownership invariant: client-custody wallet registration strictly enforces cryptographic
/// ownership verification before creating or activating the wallet row. Every call must provide
/// a server-issued challenge (from `GET /v1/wallets/challenge`) and a valid Ed25519 signature
/// matching `public_key`. The signature is verified inline via `verify_ownership` prior to any
/// database insertion, preventing unverified or spoofed public keys from being registered.
pub async fn create_wallet(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<Envelope<CreateWalletResponse>>)> {
    let user_id = authenticate(&headers, &state).await?;
    let req: CreateWalletRequest = parse_optional(&body)?;
    let label = req.label;
    let description = req.description;

    // Non-custodial: the client did the keygen; we only accept the public account.
    let public_key = req
        .public_key
        .filter(|k| !k.is_empty())
        .ok_or_else(|| ApiError::BadRequest("public_key is required (G...)".into()))?;
    if !is_valid_account(&public_key) {
        return Err(ApiError::BadRequest(
            "public_key must be a valid Stellar account (G...)".into(),
        ));
    }

    // Ownership proof: without this, anyone could register a stranger's public account and watch
    // its deposit history through the dashboard. The challenge comes from GET /v1/wallets/challenge.
    let challenge = req.challenge.filter(|c| !c.is_empty()).ok_or_else(|| {
        ApiError::BadRequest("challenge is required (GET /v1/wallets/challenge first)".into())
    })?;
    let signature = req
        .signature
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::BadRequest("signature over the challenge is required".into()))?;
    verify_ownership(&state, user_id, &public_key, &challenge, &signature)?;

    let wallet = state
        .store()
        .create_client_wallet(NewClientWallet {
            network: state.network().as_str(),
            stellar_account_g: &public_key,
            encrypted_backup: req.encrypted_backup.as_deref(),
            label: label.as_deref(),
            user_id: Some(user_id),
            description: description.as_deref(),
        })
        .await?;

    crate::audit::record(
        &state,
        user_id,
        "created master wallet",
        crate::audit::category::WALLET,
        wallet.label.as_deref(),
        &headers,
    )
    .await;

    // On testnet, fund the new account via friendbot so it exists on-chain. Best-effort: a
    // funding failure does not roll back wallet creation (the account can be funded later), but we
    // record whether it succeeded so the caller knows.
    let funded = match state.friendbot_url() {
        Some(fb) => crate::horizon::friendbot_fund(fb, &wallet.stellar_account_g)
            .await
            .is_ok(),
        None => false,
    };

    let resp = CreateWalletResponse {
        id: wallet.id,
        network: wallet.network,
        address: wallet.stellar_account_g,
        custody: wallet.custody,
        funded,
    };
    let (status, json) = Envelope::created(resp);
    Ok((status, json))
}

/// `GET /v1/wallets/{id}/backup` — the opaque client-encrypted seed backup, for new-device
/// recovery. Login-only: this blob is ciphertext under the user's password; the server cannot
/// decrypt it and neither can anyone who steals it without the password.
pub async fn get_backup(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<BackupView>>> {
    let user_id = crate::auth::require_login(&headers, &state).await?;
    // Per-user (not per-IP) so a stolen session can't sidestep the cap by rotating addresses.
    if !state.rate_limiter().check(
        &format!("backup:{user_id}"),
        "backup",
        crate::rate_limit::BACKUP_USER_LIMIT,
        crate::rate_limit::BACKUP_USER_WINDOW,
    ) {
        return Err(ApiError::TooManyRequests(
            "too many backup requests — wait a while and try again".into(),
        ));
    }
    let wallet = state.store().get_wallet(id).await?;
    if wallet.user_id != Some(user_id) {
        return Err(ApiError::NotFound);
    }
    // Fail closed: the sealed seed is never handed out without a trace. Target is the id only.
    crate::audit::record_strict(
        &state,
        user_id,
        crate::audit::action::BACKUP_RETRIEVED,
        crate::audit::category::WALLET,
        Some(&wallet.id.to_string()),
        &headers,
    )
    .await?;
    Ok(Envelope::ok(BackupView {
        wallet_id: wallet.id,
        encrypted_backup: wallet.encrypted_backup,
    }))
}

/// The stored client-encrypted backup blob (may be absent if the user opted out).
#[derive(Debug, Serialize)]
pub struct BackupView {
    pub wallet_id: Uuid,
    pub encrypted_backup: Option<String>,
}

/// `POST /v1/wallets/{id}/gas-tank` — provision the server-held gas-tank fee account that pays
/// for sponsored transactions. The tank is the ONLY server-held key for a client wallet and only
/// ever carries fee float, so worst-case exposure is the gas budget — never customer funds.
/// Idempotent-ish: a second call returns the existing tank.
pub async fn create_gas_tank(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<(StatusCode, Json<Envelope<GasTankView>>)> {
    let user_id = crate::auth::require_login(&headers, &state).await?;
    let wallet = state.store().get_wallet(id).await?;
    if wallet.user_id != Some(user_id) {
        return Err(ApiError::NotFound);
    }

    if let Some(existing) = wallet.gas_tank_account_g {
        return Ok((
            StatusCode::OK,
            Envelope::ok(GasTankView {
                wallet_id: wallet.id,
                gas_tank_address: existing,
                funded: false,
            }),
        ));
    }
    if !wallet.is_client_custody() {
        return Err(ApiError::BadRequest(
            "legacy server-custody wallets pay fees from their own account; no gas tank needed"
                .into(),
        ));
    }

    // Hold the row lock through persistence so a concurrent request cannot provision another keypair.
    let provisioning = state.store().lock_gas_tank_provision(id).await?;
    let locked_wallet = provisioning.wallet();
    if locked_wallet.user_id != Some(user_id) {
        return Err(ApiError::NotFound);
    }
    if locked_wallet.gas_tank_account_g.is_some() {
        return Err(ApiError::Conflict);
    }
    if !locked_wallet.is_client_custody() {
        return Err(ApiError::BadRequest(
            "legacy server-custody wallets pay fees from their own account; no gas tank needed"
                .into(),
        ));
    }

    // Provision a fresh keypair inside wallet-core. The mnemonic is deliberately dropped: the
    // tank is a disposable fee account, recoverable only by re-provisioning.
    let provisioned = octo_wallet_core::provision_wallet(state.sealing_key(), state.network())?;
    let wallet = state
        .store()
        .set_gas_tank(
            &provisioned.account_g,
            &provisioned.sealed.ciphertext,
            &provisioned.sealed.nonce,
            &provisioned.sealed.salt,
            i16::from(provisioned.sealed.scheme),
        )
        .await?;

    // Best-effort testnet funding so the tank account exists on-chain.
    let funded = match state.friendbot_url() {
        Some(fb) => crate::horizon::friendbot_fund(fb, &provisioned.account_g)
            .await
            .is_ok(),
        None => false,
    };

    crate::audit::record(
        &state,
        user_id,
        "provisioned a gas tank",
        crate::audit::category::WALLET,
        Some(&provisioned.account_g),
        &headers,
    )
    .await;

    let resp = GasTankView {
        wallet_id: wallet.id,
        gas_tank_address: provisioned.account_g,
        funded,
    };
    let (status, json) = Envelope::created(resp);
    Ok((status, json))
}

/// The gas tank attached to a wallet. Fund `gas_tank_address` with XLM to cover sponsored fees.
#[derive(Debug, Serialize)]
pub struct GasTankView {
    pub wallet_id: Uuid,
    pub gas_tank_address: String,
    pub funded: bool,
}

/// A wallet's gas-tank status. Public account and spend only — the sealed seed never leaves the DB.
#[derive(Debug, Serialize)]
pub struct GasTankStatusView {
    pub wallet_id: Uuid,
    pub provisioned: bool,
    pub gas_tank_address: Option<String>,
    pub sponsorship_enabled: bool,
    pub daily_budget_stroops: Option<i64>,
    /// Fees reserved today (pending + confirmed), the same figure the budget check enforces.
    pub spent_today_stroops: i64,
}

/// `GET /v1/wallets/{id}/gas-tank` — the tank's public account and today's spend against budget.
/// A wallet with no tank gets a 200 with `provisioned: false`, so a dashboard can render "not set up".
pub async fn get_gas_tank(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<GasTankStatusView>>> {
    authorize_wallet(&headers, &state, id).await?;
    let wallet = state.store().get_wallet(id).await?;
    let Some(gas_tank_address) = wallet.gas_tank_account_g else {
        return Ok(Envelope::ok(GasTankStatusView {
            wallet_id: id,
            provisioned: false,
            gas_tank_address: None,
            sponsorship_enabled: false,
            daily_budget_stroops: None,
            spent_today_stroops: 0,
        }));
    };

    let config = state.store().get_gas_sponsorship_config(id).await?;
    let spent_today_stroops = state
        .store()
        .sum_sponsored_fees_reserved_today(id)
        .await
        .map_err(|_| ApiError::Internal)?;
    Ok(Envelope::ok(GasTankStatusView {
        wallet_id: id,
        provisioned: true,
        gas_tank_address: Some(gas_tank_address),
        sponsorship_enabled: config.as_ref().is_some_and(|c| c.enabled),
        daily_budget_stroops: config.and_then(|c| c.daily_budget_stroops),
        spent_today_stroops,
    }))
}

/// `GET /v1/wallets/{id}/balances` — live on-chain balances from Horizon.
pub async fn get_balances(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<Vec<crate::horizon::Balance>>>> {
    authorize_wallet(&headers, &state, id).await?;
    let wallet = state.store().get_wallet(id).await?;
    let balances = state.horizon().balances(&wallet.stellar_account_g).await?;
    Ok(Envelope::ok(balances))
}

/// `GET /v1/wallets/{id}/transactions` — recorded deposits/withdrawals for a wallet,
/// with optional `?limit=`, `?before=` cursor pagination, and `?direction=` filter.
pub async fn list_transactions(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Query(q): Query<TransactionListParams>,
) -> ApiResult<Json<Envelope<TransactionListResponse>>> {
    authorize_wallet(&headers, &state, id).await?;
    let _ = state.store().get_wallet(id).await?;

    let direction = match q.direction.as_deref() {
        Some("deposit") => Some("deposit"),
        Some("withdrawal") => Some("withdrawal"),
        None => None,
        Some(other) => {
            return Err(ApiError::BadRequest(format!(
                "invalid direction filter '{other}'; valid values are: deposit, withdrawal"
            )));
        }
    };

    let limit = validated_limit(q.limit)?;

    // Fetch limit+1 to detect whether a next page exists.
    let rows = state
        .store()
        .list_transactions_page(id, limit + 1, direction, q.before)
        .await
        .map_err(|_| ApiError::Internal)?;

    let has_more = rows.len() > limit as usize;
    let mut data = rows;
    if has_more {
        data.truncate(limit as usize);
    }
    let next_cursor = if has_more {
        data.last().map(|r| r.id)
    } else {
        None
    };

    Ok(Envelope::ok(TransactionListResponse { data, next_cursor }))
}

fn to_view(w: octo_store::Wallet) -> WalletView {
    WalletView {
        id: w.id,
        network: w.network,
        address: w.stellar_account_g,
        custody: w.custody,
        label: w.label,
        description: w.description,
        archived_at: w.archived_at,
    }
}

/// `GET /v1/wallets/{id}`
pub async fn get_wallet(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<WalletView>>> {
    authorize_wallet(&headers, &state, id).await?;
    let w = state.store().get_wallet(id).await.map_err(|e| match e {
        octo_store::StoreError::NotFound => ApiError::NotFound,
        _ => ApiError::Internal,
    })?;
    Ok(Envelope::ok(to_view(w)))
}

/// `GET /v1/wallets` — list the authenticated user's wallets, with optional
/// `?limit=` and `?before=` cursor pagination.
pub async fn list_wallets(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListParams>,
) -> ApiResult<Json<Envelope<WalletListResponse>>> {
    let user_id = authenticate(&headers, &state).await?;

    let limit = validated_limit(q.limit)?;

    // Fetch limit+1 to detect whether a next page exists.
    let rows = state
        .store()
        .list_wallets_for_user(user_id, limit + 1, q.before, q.include_archived.unwrap_or(false))
        .await
        .map_err(|_| ApiError::Internal)?;

    let has_more = rows.len() > limit as usize;
    let mut wallets = rows;
    if has_more {
        wallets.truncate(limit as usize);
    }
    let next_cursor = if has_more {
        wallets.last().map(|w| w.id)
    } else {
        None
    };

    Ok(Envelope::ok(WalletListResponse {
        data: wallets.into_iter().map(to_view).collect(),
        next_cursor,
    }))
}

/// `PATCH /v1/wallets/:id/archive` — archive a wallet (dashboard login only).
pub async fn archive_wallet(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<WalletView>>> {
    let user_id = authenticate(&headers, &state).await?;
    let wallet = state.store().get_wallet(id).await?;
    if wallet.user_id != Some(user_id) {
        return Err(ApiError::NotFound);
    }
    state.store().archive_wallet(id).await?;
    let updated = state.store().get_wallet(id).await?;
    Ok(Envelope::ok(to_view(updated)))
}

/// `PATCH /v1/wallets/:id/unarchive` — unarchive a wallet (dashboard login only).
pub async fn unarchive_wallet(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<WalletView>>> {
    let user_id = authenticate(&headers, &state).await?;
    let wallet = state.store().get_wallet(id).await?;
    if wallet.user_id != Some(user_id) {
        return Err(ApiError::NotFound);
    }
    state.store().unarchive_wallet(id).await?;
    let updated = state.store().get_wallet(id).await?;
    Ok(Envelope::ok(to_view(updated)))
}

/// Guard check ensuring a wallet is not archived before executing a mutating operation.
pub fn ensure_wallet_not_archived(wallet: &octo_store::Wallet) -> ApiResult<()> {
    if wallet.is_archived() {
        return Err(ApiError::Forbidden("wallet is archived".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_responses_never_serialize_sealed_seed_fields() {
        let id = Uuid::nil();
        let wallet = WalletView {
            id,
            network: "testnet".into(),
            address: "Gaddress".into(),
            custody: "client".into(),
            label: None,
            description: None,
        };
        let responses = [
            serde_json::to_string(&CreateWalletResponse {
                id,
                network: "testnet".into(),
                address: "Gaddress".into(),
                custody: "client".into(),
                funded: false,
            })
            .unwrap(),
            serde_json::to_string(&wallet).unwrap(),
            serde_json::to_string(&WalletListResponse {
                data: vec![wallet],
                next_cursor: None,
            })
            .unwrap(),
            serde_json::to_string(&GasTankView {
                wallet_id: id,
                gas_tank_address: "Ggas-tank".into(),
                funded: false,
            })
            .unwrap(),
        ];

        for response in responses {
            for field in [
                "sealed_ciphertext",
                "sealed_nonce",
                "sealed_salt",
                "sealed_scheme",
            ] {
                assert!(
                    !response.contains(field),
                    "wallet response must not include {field}"
                );
            }
        }
    }
}
}
