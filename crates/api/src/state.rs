//! Shared application state: DB handle, master key, network, and Horizon config.

use crate::error::ApiError;
use crate::horizon::Horizon;
use base64::Engine;
use octo_crypto::{CryptoError, MASTER_KEY_LEN};
use octo_email::EmailSender;
use octo_resilience::{CircuitBreaker, RetryPolicy};
use octo_store::{AuditChainKey, Store, AUDIT_CHAIN_KEY_LEN};
use octo_wallet_core::StellarNetwork;
use octo_webhooks::WebhookSender;
use std::sync::Arc;
use std::{fmt, fmt::Formatter};
use zeroize::Zeroizing;

/// Cloneable, shared API state.
#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

impl fmt::Debug for AppState {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppState")
            .field("network", &self.inner.network)
            .field("horizon_url", &self.inner.horizon_url)
            .field("friendbot_url", &self.inner.friendbot_url)
            .field("public_app_url", &self.inner.public_app_url)
            .field("public_api_host", &self.inner.public_api_host)
            .field("master_key", &"[REDACTED]")
            .field("master_key_next", &self.inner.master_key_next.as_ref().map(|_| "[REDACTED]"))
            .field("jwt_secret", &"[REDACTED]")
            .field("cloudinary", &self.inner.cloudinary.as_ref().map(|_| "[REDACTED]"))
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct Inner {
    store: Store,
    /// AES-256 master key used to seal/open seeds. Held zeroized.
    master_key: Zeroizing<[u8; MASTER_KEY_LEN]>,
    /// Optional next master key present only during a rotation window.
    /// When set, the server seals new records under it, tries it first when opening (for
    /// already-migrated rows), and falls back to `master_key` for rows not yet re-sealed.
    master_key_next: Option<Zeroizing<[u8; MASTER_KEY_LEN]>>,
    network: StellarNetwork,
    horizon: Horizon,
    horizon_url: String,
    friendbot_url: Option<String>,
    /// Base URL of the hosted checkout frontend, used to build the `url` field on payment-link
    /// responses (e.g. `https://app.octo.dev/pay/<slug>`). No trailing slash.
    public_app_url: String,
    /// Hostname of the API's public base URL, used to reject direct self-referential webhooks.
    public_api_host: Option<String>,
    /// HMAC secret for signing dashboard auth JWTs.
    jwt_secret: Vec<u8>,
    /// HMAC key for the tamper-evident audit chain (`AUDIT_CHAIN_KEY`).
    audit_chain_key: AuditChainKey,
    /// Fires signed webhooks (e.g. `transaction.sponsored`) to registered endpoints.
    webhooks: WebhookSender,
    /// Sends OTP/welcome/withdrawal emails via Resend.
    email: EmailSender,
    /// Rate limiting for auth + public endpoints (in-memory or shared via Postgres).
    rate_limiter: crate::rate_limit::RateLimiter,
    /// Cloudinary credentials for signed image uploads; `None` when unconfigured, in which case
    /// the upload endpoint reports that the feature is off rather than failing obscurely.
    cloudinary: Option<CloudinaryConfig>,
}

/// Cloudinary credentials, read from the environment at startup.
#[derive(Clone)]
pub struct CloudinaryConfig {
    pub cloud_name: String,
    pub api_key: String,
    pub api_secret: String,
}

impl CloudinaryConfig {
    /// Read from `CLOUDINARY_CLOUD_NAME` / `CLOUDINARY_API_KEY` / `CLOUDINARY_API_SECRET`.
    /// All three must be present, or image uploads stay disabled.
    fn from_env() -> Option<Self> {
        let cloud_name = std::env::var("CLOUDINARY_CLOUD_NAME").ok()?;
        let api_key = std::env::var("CLOUDINARY_API_KEY").ok()?;
        let api_secret = std::env::var("CLOUDINARY_API_SECRET").ok()?;
        if cloud_name.is_empty() || api_key.is_empty() || api_secret.is_empty() {
            return None;
        }
        Some(Self {
            cloud_name,
            api_key,
            api_secret,
        })
    }
}

impl AppState {
    /// Build state. The JWT secret defaults to a random per-process value (fine for tests/dev;
    /// tokens won't survive a restart). Use [`AppState::with_jwt_secret`] in production.
    pub fn new(
        store: Store,
        master_key: [u8; MASTER_KEY_LEN],
        network: StellarNetwork,
        horizon_url: String,
        friendbot_url: Option<String>,
        email: EmailSender,
    ) -> Self {
        let mut secret = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret);
        Self::build(
            store,
            Zeroizing::new(master_key),
            None,
            network,
            horizon_url,
            friendbot_url,
            "http://localhost:3000".to_string(),
            email,
            secret,
            octo_resilience::RetryPolicy::default(),
            octo_resilience::CircuitBreaker::new(5, std::time::Duration::from_secs(30)),
        )
    }

    /// Build state with explicit resilience configuration (used by `bin/server`). Takes the
    /// master key already zeroizing, so no plain copy of it is left behind on the caller's stack.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_resilience(
        store: Store,
        master_key: Zeroizing<[u8; MASTER_KEY_LEN]>,
        network: StellarNetwork,
        horizon_url: String,
        friendbot_url: Option<String>,
        public_app_url: String,
        email: EmailSender,
        retry: octo_resilience::RetryPolicy,
        circuit: octo_resilience::CircuitBreaker,
    ) -> Self {
        let mut secret = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret);
        Self::build(
            store,
            master_key,
            None,
            network,
            horizon_url,
            friendbot_url,
            public_app_url,
            email,
            secret,
            retry,
            circuit,
        )
    }

    /// Set the JWT signing secret (e.g. from the `JWT_SECRET` env var) so tokens survive restarts.
    pub fn with_jwt_secret(mut self, secret: Vec<u8>) -> Self {
        // Arc is unique here in practice (called right after `new`), so rebuild the inner.
        let inner = Arc::make_mut(&mut self.inner);
        inner.jwt_secret = secret;
        self
    }

    /// Swap the rate-limit backend (defaults to per-process memory; use Postgres with replicas).
    pub fn with_rate_limiter(mut self, limiter: crate::rate_limit::RateLimiter) -> Self {
        Arc::make_mut(&mut self.inner).rate_limiter = limiter;
        self
    }

    /// Set the audit chain HMAC key (from `AUDIT_CHAIN_KEY`). Without it a random per-process key
    /// is used, which is fine for tests but breaks verification of chains across restarts.
    pub fn with_audit_chain_key(mut self, key: AuditChainKey) -> Self {
        Arc::make_mut(&mut self.inner).audit_chain_key = key;
        self
    }

    /// Configure the public API URL used to block direct webhook callbacks to this API.
    pub fn with_public_api_url(mut self, url: Option<&str>) -> Result<Self, &'static str> {
        let host = url
            .map(|url| {
                let parsed = url::Url::parse(url)
                    .map_err(|_| "PUBLIC_API_URL must be an absolute URL")?;
                if !matches!(parsed.scheme(), "http" | "https") {
                    return Err("PUBLIC_API_URL must use http or https");
                }
                parsed
                    .host_str()
                    .map(str::to_ascii_lowercase)
                    .ok_or("PUBLIC_API_URL must include a hostname")
            })
            .transpose()?;
        Arc::make_mut(&mut self.inner).public_api_host = host;
        Ok(self)
    }

    /// Set the next master key for zero-downtime key rotation.
    /// When set, new records are sealed under it and existing records are opened by trying it
    /// first, then `master_key` (see [`AppState::opening_keys`]).
    pub fn with_master_key_next(mut self, key: Zeroizing<[u8; MASTER_KEY_LEN]>) -> Self {
        let inner = Arc::make_mut(&mut self.inner);
        inner.master_key_next = Some(key);
        self
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        store: Store,
        master_key: Zeroizing<[u8; MASTER_KEY_LEN]>,
        master_key_next: Option<Zeroizing<[u8; MASTER_KEY_LEN]>>,
        network: StellarNetwork,
        horizon_url: String,
        friendbot_url: Option<String>,
        public_app_url: String,
        email: EmailSender,
        jwt_secret: Vec<u8>,
        retry: RetryPolicy,
        circuit: CircuitBreaker,
    ) -> Self {
        let horizon = Horizon::with_resilience(horizon_url.clone(), retry, circuit);
        let webhooks = WebhookSender::new(store.clone());
        let mut audit_key = Zeroizing::new([0u8; AUDIT_CHAIN_KEY_LEN]);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut audit_key[..]);
        Self {
            inner: Arc::new(Inner {
                rate_limiter: crate::rate_limit::RateLimiter::default(),
                cloudinary: CloudinaryConfig::from_env(),
                store,
                master_key,
                master_key_next,
                network,
                horizon,
                horizon_url,
                friendbot_url,
                public_app_url,
                public_api_host: None,
                jwt_secret,
                audit_chain_key: AuditChainKey::new(audit_key),
                webhooks,
                email,
            }),
        }
    }

    /// Decode a base64 32-byte key (from KMS/env). The decode buffer and the result are both
    /// zeroizing, so no intermediate copy of the key outlives this call.
    pub fn decode_master_key(b64: &str) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, ApiError> {
        // Sized above any valid input (44 chars → 32 bytes) so the decoder never reallocates.
        let mut raw = Zeroizing::new([0u8; 48]);
        let len = base64::engine::general_purpose::STANDARD
            .decode_slice(b64.trim(), &mut raw[..])
            .map_err(|_| ApiError::BadRequest("invalid MASTER_KEY (base64)".into()))?;
        if len != MASTER_KEY_LEN {
            let error = CryptoError::InvalidMasterKeyLength {
                expected: MASTER_KEY_LEN,
                actual: len,
            };
            return Err(ApiError::BadRequest(error.to_string()));
        }
        // Copy straight into the zeroizing result; a by-value array would leave a stack copy.
        let mut key = Zeroizing::new([0u8; MASTER_KEY_LEN]);
        key.copy_from_slice(&raw[..len]);
        Ok(key)
    }

    pub fn store(&self) -> &Store {
        &self.inner.store
    }

    pub fn rate_limiter(&self) -> &crate::rate_limit::RateLimiter {
        &self.inner.rate_limiter
    }

    /// Cloudinary credentials, or `None` when image uploads are not configured.
    pub fn cloudinary(&self) -> Option<CloudinaryConfig> {
        self.inner.cloudinary.clone()
    }

    pub fn master_key(&self) -> &[u8; MASTER_KEY_LEN] {
        &self.inner.master_key
    }

    /// Return the next master key, if one is configured for a rotation window.
    pub fn master_key_next(&self) -> Option<&[u8; MASTER_KEY_LEN]> {
        self.inner.master_key_next.as_deref()
    }

    /// Key to seal *new* records under: the next key during a rotation window, so fresh rows
    /// never need migrating; otherwise the current key.
    pub fn sealing_key(&self) -> &[u8; MASTER_KEY_LEN] {
        self.inner
            .master_key_next
            .as_deref()
            .unwrap_or(&self.inner.master_key)
    }

    /// Keys to try when opening a sealed record, newest first.
    ///
    /// Every V1 record carries the same scheme tag whichever key sealed it, so the tag cannot
    /// pick the key. AES-GCM authentication does: a wrong key fails cleanly, and the caller
    /// moves on to the next one. Migrated rows open under the next key, un-migrated rows under
    /// the current one.
    pub fn opening_keys(&self) -> impl Iterator<Item = &[u8; MASTER_KEY_LEN]> {
        self.inner
            .master_key_next
            .as_deref()
            .into_iter()
            .chain(std::iter::once(&*self.inner.master_key))
    }

    pub fn audit_chain_key(&self) -> &AuditChainKey {
        &self.inner.audit_chain_key
    }

    pub fn jwt_secret(&self) -> &[u8] {
        &self.inner.jwt_secret
    }

    pub fn network(&self) -> StellarNetwork {
        self.inner.network
    }

    pub fn horizon(&self) -> &Horizon {
        &self.inner.horizon
    }

    pub fn webhooks(&self) -> &WebhookSender {
        &self.inner.webhooks
    }

    pub fn email(&self) -> &EmailSender {
        &self.inner.email
    }

    pub fn horizon_url(&self) -> &str {
        &self.inner.horizon_url
    }

    pub fn friendbot_url(&self) -> Option<&str> {
        self.inner.friendbot_url.as_deref()
    }

    /// Base URL of the hosted checkout frontend (no trailing slash).
    pub fn public_app_url(&self) -> &str {
        &self.inner.public_app_url
    }

    pub fn public_api_host(&self) -> Option<&str> {
        self.inner.public_api_host.as_deref()
    }
}
