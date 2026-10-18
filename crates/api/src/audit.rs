//! Audit logging helpers.
//!
//! Records notable account activity (sign-in, wallet/address/key creation, withdrawals). Auditing
//! is best-effort: a failure here is logged but never blocks the primary operation.

use crate::state::AppState;
use axum::http::HeaderMap;
use uuid::Uuid;

/// Audit categories (shown as colored chips in the dashboard).
pub mod category {
    pub const AUTH: &str = "authentication";
    pub const WALLET: &str = "wallet";
    pub const ADDRESS: &str = "address";
    pub const CREDENTIALS: &str = "credentials";
    pub const WEBHOOK: &str = "configuration";
    pub const PAYMENT_LINK: &str = "configuration";
    pub const WITHDRAWAL: &str = "wallet";
    pub const SPONSORSHIP: &str = "sponsorship";

    pub const ALL: &[&str] = &[AUTH, WALLET, ADDRESS, CREDENTIALS, WEBHOOK, SPONSORSHIP];
}

/// Best-effort client IP from common proxy headers (first `X-Forwarded-For`, then `X-Real-IP`).
pub fn client_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_string())
        })
}

/// Record an audit event. Never fails the caller — logs and moves on.
pub async fn record(
    state: &AppState,
    user_id: Uuid,
    action: &str,
    category: &str,
    target: Option<&str>,
    headers: &HeaderMap,
) {
    let ip = client_ip(headers);
    if let Err(e) = state
        .store()
        .record_audit(user_id, action, category, target, ip.as_deref())
        .await
    {
        tracing::warn!(error = ?e, action, "failed to record audit log");
    }
}
