//! Login sessions: list them and revoke one or all others (e.g. after a suspected compromise).
//!
//! Every route requires a dashboard login (API keys are rejected) and is scoped to the caller's
//! own sessions: another user's session id is indistinguishable from one that doesn't exist.
//! Revocation takes effect on the revoked token's very next request (see `auth::authenticate`).

use crate::auth::{continue_session, require_login_session};
use crate::error::{ApiError, ApiResult, Envelope};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct SessionView {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// SHA-256 hex of the User-Agent that signed in, for telling devices apart.
    pub user_agent_hash: Option<String>,
    /// True for the session making this request.
    pub current: bool,
}

#[derive(Debug, Serialize)]
pub struct RevokeOthersResponse {
    /// Replacement token for the current session; the presented one is no longer valid.
    pub token: String,
    pub revoked: u64,
}

/// `GET /v1/auth/sessions` — the caller's live sessions, most recently used first.
pub async fn list_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<Vec<SessionView>>>> {
    let caller = require_login_session(&headers, &state).await?;
    let rows = state
        .store()
        .list_active_sessions(caller.user_id)
        .await
        .map_err(|_| ApiError::Internal)?;
    let views = rows
        .into_iter()
        .map(|s| SessionView {
            current: caller.session_id == Some(s.id),
            id: s.id,
            created_at: s.created_at,
            last_seen_at: s.last_seen_at,
            expires_at: s.expires_at,
            user_agent_hash: s.user_agent_hash,
        })
        .collect();
    Ok(Envelope::ok(views))
}

/// `DELETE /v1/auth/sessions/:id` — revoke one of the caller's sessions (may be the current one).
pub async fn revoke_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<Uuid>,
) -> ApiResult<Json<Envelope<serde_json::Value>>> {
    let caller = require_login_session(&headers, &state).await?;
    let revoked = state
        .store()
        .revoke_session(caller.user_id, session_id)
        .await
        .map_err(|_| ApiError::Internal)?;
    // Unknown, already revoked, and someone else's all look the same.
    if !revoked {
        return Err(ApiError::NotFound);
    }
    crate::audit::record(
        &state,
        caller.user_id,
        "revoked a session",
        crate::audit::category::AUTH,
        Some(&session_id.to_string()),
        &headers,
    )
    .await;
    Ok(Envelope::ok(serde_json::json!({ "revoked": true })))
}

/// `POST /v1/auth/sessions/revoke-others` — revoke every session except the caller's, including
/// tokens issued before session tracking, and return a fresh token for the current session.
pub async fn revoke_other_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<RevokeOthersResponse>>> {
    let caller = require_login_session(&headers, &state).await?;
    let (epoch, revoked) = state
        .store()
        .revoke_other_sessions(caller.user_id, caller.session_id)
        .await
        .map_err(|_| ApiError::Internal)?;
    // The epoch bump invalidated the presented token too, so hand back its replacement.
    let token = continue_session(&state, &caller, epoch, &headers).await?;
    crate::audit::record(
        &state,
        caller.user_id,
        "revoked all other sessions",
        crate::audit::category::AUTH,
        Some(&format!("{revoked} sessions")),
        &headers,
    )
    .await;
    Ok(Envelope::ok(RevokeOthersResponse { token, revoked }))
}
