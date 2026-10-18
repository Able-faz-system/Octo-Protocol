//! Audit log listing.

use crate::auth::authenticate;
use crate::error::{ApiError, ApiResult, Envelope};
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    /// Filter by category (authentication, wallet, address, credentials, configuration).
    pub category: Option<String>,
    /// Case-insensitive search over action/target.
    pub search: Option<String>,
}

/// `GET /v1/audit-logs` — the authenticated user's activity, newest first.
pub async fn list_audit_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Json<Envelope<Vec<octo_store::AuditLog>>>> {
    let user_id = authenticate(&headers, &state).await?;
    let category = match q.category.filter(|c| !c.is_empty() && c != "all") {
        Some(cat) => {
            if !crate::audit::category::ALL.contains(&cat.as_str()) {
                return Err(ApiError::BadRequest(format!(
                    "invalid category filter '{}'; valid categories are: {}",
                    cat,
                    crate::audit::category::ALL.join(", ")
                )));
            }
            Some(cat)
        }
        None => None,
    };
    let search = q.search.filter(|s| !s.is_empty());

    let rows = state
        .store()
        .list_audit_logs(user_id, category.as_deref(), search.as_deref(), 200)
        .await
        .map_err(|_| ApiError::Internal)?;
    Ok(Envelope::ok(rows))
}
