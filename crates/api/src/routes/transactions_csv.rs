//! `GET /v1/wallets/:id/transactions.csv` — streamed accounting export of transaction history.
//!
//! Rows are fetched in keyset batches of [`BATCH_SIZE`] and written as they are read, so memory
//! stays bounded by one batch however large the history is, and no database connection is held
//! between batches (a slow client can't pin a pool connection). Text cells are neutralised
//! against spreadsheet formula injection before RFC 4180 quoting.

use crate::auth::authorize_wallet;
use crate::error::{ApiError, ApiResult};
use crate::routes::wallets::TransactionFilterParams;
use crate::state::AppState;
use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use octo_store::{Store, Transaction, TransactionFilter};
use uuid::Uuid;

/// Rows per database round-trip; also the upper bound on rows held in memory at once.
const BATCH_SIZE: i64 = 500;

const HEADER_ROW: &str = "id,created_at,direction,status,asset_code,asset_issuer,amount_stroops,\
source_account,destination_account,stellar_tx_hash,operation_index,ledger,memo_id,address_id,\
reference\r\n";

/// `GET /v1/wallets/:id/transactions.csv` — same auth and filters as the JSON history endpoint.
pub async fn export_transactions_csv(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Query(f): Query<TransactionFilterParams>,
) -> ApiResult<Response> {
    // Identical authorization to `list_transactions` (login owner or read-scoped API key).
    authorize_wallet(&headers, &state, id).await?;
    let _ = state.store().get_wallet(id).await?;
    let filter = f.validate()?;

    // Exports scan the whole history, so cap how often one wallet can start them.
    if !state
        .rate_limiter()
        .check(
            &format!("csv_export:{id}"),
            "csv_export",
            crate::rate_limit::CSV_EXPORT_LIMIT,
            crate::rate_limit::CSV_EXPORT_WINDOW,
        )
        .await
    {
        return Err(ApiError::TooManyRequests(
            "too many exports — wait a minute and try again".into(),
        ));
    }

    let body = Body::from_stream(csv_stream(state.store().clone(), id, filter));
    let mut resp = body.into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    // The wallet id is a UUID, so the filename needs no escaping.
    if let Ok(v) = HeaderValue::from_str(&format!(
        "attachment; filename=\"transactions-{id}.csv\""
    )) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    // Financial records must not linger in shared or browser caches.
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(resp)
}

/// Where the export is: header not yet sent, mid-history after a cursor, or finished.
enum Cursor {
    Start,
    After(Option<Uuid>),
    Done,
}

/// Lazily yield the header then one CSV chunk per batch; only polled as the client reads.
fn csv_stream(
    store: Store,
    wallet_id: Uuid,
    filter: TransactionFilter,
) -> impl futures_util::Stream<Item = Result<Bytes, std::io::Error>> {
    futures_util::stream::unfold(Cursor::Start, move |cursor| {
        let store = store.clone();
        let filter = filter.clone();
        async move {
            let before = match cursor {
                Cursor::Start => {
                    let header = Bytes::from_static(HEADER_ROW.as_bytes());
                    return Some((Ok(header), Cursor::After(None)));
                }
                Cursor::After(before) => before,
                Cursor::Done => return None,
            };
            let rows = match store
                .list_transactions_page(wallet_id, &filter, BATCH_SIZE, before)
                .await
            {
                Ok(rows) => rows,
                // Headers are already sent: abort the body so the client sees a broken download,
                // never a silently truncated file that looks complete.
                Err(e) => {
                    tracing::warn!(wallet = %wallet_id, error = ?e, "csv export batch failed");
                    let err = std::io::Error::other("export aborted");
                    return Some((Err(err), Cursor::Done));
                }
            };
            let last = rows.last()?.id;
            let next = if (rows.len() as i64) < BATCH_SIZE {
                Cursor::Done
            } else {
                Cursor::After(Some(last))
            };
            let mut chunk = String::with_capacity(rows.len() * 256);
            for tx in &rows {
                write_row(&mut chunk, tx);
            }
            Some((Ok(Bytes::from(chunk)), next))
        }
    })
}

/// Append one transaction as a CSV record (CRLF-terminated, RFC 4180).
fn write_row(out: &mut String, tx: &Transaction) {
    let num = |n: Option<i64>| n.map(|v| v.to_string()).unwrap_or_default();
    let cells = [
        tx.id.to_string(),
        tx.created_at.to_rfc3339(),
        text_cell(&tx.direction),
        text_cell(&tx.status),
        text_cell(&tx.asset_code),
        text_cell(tx.asset_issuer.as_deref().unwrap_or("")),
        tx.amount_stroops.to_string(),
        text_cell(tx.source_account.as_deref().unwrap_or("")),
        text_cell(tx.destination_account.as_deref().unwrap_or("")),
        text_cell(tx.stellar_tx_hash.as_deref().unwrap_or("")),
        num(tx.operation_index.map(i64::from)),
        num(tx.ledger),
        num(tx.memo_id),
        tx.address_id.map(|a| a.to_string()).unwrap_or_default(),
        text_cell(tx.reference.as_deref().unwrap_or("")),
    ];
    out.push_str(&cells.join(","));
    out.push_str("\r\n");
}

/// Neutralise formula injection, then quote if the value needs it.
///
/// A text cell starting with `=`, `+`, `-`, `@` (or tab / carriage return, which some
/// spreadsheets strip before evaluating) is prefixed with `'` so it is shown as text and never
/// executed. Only free-text columns go through here; numeric columns are written as numbers.
pub(crate) fn text_cell(value: &str) -> String {
    let neutralised = match value.chars().next() {
        Some('=' | '+' | '-' | '@' | '\t' | '\r') => format!("'{value}"),
        _ => value.to_string(),
    };
    if neutralised.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", neutralised.replace('"', "\"\""))
    } else {
        neutralised
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formula_prefixes_are_escaped() {
        for raw in ["=HYPERLINK(\"x\")", "+1+1", "-2+3", "@SUM(A1)", "\tcmd", "\rcmd"] {
            let cell = text_cell(raw);
            let unquoted = cell.trim_start_matches('"');
            assert!(unquoted.starts_with('\''), "{raw:?} was not neutralised: {cell}");
        }
    }

    #[test]
    fn plain_values_pass_through() {
        assert_eq!(text_cell("USDC"), "USDC");
        assert_eq!(text_cell(""), "");
    }

    #[test]
    fn delimiters_and_quotes_are_quoted() {
        assert_eq!(text_cell("a,b"), "\"a,b\"");
        assert_eq!(text_cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(text_cell("=a,b"), "\"'=a,b\"");
    }
}
