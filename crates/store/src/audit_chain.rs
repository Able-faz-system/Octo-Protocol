//! Tamper-evident audit log: a per-user HMAC-SHA256 hash chain over `audit_logs` (migration 0029).
//!
//! Each row's `row_hash` is `HMAC(key, prev_hash || fields)`, and `audit_chain_heads` pins the
//! newest link under its own MAC. The key lives outside the database, so a DB-only attacker can't
//! forge links: editing a row breaks its hash, deleting one leaves a `seq` gap, and deleting from
//! the end disagrees with the head. Appends are serialized per user with a transaction-scoped
//! advisory lock, so concurrent writers produce one linear chain. Limitations: see
//! `docs/audit-log.md`.

use crate::{Store, StoreError};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Length of the audit chain HMAC key, in bytes.
pub const AUDIT_CHAIN_KEY_LEN: usize = 32;

/// `prev_hash` of the first row in every user's chain.
const GENESIS_PREV_HASH: [u8; 32] = [0u8; 32];
/// Domain separators so a row MAC can never be replayed as a head MAC (or vice versa).
const ROW_DOMAIN: &[u8] = b"octo/audit-row/v1";
const HEAD_DOMAIN: &[u8] = b"octo/audit-head/v1";
/// Advisory-lock namespace ("AUDT"), keeping the per-user lock clear of any other lock users.
const LOCK_NAMESPACE: i32 = 0x4155_4454;
/// Rows fetched per verification round trip.
const VERIFY_BATCH: i64 = 1000;

/// Secret HMAC key for the audit chain (`AUDIT_CHAIN_KEY`). Zeroized on drop, redacted in `Debug`.
#[derive(Clone)]
pub struct AuditChainKey(Zeroizing<[u8; AUDIT_CHAIN_KEY_LEN]>);

impl AuditChainKey {
    pub fn new(key: Zeroizing<[u8; AUDIT_CHAIN_KEY_LEN]>) -> Self {
        Self(key)
    }

    fn mac(&self) -> HmacSha256 {
        <HmacSha256 as Mac>::new_from_slice(&self.0[..]).expect("HMAC accepts any key length")
    }
}

impl std::fmt::Debug for AuditChainKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuditChainKey(<redacted>)")
    }
}

/// Outcome of verifying one user's chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditChainStatus {
    /// Every row links correctly and the last row matches the head.
    Intact,
    /// The user has only rows written before chaining existed; nothing to verify yet.
    Unchained,
    /// Verification failed. `seq` is the first chain position that failed, when there is one.
    Broken {
        seq: Option<i64>,
        reason: &'static str,
    },
}

/// Per-user verification result.
#[derive(Debug, Clone)]
pub struct AuditChainReport {
    pub user_id: Uuid,
    pub rows_verified: u64,
    pub unchained_rows: u64,
    pub status: AuditChainStatus,
}

/// The hashed fields of one audit row.
struct LinkFields<'a> {
    id: Uuid,
    user_id: Uuid,
    seq: i64,
    action: &'a str,
    category: &'a str,
    target: Option<&'a str>,
    ip_address: Option<&'a str>,
    created_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct ChainRow {
    id: Uuid,
    user_id: Uuid,
    seq: i64,
    prev_hash: Option<Vec<u8>>,
    row_hash: Option<Vec<u8>>,
    action: String,
    category: String,
    target: Option<String>,
    ip_address: Option<String>,
    created_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct LegacyRow {
    id: Uuid,
    action: String,
    category: String,
    target: Option<String>,
    ip_address: Option<String>,
    created_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct HeadRow {
    seq: i64,
    row_hash: Vec<u8>,
    head_mac: Vec<u8>,
}

/// Length-prefixed string, so field boundaries can't be shifted between adjacent fields.
fn put_str(mac: &mut HmacSha256, s: &str) {
    mac.update(&(s.len() as u64).to_be_bytes());
    mac.update(s.as_bytes());
}

/// Tagged optional string, so `None` and `Some("")` hash differently.
fn put_opt(mac: &mut HmacSha256, s: Option<&str>) {
    match s {
        None => mac.update(&[0]),
        Some(s) => {
            mac.update(&[1]);
            put_str(mac, s);
        }
    }
}

fn finish(mac: HmacSha256) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

fn row_hash(key: &AuditChainKey, prev_hash: &[u8; 32], f: &LinkFields<'_>) -> [u8; 32] {
    let mut mac = key.mac();
    mac.update(ROW_DOMAIN);
    mac.update(prev_hash);
    mac.update(f.id.as_bytes());
    mac.update(f.user_id.as_bytes());
    mac.update(&f.seq.to_be_bytes());
    // Postgres stores microseconds, so that is the precision that round-trips.
    mac.update(&f.created_at.timestamp_micros().to_be_bytes());
    put_str(&mut mac, f.action);
    put_str(&mut mac, f.category);
    put_opt(&mut mac, f.target);
    put_opt(&mut mac, f.ip_address);
    finish(mac)
}

fn head_mac(key: &AuditChainKey, user_id: Uuid, seq: i64, row_hash: &[u8; 32]) -> [u8; 32] {
    let mut mac = key.mac();
    mac.update(HEAD_DOMAIN);
    mac.update(user_id.as_bytes());
    mac.update(&seq.to_be_bytes());
    mac.update(row_hash);
    finish(mac)
}

fn to_hash(bytes: &[u8]) -> Option<[u8; 32]> {
    bytes.try_into().ok()
}

/// Truncate to the microsecond precision Postgres keeps, so the hashed value equals the stored one.
fn now_micros() -> DateTime<Utc> {
    let now = Utc::now();
    DateTime::from_timestamp_micros(now.timestamp_micros()).unwrap_or(now)
}

impl HeadRow {
    /// The head's `(seq, row_hash)` if its MAC checks out.
    fn verified(&self, key: &AuditChainKey, user_id: Uuid) -> Option<(i64, [u8; 32])> {
        let hash = to_hash(&self.row_hash)?;
        (head_mac(key, user_id, self.seq, &hash).as_slice() == self.head_mac.as_slice())
            .then_some((self.seq, hash))
    }
}

impl Store {
    /// Append an audit-log entry to the user's hash chain. Best-effort: failures are surfaced to
    /// the caller, which logs and continues (auditing must never block the primary operation).
    ///
    /// Refuses with [`StoreError::AuditChainCorrupt`] when the chain head is missing or fails its
    /// MAC — appending would otherwise sign over the tampering and hide it.
    pub async fn record_audit(
        &self,
        key: &AuditChainKey,
        user_id: Uuid,
        action: &str,
        category: &str,
        target: Option<&str>,
        ip_address: Option<&str>,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        // Serialize appends per user, so seq and prev_hash are assigned in one linear order.
        sqlx::query("SELECT pg_advisory_xact_lock($1, hashtext($2::text))")
            .bind(LOCK_NAMESPACE)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;

        let (tip_seq, prev) = chain_tip(&mut tx, key, user_id).await?;
        let seq = tip_seq + 1;
        let id = Uuid::new_v4();
        let created_at = now_micros();
        let hash = row_hash(
            key,
            &prev,
            &LinkFields {
                id,
                user_id,
                seq,
                action,
                category,
                target,
                ip_address,
                created_at,
            },
        );
        sqlx::query(
            "INSERT INTO audit_logs
                 (id, user_id, action, category, target, ip_address, created_at,
                  seq, prev_hash, row_hash)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(id)
        .bind(user_id)
        .bind(action)
        .bind(category)
        .bind(target)
        .bind(ip_address)
        .bind(created_at)
        .bind(seq)
        .bind(prev.as_slice())
        .bind(hash.as_slice())
        .execute(&mut *tx)
        .await?;

        write_head(&mut tx, key, user_id, seq, &hash).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Verify one user's audit chain end to end, in batches of [`VERIFY_BATCH`] rows.
    pub async fn verify_audit_chain(
        &self,
        key: &AuditChainKey,
        user_id: Uuid,
    ) -> Result<AuditChainReport, StoreError> {
        let unchained: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_logs WHERE user_id = $1 AND seq IS NULL",
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;
        let mut report = AuditChainReport {
            user_id,
            rows_verified: 0,
            unchained_rows: u64::try_from(unchained).unwrap_or(0),
            status: AuditChainStatus::Intact,
        };
        let broken = |seq, reason| AuditChainStatus::Broken { seq, reason };

        let mut last_seq = 0i64;
        let mut prev = GENESIS_PREV_HASH;
        loop {
            let rows = sqlx::query_as::<_, ChainRow>(
                "SELECT id, user_id, seq, prev_hash, row_hash, action, category, target,
                        ip_address, created_at
                 FROM audit_logs
                 WHERE user_id = $1 AND seq > $2
                 ORDER BY seq
                 LIMIT $3",
            )
            .bind(user_id)
            .bind(last_seq)
            .bind(VERIFY_BATCH)
            .fetch_all(&self.pool)
            .await?;
            if rows.is_empty() {
                break;
            }
            for row in &rows {
                let expected = last_seq + 1;
                if row.seq != expected {
                    report.status = broken(Some(expected), "row missing (sequence gap)");
                    return Ok(report);
                }
                if row.prev_hash.as_deref().and_then(to_hash) != Some(prev) {
                    report.status = broken(Some(row.seq), "prev_hash does not link to prior row");
                    return Ok(report);
                }
                let recomputed = row_hash(
                    key,
                    &prev,
                    &LinkFields {
                        id: row.id,
                        user_id: row.user_id,
                        seq: row.seq,
                        action: &row.action,
                        category: &row.category,
                        target: row.target.as_deref(),
                        ip_address: row.ip_address.as_deref(),
                        created_at: row.created_at,
                    },
                );
                if row.row_hash.as_deref().and_then(to_hash) != Some(recomputed) {
                    report.status = broken(Some(row.seq), "row hash mismatch (row was edited)");
                    return Ok(report);
                }
                prev = recomputed;
                last_seq = row.seq;
                report.rows_verified += 1;
            }
        }

        let head = sqlx::query_as::<_, HeadRow>(
            "SELECT seq, row_hash, head_mac FROM audit_chain_heads WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        report.status = match (head, last_seq) {
            (None, 0) if report.unchained_rows > 0 => AuditChainStatus::Unchained,
            (None, 0) => AuditChainStatus::Intact,
            (None, _) => broken(None, "chain head missing"),
            (Some(head), _) => match head.verified(key, user_id) {
                None => broken(None, "chain head MAC invalid"),
                Some((seq, _)) if seq > last_seq => {
                    broken(Some(last_seq + 1), "rows deleted from the end of the chain")
                }
                Some((seq, hash)) if seq < last_seq || hash != prev => {
                    broken(Some(seq), "chain head does not match the last row")
                }
                Some(_) if report.unchained_rows > 0 => {
                    broken(None, "unchained rows present after the chain started")
                }
                Some(_) => AuditChainStatus::Intact,
            },
        };
        Ok(report)
    }

    /// Verify every user's audit chain. Used by `octo-server verify-audit-chain`.
    pub async fn verify_all_audit_chains(
        &self,
        key: &AuditChainKey,
    ) -> Result<Vec<AuditChainReport>, StoreError> {
        let user_ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT user_id FROM audit_logs UNION SELECT user_id FROM audit_chain_heads
             ORDER BY 1",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut reports = Vec::with_capacity(user_ids.len());
        for user_id in user_ids {
            reports.push(self.verify_audit_chain(key, user_id).await?);
        }
        Ok(reports)
    }
}

/// The `(seq, row_hash)` to append after. Starts a new chain (adopting pre-0026 rows) when the
/// user has none, and refuses to extend a chain whose head is missing or forged.
async fn chain_tip(
    tx: &mut Transaction<'_, Postgres>,
    key: &AuditChainKey,
    user_id: Uuid,
) -> Result<(i64, [u8; 32]), StoreError> {
    let head = sqlx::query_as::<_, HeadRow>(
        "SELECT seq, row_hash, head_mac FROM audit_chain_heads WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(head) = head {
        return head.verified(key, user_id).ok_or(StoreError::AuditChainCorrupt);
    }

    let chained: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM audit_logs WHERE user_id = $1 AND seq IS NOT NULL)",
    )
    .bind(user_id)
    .fetch_one(&mut **tx)
    .await?;
    if chained {
        return Err(StoreError::AuditChainCorrupt);
    }
    adopt_legacy_rows(tx, key, user_id).await
}

/// Chain a user's pre-0026 rows in `(created_at, id)` order. Runs once, when their chain starts.
async fn adopt_legacy_rows(
    tx: &mut Transaction<'_, Postgres>,
    key: &AuditChainKey,
    user_id: Uuid,
) -> Result<(i64, [u8; 32]), StoreError> {
    let legacy = sqlx::query_as::<_, LegacyRow>(
        "SELECT id, action, category, target, ip_address, created_at
         FROM audit_logs
         WHERE user_id = $1 AND seq IS NULL
         ORDER BY created_at, id
         FOR UPDATE",
    )
    .bind(user_id)
    .fetch_all(&mut **tx)
    .await?;

    let mut seq = 0i64;
    let mut prev = GENESIS_PREV_HASH;
    for row in &legacy {
        seq += 1;
        let hash = row_hash(
            key,
            &prev,
            &LinkFields {
                id: row.id,
                user_id,
                seq,
                action: &row.action,
                category: &row.category,
                target: row.target.as_deref(),
                ip_address: row.ip_address.as_deref(),
                created_at: row.created_at,
            },
        );
        sqlx::query("UPDATE audit_logs SET seq = $2, prev_hash = $3, row_hash = $4 WHERE id = $1")
            .bind(row.id)
            .bind(seq)
            .bind(prev.as_slice())
            .bind(hash.as_slice())
            .execute(&mut **tx)
            .await?;
        prev = hash;
    }
    Ok((seq, prev))
}

/// Upsert the user's chain head to `(seq, row_hash)` under a fresh head MAC.
async fn write_head(
    tx: &mut Transaction<'_, Postgres>,
    key: &AuditChainKey,
    user_id: Uuid,
    seq: i64,
    row_hash: &[u8; 32],
) -> Result<(), StoreError> {
    let mac = head_mac(key, user_id, seq, row_hash);
    sqlx::query(
        "INSERT INTO audit_chain_heads (user_id, seq, row_hash, head_mac, updated_at)
         VALUES ($1, $2, $3, $4, now())
         ON CONFLICT (user_id) DO UPDATE
         SET seq = EXCLUDED.seq, row_hash = EXCLUDED.row_hash,
             head_mac = EXCLUDED.head_mac, updated_at = now()",
    )
    .bind(user_id)
    .bind(seq)
    .bind(row_hash.as_slice())
    .bind(mac.as_slice())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

