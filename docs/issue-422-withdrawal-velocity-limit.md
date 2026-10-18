# Issue #422 — Daily Withdrawal Velocity Limit per Wallet

## Background

Withdrawals are currently bounded only by wallet balance and the destination allowlist. There is
no cap on how much can be withdrawn in a given time window. A compromised session or API key that
has access to an allowlisted destination can drain a wallet to zero in a single burst — without
any circuit-breaker beyond the balance itself.

The sponsorship subsystem already solves an identical problem: a configurable daily budget is
enforced atomically via an advisory lock and a conditional CTE, meaning concurrent requests
cannot race past the cap. The withdrawal velocity limit replicates that pattern directly.

### Key facts from the current codebase

- **Withdrawal entry point** — `crates/api/src/routes/submit.rs`. All outbound payments funnel
  through `relay_signed_transaction`, regardless of whether they came via the OTP-confirm flow
  or the direct `submit-signed` endpoint.
- **No cap today** — `store.record_withdrawal_transaction(...)` is a plain `INSERT` with no
  budget guard. It records history after the fact; it does not gate the submission.
- **Atomic budget pattern** — `Store::try_reserve_sponsored_transaction`
  (`crates/store/src/lib.rs`) is the reference implementation:
  1. Opens a Postgres transaction.
  2. Acquires `SELECT pg_advisory_xact_lock($lock_key)` — a wallet-scoped advisory lock so
     concurrent requests for the same wallet are serialised while other wallets are unaffected.
  3. Runs a conditional INSERT via a CTE that sums today's spend and only inserts when
     `spent.total + new_amount <= daily_cap`. `fetch_optional` returns `None` → `BudgetExceeded`
     when the guard rejects.
  4. Commits (releases the lock) before returning.
  - A bare conditional CTE is explicitly not sufficient under `READ COMMITTED`: concurrent
    transactions each see a snapshot before the others' inserts are visible, so N parallel
    requests can all pass the guard. The advisory lock is the essential serialisation primitive.
- **Lock key derivation** — `i64::from_be_bytes(b[0..8]) ^ i64::from_be_bytes(b[8..16])` over
  the wallet UUID bytes. This produces a stable, wallet-unique `i64` suitable for
  `pg_advisory_xact_lock`.
- **`transactions` table** — `record_withdrawal_transaction` inserts rows with
  `direction = 'withdrawal'`. These rows are the natural source for summing daily spend.
- **Audit log** — `crates/api/src/audit.rs`, `store.record_audit(...)`. Rejections must be
  recorded here so operators can detect anomalous bursts.

## Goal

- Add a per-wallet **daily withdrawal cap** (total stroops across the UTC calendar day) and an
  optional **per-transaction cap** (max stroops per individual withdrawal).
- Both caps are configurable per wallet; defaults are conservative.
- The check is atomic — concurrent withdrawals cannot race past either cap.
- Cap changes require OTP (reuse the existing withdrawal OTP flow) and are audit-logged.
- Rejections are audit-logged so anomalous bursts are visible to operators.

## Design

### Schema changes

```sql
-- Migration: add velocity cap config table
CREATE TABLE withdrawal_velocity_configs (
    wallet_id              UUID        PRIMARY KEY REFERENCES wallets(id),
    daily_cap_stroops      BIGINT      NOT NULL,
    per_tx_cap_stroops     BIGINT,                        -- NULL = no per-tx cap
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Migration: add a reservations table for in-flight (pre-Horizon) amounts
-- (alternative: sum from `transactions` directly — see discussion below)
CREATE TABLE withdrawal_reservations (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_id         UUID        NOT NULL REFERENCES wallets(id),
    amount_stroops    BIGINT      NOT NULL,
    tx_hash           TEXT        NOT NULL UNIQUE,
    status            TEXT        NOT NULL DEFAULT 'pending',  -- 'pending' | 'settled' | 'failed'
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX withdrawal_reservations_wallet_day
    ON withdrawal_reservations (wallet_id, created_at)
    WHERE status IN ('pending', 'settled');
```

**Why a separate reservations table?**  The existing `transactions` table records the outcome
after Horizon responds; there is a window between the velocity check and the Horizon response
where a concurrent request could see a lower-than-actual sum. A reservations table lets the
cap be held atomically during that window, exactly mirroring how `sponsored_transactions` holds
fee reservations for the sponsorship budget.

Alternatively, the daily cap can be enforced directly against `transactions` (summing
`'pending'` and `'confirmed'` rows) if a `'pending'` status row is inserted atomically before
Horizon submission and updated afterwards. Either approach works; the reservations table is
explicit and easier to prune.

### `withdrawal_velocity_configs` defaults

```rust
pub const DEFAULT_DAILY_CAP_STROOPS: i64 = 100_000_000_000; // 10 000 XLM
pub const DEFAULT_PER_TX_CAP_STROOPS: Option<i64> = Some(10_000_000_000); // 1 000 XLM
```

These are applied when no config row exists for a wallet.

### Store methods

```rust
/// Fetch a wallet's velocity config, falling back to defaults.
pub async fn get_withdrawal_velocity_config(
    &self,
    wallet_id: Uuid,
) -> Result<WithdrawalVelocityConfig, StoreError>;

/// Update a wallet's velocity config (called after OTP verification in the route handler).
pub async fn upsert_withdrawal_velocity_config(
    &self,
    wallet_id: Uuid,
    daily_cap_stroops: i64,
    per_tx_cap_stroops: Option<i64>,
) -> Result<WithdrawalVelocityConfig, StoreError>;

/// Atomically reserve `amount_stroops` against the daily cap.
///
/// Acquires a wallet-scoped advisory lock, sums today's pending+settled reservations,
/// and inserts only when `total + amount <= daily_cap`. Returns `StoreError::BudgetExceeded`
/// when the cap would be breached. `tx_hash` is the unique key for idempotency.
pub async fn try_reserve_withdrawal(
    &self,
    wallet_id: Uuid,
    amount_stroops: i64,
    tx_hash: &str,
    daily_cap_stroops: i64,
    per_tx_cap_stroops: Option<i64>,
) -> Result<WithdrawalReservation, StoreError>;

/// Mark a reservation as settled or failed after Horizon responds.
pub async fn settle_withdrawal_reservation(
    &self,
    id: Uuid,
    status: &str, // "settled" | "failed"
) -> Result<(), StoreError>;
```

#### `try_reserve_withdrawal` implementation sketch

```rust
pub async fn try_reserve_withdrawal(
    &self,
    wallet_id: Uuid,
    amount_stroops: i64,
    tx_hash: &str,
    daily_cap_stroops: i64,
    per_tx_cap_stroops: Option<i64>,
) -> Result<WithdrawalReservation, StoreError> {
    // Per-transaction cap is a cheap guard before we touch the DB.
    if let Some(per_tx) = per_tx_cap_stroops {
        if amount_stroops > per_tx {
            return Err(StoreError::BudgetExceeded);
        }
    }

    let mut tx = self.pool.begin().await?;

    // Wallet-scoped advisory lock — same derivation as sponsored_transactions.
    let lock_key = {
        let b = wallet_id.as_bytes();
        i64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
            ^ i64::from_be_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]])
    };
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(lock_key)
        .execute(&mut *tx)
        .await?;

    let row = sqlx::query_as::<_, WithdrawalReservation>(
        r#"
        WITH spent AS (
            SELECT COALESCE(SUM(amount_stroops), 0)::bigint AS total
            FROM withdrawal_reservations
            WHERE wallet_id = $1
              AND status IN ('pending', 'settled')
              AND created_at >= date_trunc('day', now() AT TIME ZONE 'UTC')
        )
        INSERT INTO withdrawal_reservations (wallet_id, amount_stroops, tx_hash)
        SELECT $1, $2, $3
        FROM spent
        WHERE spent.total + $2 <= $4
        RETURNING *
        "#,
    )
    .bind(wallet_id)
    .bind(amount_stroops)
    .bind(tx_hash)
    .bind(daily_cap_stroops)
    .fetch_optional(&mut *tx)
    .await
    .map_err(StoreError::from_sqlx_conflict)?;

    tx.commit().await?;

    row.ok_or(StoreError::BudgetExceeded)
}
```

### Changes to `relay_signed_transaction`

```
relay_signed_transaction (submit.rs)
  1. validate_signed_xdr          ← existing
  2. allowlist check              ← existing
  3. [NEW] velocity cap check     ← insert here
  4. horizon.submit_transaction   ← existing
  5. settle_withdrawal_reservation ← [NEW] after Horizon responds
  6. record_withdrawal_transaction ← existing (history)
```

```rust
// After allowlist check, before Horizon submit:
if let Some(p) = &payment {
    let cfg = state
        .store()
        .get_withdrawal_velocity_config(wallet_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let reservation = state
        .store()
        .try_reserve_withdrawal(
            wallet_id,
            p.amount_stroops,
            &precomputed_hash,
            cfg.daily_cap_stroops,
            cfg.per_tx_cap_stroops,
        )
        .await;

    match reservation {
        Ok(r) => r,
        Err(StoreError::BudgetExceeded) => {
            // Audit-log the rejection before returning.
            if let Some(uid) = audit_user {
                crate::audit::record(
                    &state, uid,
                    "withdrawal rejected — daily velocity cap exceeded",
                    crate::audit::category::WALLET,
                    Some(&p.destination),
                    &headers,
                ).await;
            }
            return Err(ApiError::BadRequest(
                "daily withdrawal cap exceeded for this wallet".into(),
            ));
        }
        Err(_) => return Err(ApiError::Internal),
    }
}
```

After Horizon responds, call `settle_withdrawal_reservation(reservation.id, status)` so the
reservation row reflects the final outcome and the daily sum stays accurate.

### Cap management endpoints

Changing the cap is a sensitive operation — an attacker who can change the cap can then drain
the wallet. Gate it behind OTP, exactly like `withdraw/confirm`.

```
POST /v1/wallets/:id/velocity-config/request-otp
POST /v1/wallets/:id/velocity-config/confirm
GET  /v1/wallets/:id/velocity-config
```

The OTP flow reuses `store.create_otp` / `store.verify_and_consume_otp` with
`purpose = "velocity_config"`. The binding key (`tx_hash_bound`) can be a canonical hash of
the proposed new config values (e.g. `sha256("{daily_cap},{per_tx_cap}")`), so the OTP is
tied to the exact change being made and cannot be replayed for a different cap value.

After OTP verification:
```rust
state.store().upsert_withdrawal_velocity_config(wallet_id, daily_cap, per_tx_cap).await?;
crate::audit::record(
    &state, user_id,
    &format!("updated withdrawal velocity config (daily_cap={daily_cap}, per_tx_cap={per_tx_cap:?})"),
    crate::audit::category::WALLET,
    None,
    &headers,
).await;
```

### Midnight rollover

The `date_trunc('day', now() AT TIME ZONE 'UTC')` predicate in the CTE resets the cap window
at UTC midnight. This is the same approach used by the sponsorship budget; no cron job or
background task is needed.

The issue requires boundary tests at the rollover. This is achievable in integration tests by
either:
- Using `SET LOCAL TIME ZONE` within a test transaction to shift the DB clock, or
- Inserting a reservation row backdated to 23:59:59 yesterday and confirming a new reservation
  at 00:00:01 today is not blocked by it.

## Implementation tasks

1. **`crates/store/migrations/`** — Add migration: `withdrawal_velocity_configs` and
   `withdrawal_reservations` tables with index.

2. **`crates/store/src/models.rs`** — Add `WithdrawalVelocityConfig` and
   `WithdrawalReservation` structs.

3. **`crates/store/src/lib.rs`** — Add `get_withdrawal_velocity_config`,
   `upsert_withdrawal_velocity_config`, `try_reserve_withdrawal`, and
   `settle_withdrawal_reservation`.

4. **`crates/api/src/routes/submit.rs`** — Insert velocity cap check and reservation
   settlement into `relay_signed_transaction`.

5. **`crates/api/src/routes/`** — Add `velocity_config.rs` with `request_otp`, `confirm`,
   and `get_config` handlers.

6. **`crates/api/src/lib.rs`** — Register the three new velocity-config routes.

7. **`docs/api.md`** — Document `GET /v1/wallets/:id/velocity-config` and the two OTP
   mutation endpoints.

## Security considerations

- **Concurrency** — The advisory-lock + conditional-CTE approach is the only correct pattern
  under `READ COMMITTED`. Do not replace it with application-level checks.
- **Per-tx cap bypass** — Check the per-tx cap before touching the DB (it is a cheap local
  comparison). The daily cap requires the lock.
- **Cap change gating** — If a stolen session can raise the daily cap, the velocity limit
  offers no protection. The OTP gate on cap changes is mandatory, not optional.
- **Audit on rejection** — Repeated rejections indicate either a bug or an active drain attempt
  in progress; they must be in the audit log so operators can respond.
- **Failed reservations** — `settle_withdrawal_reservation(id, "failed")` must be called when
  Horizon rejects or times out, otherwise failed attempts consume cap quota permanently.
- **Overflow** — `daily_cap_stroops` is `BIGINT` (i64). The total XLM supply is ~50 billion,
  which is 5×10¹⁶ stroops — safely inside i64 max (≈9.2×10¹⁸). No overflow risk.
