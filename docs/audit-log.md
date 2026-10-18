# Audit log

`GET /v1/audit-logs` returns the signed-in user's account activity (see [api.md](api.md)). Rows are
written by `crate::audit::record` in `crates/api/src/audit.rs`. Recording is **best-effort**: a
failure is logged and never fails the request that triggered it. The exception is
`crate::audit::record_strict`, used where an untraced access is unacceptable (seed-backup
retrieval): if the row can't be written the request fails with 500 and nothing is returned.

The table is **append-only at the database level** (migration `0026_audit_logs_append_only.sql`):
`UPDATE`, `DELETE` and `TRUNCATE` raise unless the session's role is a member of
`octo_audit_retention`, or the delete is the `ON DELETE CASCADE` from a user row that is already
gone. See [postgres-roles.md](postgres-roles.md) for who holds that role.

## Categories

The category set lives in `crate::audit::category`. The wire value is what a client filters on
with `GET /v1/audit-logs?category=<value>`.

| Constant | Wire value | Meaning |
|---|---|---|
| `AUTH` | `authentication` | Account session lifecycle: sign-up, sign-in, token refresh, sign-out |
| `WALLET` | `wallet` | Wallet lifecycle and anything that relays a transaction from a wallet |
| `ADDRESS` | `address` | Customer deposit addresses |
| `CREDENTIALS` | `credentials` | Per-wallet API key issuance and revocation |
| `SPONSORSHIP` | `sponsorship` | Gas-tank fee sponsorship: sponsored transactions and config changes |
| `WEBHOOK` | `configuration` | Reserved for webhook configuration changes — **no call site emits it yet** |
| `WITHDRAWAL` | `wallet` | Alias of `WALLET` (same wire value) — **no call site uses it**; withdrawals emit `WALLET` |

Two constants share the wire value `wallet`, so filtering by `wallet` returns both.

## Call sites

Every `crate::audit::record` / `record_strict` call in `crates/api/src` (14 in total):

| Category | Action text | Emitted from | Trigger |
|---|---|---|---|
| `authentication` | `created an account` | `auth.rs` `signup` | `POST /v1/auth/signup` |
| `authentication` | `signed in` | `auth.rs` `login` | `POST /v1/auth/login` (successful) |
| `authentication` | `refreshed session token` | `auth.rs` `refresh` | `POST /v1/auth/refresh` |
| `authentication` | `logged out` | `auth.rs` `logout` | `POST /v1/auth/logout` |
| `wallet` | `created master wallet` | `routes/wallets.rs` `create_wallet` | `POST /v1/wallets` |
| `wallet` | `retrieved encrypted seed backup` (target: wallet id; strict) | `routes/wallets.rs` `get_backup` | `GET /v1/wallets/{id}/backup` — also rate-limited to 5/hour per user |
| `wallet` | `provisioned a gas tank` | `routes/wallets.rs` `create_gas_tank` | `POST /v1/wallets/{id}/gas-tank` |
| `wallet` | `submitted a signed transaction (<status>)` | `routes/submit.rs` `submit_signed` | `POST /v1/wallets/{id}/submit-signed`, only when called with a dashboard JWT |
| `wallet` | `confirmed a withdrawal (<status>)` | `routes/submit.rs` `withdraw_confirm` | `POST /v1/wallets/{id}/withdraw/confirm` |
| `address` | `generated a deposit address` | `routes/addresses.rs` `create_address` | `POST /v1/wallets/{id}/addresses`, when the wallet has an owner |
| `credentials` | `generated an API key` | `routes/apikeys.rs` `generate_key` | `POST /v1/wallets/{id}/api-key` |
| `credentials` | `revoked API key` | `routes/apikeys.rs` `delete_key` | `DELETE /v1/wallets/{id}/api-key` |
| `sponsorship` | `sponsored a transaction (<status>)` | `routes/sponsor.rs` `sponsor` | `POST /v1/wallets/{id}/sponsor`, only when called with a dashboard JWT |
| `sponsorship` | `updated sponsorship config (enabled: <bool>)` | `routes/sponsorship.rs` `put_config` | `PUT /v1/wallets/{id}/sponsorship` |

To re-verify this table is exhaustive: `grep -rn "audit::record" crates/api/src` (matches `record_strict` too).

## Keeping the lists in sync

Three places name the categories and must agree: the constants in `audit.rs`, this table, and the
`category` filter on `GET /v1/audit-logs` (`routes/audit.rs`). Any change to the constants must
update the other two in the same PR. The filter currently forwards any non-empty string to the
store unvalidated (an unknown category simply returns no rows); when it is changed to reject
unknown values, it should validate against `category::*` so the accepted set and the emitted set
cannot drift.

## Adding an event or a category

1. **Reuse an existing category** when the event is another action on the same kind of thing (a new
   wallet operation is `wallet`, a new sign-in method is `authentication`). Categories are filter
   chips in the dashboard, so keep the set small.
2. **Add a category** only when a user would plausibly want to filter for the new events on their
   own and none of the existing meanings fit. Add the constant in `audit.rs`, a row to both tables
   above, and update the filter validation.
3. Call `crate::audit::record(&state, user_id, action, category::X, target, &headers).await` after
   the operation has succeeded. Use a past-tense action, put the resource (label, hash, account)
   in `target`, and never put secrets or key material in either.
4. Record only when there is a user to attribute to. API-key callers have no user, so those paths
   skip the record (see `submit_signed` and `sponsor`).
