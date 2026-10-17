# Audit log

`GET /v1/audit-logs` returns the signed-in user's account activity (see [api.md](api.md)). Rows are
written by `crate::audit::record` in `crates/api/src/audit.rs`. Recording is **best-effort**: a
failure is logged and never fails the request that triggered it.

## Tamper evidence (hash chain)

Each user's rows form an HMAC-SHA256 chain (migration `0026_audit_hash_chain.sql`, code in
`crates/store/src/audit_chain.rs`):

- `seq` is the row's 1-based position in that user's chain; `prev_hash` is the previous row's
  `row_hash` (32 zero bytes for `seq = 1`).
- `row_hash = HMAC(AUDIT_CHAIN_KEY, "octo/audit-row/v1" ‖ prev_hash ‖ id ‖ user_id ‖ seq ‖
  created_at(µs) ‖ action ‖ category ‖ target ‖ ip_address)`, with length-prefixed strings and
  tagged optionals so no two field layouts collide.
- `audit_chain_heads` stores each user's newest `(seq, row_hash)` under its own MAC, so deleting
  rows off the end (or every row) is caught too.

The key comes from `AUDIT_CHAIN_KEY` and is never stored in the database, which is what makes
the chain meaningful: with a plain hash, anyone able to edit a row could recompute every later
hash. Keep the key stable and backed up like `MASTER_KEY`; losing or changing it makes every
existing chain unverifiable.

**Concurrency.** `record_audit` runs in one transaction that takes
`pg_advisory_xact_lock(<AUDT>, hashtext(user_id))` before reading the head, so concurrent writers
for one user append in a single linear order (different users never contend). A partial unique
index on `(user_id, seq)` backstops the lock.

**Writer refuses to launder tampering.** If a user's head is missing while chained rows exist,
or its MAC is wrong, `record_audit` returns `AuditChainCorrupt` instead of appending (it would
otherwise sign a fresh head over the damage). Recording is best-effort, so this shows up as a
`failed to record audit log` warning; investigate before anything else.

**Verify** with `octo-server verify-audit-chain` (all users) or
`octo-server verify-audit-chain --user <uuid>`. It needs only `DATABASE_URL` and
`AUDIT_CHAIN_KEY`, reads in batches of 1000 rows, logs each broken chain with the first failing
`seq` and a reason, and exits non-zero if any chain is broken. Run it on a schedule and alert on
failure.

**Limits.**
- Rows written before migration 0026 are adopted into the chain, in `(created_at, id)` order, on
  that user's first new event. The chain proves nothing about edits made *before* adoption.
  Until then the verifier reports the user as `Unchained`, not broken.
- During a rolling deploy, an old server instance still writes unchained rows. For users whose
  chain has already started, those rows are reported as broken (`unchained rows present after
  the chain started`). Drain old instances before the first verification run.
- Removing a user's head **and** all their chained rows looks like a user with no history.
  `ON DELETE CASCADE` from `users` does exactly that, by design.
- Someone who keeps an old copy of a head row can roll a chain back to that point. To close
  that gap, export heads to append-only storage outside the database on a schedule.
- As an extra layer, the application's DB role can be denied `UPDATE`/`DELETE` on `audit_logs`.
  Legacy adoption needs `UPDATE` only on rows where `seq IS NULL`.

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

Every `crate::audit::record` call in `crates/api/src`:

| Category | Action text | Emitted from | Trigger |
|---|---|---|---|
| `authentication` | `created an account` | `auth.rs` `signup` | `POST /v1/auth/signup` |
| `authentication` | `signed in` | `auth.rs` `login` | `POST /v1/auth/login` (successful) |
| `authentication` | `refreshed session token` | `auth.rs` `refresh` | `POST /v1/auth/refresh` |
| `authentication` | `logged out` | `auth.rs` `logout` | `POST /v1/auth/logout` |
| `authentication` | `changed password` | `auth.rs` `change_password` | `POST /v1/auth/change-password` |
| `authentication` | `reset their password` | `auth.rs` `confirm_password_reset` | `POST /v1/auth/confirm-password-reset` |
| `authentication` | `changed their email` | `auth.rs` `confirm_email_change` | `POST /v1/auth/change-email/confirm` |
| `authentication` | `revoked a session` | `routes/sessions.rs` `revoke_session` | `DELETE /v1/auth/sessions/{id}` (target: session id) |
| `authentication` | `revoked all other sessions` | `routes/sessions.rs` `revoke_other_sessions` | `POST /v1/auth/sessions/revoke-others` |
| `wallet` | `created master wallet` | `routes/wallets.rs` `create_wallet` | `POST /v1/wallets` |
| `wallet` | `provisioned a gas tank` | `routes/wallets.rs` `create_gas_tank` | `POST /v1/wallets/{id}/gas-tank` |
| `wallet` | `submitted a signed transaction (<status>)` | `routes/submit.rs` `submit_signed` | `POST /v1/wallets/{id}/submit-signed`, only when called with a dashboard JWT |
| `wallet` | `confirmed a withdrawal (<status>)` | `routes/submit.rs` `withdraw_confirm` | `POST /v1/wallets/{id}/withdraw/confirm` |
| `address` | `generated a deposit address` | `routes/addresses.rs` `create_address` | `POST /v1/wallets/{id}/addresses`, when the wallet has an owner |
| `credentials` | `generated an API key` | `routes/apikeys.rs` `generate_key` | `POST /v1/wallets/{id}/api-key` |
| `credentials` | `revoked API key` | `routes/apikeys.rs` `delete_key` | `DELETE /v1/wallets/{id}/api-key` |
| `sponsorship` | `sponsored a transaction (<status>)` | `routes/sponsor.rs` `sponsor` | `POST /v1/wallets/{id}/sponsor`, only when called with a dashboard JWT |
| `sponsorship` | `updated sponsorship config (enabled: <bool>)` | `routes/sponsorship.rs` `put_config` | `PUT /v1/wallets/{id}/sponsorship` |

To re-verify this table is exhaustive: `grep -rn "audit::record" crates/api/src`.

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
