# Issue #423 — Require OTP Confirmation to Change the Withdrawal Allowlist

## Background

The withdrawal allowlist is the primary anti-fraud control for outbound payments: once enabled,
a wallet can only send to pre-approved destinations. The allowlist requires a **dashboard login
JWT** to manage — the intent being that the credential that can widen the allowlist must be
stronger than the API key the allowlist is meant to contain.

That reasoning has a gap. A stolen login session (e.g. a hijacked browser cookie) can silently
add an attacker-controlled address to the allowlist. From that point, the only remaining barrier
is the withdrawal OTP — which an attacker who controls the session can also receive if they have
access to the email account. The allowlist mutation being undetected and ungated means the
attacker can prepare the drain well before triggering it.

Gating allowlist changes behind a fresh OTP makes this attack require two independent email
accesses: one to pass the allowlist OTP, and one to pass the withdrawal OTP. That is a
meaningfully higher bar.

### Key facts from the current codebase

- **`crates/api/src/routes/whitelist.rs`** — all mutating handlers (`add_address`,
  `remove_address`, `put_config`) call `owned_wallet(...)`, which calls `require_login`. Login
  JWT is required; API keys are rejected. There is **no OTP gate today**.
- **OTP infrastructure** — fully built in `crates/email/src/lib.rs` and `crates/store/src/lib.rs`:
  - `octo_email::generate_otp()` — 6-digit zero-padded string from `OsRng`.
  - `octo_email::hash_otp(code)` — SHA-256 hex; only the hash is stored.
  - `store.create_otp(user_id, purpose, code_hash, tx_hash_bound, ttl)` — inserts into
    `email_otps`. The `tx_hash_bound` column (`Option<&str>`) binds the OTP to an arbitrary
    string — it is used for withdrawal to bind the OTP to the exact transaction hash. The same
    column is used here to bind the OTP to the exact mutation being confirmed.
  - `store.verify_and_consume_otp(user_id, purpose, code_hash, tx_hash_bound)` — atomic
    verify-and-mark-consumed. Rejects expired, consumed, over-attempted, or wrong-bound codes.
    Returns `StoreError::InvalidOtp` for any failure, preventing guessing from distinguishing
    cases.
- **Withdrawal OTP pattern** (`crates/api/src/routes/submit.rs`) — the reference implementation:
  two endpoints, `withdraw/request-otp` and `withdraw/confirm`, with the mutation happening
  only on the confirm path after `verify_and_consume_otp` succeeds.
- **Address normalisation** — `octo_wallet_core::to_base_account` converts M…/G… addresses to
  their canonical G… form before storage. This must happen before the mutation-binding hash is
  computed, so the OTP is bound to the canonical form.

## Goal

- Gate `POST /v1/wallets/:id/whitelist` (add address) and
  `DELETE /v1/wallets/:id/whitelist/:entry_id` (remove address) behind a fresh email OTP.
- `PUT /v1/wallets/:id/whitelist/config` (toggle enable/disable) also requires an OTP, since
  enabling the allowlist is equivalent in risk to adding an address.
- The OTP is bound to the **exact mutation** — an OTP issued to add address A cannot be
  replayed to add address B or to remove a different address.
- Optionally, a newly added address enters a **cooling-off period** before it becomes active
  for enforcement, giving the account owner a window to notice and revoke an unauthorised
  addition.

## Design

### Two-step flow per mutation

Each mutating endpoint gets a sibling `request-otp` endpoint. The confirm endpoint performs the
actual mutation only after OTP verification.

```
POST /v1/wallets/:id/whitelist/request-otp        ← issue OTP for an upcoming mutation
POST /v1/wallets/:id/whitelist                    ← add address (now requires OTP)
DELETE /v1/wallets/:id/whitelist/:entry_id        ← remove address (now requires OTP)
PUT /v1/wallets/:id/whitelist/config              ← toggle (now requires OTP)
```

The single `request-otp` endpoint issues a code for any allowlist mutation. The mutation type
and its canonical parameters are encoded into a **mutation key** that is stored as
`tx_hash_bound`. The mutation key is a SHA-256 hex digest of `"{mutation_type}:{canonical_params}"`.

#### Mutation key derivation

```rust
fn mutation_key(kind: &str, params: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("{kind}:{params}").as_bytes());
    hex::encode(digest)
}
```

| Operation | `kind` | `params` |
|---|---|---|
| Add address | `"add"` | base G… address |
| Remove address | `"remove"` | entry UUID |
| Enable allowlist | `"config"` | `"enabled=true"` |
| Disable allowlist | `"config"` | `"enabled=false"` |

Using the entry UUID (not the address) for removals means the OTP is bound to the specific
database row, not the address string — preventing an OTP issued for one row from removing a
different row that happens to share the address.

### `POST /v1/wallets/:id/whitelist/request-otp`

**Auth:** login JWT (`require_login`). No API key.

**Request body:**

```json
{
  "mutation": "add",
  "address": "GABC...",      // required when mutation = "add"
  "entry_id": null           // required when mutation = "remove"
}
```

```json
{
  "mutation": "config",
  "enabled": true
}
```

**Handler logic:**

1. `require_login` → `owned_wallet`.
2. Normalise address (if add) via `to_base_account`; validate entry exists (if remove).
3. Compute `mutation_key(kind, params)`.
4. `octo_email::generate_otp()` → `octo_email::hash_otp(&code)`.
5. `store.create_otp(user_id, "allowlist", &code_hash, Some(&mutation_key), Duration::minutes(10))`.
6. `state.email().send_otp(&user.email, "allowlist change", &code)`.

**Response:**

```json
{ "statusCode": 200, "message": "OK", "data": { "sent": true } }
```

### `POST /v1/wallets/:id/whitelist` (add address, updated)

**Request body:**

```json
{
  "address": "GABC...",
  "label": "Optional label",
  "code": "042817"
}
```

**Handler logic:**

1. `require_login` → `owned_wallet`.
2. Normalise `address` via `to_base_account`.
3. Compute `mutation_key("add", &base_address)`.
4. `store.verify_and_consume_otp(user_id, "allowlist", &hash_otp(code), Some(&mutation_key))`.
   Return `400 "invalid or expired code"` on `StoreError::InvalidOtp`.
5. `store.add_whitelisted_address(wallet_id, &base_address, label)`.
6. Audit-log: `"added address to withdrawal allowlist"`, target = base_address.

If the cooling-off period feature is included, insert the address with an `active_at` timestamp
of `now() + cooling_off_duration` and enforce that only rows where `active_at <= now()` are
accepted at the allowlist check in `relay_signed_transaction`.

### `DELETE /v1/wallets/:id/whitelist/:entry_id` (remove address, updated)

**Request body:**

```json
{ "code": "042817" }
```

**Handler logic:**

1. `require_login` → `owned_wallet`.
2. Verify the entry exists and belongs to this wallet (return `404` if not, to avoid leaking
   other wallets' entry IDs).
3. Compute `mutation_key("remove", &entry_id.to_string())`.
4. `store.verify_and_consume_otp(user_id, "allowlist", &hash_otp(code), Some(&mutation_key))`.
5. `store.remove_whitelisted_address(wallet_id, entry_id)`.
6. Audit-log: `"removed address from withdrawal allowlist"`, target = entry_id.

### `PUT /v1/wallets/:id/whitelist/config` (toggle, updated)

**Request body:**

```json
{ "enabled": true, "code": "042817" }
```

**Handler logic:**

1. `require_login` → `owned_wallet`.
2. Compute `mutation_key("config", &format!("enabled={}", enabled))`.
3. `store.verify_and_consume_otp(user_id, "allowlist", &hash_otp(code), Some(&mutation_key))`.
4. Existing pre-condition check (non-empty list before enabling) — unchanged.
5. `store.upsert_withdrawal_allowlist_config(wallet_id, enabled)`.
6. Audit-log: `"updated withdrawal allowlist config"`, target = `format!("enabled={enabled}")`.

### Cooling-off period (optional)

A newly added address could be withheld from enforcement for a configurable window (default: 30
minutes) to give the account owner a window to notice and revoke an unauthorised addition even
after the OTP was passed.

```sql
-- Migration: add active_at column
ALTER TABLE whitelisted_addresses
    ADD COLUMN active_at TIMESTAMPTZ NOT NULL DEFAULT now();
```

`add_whitelisted_address` sets `active_at = now() + interval '30 minutes'` (or the configured
value).

The allowlist check in `relay_signed_transaction` (`submit.rs`) then becomes:

```rust
state.store().is_address_whitelisted_and_active(wallet_id, &base_destination).await
// SELECT id FROM whitelisted_addresses
// WHERE wallet_id = $1 AND address = $2 AND active_at <= now()
```

### Audit trail

Every successful mutation must produce an audit-log row via `crate::audit::record(...)`.
The relevant `category` constant is `crate::audit::category::WALLET`.

| Event | Action string |
|---|---|
| OTP issued | `"issued allowlist OTP ({mutation_type})"` |
| Address added | `"added address to withdrawal allowlist"` |
| Address removed | `"removed address from withdrawal allowlist"` |
| Allowlist enabled | `"enabled withdrawal allowlist"` |
| Allowlist disabled | `"disabled withdrawal allowlist"` |

Failed OTP attempts are implicit in the `email_otps.attempts` counter but should also be
logged when the increment saturates (`attempts >= 5`) to surface brute-force attempts.

## Implementation tasks

1. **`crates/store/migrations/`** — Add `active_at` column to `whitelisted_addresses` (if
   cooling-off is included).

2. **`crates/store/src/lib.rs`** — Add `is_address_whitelisted_and_active` if cooling-off is
   included; otherwise the existing `is_address_whitelisted` gains an `active_at <= now()`
   predicate.

3. **`crates/api/src/routes/whitelist.rs`**:
   - Add `AllowlistOtpRequest` struct and `request_otp` handler.
   - Add `code: Option<String>` field to `AddWhitelistedAddressRequest`.
   - Add `code: Option<String>` to the `DELETE` body (new `RemoveWhitelistedAddressRequest`
     struct — the endpoint currently takes no body).
   - Add `code: Option<String>` to `AllowlistConfigRequest`.
   - Insert OTP verify-and-consume calls in `add_address`, `remove_address`, and `put_config`.
   - Add `mutation_key` helper function.

4. **`crates/api/src/lib.rs`** — Register the new
   `POST /v1/wallets/:id/whitelist/request-otp` route.

5. **`crates/api/src/routes/submit.rs`** — Update `is_address_whitelisted` call to
   `is_address_whitelisted_and_active` if cooling-off is included.

6. **`docs/api.md`** — Document the new `request-otp` endpoint and the updated request bodies
   for the mutating endpoints.

## Security considerations

- **Binding the OTP to the mutation** — without `mutation_key`, an OTP issued to add address A
  could be replayed to add address B in a race between issuing and consuming. The binding makes
  the code single-use per exact operation.
- **Entry-ID binding for removals** — binding removals to the entry UUID (not the address)
  prevents an OTP for removing entry X from being used to remove entry Y that happens to hold
  the same address (possible if the address was added twice due to a race).
- **Error messages** — `verify_and_consume_otp` returns `StoreError::InvalidOtp` for all
  failure cases (wrong code, expired, consumed, wrong bound). Surface this as a generic
  `"invalid or expired code"` — never distinguish between cases in the response, as guessing
  attacks exploit the distinction.
- **OTP TTL** — 10 minutes, consistent with the withdrawal OTP TTL. Short enough to limit the
  window of a stolen code.
- **Rate limiting** — `verify_and_consume_otp` increments `attempts` on each wrong guess and
  hard-stops at 5. This is already in place in the store layer; no additional rate limit is
  needed at the route level for the OTP check itself, but the standard per-IP rate limiter on
  the API still applies.
- **Cooling-off period** — even with the OTP gate, a 30-minute cooling-off period for new
  addresses gives a second line of defence: if the OTP email was compromised, the account owner
  receives the OTP notification email and has a window to revoke the address before it becomes
  usable for withdrawals. The OTP and the cooling-off period are independent controls; the
  cooling-off period can be added incrementally.
- **API key cannot trigger** — `require_login` is already in place and already rejects API
  keys. No change needed here, but it must not be downgraded.
