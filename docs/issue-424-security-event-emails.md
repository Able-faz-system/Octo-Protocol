# Issue #424 — Email Users on Security-Sensitive Account Events

## Background

Several high-value account mutations currently happen silently: an API key can be regenerated,
the withdrawal allowlist can be changed, and a login can succeed from a network the account has
never used before — all without the account owner receiving any notification. An attacker who
gains access to the account can perform these mutations undetected for as long as they like.

A notification email sent immediately after each event gives the account owner an out-of-band
signal. If it was not them, they have a window to act (revoke the API key, lock the account,
contact support) before further damage is done. The "this wasn't me" pointer in each email is
the critical affordance — without it, the notification is just noise.

These emails are best-effort. They must never block or fail the primary request.

### Key facts from the current codebase

- **Email infrastructure** — `crates/email/src/lib.rs`. `EmailSender` posts to Resend's REST
  API (`https://api.resend.com/emails`). `state.email()` returns the sender. Calling
  `state.email().send(to, subject, html)` propagates `EmailError` — callers on non-critical
  paths must wrap the call in `let _ = ...` so a Resend failure does not abort the primary
  operation.
- **Templates** — `crates/email/src/templates.rs`. All existing templates HTML-escape
  untrusted values through `html_escape()` / `escape_html()` before interpolation. New
  templates must follow the same pattern without exception.
- **Existing templates** — `otp_email`, `welcome_email`, `email_changed_email`,
  `withdrawal_success_email`, `withdrawal_failed_email`. The `email_changed_email` template is
  the closest precedent for a security-alert email: it uses `Icon::Warn`, states what changed,
  and tells the user what to do if it wasn't them.
- **Test fixtures** — `EmailSender::new_captured()` records sent emails in memory. Tests assert
  event emails are sent using `sender.last_otp_for(to)` for OTP emails, or by inspecting the
  captured list for general `send(...)` calls. For general `send` calls a parallel
  `CapturedEmail` struct and `last_email_for(to)` accessor should be added alongside the
  existing `CapturedOtp` infrastructure.
- **No templates or send-calls exist today** for API key regeneration, allowlist changes, new
  device/IP login, or username change.

## Goal

Add notification emails for the following events, sent to the account's registered email address:

| Event | Trigger point |
|---|---|
| API key regenerated | `POST /v1/wallets/:id/api-keys` (after key is stored) |
| Allowlist address added | `POST /v1/wallets/:id/whitelist` (after OTP confirm, per issue #423) |
| Allowlist address removed | `DELETE /v1/wallets/:id/whitelist/:entry_id` (after OTP confirm) |
| Login from new IP | `POST /v1/auth/login` (when IP has not been seen before for this user) |
| Username / email change | `PUT /v1/auth/me` or equivalent (after change is committed) |

Each email must:
- State exactly what happened (event type, any relevant detail).
- Name the approximate time and, where available, the IP address.
- Include a "this wasn't me" pointer with a link to the support page or account-lock endpoint.
- HTML-escape every value interpolated from external input.

## Design

### New templates (`crates/email/src/templates.rs`)

All templates follow the same `shell(body_html, icon)` structure as existing templates. Every
user-supplied or system-generated string that enters the HTML is wrapped in `html_escape()`
before interpolation.

#### `api_key_regenerated_email`

```rust
pub fn api_key_regenerated_email(wallet_label: &str, ip: &str, timestamp: &str) -> String {
    let (wallet_label, ip, timestamp) = (
        html_escape(wallet_label),
        html_escape(ip),
        html_escape(timestamp),
    );
    shell(
        &format!(
            "<p style=\"...\">API key regenerated</p>\
<p style=\"...\">The API key for wallet <strong>{wallet_label}</strong> was regenerated.</p>\
<div style=\"...\">\
<p style=\"...\"><strong>Time:</strong> {timestamp}</p>\
<p style=\"...\"><strong>IP address:</strong> {ip}</p>\
</div>\
<p style=\"...\">If this wasn't you, revoke the key immediately from your dashboard \
and <a href=\"https://octohq.org/support\">contact support</a>.</p>"
        ),
        Icon::Warn,
    )
}
```

#### `allowlist_changed_email`

```rust
pub fn allowlist_changed_email(
    action: &str,          // "added" | "removed"
    address: &str,         // G… address
    ip: &str,
    timestamp: &str,
) -> String {
    let (action, address, ip, timestamp) = (
        html_escape(action),
        html_escape(address),
        html_escape(ip),
        html_escape(timestamp),
    );
    shell(
        &format!(
            "<p style=\"...\">Withdrawal allowlist changed</p>\
<p style=\"...\">An address was {action} your withdrawal allowlist.</p>\
<div style=\"...\">\
<p style=\"...\"><strong>Address:</strong> {address}</p>\
<p style=\"...\"><strong>Time:</strong> {timestamp}</p>\
<p style=\"...\"><strong>IP address:</strong> {ip}</p>\
</div>\
<p style=\"...\">If this wasn't you, disable your allowlist and \
<a href=\"https://octohq.org/support\">contact support</a> immediately.</p>"
        ),
        Icon::Warn,
    )
}
```

#### `new_ip_login_email`

```rust
pub fn new_ip_login_email(ip: &str, timestamp: &str, user_agent: &str) -> String {
    let (ip, timestamp, user_agent) = (
        html_escape(ip),
        html_escape(timestamp),
        html_escape(user_agent),
    );
    shell(
        &format!(
            "<p style=\"...\">New login from an unrecognised device</p>\
<p style=\"...\">Your account was accessed from a network we haven't seen before.</p>\
<div style=\"...\">\
<p style=\"...\"><strong>IP address:</strong> {ip}</p>\
<p style=\"...\"><strong>Time:</strong> {timestamp}</p>\
<p style=\"...\"><strong>Device:</strong> {user_agent}</p>\
</div>\
<p style=\"...\">If this wasn't you, \
<a href=\"https://octohq.org/support\">contact support</a> and change your password immediately.</p>"
        ),
        Icon::Warn,
    )
}
```

`user_agent` is taken from the `User-Agent` request header, truncated to a safe maximum length
(e.g. 200 chars) before interpolation to prevent email-client rendering attacks from
arbitrarily long agent strings.

#### `account_detail_changed_email`

Covers username and email changes (in addition to the existing `email_changed_email` which
notifies the old address).

```rust
pub fn account_detail_changed_email(field: &str, ip: &str, timestamp: &str) -> String {
    let (field, ip, timestamp) = (
        html_escape(field),
        html_escape(ip),
        html_escape(timestamp),
    );
    shell(
        &format!(
            "<p style=\"...\">Account detail changed</p>\
<p style=\"...\">Your account's <strong>{field}</strong> was updated.</p>\
<div style=\"...\">\
<p style=\"...\"><strong>Time:</strong> {timestamp}</p>\
<p style=\"...\"><strong>IP address:</strong> {ip}</p>\
</div>\
<p style=\"...\">If this wasn't you, \
<a href=\"https://octohq.org/support\">contact support</a> immediately.</p>"
        ),
        Icon::Warn,
    )
}
```

### Send-call placement

Each send call follows the same pattern: fire-and-forget with `let _ = ...`, placed
**after** the primary operation succeeds. Never place it before the mutation or in a position
where email failure could roll back the mutation.

#### API key regenerated — `crates/api/src/routes/apikeys.rs`

```rust
// After store.create_api_key(...) succeeds:
let html = octo_email::templates::api_key_regenerated_email(
    &wallet.label.as_deref().unwrap_or("unnamed wallet"),
    ip_from_headers(&headers).as_deref().unwrap_or("unknown"),
    &chrono::Utc::now().to_rfc2822(),
);
let _ = state.email().send(&user.email, "API key regenerated", &html).await;
```

#### Allowlist changed — `crates/api/src/routes/whitelist.rs`

For `add_address` (after store call):

```rust
let html = octo_email::templates::allowlist_changed_email(
    "added to",
    &base_address,
    ip_from_headers(&headers).as_deref().unwrap_or("unknown"),
    &chrono::Utc::now().to_rfc2822(),
);
let _ = state.email().send(&user.email, "Withdrawal allowlist changed", &html).await;
```

For `remove_address` (after store call), use `"removed from"` as the `action` argument.

To send these emails the whitelist handlers need access to the user's email address. Currently
`owned_wallet` returns only the `Wallet`. The handlers will need an additional
`store.get_user(user_id)` call (the same pattern used in `submit.rs`).

#### Login from new IP — `crates/api/src/auth.rs` (or the login route handler)

New-IP detection requires storing known IPs. Options in ascending complexity:

1. **Audit log check (minimal)** — query `audit_logs` for any prior `"logged in"` entry from
   this user that was recorded with the same IP. If none exists, treat it as a new IP. This
   reuses existing infrastructure at the cost of a query on every login.

2. **Dedicated `known_ips` table** — store `(user_id, ip_hash, first_seen_at)`. Hash the IP
   before storage to avoid retaining PII beyond what is needed. On login, look up the hash; if
   absent, insert and send the alert.

Option 1 is simpler and sufficient for the initial implementation. Option 2 is preferable if
PII minimisation is a concern.

```rust
// In the login handler, after JWT is issued and session established:
let ip = ip_from_headers(&headers).unwrap_or_default();
let is_new_ip = state
    .store()
    .login_ip_is_new(user_id, &ip)
    .await
    .unwrap_or(false); // default false — don't alert on store error

if is_new_ip {
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");
    let user_agent = &user_agent[..user_agent.len().min(200)]; // truncate
    let html = octo_email::templates::new_ip_login_email(
        &ip,
        &chrono::Utc::now().to_rfc2822(),
        user_agent,
    );
    let _ = state.email().send(&user.email, "New login from an unrecognised device", &html).await;
}
```

`login_ip_is_new(user_id, ip)` returns `true` and records the IP if the `(user_id, ip)` pair
has not been seen before.

#### Username / email changed

The existing `email_changed_email` already notifies the old address after an email change. A
call to `account_detail_changed_email` should also be sent to the **new** address for email
changes, and to the current address for username changes.

### Helper: `ip_from_headers`

Extract the real client IP, respecting `X-Forwarded-For` when the server sits behind a trusted
proxy. This helper should be centralised in `crates/api/src/` rather than duplicated per
handler.

```rust
/// Extract the most-proximate client IP from request headers.
/// Reads `X-Forwarded-For` first, then `X-Real-Ip`, then returns `None`.
/// Only the first (leftmost) `X-Forwarded-For` value is used — this is the
/// client IP when the proxy chain is trusted. If untrusted proxies are possible,
/// read the rightmost value instead.
pub fn ip_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_owned())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_owned())
        })
}
```

### Test fixture extension

`EmailSender::new_captured()` currently captures OTPs via `CapturedOtp`. Add a parallel type
for general `send(...)` calls:

```rust
#[cfg(feature = "test-fixtures")]
#[derive(Debug, Clone)]
pub struct CapturedEmail {
    pub to: String,
    pub subject: String,
    pub html: String,
}
```

Add `captured_emails: Option<Arc<Mutex<Vec<CapturedEmail>>>>` to `EmailSender`, populated by
`send(...)` when in captured mode. Add `last_email_for(to: &str) -> Option<CapturedEmail>` and
`emails_for(to: &str) -> Vec<CapturedEmail>` accessors.

Integration tests then assert, for example:

```rust
let email = sender.last_email_for(&user.email).expect("notification sent");
assert!(email.subject.contains("API key regenerated"));
assert!(email.html.contains("this wasn't you"));
```

## Implementation tasks

1. **`crates/email/src/templates.rs`** — Add `api_key_regenerated_email`,
   `allowlist_changed_email`, `new_ip_login_email`, and `account_detail_changed_email`.

2. **`crates/email/src/lib.rs`** — Add `CapturedEmail` struct; extend `EmailSender` with
   `captured_emails` field (test-fixtures only); update `send(...)` to push into it; add
   `last_email_for` and `emails_for` accessors.

3. **`crates/api/src/lib.rs`** (or a new `crates/api/src/helpers.rs`) — Add
   `ip_from_headers` helper.

4. **`crates/api/src/routes/apikeys.rs`** — Add send call after key creation.

5. **`crates/api/src/routes/whitelist.rs`** — Add send calls in `add_address` and
   `remove_address` (requires `get_user` call to retrieve email address).

6. **`crates/store/src/lib.rs`** — Add `login_ip_is_new(user_id, ip)` (using audit log check
   or a new `known_ips` table).

7. **Login route handler** — Add new-IP detection and alert send.

8. **Account-detail-change handler** — Add `account_detail_changed_email` send.

## Security considerations

- **Best-effort, never blocking** — every `state.email().send(...)` call must be wrapped in
  `let _ = ...`. A Resend outage must not break API key rotation or logins.
- **HTML escaping is mandatory** — all values that enter template HTML (IP addresses,
  user-agent strings, wallet labels, email addresses, addresses) are untrusted. Every new
  template must use `html_escape()`. An unescaped `<script>` tag in a wallet label or IP field
  is an XSS vector in HTML-capable email clients.
- **User-Agent truncation** — user-agent strings are user-controlled and can be arbitrarily
  long. Truncate to a safe maximum (200 chars) before interpolation.
- **IP header trust** — `X-Forwarded-For` is only trustworthy when the server sits behind a
  known, trusted proxy that sets the header. If the API is directly internet-exposed, this
  header can be spoofed and should not be used. Document the deployment assumption.
- **New-IP detection accuracy** — Option 1 (audit log) can produce false positives if the
  audit log is pruned. Option 2 (dedicated table with IP hash) is more reliable. Either way,
  a false positive only results in an extra notification email — it does not block the login.
- **PII in emails and logs** — IP addresses are PII in some jurisdictions. Avoid logging raw
  IPs beyond what the existing audit log already stores.
- **Email to old address on email change** — `email_changed_email` (already in place) sends to
  the old address. The new `account_detail_changed_email` goes to the new address. Both calls
  are needed.
