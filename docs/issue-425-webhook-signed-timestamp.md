# Issue #425 — Add a Signed Timestamp to Webhook Deliveries to Stop Replay

## Background

Octo signs each webhook delivery with HMAC-SHA256 over the raw JSON body bytes, sending the
result in `X-Octo-Signature`. The signature is correct for authenticating the payload's origin,
but it carries no freshness information. A valid signature never expires. A captured delivery
can be replayed indefinitely — months or years later — and any consumer that checks only the
signature will accept it.

The standard mitigation, used by Stripe, GitHub, and others, is to include a Unix timestamp in
the signed input. The consumer checks that the timestamp is within a tolerance window (typically
5 minutes) of the current time before accepting the delivery. A captured payload is useless
once the window has passed.

### Key facts from the current codebase

- **`crates/webhooks/src/sign.rs`** — `sign(secret, body)` computes HMAC-SHA256 over `body`
  only. `verify(secret, body, sig_hex)` uses `mac.verify_slice` (constant-time via the
  `subtle` crate). The header name `SIGNATURE_HEADER = "X-Octo-Signature"` is a named
  constant.
- **`crates/webhooks/src/lib.rs`** — `attempt_once` builds the HTTP request. It adds two
  headers today: `content-type: application/json` and `X-Octo-Signature`. The signature is
  computed once in `deliver_with_retry` and passed as `signature_ref: &str` into the retry
  loop — it is safe to compute once because the body bytes do not change between retries.
- **Signed input today**: the raw body bytes — `serde_json::to_vec(&body)` of the event
  envelope `{"event": "...", "data": {...}}`.
- **No timestamp in any header or in the HMAC input today.**
- **`response_snippet`** redacts both the signature hex and `ep.secret` from logged response
  bodies. Any new sensitive values included in headers must also be added to the redaction set
  if they appear in headers that an endpoint might echo back.
- **`sign::verify`** is currently used only in tests; no server-side inbound verification
  exists. The updated `verify_with_tolerance` helper is primarily for consumer use and for
  integration tests.

## Goal

- Send `X-Octo-Timestamp` (Unix epoch seconds as a decimal string) with every delivery.
- Sign `"{timestamp}.{body_bytes}"` instead of `body_bytes` alone — so the timestamp is
  cryptographically bound to the payload and cannot be changed by an intermediary.
- Keep `X-Octo-Signature` as the header name (no rename needed).
- Provide a `verify_with_tolerance` helper for consumers and integration tests.
- Retain the old body-only `sign` / `verify` functions for a **deprecation period** so existing
  consumers are not immediately broken. Remove them once all consumers have migrated.

## Design

### Changes to `crates/webhooks/src/sign.rs`

#### New signing input format

The signed message is constructed as:

```
timestamp_str + "." + body_bytes
```

where `timestamp_str` is the Unix epoch seconds as a decimal ASCII string (e.g. `"1761523200"`).
This is the same convention Stripe uses (`t=<timestamp>,v1=<sig>` in their header; we keep the
format simpler with separate headers).

```rust
/// Build the signing input: `"{timestamp}.{body}"`.
fn signing_input(timestamp_secs: i64, body: &[u8]) -> Vec<u8> {
    let prefix = format!("{timestamp_secs}.");
    let mut input = Vec::with_capacity(prefix.len() + body.len());
    input.extend_from_slice(prefix.as_bytes());
    input.extend_from_slice(body);
    input
}
```

#### Updated `sign` function

```rust
/// Compute the HMAC-SHA256 signature over `"{timestamp_secs}.{body}"`.
pub fn sign_with_timestamp(secret: &[u8], timestamp_secs: i64, body: &[u8]) -> String {
    let input = signing_input(timestamp_secs, body);
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret)
        .expect("HMAC accepts any key length");
    mac.update(&input);
    hex::encode(mac.finalize().into_bytes())
}
```

The old `sign(secret, body)` is kept unchanged for the deprecation period. It must not call
`sign_with_timestamp` internally — the two must remain independent so old consumers can still
verify against the old header until they migrate.

#### New `verify_with_tolerance` helper

```rust
/// Verify a timestamped signature and reject deliveries outside `tolerance`.
///
/// Returns `Err(ReplayError::Expired)` when the timestamp is outside the tolerance window,
/// `Err(ReplayError::Invalid)` when the HMAC does not match or the signature is malformed.
/// `now_secs` is injected so tests can pass a fixed clock.
pub fn verify_with_tolerance(
    secret: &[u8],
    body: &[u8],
    timestamp_secs: i64,
    signature_hex: &str,
    now_secs: i64,
    tolerance_secs: i64,
) -> Result<(), ReplayError> {
    // Check freshness before the HMAC — a timing oracle on the tolerance check would require
    // the attacker to already know the timestamp, which they do (it is in the header). The
    // HMAC check must still be constant-time regardless.
    if (now_secs - timestamp_secs).abs() > tolerance_secs {
        return Err(ReplayError::Expired);
    }
    let input = signing_input(timestamp_secs, body);
    let Ok(sig) = hex::decode(signature_hex) else {
        return Err(ReplayError::Invalid);
    };
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret)
        .expect("HMAC accepts any key length");
    mac.update(&input);
    mac.verify_slice(&sig)
        .map_err(|_| ReplayError::Invalid)
}

#[derive(Debug, PartialEq)]
pub enum ReplayError {
    /// Timestamp is outside the tolerance window.
    Expired,
    /// Signature is malformed or does not match.
    Invalid,
}

/// Default tolerance: 5 minutes.
pub const DEFAULT_TOLERANCE_SECS: i64 = 300;
```

The HMAC comparison uses `mac.verify_slice` — constant-time — for the same reason documented
in the existing `verify` function. This must not be changed to a variable-time `==`.

The `abs()` on the time difference handles both future-dated and past-dated timestamps within
the tolerance window, accommodating minor clock skew between the server and the consumer.

### Changes to `crates/webhooks/src/lib.rs`

#### New header constant

```rust
/// The HTTP header carrying the delivery timestamp (Unix epoch seconds, decimal string).
pub const TIMESTAMP_HEADER: &str = "X-Octo-Timestamp";
```

Add to `sign.rs` alongside `SIGNATURE_HEADER` so consumers can import both from one place.

#### Updated `deliver_with_retry`

The timestamp is captured **once** per delivery job, before the retry loop, so all retry
attempts carry the same timestamp and the same signature — consistent with the existing pattern
of computing the signature once and passing `signature_ref` into the loop.

```rust
async fn deliver_with_retry(
    &self,
    ep: &octo_store::WebhookEndpoint,
    event_type: &str,
    body: &serde_json::Value,
    body_bytes: &[u8],
) -> bool {
    // Timestamp and signature captured once; reused across retries.
    let timestamp_secs = chrono::Utc::now().timestamp();
    let signature = sign::sign_with_timestamp(ep.secret.as_bytes(), timestamp_secs, body_bytes);
    let timestamp_str = timestamp_secs.to_string();

    // ... (circuit breaker, attempts counter, last outcome — unchanged)

    let result = tokio::time::timeout(
        self.delivery_timeout,
        octo_resilience::execute(&circuit, &self.retry_policy, CallKind::ReadOnly, move || {
            attempts_ref.fetch_add(1, Ordering::Relaxed);
            async move {
                let outcome = self
                    .attempt_once(ep, signature_ref, &timestamp_str, body_bytes)
                    .await;
                // ...
            }
        }),
    )
    .await;
    // ...
}
```

#### Updated `attempt_once`

```rust
async fn attempt_once(
    &self,
    ep: &octo_store::WebhookEndpoint,
    signature: &str,
    timestamp: &str,
    body_bytes: &[u8],
) -> AttemptOutcome {
    let resp = self
        .http
        .post(&ep.url)
        .header("content-type", "application/json")
        .header(sign::SIGNATURE_HEADER, signature)
        .header(sign::TIMESTAMP_HEADER, timestamp)   // ← new
        .body(body_bytes.to_vec())
        .send()
        .await;
    // ... (response streaming, snippet — unchanged)
}
```

The `timestamp` value is a decimal string of epoch seconds — it is not a secret and does not
need to be added to the `response_snippet` redaction set.

### Deprecation of the old body-only signature

During the deprecation period, `deliver_with_retry` sends **both** headers:

```
X-Octo-Signature:  <HMAC over timestamp.body>   ← new format
X-Octo-Timestamp:  <epoch seconds>
X-Octo-Signature-Legacy: <HMAC over body only>  ← old format, deprecated
```

`X-Octo-Signature-Legacy` gives existing consumers that check `X-Octo-Signature` a grace
period to migrate. After the deprecation window, `X-Octo-Signature-Legacy` is removed from
the send path and the old `sign` / `verify` functions are deleted.

Add the legacy header constant:

```rust
/// Deprecated: HMAC over body only, without timestamp. Removed after migration window.
pub const SIGNATURE_HEADER_LEGACY: &str = "X-Octo-Signature-Legacy";
```

### Consumer verification sample (for docs)

Per the issue's acceptance criteria, documentation must include consumer verification samples.

**Node.js:**

```js
const crypto = require('crypto');

const TOLERANCE_SECS = 300; // 5 minutes

function verifyOctoWebhook(secret, body, sigHex, timestampStr) {
    const nowSecs = Math.floor(Date.now() / 1000);
    const ts = parseInt(timestampStr, 10);
    if (Math.abs(nowSecs - ts) > TOLERANCE_SECS) {
        throw new Error('Webhook timestamp outside tolerance window — possible replay');
    }
    const input = Buffer.concat([
        Buffer.from(`${ts}.`),
        Buffer.isBuffer(body) ? body : Buffer.from(body),
    ]);
    const expected = crypto
        .createHmac('sha256', secret)
        .update(input)
        .digest('hex');
    // Constant-time comparison to prevent timing attacks.
    if (expected.length !== sigHex.length) throw new Error('Invalid signature');
    if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sigHex))) {
        throw new Error('Webhook signature invalid');
    }
}
```

**Python:**

```python
import hashlib, hmac, time

TOLERANCE_SECS = 300

def verify_octo_webhook(secret: bytes, body: bytes, sig_hex: str, timestamp_str: str) -> None:
    ts = int(timestamp_str)
    if abs(time.time() - ts) > TOLERANCE_SECS:
        raise ValueError("Webhook timestamp outside tolerance window — possible replay")
    signing_input = f"{ts}.".encode() + body
    expected = hmac.new(secret, signing_input, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig_hex):
        raise ValueError("Webhook signature invalid")
```

Both samples use constant-time comparison (`crypto.timingSafeEqual` / `hmac.compare_digest`)
for the same reason the server does: a variable-time comparison leaks timing information.

## Implementation tasks

1. **`crates/webhooks/src/sign.rs`**:
   - Add `signing_input` private helper.
   - Add `sign_with_timestamp(secret, timestamp_secs, body) -> String`.
   - Add `verify_with_tolerance(secret, body, timestamp_secs, sig_hex, now_secs, tolerance_secs) -> Result<(), ReplayError>`.
   - Add `ReplayError` enum and `DEFAULT_TOLERANCE_SECS` constant.
   - Add `TIMESTAMP_HEADER` and `SIGNATURE_HEADER_LEGACY` constants.
   - Keep existing `sign` and `verify` intact (deprecation period).

2. **`crates/webhooks/src/lib.rs`**:
   - Update `deliver_with_retry` to capture timestamp once and call `sign_with_timestamp`.
   - Update `attempt_once` signature to accept `timestamp: &str`; add `TIMESTAMP_HEADER` to
     the outgoing request.
   - Add `SIGNATURE_HEADER_LEGACY` header with body-only signature during deprecation period.

3. **`docs/api.md`** (or a new `docs/webhooks.md`):
   - Document `X-Octo-Timestamp` and updated `X-Octo-Signature` format.
   - Include the Node.js and Python consumer verification samples.
   - Note the deprecation of `X-Octo-Signature-Legacy` and the migration timeline.

## Security considerations

- **Timestamp in the HMAC input, not just the header** — sending `X-Octo-Timestamp` without
  mixing it into the HMAC input would let an attacker strip the old timestamp and replace it
  with a current one, bypassing the replay protection entirely. The timestamp must be part of
  the signed message.
- **Constant-time comparison** — `mac.verify_slice` must remain the comparison primitive. Any
  future refactor that replaces it with `== ` over the decoded bytes or the hex strings
  re-introduces a timing oracle. The doc-comment on `verify_with_tolerance` states this
  explicitly.
- **Tolerance window direction** — using `abs()` accepts timestamps that are slightly in the
  future (clock skew between server and consumer). This is intentional and standard. The window
  is short (5 minutes default), limiting the attack surface.
- **Replay within the window** — within the tolerance window a valid delivery can still be
  replayed. Consumers that need strict once-only delivery must track seen delivery IDs (e.g.
  the event `id` in the envelope) in addition to checking the timestamp. The timestamp check
  is a significant improvement over no check at all; document this residual risk.
- **Signature computed once per delivery job** — the timestamp and signature are captured
  before the retry loop. A delivery that is retried over several minutes could carry a
  timestamp that is minutes old by the final attempt. With a 5-minute tolerance and a 20-second
  delivery timeout (`delivery_timeout`), this is not a problem in practice. If the delivery
  timeout were ever extended beyond the tolerance window, the timestamp would need to be
  refreshed per attempt.
- **Legacy header removal** — the `X-Octo-Signature-Legacy` header must have a firm removal
  date communicated to consumers. Leaving it indefinitely defeats the purpose of this change:
  a consumer that never migrates off the legacy header is still vulnerable to replay.
