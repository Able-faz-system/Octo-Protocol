-- Idempotency keys for retried creates (Issue #453), starting with payment link creation.
--
-- One row per (wallet, operation scope, client key). `request_hash` is the SHA-256 of the raw
-- request body, so the same key with a different body is detected and refused. `response` is
-- NULL while the first request is still in flight; once set it is replayed verbatim.
CREATE TABLE idempotency_keys (
    wallet_id    UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    scope        TEXT NOT NULL,
    key          TEXT NOT NULL CHECK (length(key) BETWEEN 1 AND 255),
    request_hash TEXT NOT NULL,
    status_code  SMALLINT,
    response     JSONB,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (wallet_id, scope, key)
);

-- The hourly purge deletes by expiry.
CREATE INDEX idx_idempotency_keys_expires_at ON idempotency_keys (expires_at);
