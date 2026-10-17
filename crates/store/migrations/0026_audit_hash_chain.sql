-- Tamper-evident audit log: a per-user HMAC hash chain (issue #437).
--
-- Each chained row stores its position (`seq`, 1-based per user), the previous row's hash
-- (`prev_hash`, 32 zero bytes for seq = 1) and its own `row_hash` = HMAC-SHA256(AUDIT_CHAIN_KEY,
-- prev_hash || row fields). The key never touches the database, so someone with DB write access
-- can't recompute hashes after an edit. `audit_chain_heads` pins the newest link per user under its
-- own MAC, so deleting rows off the end of a chain is detected too.
--
-- Rows written before this migration stay unchained (seq IS NULL) until that user's next audit
-- event, which adopts them into the chain in (created_at, id) order. See docs/audit-log.md.

ALTER TABLE audit_logs
    ADD COLUMN seq       BIGINT,
    ADD COLUMN prev_hash BYTEA,
    ADD COLUMN row_hash  BYTEA;

-- A row is either fully chained or fully legacy, never half of each.
ALTER TABLE audit_logs
    ADD CONSTRAINT audit_logs_chain_complete CHECK (
        (seq IS NULL AND prev_hash IS NULL AND row_hash IS NULL)
        OR (seq >= 1 AND octet_length(prev_hash) = 32 AND octet_length(row_hash) = 32)
    );

-- Backstop for the writer's per-user lock: two rows can never claim the same chain position.
CREATE UNIQUE INDEX idx_audit_user_seq ON audit_logs (user_id, seq) WHERE seq IS NOT NULL;

CREATE TABLE audit_chain_heads (
    user_id    UUID        PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    seq        BIGINT      NOT NULL CHECK (seq >= 1),
    row_hash   BYTEA       NOT NULL CHECK (octet_length(row_hash) = 32),
    head_mac   BYTEA       NOT NULL CHECK (octet_length(head_mac) = 32),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
