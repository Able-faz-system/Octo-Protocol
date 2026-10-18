-- Shared fixed-window rate-limit counters, so limits hold across API replicas and restarts.
--
-- UNLOGGED: counters are hot, short-lived and cheap to lose. They survive app restarts and
-- clean Postgres restarts; only a Postgres crash truncates them (limits briefly reset).
CREATE UNLOGGED TABLE rate_limit_buckets (
    key        TEXT        NOT NULL,
    class      TEXT        NOT NULL,
    hits       BIGINT      NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (key, class)
);

-- The periodic prune deletes by expiry.
CREATE INDEX idx_rate_limit_buckets_expires_at ON rate_limit_buckets (expires_at);
