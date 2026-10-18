-- Dead-letter state for webhook deliveries whose retries are exhausted (#458).
--
-- 'dead' is terminal: the sender gave up on an event after its retry policy ran out (or the
-- endpoint gave a non-retriable answer). 'failed' is kept for rows written before this
-- migration and for deliveries that were never attempted (e.g. an unsafe URL) or were
-- diagnostic only (test pings).
ALTER TABLE webhook_deliveries DROP CONSTRAINT webhook_deliveries_status_check;
ALTER TABLE webhook_deliveries ADD CONSTRAINT webhook_deliveries_status_check
    CHECK (status IN ('pending', 'delivered', 'failed', 'dead'));

-- Serves `GET .../deliveries?status=dead` without scanning an endpoint's whole history.
CREATE INDEX idx_webhook_deliveries_endpoint_status
    ON webhook_deliveries (endpoint_id, status, created_at DESC);

-- Consecutive dead deliveries, reset by any successful delivery. When it reaches the
-- operator-configured threshold the endpoint is deactivated and `auto_disabled_at` is stamped.
ALTER TABLE webhook_endpoints
    ADD COLUMN consecutive_dead_deliveries INTEGER NOT NULL DEFAULT 0
        CHECK (consecutive_dead_deliveries >= 0),
    ADD COLUMN auto_disabled_at TIMESTAMPTZ;
