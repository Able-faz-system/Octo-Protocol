-- Migration 0021: soft-delete webhook endpoints to preserve delivery history.
--
-- Audit of current foreign key behavior:
-- In 0001_init.sql, `webhook_deliveries.endpoint_id` references `webhook_endpoints(id) ON DELETE CASCADE`.
-- A hard DELETE on `webhook_endpoints` cascades and permanently purges all historical delivery records
-- for that endpoint, destroying the audit trail.
--
-- Adding `deleted_at TIMESTAMPTZ` allows retiring endpoints while keeping historical deliveries intact
-- and attributable.

ALTER TABLE webhook_endpoints
    ADD COLUMN deleted_at TIMESTAMPTZ;

-- Filtered index to exclude soft-deleted endpoints on active delivery paths.
CREATE INDEX idx_webhook_endpoints_active_not_deleted
    ON webhook_endpoints (wallet_id)
    WHERE deleted_at IS NULL AND active = true;

-- Filtered index for listing endpoints for a wallet.
CREATE INDEX idx_webhook_endpoints_wallet_not_deleted
    ON webhook_endpoints (wallet_id, created_at)
    WHERE deleted_at IS NULL;
