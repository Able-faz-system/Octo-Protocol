-- Covering index for the ingest supervisor's wallets_due_for_poll query.
--
-- wallets_due_for_poll runs on every supervisor tick for every network, joining
-- wallets with ingest_cursor to schedule poll jobs with activity-based backoff.
-- An index on wallets(network) and ingest_cursor(wallet_id, last_polled_at, updated_at)
-- avoids sequential scans on both tables as wallet count scales.

CREATE INDEX IF NOT EXISTS idx_wallets_network
    ON wallets (network);

CREATE INDEX IF NOT EXISTS idx_ingest_cursor_poll_schedule
    ON ingest_cursor (wallet_id, last_polled_at, updated_at);
