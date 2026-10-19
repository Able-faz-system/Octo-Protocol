-- Indexes for filtered transaction history (Issue #451).
--
-- The main path is "one wallet, newest first, optionally bounded by a date range", paged by the
-- keyset (created_at, id). This composite serves the wallet equality, the range and the ORDER BY
-- in one index scan, and supersedes the single-column idx_tx_wallet (same leading column).
CREATE INDEX idx_tx_wallet_created
    ON transactions (wallet_id, created_at DESC, id DESC);

DROP INDEX IF EXISTS idx_tx_wallet;

-- Reconciliation is usually per asset; status/direction are low-cardinality and filter cheaply
-- on top of either index.
CREATE INDEX idx_tx_wallet_asset_created
    ON transactions (wallet_id, asset_code, created_at DESC, id DESC);
