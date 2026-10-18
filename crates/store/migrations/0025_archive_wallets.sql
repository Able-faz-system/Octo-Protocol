-- Wallet archival: records when a wallet was retired without losing history.
ALTER TABLE wallets ADD COLUMN archived_at TIMESTAMPTZ;
CREATE INDEX idx_wallets_archived_at ON wallets (archived_at);
