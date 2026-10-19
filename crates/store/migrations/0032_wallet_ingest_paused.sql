-- Per-wallet ingest pause (Issue #450): operators can stop polling a misbehaving wallet
-- without deleting it. Pausing never touches ingest_cursor, so a resume continues from the
-- saved paging token with no gap and no replay.
ALTER TABLE wallets
    ADD COLUMN ingest_paused    BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN ingest_paused_at TIMESTAMPTZ;

-- The supervisor's due-for-poll scan only ever walks unpaused wallets of one network by id.
CREATE INDEX idx_wallets_ingest_active
    ON wallets (network, id)
    WHERE ingest_paused = false;
