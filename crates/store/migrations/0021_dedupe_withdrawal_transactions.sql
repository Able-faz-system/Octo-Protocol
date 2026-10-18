-- Withdrawal history rows had no uniqueness guard (unlike deposits' (tx_hash, operation_index)
-- index), so a retried status update could record the same outbound transfer twice.

-- Collapse any existing duplicates first so the unique index can build: keep one row per
-- (wallet_id, stellar_tx_hash), preferring a confirmed row, then the earliest.
DELETE FROM transactions t
USING (
    SELECT id,
           row_number() OVER (
               PARTITION BY wallet_id, stellar_tx_hash
               ORDER BY (status = 'confirmed') DESC, created_at, id
           ) AS rn
    FROM transactions
    WHERE direction = 'withdrawal' AND stellar_tx_hash IS NOT NULL
) d
WHERE t.id = d.id AND d.rn > 1;

-- One history row per outbound transaction per wallet. Rows without a hash stay unconstrained.
CREATE UNIQUE INDEX idx_tx_withdrawal_unique
    ON transactions (wallet_id, stellar_tx_hash)
    WHERE stellar_tx_hash IS NOT NULL AND direction = 'withdrawal';
