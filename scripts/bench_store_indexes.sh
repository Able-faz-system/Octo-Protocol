#!/usr/bin/env bash
# DEV / BENCHMARKING TOOL — not run in CI, not part of the app. Throwaway data generator + EXPLAIN
# ANALYZE harness for the sponsored_transactions / audit_logs indexing overhaul
# (hard/store/indexing-overhaul-with-load-test). Never point this at a real environment.
#
# Usage:
#   DATABASE_URL=postgres://octo:octo@localhost:5432/octo ./scripts/bench_store_indexes.sh seed
#   DATABASE_URL=postgres://octo:octo@localhost:5432/octo ./scripts/bench_store_indexes.sh explain | tee /tmp/before.txt
#   # ... apply the crates/store/migrations/0008_*.sql migration (cargo run's Store::migrate, or
#   #     sqlx migrate run) ...
#   DATABASE_URL=postgres://octo:octo@localhost:5432/octo ./scripts/bench_store_indexes.sh explain | tee /tmp/after.txt
#   DATABASE_URL=postgres://octo:octo@localhost:5432/octo ./scripts/bench_store_indexes.sh clean
#
# `seed` inserts SPONSORED_ROWS sponsored_transactions rows (default 500000) and AUDIT_ROWS
# audit_logs rows (default 200000) across N_WALLETS/N_USERS (default 300 each), skewed so a small
# minority of wallets/users own a disproportionate share — mirroring a handful of "hot" production
# accounts. `explain` runs EXPLAIN (ANALYZE, BUFFERS) for every hot query path in
# crates/store/src/lib.rs against the current busiest wallet/user, so it can be captured verbatim
# before and after the index migration. `clean` deletes only the rows this script inserted (all
# tagged with a 'bench-seed-' prefix), leaving any other data in the database untouched.
set -euo pipefail

: "${DATABASE_URL:?Set DATABASE_URL to a scratch/dev Postgres, e.g. the docker-compose db service}"
SPONSORED_ROWS="${SPONSORED_ROWS:-500000}"
AUDIT_ROWS="${AUDIT_ROWS:-200000}"
N_WALLETS="${N_WALLETS:-300}"
N_USERS="${N_USERS:-300}"

psql_run() {
    psql "$DATABASE_URL" -X -q -v ON_ERROR_STOP=1 "$@"
}

cmd_seed() {
    echo "Seeding ${N_WALLETS} wallets / ${N_USERS} users, ${SPONSORED_ROWS} sponsored_transactions, ${AUDIT_ROWS} audit_logs ..." >&2

    psql_run -v n_wallets="$N_WALLETS" -v n_users="$N_USERS" \
        -v sponsored_rows="$SPONSORED_ROWS" -v audit_rows="$AUDIT_ROWS" <<'SQL'
BEGIN;

-- Wallets and users to hang the load-test rows off of. Skewed pick functions below concentrate
-- most rows on the first few ids (index 0), simulating a handful of hot accounts.
INSERT INTO wallets (network, stellar_account_g, sealed_ciphertext, sealed_nonce, sealed_salt, label)
SELECT
    'testnet',
    'bench-seed-wallet-' || gs.i,
    ('\x' || md5('ciphertext' || gs.i))::bytea,
    ('\x' || left(md5('nonce' || gs.i), 24))::bytea,
    ('\x' || md5('salt' || gs.i))::bytea,
    'bench-seed'
FROM generate_series(1, :n_wallets) AS gs(i);

INSERT INTO users (email, password_hash)
SELECT
    'bench-seed-user-' || gs.i || '@example.invalid',
    'bench-seed-not-a-real-hash'
FROM generate_series(1, :n_users) AS gs(i);

-- Power-law-ish pick: pow(random(), 4) concentrates near 0, so low-index wallets/users
-- (the "hot" ones) get picked far more often than the rest of the pool.
INSERT INTO sponsored_transactions (wallet_id, inner_tx_hash, fee_stroops, status, fee_bump_tx_hash, created_at)
SELECT
    w.id,
    'bench-seed-inner-' || gs.i,
    100 + floor(random() * 100000)::bigint,
    CASE WHEN r.status_r < 0.7 THEN 'confirmed'
         WHEN r.status_r < 0.9 THEN 'pending'
         ELSE 'failed' END,
    CASE WHEN r.status_r < 0.7 THEN 'bench-seed-bump-' || gs.i ELSE NULL END,
    now() - (power(random(), 3) * interval '400 days')
FROM generate_series(1, :sponsored_rows) AS gs(i)
CROSS JOIN LATERAL (SELECT random() AS status_r) r
JOIN LATERAL (
    SELECT id FROM wallets
    WHERE label = 'bench-seed'
    ORDER BY stellar_account_g
    OFFSET floor(power(random(), 4) * :n_wallets)
    LIMIT 1
) w ON true;

INSERT INTO audit_logs (user_id, action, category, target, ip_address, created_at)
SELECT
    u.id,
    (ARRAY['signed in', 'signed out', 'created wallet bench-seed wallet', 'rotated api key',
           'updated webhook endpoint', 'changed password', 'enabled two factor auth'])[1 + floor(random() * 7)::int],
    (ARRAY['authentication', 'wallet', 'address', 'credentials', 'configuration'])[1 + floor(random() * 5)::int],
    CASE WHEN random() < 0.6 THEN 'bench-seed-target-' || gs.i ELSE NULL END,
    '203.0.113.' || (1 + floor(random() * 254)::int),
    now() - (power(random(), 3) * interval '400 days')
FROM generate_series(1, :audit_rows) AS gs(i)
JOIN LATERAL (
    SELECT id FROM users
    WHERE email LIKE 'bench-seed-user-%'
    ORDER BY email
    OFFSET floor(power(random(), 4) * :n_users)
    LIMIT 1
) u ON true;

COMMIT;
SQL

    echo "Seed complete." >&2
}

cmd_explain() {
    psql_run <<'SQL'
-- Pick the current busiest wallet/user so EXPLAIN ANALYZE exercises the realistic "hot account"
-- case, not a cold/empty one.
SELECT wallet_id AS hot_wallet FROM sponsored_transactions
WHERE inner_tx_hash LIKE 'bench-seed-inner-%'
GROUP BY wallet_id ORDER BY count(*) DESC LIMIT 1 \gset

SELECT user_id AS hot_user FROM audit_logs
WHERE target LIKE 'bench-seed-target-%' OR action IS NOT NULL
GROUP BY user_id ORDER BY count(*) DESC LIMIT 1 \gset

\echo '=== list_sponsored_transactions (no status filter, first page) ==='
EXPLAIN (ANALYZE, BUFFERS)
SELECT * FROM sponsored_transactions
WHERE wallet_id = :'hot_wallet'
ORDER BY created_at DESC, id DESC
LIMIT 25;

\echo '=== list_sponsored_transactions (status = confirmed) ==='
EXPLAIN (ANALYZE, BUFFERS)
SELECT * FROM sponsored_transactions
WHERE wallet_id = :'hot_wallet'
  AND status = 'confirmed'
ORDER BY created_at DESC, id DESC
LIMIT 25;

\echo '=== sum_sponsored_fees_reserved_today / try_reserve_sponsored_transaction budget check ==='
EXPLAIN (ANALYZE, BUFFERS)
SELECT COALESCE(SUM(fee_stroops), 0)::bigint
FROM sponsored_transactions
WHERE wallet_id = :'hot_wallet'
  AND status IN ('pending', 'confirmed')
  AND created_at >= date_trunc('day', now() AT TIME ZONE 'UTC');

\echo '=== sum_sponsored_fees_today (confirmed only) ==='
EXPLAIN (ANALYZE, BUFFERS)
SELECT COALESCE(SUM(fee_stroops), 0)::bigint
FROM sponsored_transactions
WHERE wallet_id = :'hot_wallet'
  AND status = 'confirmed'
  AND created_at >= date_trunc('day', now() AT TIME ZONE 'UTC');

\echo '=== list_audit_logs (category only) ==='
EXPLAIN (ANALYZE, BUFFERS)
SELECT * FROM audit_logs
WHERE user_id = :'hot_user'
  AND category = 'authentication'
ORDER BY created_at DESC
LIMIT 25;

\echo '=== list_audit_logs (ILIKE search, the trigram-index case) ==='
EXPLAIN (ANALYZE, BUFFERS)
SELECT * FROM audit_logs
WHERE user_id = :'hot_user'
  AND (action ILIKE '%wallet%' OR coalesce(target, '') ILIKE '%wallet%')
ORDER BY created_at DESC
LIMIT 25;

\echo '=== wallets_due_for_poll (ingest supervisor tick) ==='
EXPLAIN (ANALYZE, BUFFERS)
SELECT w.* FROM wallets w
LEFT JOIN ingest_cursor c ON c.wallet_id = w.id
WHERE w.network = 'testnet'
  AND (
    c.last_polled_at IS NULL
    OR c.updated_at IS NULL
    OR c.last_polled_at < now() - make_interval(secs =>
         CASE
           WHEN c.updated_at > now() - make_interval(secs => 60.0) THEN 0
           WHEN c.updated_at <= now() - make_interval(secs => 300.0) THEN 100000.0
           ELSE 100.0
         END)
  )
ORDER BY w.created_at;

-- EXPLAIN ANALYZE actually executes INSERTs, so wrap each probe in its own rolled-back
-- transaction — the seeded data (and the row count the other queries above measured against)
-- must be left untouched.
\echo '=== write path: INSERT into sponsored_transactions (index maintenance cost) ==='
BEGIN;
EXPLAIN (ANALYZE, BUFFERS)
INSERT INTO sponsored_transactions (wallet_id, inner_tx_hash, fee_stroops, status)
VALUES (:'hot_wallet', 'bench-seed-explain-insert-probe', 1000, 'pending');
ROLLBACK;

\echo '=== write path: INSERT into audit_logs (index maintenance cost) ==='
BEGIN;
EXPLAIN (ANALYZE, BUFFERS)
INSERT INTO audit_logs (user_id, action, category, target)
VALUES (:'hot_user', 'bench probe', 'authentication', NULL);
ROLLBACK;
SQL
}

cmd_clean() {
    echo "Removing bench-seed rows ..." >&2
    psql_run <<'SQL'
DELETE FROM sponsored_transactions WHERE inner_tx_hash LIKE 'bench-seed-%';
DELETE FROM audit_logs WHERE target LIKE 'bench-seed-target-%' OR action = 'bench probe';
DELETE FROM wallets WHERE label = 'bench-seed';
DELETE FROM users WHERE email LIKE 'bench-seed-user-%@example.invalid';
SQL
    echo "Clean complete." >&2
}

case "${1:-}" in
    seed) cmd_seed ;;
    explain) cmd_explain ;;
    clean) cmd_clean ;;
    *)
        echo "Usage: $0 {seed|explain|clean}" >&2
        exit 1
        ;;
esac
