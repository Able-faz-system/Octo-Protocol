# Running octo-server with multiple replicas

`octo-server` runs the REST API and the deposit ingest supervisor in one process. You can run
any number of replicas against one Postgres database. Two pieces of state are shared through
that database so replicas behave like a single service.

```
            load balancer
        ┌────────┼────────┐
        ▼        ▼        ▼
   replica A  replica B  replica C      every replica serves the API
   (leader)   (standby)  (standby)      only the lock holder ingests
        │        │        │
        └────────┼────────┘
                 ▼
             Postgres  ── rate_limit_buckets          (shared API rate limits)
                       ── advisory lock (OCTI, net)  (ingest leader election)
```

## Ingest: one leader per network

- On startup every replica calls `pg_try_advisory_lock` for the network it serves. One wins
  and ingests. The others log `another instance is ingesting; standing by`, then retry every
  `INGEST_LOCK_RETRY_SECS` (default 5).
- The lock is session-level and lives on a dedicated connection taken out of the pool. The
  leader releases it on graceful shutdown, and Postgres frees it when that session ends, so a
  crashed leader needs no cleanup.
- **Failover:** a standby takes over within one retry interval after the leader's session
  ends. A leader that is killed or shut down closes its socket immediately. For a leader whose
  host or network disappears, Postgres only notices once TCP keepalive gives up. Set server-side
  `tcp_keepalives_idle` / `tcp_keepalives_interval` / `tcp_keepalives_count` to bound that
  (for example 10s / 5s / 3).
- Before every tick the leader checks `pg_locks` to confirm it still holds the lock. If its
  lock session has died, it stops ingesting and returns to standby instead of running alongside
  the new leader.
- Even if two ingesters briefly overlap, data stays correct: deposits are deduplicated on the
  Horizon operation id (see `docs/ingest-integration.md`). The lock exists to save Horizon quota
  and avoid cursor contention.
- Replicas that serve different networks (`NETWORK`) on the same database each elect their own
  leader. The network name is the second lock key.

## API rate limits: shared counters

`RATE_LIMIT_BACKEND=postgres` (the default) keeps fixed-window counters in the
`rate_limit_buckets` table. Every replica updates them with one atomic upsert, so a limit of 10
per minute stays 10 across N replicas, and the counters survive app restarts. Each replica prunes
expired windows every minute.

`RATE_LIMIT_BACKEND=memory` keeps per-process counters. Use it only for a single instance: with N
replicas the effective limit is N times higher, and every restart resets it.

If Postgres errors during a check, that replica falls back to its in-memory counter. Limits are
still enforced, just per-process, until the database recovers.

## Connection budget

Each replica opens up to `DB_MAX_CONNECTIONS` pooled connections (default 10). The ingest leader
also holds 1 dedicated lock connection. Keep
`replicas × (DB_MAX_CONNECTIONS + 1)` comfortably below Postgres' `max_connections`.

**Do not put a transaction-mode pooler (for example PgBouncer `pool_mode=transaction`) in front
of these connections.** Session advisory locks and the per-session `statement_timeout` need
session pooling or direct connections.

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `DB_MAX_CONNECTIONS` | 10 | Pool size (1–1000) |
| `DB_ACQUIRE_TIMEOUT_SECS` | 30 | Max wait for a pooled connection (≥ 1) |
| `DB_IDLE_TIMEOUT_SECS` | 600 | Close idle pooled connections after this (≥ 1) |
| `DB_STATEMENT_TIMEOUT_SECS` | 30 | Per-statement cap on every pooled connection; `0` disables it. Migrations always run without it. |
| `RATE_LIMIT_BACKEND` | `postgres` | `postgres` or `memory` |
| `INGEST_LOCK_RETRY_SECS` | 5 | Standby lock-retry interval (≥ 1); bounds failover time |

Invalid values stop the server at startup with a message naming the variable.
