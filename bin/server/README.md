# octo-server

The deployable binary. Composes `octo-api` + `octo-ingest` into one process (splittable
later to scale ingest independently). Wired in Step 11.

Safe to run as several replicas on one database: API rate limits are shared through Postgres,
and an advisory lock makes exactly one replica per network run ingest. See
[`docs/ha-topology.md`](../../docs/ha-topology.md) for the topology, failover behaviour, and the
`DB_*`, `RATE_LIMIT_BACKEND` and `INGEST_LOCK_RETRY_SECS` settings.
