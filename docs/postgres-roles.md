# Least-privilege Postgres roles

By default the server connects as whatever `DATABASE_URL` names — usually the database owner — and
runs migrations on boot. That means a SQL-injection foothold or an application bug has schema-level
reach: `DROP TABLE`, `ALTER TABLE ... DISABLE TRIGGER`, `TRUNCATE audit_logs`. Production should
split the two jobs across separate roles.

## Roles

| Role | Login | Owns / can do | Used by |
|---|---|---|---|
| `octo_migrator` | yes | Owns the schema and every table; DDL; `CREATE` on the database (trusted extensions such as `pg_trgm`) | `octo-server --migrate-only`, during deploys only |
| `octo_app` | yes | `SELECT, INSERT, UPDATE, DELETE` on tables, `USAGE, SELECT` on sequences. No DDL, no `TRUNCATE`, no ownership, no temp tables. `UPDATE/DELETE` on `audit_logs` and all writes to `_sqlx_migrations` revoked | The running API (`RUN_MIGRATIONS=false`) |
| `octo_audit_retention` | no | Membership bypasses the `audit_logs` append-only trigger (migration `0026`) | Granted temporarily to a purge login, never to `octo_app` |

Why the runtime role must not own tables: an owner can `ALTER TABLE audit_logs DISABLE TRIGGER`,
which defeats the append-only guarantee in [audit-log.md](audit-log.md). Why temp tables are revoked:
a temp table named like a real one is resolved first by default and can spoof unqualified lookups.

`users -> audit_logs` is `ON DELETE CASCADE`. Postgres runs that cascade as the table owner, so
`octo_app` needs no `DELETE` on `audit_logs` for signup rollback (`delete_unverified_user`) to work.

## Exact grants

`scripts/db/init-roles.sh` is the source of truth; it is idempotent and runs as a superuser. The
statements it applies (with `octo` / `public` as the database / schema):

```sql
CREATE ROLE octo_migrator LOGIN PASSWORD '…';
CREATE ROLE octo_app      LOGIN PASSWORD '…';
CREATE ROLE octo_audit_retention NOLOGIN;

REVOKE ALL    ON DATABASE octo   FROM PUBLIC;   -- drops PUBLIC CONNECT and TEMP
REVOKE CREATE ON SCHEMA   public FROM PUBLIC;
GRANT  CONNECT ON DATABASE octo TO octo_migrator, octo_app;

GRANT CREATE ON DATABASE octo TO octo_migrator;
ALTER SCHEMA public OWNER TO octo_migrator;

GRANT USAGE ON SCHEMA public TO octo_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES    IN SCHEMA public TO octo_app;
GRANT USAGE, SELECT                  ON ALL SEQUENCES IN SCHEMA public TO octo_app;
ALTER DEFAULT PRIVILEGES FOR ROLE octo_migrator IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO octo_app;
ALTER DEFAULT PRIVILEGES FOR ROLE octo_migrator IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO octo_app;

-- Applied once the tables exist (re-run the script after migrating):
REVOKE UPDATE, DELETE, TRUNCATE        ON public.audit_logs       FROM octo_app;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public._sqlx_migrations FROM octo_app;
```

## Fresh database

1. Run `scripts/db/init-roles.sh` as a superuser (`OCTO_MIGRATOR_PASSWORD`, `OCTO_APP_PASSWORD`).
2. Apply migrations as the migrator — only `DATABASE_URL` is needed, no app secrets:
   `DATABASE_URL=postgres://octo_migrator:…@host/octo octo-server --migrate-only`
3. Re-run `scripts/db/init-roles.sh` so the table-specific `REVOKE`s land.
4. Start the server as the runtime role with `RUN_MIGRATIONS=false`:
   `DATABASE_URL=postgres://octo_app:…@host/octo`

Repeat steps 2–3 on every deploy that adds a migration. New tables pick up `octo_app` grants
automatically through the default privileges; only the narrowing `REVOKE`s need the re-run.

A local version of the whole flow is in
[examples/docker-compose.least-privilege.yml](examples/docker-compose.least-privilege.yml).

## Existing database (owned by the old app role)

Transfer ownership of every object to `octo_migrator`, then follow the fresh-database steps from 1:

```sql
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT format('ALTER %s %I.%I OWNER TO octo_migrator',
                         CASE c.relkind WHEN 'S' THEN 'SEQUENCE' ELSE 'TABLE' END,
                         n.nspname, c.relname) AS stmt
           FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'S')
             AND NOT EXISTS (SELECT 1 FROM pg_depend d          -- skip identity/serial sequences;
                             WHERE d.objid = c.oid AND d.deptype IN ('a', 'i')) -- they follow their table
  LOOP EXECUTE r.stmt; END LOOP;
END $$;
ALTER FUNCTION audit_logs_retention_allowed() OWNER TO octo_migrator;
ALTER FUNCTION audit_logs_block_mutation()    OWNER TO octo_migrator;
ALTER FUNCTION audit_logs_block_truncate()    OWNER TO octo_migrator;
```

## Purging audit rows (retention)

Audit rows are append-only. When a retention policy genuinely requires deleting them:

```sql
GRANT octo_audit_retention TO <dedicated purge login>;   -- never octo_app
-- connect as that login, delete the rows, then:
REVOKE octo_audit_retention FROM <dedicated purge login>;
```

Record who ran the purge and why outside the database (change ticket) — the purge itself is, by
design, the one thing `audit_logs` cannot record about itself.

## Status

The script and runbook have **not yet been run end-to-end against a fresh database** (acceptance
criterion of #439). Do that before relying on it in production and remove this note.
