#!/usr/bin/env bash
# Create octo's least-privilege Postgres roles (issue #439). See docs/postgres-roles.md.
#
# Idempotent; run as a superuser against the target database, BEFORE the first migration:
#   PGHOST=... PGUSER=postgres PGDATABASE=octo \
#   OCTO_MIGRATOR_PASSWORD=... OCTO_APP_PASSWORD=... ./scripts/db/init-roles.sh
#
# Also works unmodified as a /docker-entrypoint-initdb.d script (it reads POSTGRES_DB/USER there).
set -euo pipefail

: "${OCTO_MIGRATOR_PASSWORD:?OCTO_MIGRATOR_PASSWORD is required}"
: "${OCTO_APP_PASSWORD:?OCTO_APP_PASSWORD is required}"
DB="${PGDATABASE:-${POSTGRES_DB:-octo}}"
SCHEMA="${OCTO_SCHEMA:-public}"

psql -v ON_ERROR_STOP=1 \
  --username "${PGUSER:-${POSTGRES_USER:-postgres}}" --dbname "$DB" \
  -v db="$DB" -v schema="$SCHEMA" \
  -v migrator_pw="$OCTO_MIGRATOR_PASSWORD" -v app_pw="$OCTO_APP_PASSWORD" <<'SQL'
-- Passwords go through psql variables so they never appear in `ps` or server logs as literals.
SELECT format('CREATE ROLE octo_migrator LOGIN PASSWORD %L', :'migrator_pw')
  WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'octo_migrator') \gexec
SELECT format('CREATE ROLE octo_app LOGIN PASSWORD %L', :'app_pw')
  WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'octo_app') \gexec
-- Bypass for the audit_logs append-only trigger (0026). NOLOGIN and granted to nobody by default.
SELECT 'CREATE ROLE octo_audit_retention NOLOGIN'
  WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'octo_audit_retention') \gexec

-- Nobody but the migrator may create objects; no temp tables (they can shadow names).
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
REVOKE CREATE ON SCHEMA :"schema" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db" TO octo_migrator, octo_app;

-- Migrator: owns the schema contents. CREATE on the database lets it add trusted extensions.
GRANT CREATE ON DATABASE :"db" TO octo_migrator;
ALTER SCHEMA :"schema" OWNER TO octo_migrator;

-- Runtime: DML only, no DDL, no TRUNCATE, no ownership.
GRANT USAGE ON SCHEMA :"schema" TO octo_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA :"schema" TO octo_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA :"schema" TO octo_app;
ALTER DEFAULT PRIVILEGES FOR ROLE octo_migrator IN SCHEMA :"schema"
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO octo_app;
ALTER DEFAULT PRIVILEGES FOR ROLE octo_migrator IN SCHEMA :"schema"
  GRANT USAGE, SELECT ON SEQUENCES TO octo_app;
SQL

# Table-specific narrowing only applies once the tables exist (i.e. on re-runs after migrating).
psql -v ON_ERROR_STOP=1 \
  --username "${PGUSER:-${POSTGRES_USER:-postgres}}" --dbname "$DB" -v schema="$SCHEMA" <<'SQL'
SELECT format('REVOKE UPDATE, DELETE, TRUNCATE ON %I.audit_logs FROM octo_app', :'schema')
  WHERE to_regclass(format('%I.audit_logs', :'schema')) IS NOT NULL \gexec
SELECT format('REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON %I._sqlx_migrations FROM octo_app', :'schema')
  WHERE to_regclass(format('%I._sqlx_migrations', :'schema')) IS NOT NULL \gexec
SQL
