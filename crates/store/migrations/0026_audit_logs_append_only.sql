-- Enforce append-only audit_logs at the database level (issue #438).
--
-- Until now "append-only" was a convention. These triggers make UPDATE, DELETE and TRUNCATE raise,
-- so a SQL-injection foothold or an application bug can't rewrite or erase the trail.
--
-- Two deliberate escape hatches:
--   1. Retention: a session whose role is a member of `octo_audit_retention` may delete/update.
--      The role is created out-of-band by an operator (see docs/postgres-roles.md); it is never
--      granted to the runtime role. If it does not exist, nobody has the bypass.
--   2. FK cascade: `users ON DELETE CASCADE` must keep working (signup rollback deletes an
--      unverified user who already has a "created an account" row). By the time the cascade
--      reaches audit_logs the parent user row is gone, so only orphaned rows can be deleted.
--
-- Note: superusers and the table owner can still DISABLE TRIGGER; the runtime role must therefore
-- be neither (again, see docs/postgres-roles.md).

-- Every function pins search_path (pg_temp last) so a session can't shadow pg_roles or users with
-- a temp table of the same name and fake the checks below.
CREATE OR REPLACE FUNCTION audit_logs_retention_allowed() RETURNS boolean
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    -- Checked in two steps: pg_has_role raises if the role does not exist.
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'octo_audit_retention') THEN
        RETURN false;
    END IF;
    RETURN pg_has_role(current_user, 'octo_audit_retention', 'MEMBER');
END;
$$;

CREATE OR REPLACE FUNCTION audit_logs_block_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    owner_gone boolean;
BEGIN
    IF audit_logs_retention_allowed() THEN
        RETURN COALESCE(NEW, OLD);
    END IF;
    -- Cascade from a deleted user: the owning row (same schema as audit_logs) is already gone.
    IF TG_OP = 'DELETE' THEN
        EXECUTE format('SELECT NOT EXISTS (SELECT 1 FROM %I.users WHERE id = $1)', TG_TABLE_SCHEMA)
            INTO owner_gone USING OLD.user_id;
        IF owner_gone THEN
            RETURN OLD;
        END IF;
    END IF;
    RAISE EXCEPTION 'audit_logs is append-only: % is not permitted', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE OR REPLACE FUNCTION audit_logs_block_truncate() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF audit_logs_retention_allowed() THEN
        RETURN NULL;
    END IF;
    RAISE EXCEPTION 'audit_logs is append-only: TRUNCATE is not permitted'
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER audit_logs_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_logs_block_mutation();

CREATE TRIGGER audit_logs_no_truncate
    BEFORE TRUNCATE ON audit_logs
    FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_block_truncate();
