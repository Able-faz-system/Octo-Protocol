-- Let the audit hash chain adopt legacy rows despite the append-only trigger (0026 + 0029).
--
-- 0029 adopts pre-chain rows (seq IS NULL) by filling seq / prev_hash / row_hash in place. The
-- append-only trigger from 0026 would reject that UPDATE. This narrows the exception as far as
-- possible: an UPDATE is allowed only when the row is still unchained and every column other
-- than the three chain columns is unchanged. Chained rows, and any edit to row content, stay
-- blocked. Everything else (DELETE rules, retention role, FK cascade) is unchanged.
CREATE OR REPLACE FUNCTION audit_logs_block_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    owner_gone boolean;
BEGIN
    IF audit_logs_retention_allowed() THEN
        RETURN COALESCE(NEW, OLD);
    END IF;
    -- Legacy-row adoption into the hash chain: fill the chain columns of an unchained row only.
    IF TG_OP = 'UPDATE'
       AND OLD.seq IS NULL AND OLD.prev_hash IS NULL AND OLD.row_hash IS NULL
       AND NEW.seq IS NOT NULL
       AND (to_jsonb(NEW) - 'seq' - 'prev_hash' - 'row_hash')
           = (to_jsonb(OLD) - 'seq' - 'prev_hash' - 'row_hash') THEN
        RETURN NEW;
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
