-- Increment 4 migration: fix tenant isolation bugs found in security review.
--
-- 1. registered_apis.name was UNIQUE globally (leftover from schema.sql,
--    before tenant_id existed). Fix: scope uniqueness to (tenant_id, name).
--
-- 2. api_credentials had no uniqueness constraint on
--    (registered_api_id, header_name), so re-adding a credential created
--    a shadow row instead of replacing the first. Fix: add the constraint
--    so add_credential can upsert cleanly.
--
-- Idempotent: safe to re-run on every docker-compose up --build.
-- PostgreSQL has no ADD CONSTRAINT IF NOT EXISTS syntax, so each
-- constraint is guarded by a DO block that checks pg_constraint first.

-- Drop the old global unique constraint if it still exists (idempotent).
ALTER TABLE registered_apis DROP CONSTRAINT IF EXISTS registered_apis_name_key;

-- Add per-tenant uniqueness constraint (idempotent via pg_constraint check).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'registered_apis_tenant_name_key'
    ) THEN
        ALTER TABLE registered_apis
            ADD CONSTRAINT registered_apis_tenant_name_key UNIQUE (tenant_id, name);
    END IF;
END;
$$;

-- Add per-API-per-header uniqueness constraint (idempotent via pg_constraint check).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'api_credentials_api_header_key'
    ) THEN
        ALTER TABLE api_credentials
            ADD CONSTRAINT api_credentials_api_header_key UNIQUE (registered_api_id, header_name);
    END IF;
END;
$$;