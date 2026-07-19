-- Increment 3 migration. Run once against the existing mcp_gateway DB.
-- DESTRUCTIVE: truncates registered_apis (dev only -- no real data yet).
-- In production this would be a proper versioned migration (Alembic etc).

BEGIN;

CREATE TABLE IF NOT EXISTS tenants (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT UNIQUE NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS api_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key_hash    TEXT NOT NULL UNIQUE,   -- SHA-256 hex of the raw key
    label       TEXT,                   -- human-readable name for the key
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at  TIMESTAMPTZ             -- NULL = active
);

-- registered_apis needs tenant_id. Clear first since NOT NULL can't be added
-- to existing rows without a default, and we have no prod data to preserve.
TRUNCATE registered_apis CASCADE;
ALTER TABLE registered_apis
    ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE registered_apis
    ALTER COLUMN tenant_id SET NOT NULL;

-- Per-API encrypted credentials. One API can have multiple credentials
-- (e.g. an Authorization header and a separate X-Workspace-Id header).
-- The execution proxy fetches all rows for a given api and injects each
-- as a header, decrypted, right before the outbound HTTP request is sent.
-- The decrypted value never appears in logs, return values, or DB columns.
CREATE TABLE IF NOT EXISTS api_credentials (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    registered_api_id   UUID NOT NULL REFERENCES registered_apis(id) ON DELETE CASCADE,
    header_name         TEXT NOT NULL,       -- e.g. "Authorization"
    encrypted_value     BYTEA NOT NULL,      -- Fernet-encrypted header value
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMIT;