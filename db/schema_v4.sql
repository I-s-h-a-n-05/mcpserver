-- Increment 5 migration: tool call audit log.
--
-- Required before any write-capable (POST/PUT/PATCH/DELETE) real tool goes
-- live. This is the only record of which tenant called which tool, with
-- what arguments, and whether it succeeded -- there is no other audit
-- trail once real production tools are registered.
--
-- Arguments are agent-supplied inputs only. Credentials are never stored
-- here -- decrypted credential values never leave execution_proxy.execute()
-- (see execution_proxy.py), so there is nothing secret to accidentally log.
--
-- Idempotent: safe to re-run on every docker-compose up --build.

CREATE TABLE IF NOT EXISTS tool_call_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    tool_name   TEXT NOT NULL,
    arguments   JSONB NOT NULL DEFAULT '{}'::jsonb,
    status      TEXT NOT NULL,        -- 'success' or 'error'
    detail      TEXT,                 -- error message on failure, NULL on success
    called_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Access pattern is always "most recent calls for this tenant" (the admin
-- /logs endpoint below), so index on that combination directly.
CREATE INDEX IF NOT EXISTS tool_call_log_tenant_called_at_idx
    ON tool_call_log (tenant_id, called_at DESC);