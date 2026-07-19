-- Increment 2 schema. Deliberately NO tenant_id, NO api_keys, NO credentials
-- table yet -- those arrive with the auth/multi-tenancy increment. Every API
-- registered here is globally visible to any caller, which is fine for this
-- increment's purpose (prove DB -> tool conversion -> real HTTP execution)
-- and NOT how this looks in production.

CREATE TABLE IF NOT EXISTS registered_apis (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT UNIQUE NOT NULL,          -- becomes the MCP tool name
    description TEXT NOT NULL,          -- becomes the MCP tool description
    method TEXT NOT NULL,               -- GET, POST, PUT, DELETE, etc.
    url_template TEXT NOT NULL,         -- e.g. https://api.github.com/repos/{owner}/{repo}
    path_params JSONB NOT NULL DEFAULT '{}'::jsonb,   -- {"owner": {"type": "string", "description": "..."}}
    query_params JSONB NOT NULL DEFAULT '{}'::jsonb,
    body_params JSONB NOT NULL DEFAULT '{}'::jsonb,
    static_headers JSONB NOT NULL DEFAULT '{}'::jsonb, -- non-secret headers, e.g. Accept
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);