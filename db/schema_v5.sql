-- Increment 6 migration: OAuth 2.0 token storage.
--
-- Supports the authorization code grant flow. The admin registers
-- client credentials (client_id, client_secret, token_url) for a given
-- registered API via POST /admin/apis/{name}/oauth-client. Later,
-- POST /admin/oauth/authorize + GET /admin/oauth/callback (increment 3)
-- complete the consent flow and fill in encrypted_access_token,
-- encrypted_refresh_token, and token_expiry.
--
-- execution_proxy reads this table on every tool call. If a row exists
-- and token_expiry is within 5 minutes, it refreshes the access token
-- inline using the stored refresh_token + client credentials, then
-- updates this table with the new values before proceeding.
--
-- Everything secret (client_secret, access_token, refresh_token) is
-- Fernet-encrypted at rest. Decryption happens only inside
-- execution_proxy.execute() and the refresh helper, never in registry.py.
--
-- One row per registered API. UNIQUE(registered_api_id) enforces this.
--
-- Idempotent: safe to re-run on every docker-compose up --build.

CREATE TABLE IF NOT EXISTS oauth_tokens (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    registered_api_id           UUID NOT NULL REFERENCES registered_apis(id)
                                    ON DELETE CASCADE,
    provider_name               TEXT NOT NULL,      -- human label, e.g. "google", "salesforce"
    client_id                   TEXT NOT NULL,      -- public, not encrypted
    encrypted_client_secret     BYTEA NOT NULL,     -- Fernet-encrypted
    token_url                   TEXT NOT NULL,      -- provider token endpoint
    scope                       TEXT,               -- space-separated scopes, e.g. "read:org repo"
    -- Filled in after consent flow (increment 3). NULL = not yet authorized.
    encrypted_access_token      BYTEA,
    encrypted_refresh_token     BYTEA,
    token_expiry                TIMESTAMPTZ,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (registered_api_id)  -- one OAuth credential set per API
);