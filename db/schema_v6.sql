-- Increment 7 migration: OAuth consent flow support.
--
-- 1. oauth_tokens.authorization_url -- provider's authorization endpoint,
--    needed to build the redirect URL in /admin/oauth/authorize.
--    Added as nullable (existing rows just won't have it set yet).
--
-- 2. oauth_pending_states -- short-lived CSRF state records. Created when
--    /admin/oauth/authorize fires, consumed (deleted) when the browser
--    returns to /admin/oauth/callback. Expires after 10 minutes.
--    One-time-use: consume_oauth_state deletes the row on read, so a
--    replayed callback with the same state token gets nothing.
--
-- Idempotent: safe to re-run on every docker-compose up --build.

ALTER TABLE oauth_tokens ADD COLUMN IF NOT EXISTS authorization_url TEXT;

CREATE TABLE IF NOT EXISTS oauth_pending_states (
    state_token     TEXT PRIMARY KEY,
    api_id          UUID NOT NULL REFERENCES registered_apis(id) ON DELETE CASCADE,
    redirect_uri    TEXT NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL DEFAULT (now() + INTERVAL '10 minutes'),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Clean up stale state records on each migration run (harmless, idempotent).
DELETE FROM oauth_pending_states WHERE expires_at < now();