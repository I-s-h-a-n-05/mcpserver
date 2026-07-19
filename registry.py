"""
API Registry Service. The only module allowed to touch registered_apis,
tenants, api_keys, and api_credentials tables directly.

Every public method that reads or writes API definitions takes an explicit
tenant_id parameter. The callers (MCP handlers) read tenant_id from the
contextvar; admin endpoints supply it from the request body/path.

This separation means the registry never reads HTTP context directly --
it's a pure DB service layer, testable without running a web server.
"""

import json
from dataclasses import dataclass
from typing import Any, Optional

import ssrf_guard
from db_pool import get_pool

ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}


@dataclass
class RegisteredApi:
    id: str
    tenant_id: str
    name: str
    description: str
    method: str
    url_template: str
    path_params: dict[str, Any]
    query_params: dict[str, Any]
    body_params: dict[str, Any]
    static_headers: dict[str, Any]

    @classmethod
    def from_row(cls, row) -> "RegisteredApi":
        return cls(
            id=str(row["id"]),
            tenant_id=str(row["tenant_id"]),
            name=row["name"],
            description=row["description"],
            method=row["method"],
            url_template=row["url_template"],
            path_params=json.loads(row["path_params"]),
            query_params=json.loads(row["query_params"]),
            body_params=json.loads(row["body_params"]),
            static_headers=json.loads(row["static_headers"]),
        )


# ---- Tenant management -------------------------------------------------------

async def create_tenant(name: str) -> dict:
    pool = get_pool()
    row = await pool.fetchrow(
        """
        INSERT INTO tenants (name) VALUES ($1)
        ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
        RETURNING id, name
        """,
        name,
    )
    return {"id": str(row["id"]), "name": row["name"]}


async def create_api_key(tenant_id: str, label: str, key_hash: str) -> dict:
    pool = get_pool()
    row = await pool.fetchrow(
        """
        INSERT INTO api_keys (tenant_id, key_hash, label)
        VALUES ($1, $2, $3)
        RETURNING id, label, created_at
        """,
        tenant_id, key_hash, label,
    )
    return {"id": str(row["id"]), "label": row["label"]}


async def revoke_api_key(tenant_id: str, key_id: str) -> bool:
    """
    Sets revoked_at so resolve_api_key stops accepting this key on the next
    request. Scoped to tenant_id so one tenant can't revoke another
    tenant's key by guessing/enumerating key ids.
    """
    pool = get_pool()
    result = await pool.execute(
        """
        UPDATE api_keys SET revoked_at = now()
        WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL
        """,
        key_id, tenant_id,
    )
    return result.endswith(" 1")


async def list_api_keys(tenant_id: str) -> list[dict]:
    pool = get_pool()
    rows = await pool.fetch(
        """
        SELECT id, label, created_at, revoked_at FROM api_keys
        WHERE tenant_id = $1 ORDER BY created_at
        """,
        tenant_id,
    )
    return [
        {
            "id": str(r["id"]),
            "label": r["label"],
            "created_at": r["created_at"].isoformat(),
            "revoked": r["revoked_at"] is not None,
        }
        for r in rows
    ]


# ---- API registration --------------------------------------------------------

async def create_api(
    tenant_id: str,
    name: str,
    description: str,
    method: str,
    url_template: str,
    path_params: dict[str, Any] | None = None,
    query_params: dict[str, Any] | None = None,
    body_params: dict[str, Any] | None = None,
    static_headers: dict[str, Any] | None = None,
) -> RegisteredApi:
    method = method.upper()
    if method not in ALLOWED_METHODS:
        raise ValueError(f"Unsupported HTTP method: {method!r}. Allowed: {sorted(ALLOWED_METHODS)}")

    ssrf_guard.validate_url_syntax(url_template)

    pool = get_pool()
    row = await pool.fetchrow(
        """
        INSERT INTO registered_apis
            (tenant_id, name, description, method, url_template,
             path_params, query_params, body_params, static_headers)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING *
        """,
        tenant_id,
        name,
        description,
        method,
        url_template,
        json.dumps(path_params or {}),
        json.dumps(query_params or {}),
        json.dumps(body_params or {}),
        json.dumps(static_headers or {}),
    )
    return RegisteredApi.from_row(row)


async def list_apis(tenant_id: str) -> list[RegisteredApi]:
    pool = get_pool()
    rows = await pool.fetch(
        "SELECT * FROM registered_apis WHERE tenant_id = $1 ORDER BY name",
        tenant_id,
    )
    return [RegisteredApi.from_row(r) for r in rows]


async def get_api(name: str, tenant_id: str) -> Optional[RegisteredApi]:
    pool = get_pool()
    row = await pool.fetchrow(
        "SELECT * FROM registered_apis WHERE name = $1 AND tenant_id = $2",
        name, tenant_id,
    )
    return RegisteredApi.from_row(row) if row else None


async def delete_api(name: str, tenant_id: str) -> bool:
    pool = get_pool()
    result = await pool.execute(
        "DELETE FROM registered_apis WHERE name = $1 AND tenant_id = $2",
        name, tenant_id,
    )
    return result.endswith(" 1")


# ---- Credential management ---------------------------------------------------

async def add_credential(
    registered_api_id: str,
    header_name: str,
    encrypted_value: bytes,
) -> dict:
    """
    Upsert on (registered_api_id, header_name) -- see schema_v3.sql. Before
    this constraint existed, re-adding a credential for the same header
    (e.g. rotating a token) created a second row and execution_proxy would
    apply whichever one the query happened to return first, silently.
    """
    pool = get_pool()
    row = await pool.fetchrow(
        """
        INSERT INTO api_credentials (registered_api_id, header_name, encrypted_value)
        VALUES ($1, $2, $3)
        ON CONFLICT (registered_api_id, header_name)
        DO UPDATE SET encrypted_value = EXCLUDED.encrypted_value, created_at = now()
        RETURNING id
        """,
        registered_api_id, header_name, encrypted_value,
    )
    return {"id": str(row["id"])}


async def get_credentials(registered_api_id: str) -> list[dict]:
    """Returns raw rows -- decryption happens in execution_proxy, not here."""
    pool = get_pool()
    rows = await pool.fetch(
        "SELECT header_name, encrypted_value FROM api_credentials WHERE registered_api_id = $1",
        registered_api_id,
    )
    return [{"header_name": r["header_name"], "encrypted_value": bytes(r["encrypted_value"])} for r in rows]


# ---- Tool call audit log ------------------------------------------------------

async def log_tool_call(
    tenant_id: str,
    tool_name: str,
    arguments: dict[str, Any],
    status: str,
    detail: Optional[str] = None,
) -> None:
    """
    Records every tool invocation attempt, success or failure. Once real
    (especially write-capable) tools are registered, this is the only
    record of "which tenant called what, with which arguments, and did it
    work" -- there is no other audit trail in this system.

    Safe to log `arguments` as-is: these are agent-supplied inputs only.
    Credentials are injected separately inside execution_proxy and are
    never part of `arguments`, so nothing secret ends up in this table.
    """
    pool = get_pool()
    await pool.execute(
        """
        INSERT INTO tool_call_log (tenant_id, tool_name, arguments, status, detail)
        VALUES ($1, $2, $3, $4, $5)
        """,
        tenant_id, tool_name, json.dumps(arguments), status, detail,
    )


# ---- OAuth token storage ------------------------------------------------------

async def set_oauth_client(
    registered_api_id: str,
    provider_name: str,
    client_id: str,
    encrypted_client_secret: bytes,
    token_url: str,
    authorization_url: str,
    scope: Optional[str] = None,
) -> dict:
    """
    Upsert the client credentials for an OAuth-protected API.
    Does NOT touch encrypted_access_token / encrypted_refresh_token / token_expiry
    -- those arrive later via the consent flow (increment 3) or via
    update_oauth_tokens after a refresh.
    """
    pool = get_pool()
    row = await pool.fetchrow(
        """
        INSERT INTO oauth_tokens
            (registered_api_id, provider_name, client_id,
             encrypted_client_secret, token_url, authorization_url, scope)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (registered_api_id) DO UPDATE SET
            provider_name           = EXCLUDED.provider_name,
            client_id               = EXCLUDED.client_id,
            encrypted_client_secret = EXCLUDED.encrypted_client_secret,
            token_url               = EXCLUDED.token_url,
            authorization_url       = EXCLUDED.authorization_url,
            scope                   = EXCLUDED.scope,
            updated_at              = now()
        RETURNING id, provider_name, client_id, token_url, authorization_url,
                  scope, encrypted_access_token, token_expiry
        """,
        registered_api_id, provider_name, client_id,
        encrypted_client_secret, token_url, authorization_url, scope,
    )
    return {
        "id": str(row["id"]),
        "provider_name": row["provider_name"],
        "client_id": row["client_id"],
        "token_url": row["token_url"],
        "authorization_url": row["authorization_url"],
        "scope": row["scope"],
        "authorized": row["encrypted_access_token"] is not None,
    }


async def get_oauth_token(registered_api_id: str) -> Optional[dict]:
    """
    Returns the full oauth_tokens row for this API, or None if no OAuth
    credentials are registered. Encrypted values are returned as raw bytes
    -- decryption is the caller's responsibility (execution_proxy only).
    """
    pool = get_pool()
    row = await pool.fetchrow(
        """
        SELECT id, provider_name, client_id, encrypted_client_secret,
               token_url, authorization_url, scope, encrypted_access_token,
               encrypted_refresh_token, token_expiry
        FROM oauth_tokens
        WHERE registered_api_id = $1
        """,
        registered_api_id,
    )
    if row is None:
        return None
    return {
        "id": str(row["id"]),
        "provider_name": row["provider_name"],
        "client_id": row["client_id"],
        "encrypted_client_secret": bytes(row["encrypted_client_secret"]),
        "token_url": row["token_url"],
        "authorization_url": row["authorization_url"],
        "scope": row["scope"],
        "encrypted_access_token": bytes(row["encrypted_access_token"]) if row["encrypted_access_token"] else None,
        "encrypted_refresh_token": bytes(row["encrypted_refresh_token"]) if row["encrypted_refresh_token"] else None,
        "token_expiry": row["token_expiry"],
    }


async def update_oauth_tokens(
    registered_api_id: str,
    encrypted_access_token: bytes,
    encrypted_refresh_token: Optional[bytes],
    token_expiry,
) -> None:
    """
    Called after a successful token refresh (or after the initial consent
    callback in increment 3). Stores the new encrypted tokens and expiry.
    If the provider did not return a new refresh_token (some don't), pass
    None and the existing refresh_token is left unchanged.
    """
    pool = get_pool()
    if encrypted_refresh_token is not None:
        await pool.execute(
            """
            UPDATE oauth_tokens SET
                encrypted_access_token  = $1,
                encrypted_refresh_token = $2,
                token_expiry            = $3,
                updated_at              = now()
            WHERE registered_api_id = $4
            """,
            encrypted_access_token, encrypted_refresh_token,
            token_expiry, registered_api_id,
        )
    else:
        # Provider didn't rotate the refresh token -- leave it alone.
        await pool.execute(
            """
            UPDATE oauth_tokens SET
                encrypted_access_token = $1,
                token_expiry           = $2,
                updated_at             = now()
            WHERE registered_api_id = $3
            """,
            encrypted_access_token, token_expiry, registered_api_id,
        )


# ---- OAuth pending state (CSRF protection for consent flow) -------------------

async def create_oauth_state(state_token: str, api_id: str, redirect_uri: str) -> None:
    """
    Store a one-time state token before redirecting the browser to the
    provider's consent screen. Expires in 10 minutes (set by DB default).
    Also deletes any already-expired state records for this api_id to keep
    the table clean without needing a separate cleanup job.
    """
    pool = get_pool()
    await pool.execute(
        "DELETE FROM oauth_pending_states WHERE api_id = $1 AND expires_at < now()",
        api_id,
    )
    await pool.execute(
        """
        INSERT INTO oauth_pending_states (state_token, api_id, redirect_uri)
        VALUES ($1, $2, $3)
        """,
        state_token, api_id, redirect_uri,
    )


async def consume_oauth_state(state_token: str) -> Optional[dict]:
    """
    Look up and atomically delete a pending state record. Returns None if
    the token doesn't exist, has already been used, or has expired.
    One-time-use: once this returns a record, the token is gone.
    """
    pool = get_pool()
    row = await pool.fetchrow(
        """
        DELETE FROM oauth_pending_states
        WHERE state_token = $1 AND expires_at > now()
        RETURNING api_id, redirect_uri
        """,
        state_token,
    )
    if row is None:
        return None
    return {"api_id": str(row["api_id"]), "redirect_uri": row["redirect_uri"]}


async def list_tool_calls(tenant_id: str, limit: int = 100) -> list[dict]:
    pool = get_pool()
    rows = await pool.fetch(
        """
        SELECT id, tool_name, arguments, status, detail, called_at
        FROM tool_call_log
        WHERE tenant_id = $1
        ORDER BY called_at DESC
        LIMIT $2
        """,
        tenant_id, limit,
    )
    return [
        {
            "id": str(r["id"]),
            "tool_name": r["tool_name"],
            "arguments": json.loads(r["arguments"]),
            "status": r["status"],
            "detail": r["detail"],
            "called_at": r["called_at"].isoformat(),
        }
        for r in rows
    ]