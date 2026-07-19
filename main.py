"""
Increment 4: admin auth, SSRF guard, key revocation, demo-mode gating.

What changed from increment 3:
  - All /admin/* endpoints now require X-Admin-Key, verified against
    ADMIN_API_KEY (env var, constant-time compare, fails closed if unset).
    Previously these were unauthenticated -- anyone who could reach the
    server could create tenants, mint API keys, and register arbitrary
    URLs as tools.
  - registry.create_api validates url_template through ssrf_guard at
    registration time, and execution_proxy re-validates the resolved URL
    at call time (DNS can change between the two).
  - New DELETE /admin/tenants/{tenant_id}/keys/{key_id} to revoke a
    compromised key. Previously there was no revocation path via the API.
  - /demo/reset and /demo/mcp-roundtrip now 404 unless DEMO_MODE=true.
    /demo/reset does a destructive TRUNCATE CASCADE -- it should not be
    reachable in any environment holding real tenant data.
  - crypto.init_crypto() called at startup -- server refuses to start
    without FERNET_KEY set. db_pool now does the same for DATABASE_URL.

UI:
  - GET  /             serves frontend.html (demo dashboard)
  - POST /demo/reset   truncates all tenant data -- DEMO_MODE only
  - POST /demo/mcp-roundtrip  runs a full MCP client session internally
    and returns structured results for the dashboard -- DEMO_MODE only
"""

import contextlib
import json
import os
import secrets
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlencode

import mcp.types as types
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from pydantic import BaseModel

import crypto
import registry
import ssrf_guard
from auth import generate_api_key, hash_key, resolve_api_key, tenant_id_var, verify_admin_key
from db_pool import close_pool, get_pool, init_pool
from execution_proxy import ExecutionError, execute
from tool_builder import build_tool
import httpx

DEMO_MODE = os.environ.get("DEMO_MODE", "").lower() == "true"

# ---------------------------------------------------------------------------
# MCP protocol handlers
# ---------------------------------------------------------------------------

mcp_server = Server("leapfrog-mcp-gateway")


@mcp_server.list_tools()
async def list_tools() -> list[types.Tool]:
    tenant_id = tenant_id_var.get()
    apis = await registry.list_apis(tenant_id)
    return [build_tool(api) for api in apis]


@mcp_server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    tenant_id = tenant_id_var.get()
    api = await registry.get_api(name, tenant_id)
    if api is None:
        await registry.log_tool_call(tenant_id, name, arguments, status="error", detail="Unknown tool")
        raise ValueError(f"Unknown tool: {name}")

    try:
        result = await execute(api, arguments)
    except ExecutionError as e:
        await registry.log_tool_call(tenant_id, name, arguments, status="error", detail=str(e))
        return [types.TextContent(type="text", text=f"Error: {e}")]

    await registry.log_tool_call(tenant_id, name, arguments, status="success", detail=None)
    return [types.TextContent(type="text", text=json.dumps(result))]


# ---------------------------------------------------------------------------
# Streamable HTTP transport
# ---------------------------------------------------------------------------

session_manager = StreamableHTTPSessionManager(
    app=mcp_server,
    event_store=None,
    stateless=True,
)


async def _send_401(send) -> None:
    await send({
        "type": "http.response.start",
        "status": 401,
        "headers": [[b"content-type", b"application/json"]],
    })
    await send({
        "type": "http.response.body",
        "body": b'{"error": "Unauthorized: missing or invalid API key"}',
        "more_body": False,
    })


async def handle_streamable_http(scope, receive, send) -> None:
    """
    Auth gate for the MCP endpoint. Runs before the MCP session manager.

    Extracts X-API-Key from request headers, resolves it to a tenant_id,
    sets the contextvar, then passes control to the session manager.
    The contextvar is available to list_tools and call_tool because they
    run in the same async call chain as this function.
    """
    headers = dict(scope.get("headers", []))
    raw_key = headers.get(b"x-api-key", b"").decode()

    tenant_id = await resolve_api_key(raw_key)
    if tenant_id is None:
        await _send_401(send)
        return

    token = tenant_id_var.set(tenant_id)
    try:
        await session_manager.handle_request(scope, receive, send)
    finally:
        tenant_id_var.reset(token)


# ---------------------------------------------------------------------------
# FastAPI app + lifespan
# ---------------------------------------------------------------------------

@contextlib.asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    crypto.init_crypto()   # fails loudly if FERNET_KEY missing
    if not os.environ.get("ADMIN_API_KEY", "").strip():
        raise RuntimeError(
            "ADMIN_API_KEY environment variable is not set. All /admin/* "
            "endpoints fail closed without it, so the server refuses to "
            "start rather than come up in a state where admin routes are "
            "unreachable (or, if this check is ever removed, unauthenticated)."
        )
    await init_pool()
    async with session_manager.run():
        yield
    await close_pool()


app = FastAPI(lifespan=lifespan)
app.mount("/mcp", app=handle_streamable_http)


async def require_admin(x_admin_key: str = Header(default="")) -> None:
    """FastAPI dependency -- attach to every /admin/* route."""
    if not verify_admin_key(x_admin_key):
        raise HTTPException(status_code=401, detail="Unauthorized: missing or invalid X-Admin-Key")


# ---------------------------------------------------------------------------
# Frontend
# ---------------------------------------------------------------------------

@app.get("/")
async def serve_frontend():
    # No-cache so the browser always fetches fresh HTML after docker-compose up --build.
    # Without this, a rebuilt image with updated HTML is ignored by the browser
    # until the user manually hard-refreshes (Ctrl+Shift+R).
    return FileResponse("frontend.html", headers={
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "Pragma": "no-cache",
    })


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "healthy"}


# ---------------------------------------------------------------------------
# Demo utility endpoints -- DEMO_MODE only. Never enable this in an
# environment holding real tenant data: /demo/reset TRUNCATEs everything.
# ---------------------------------------------------------------------------

def _require_demo_mode() -> None:
    if not DEMO_MODE:
        raise HTTPException(status_code=404, detail="Not found")


@app.post("/demo/reset")
async def demo_reset():
    """Wipe all tenant data so the demo can be re-run cleanly."""
    _require_demo_mode()
    pool = get_pool()
    await pool.execute("TRUNCATE tenants CASCADE;")
    return {"status": "reset complete"}


@app.post("/demo/mcp-roundtrip")
async def demo_mcp_roundtrip(request: Request):
    """
    Run a full MCP client session against this server and return structured
    results for the dashboard to render.  The server calls itself on
    127.0.0.1:8000 using the provided API key.
    """
    _require_demo_mode()
    body = await request.json()
    api_key = body.get("api_key", "")
    if not api_key:
        raise HTTPException(status_code=400, detail="api_key required")

    try:
        result = {"initialize": False, "tools": [], "call_result": None}
        async with streamablehttp_client(
            "http://127.0.0.1:8000/mcp",
            headers={"X-API-Key": api_key},
        ) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result["initialize"] = True

                tools = await session.list_tools()
                result["tools"] = [t.name for t in tools.tools]

                if "get_github_repo" in result["tools"]:
                    tool_result = await session.call_tool(
                        "get_github_repo",
                        {"owner": "anthropics", "repo": "anthropic-sdk-python"},
                    )
                    raw = tool_result.content[0].text
                    try:
                        data = json.loads(raw)
                        result["call_result"] = {
                            "stars": data.get("stargazers_count"),
                            "language": data.get("language"),
                            "full_name": data.get("full_name"),
                            "description": data.get("description"),
                        }
                    except json.JSONDecodeError:
                        result["call_result"] = {"raw": raw[:300]}

        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# Admin endpoints -- all require X-Admin-Key (see require_admin above).
# ---------------------------------------------------------------------------

class CreateTenantRequest(BaseModel):
    name: str


@app.post("/admin/tenants", dependencies=[Depends(require_admin)])
async def create_tenant(req: CreateTenantRequest):
    # registry.create_tenant is an upsert -- returns existing tenant if name
    # already exists instead of raising a conflict. This makes the demo
    # re-runnable without needing a manual reset between runs.
    tenant = await registry.create_tenant(req.name)
    return tenant


class CreateKeyRequest(BaseModel):
    label: str = "default"


@app.post("/admin/tenants/{tenant_id}/keys", dependencies=[Depends(require_admin)])
async def create_api_key(tenant_id: str, req: CreateKeyRequest):
    raw_key = generate_api_key()
    await registry.create_api_key(tenant_id, req.label, hash_key(raw_key))
    return {
        "api_key": raw_key,
        "warning": "Store this key now. It will not be shown again.",
    }


@app.get("/admin/tenants/{tenant_id}/keys", dependencies=[Depends(require_admin)])
async def list_api_keys(tenant_id: str):
    return await registry.list_api_keys(tenant_id)


@app.delete("/admin/tenants/{tenant_id}/keys/{key_id}", dependencies=[Depends(require_admin)])
async def revoke_api_key(tenant_id: str, key_id: str):
    revoked = await registry.revoke_api_key(tenant_id, key_id)
    if not revoked:
        raise HTTPException(status_code=404, detail="Key not found, already revoked, or wrong tenant")
    return {"revoked": key_id}


@app.get("/admin/tenants/{tenant_id}/logs", dependencies=[Depends(require_admin)])
async def get_tool_call_logs(tenant_id: str, limit: int = 100):
    return await registry.list_tool_calls(tenant_id, limit)


class CreateApiRequest(BaseModel):
    tenant_id: str
    name: str
    description: str
    method: str
    url_template: str
    path_params: dict = {}
    query_params: dict = {}
    body_params: dict = {}
    static_headers: dict = {}


@app.post("/admin/apis", dependencies=[Depends(require_admin)])
async def create_api(req: CreateApiRequest):
    existing = await registry.get_api(req.name, req.tenant_id)
    if existing is not None:
        raise HTTPException(status_code=409, detail=f"API '{req.name}' already registered")
    try:
        api = await registry.create_api(**req.model_dump())
    except (ValueError, ssrf_guard.SsrfBlockedError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"id": api.id, "name": api.name}


@app.get("/admin/apis", dependencies=[Depends(require_admin)])
async def list_apis(tenant_id: str):
    apis = await registry.list_apis(tenant_id)
    return [
        {"id": a.id, "name": a.name, "description": a.description, "method": a.method}
        for a in apis
    ]


@app.delete("/admin/apis/{name}", dependencies=[Depends(require_admin)])
async def delete_api(name: str, tenant_id: str):
    deleted = await registry.delete_api(name, tenant_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"API '{name}' not found")
    return {"deleted": name}


class SetOAuthClientRequest(BaseModel):
    tenant_id: str
    provider_name: str      # human label, e.g. "google", "salesforce"
    client_id: str
    client_secret: str      # encrypted before storage -- never saved plaintext
    token_url: str          # provider's token endpoint (for code exchange + refresh)
    authorization_url: str  # provider's consent page (for the browser redirect)
    scope: str = ""         # space-separated scopes, e.g. "read:org repo"


@app.post("/admin/apis/{api_name}/oauth-client", dependencies=[Depends(require_admin)])
async def set_oauth_client(api_name: str, req: SetOAuthClientRequest):
    """
    Register OAuth2 client credentials for an API. This stores the
    client_id and encrypted client_secret, but does NOT complete the OAuth
    flow -- the access/refresh tokens arrive later via /admin/oauth/authorize.
    Until that step is done, any call to this tool will return an error
    telling you to complete authorization.
    """
    api = await registry.get_api(api_name, req.tenant_id)
    if api is None:
        raise HTTPException(status_code=404, detail=f"API '{api_name}' not found")
    encrypted_secret = crypto.encrypt(req.client_secret)
    result = await registry.set_oauth_client(
        registered_api_id=api.id,
        provider_name=req.provider_name,
        client_id=req.client_id,
        encrypted_client_secret=encrypted_secret,
        token_url=req.token_url,
        authorization_url=req.authorization_url,
        scope=req.scope or None,
    )
    return result


@app.get("/admin/oauth/authorize")
async def oauth_authorize(
    api_name: str,
    tenant_id: str,
    request: Request,
    x_admin_key: Optional[str] = Header(default=None),
    admin_key: Optional[str] = None,  # query param alternative for browser navigation
):
    """
    Step 1 of the OAuth consent flow. Open this URL in your browser --
    it redirects to the provider's consent screen. After you click Allow,
    the provider redirects your browser to /admin/oauth/callback, which
    completes the flow automatically.

    Accepts the admin key either as X-Admin-Key header (curl/API) or as
    ?admin_key=... query parameter (direct browser navigation / dashboard).
    The state parameter is a one-time CSRF token stored in the DB. It
    expires in 10 minutes and is deleted the moment the callback uses it.
    """
    key = x_admin_key or admin_key
    if not key or not verify_admin_key(key):
        raise HTTPException(status_code=401, detail="Unauthorized: missing or invalid admin key")

    api = await registry.get_api(api_name, tenant_id)
    if api is None:
        raise HTTPException(status_code=404, detail=f"API '{api_name}' not found")

    oauth = await registry.get_oauth_token(api.id)
    if oauth is None:
        raise HTTPException(
            status_code=400,
            detail=f"No OAuth client registered for '{api_name}'. "
                   f"Call POST /admin/apis/{api_name}/oauth-client first.",
        )
    if not oauth.get("authorization_url"):
        raise HTTPException(
            status_code=400,
            detail="authorization_url is not set for this OAuth client.",
        )

    state_token = secrets.token_hex(32)
    redirect_uri = str(request.base_url).rstrip("/") + "/admin/oauth/callback"

    await registry.create_oauth_state(state_token, api.id, redirect_uri)

    params: dict[str, str] = {
        "client_id": oauth["client_id"],
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "state": state_token,
    }
    if oauth.get("scope"):
        params["scope"] = oauth["scope"]

    consent_url = oauth["authorization_url"] + "?" + urlencode(params)
    return RedirectResponse(consent_url)


@app.get("/admin/oauth/callback")
async def oauth_callback(code: str, state: str):
    """
    Step 2 of the OAuth consent flow. The provider redirects the browser
    here after the admin clicks Allow. This endpoint:
      1. Validates + consumes the one-time state token (CSRF check)
      2. Exchanges the authorization code for access + refresh tokens
      3. Encrypts and stores the tokens in oauth_tokens
      4. Returns a simple success page the admin can close

    No X-Admin-Key header required here -- browsers can't set custom headers
    on OAuth redirects. The state token provides equivalent protection.
    """
    state_record = await registry.consume_oauth_state(state)
    if state_record is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid, expired, or already-used OAuth state token. "
                   "Restart the flow via /admin/oauth/authorize.",
        )

    api_id = state_record["api_id"]
    redirect_uri = state_record["redirect_uri"]

    oauth = await registry.get_oauth_token(api_id)
    if oauth is None:
        raise HTTPException(status_code=500, detail="OAuth client record missing after state lookup")

    client_secret = crypto.decrypt(oauth["encrypted_client_secret"])

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                oauth["token_url"],
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": oauth["client_id"],
                    "client_secret": client_secret,
                },
            )
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Token exchange request failed: {e}")
    finally:
        del client_secret  # Wipe plaintext from scope ASAP

    if resp.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail=f"Provider rejected token exchange: HTTP {resp.status_code}",
        )

    try:
        data = resp.json()
    except ValueError:
        raise HTTPException(status_code=502, detail="Provider returned non-JSON in token exchange")

    access_token = data.get("access_token")
    if not access_token:
        raise HTTPException(status_code=502, detail="Provider response missing access_token")

    refresh_token = data.get("refresh_token")
    expires_in = data.get("expires_in")
    now = datetime.now(tz=timezone.utc)
    token_expiry = (now + timedelta(seconds=int(expires_in))) if expires_in else None

    encrypted_access = crypto.encrypt(access_token)
    encrypted_refresh = crypto.encrypt(refresh_token) if refresh_token else None

    del access_token  # Wipe plaintext from scope ASAP
    del refresh_token

    await registry.update_oauth_tokens(api_id, encrypted_access, encrypted_refresh, token_expiry)

    return HTMLResponse("""
        <html><body style="font-family:sans-serif;padding:2rem;">
        <h2>&#x2705; Authorization complete</h2>
        <p>Tokens stored successfully. You can close this tab.</p>
        </body></html>
    """)


class AddCredentialRequest(BaseModel):
    tenant_id: str
    header_name: str    # e.g. "Authorization"
    header_value: str   # e.g. "Bearer ghp_xxxx" -- encrypted before storage


@app.post("/admin/apis/{api_name}/credentials", dependencies=[Depends(require_admin)])
async def add_credential(api_name: str, req: AddCredentialRequest):
    api = await registry.get_api(api_name, req.tenant_id)
    if api is None:
        raise HTTPException(status_code=404, detail=f"API '{api_name}' not found")
    encrypted = crypto.encrypt(req.header_value)
    result = await registry.add_credential(api.id, req.header_name, encrypted)
    return {"id": result["id"], "header_name": req.header_name}