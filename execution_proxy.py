"""
Execution Proxy. Builds and sends the real outbound HTTP request for a
call_tool invocation.

Credential injection happens here and only here. Two credential sources,
checked in order -- an API can have one or the other, not both:

  1. OAuth access token (oauth_tokens table) -- used when the API is
     OAuth2-protected. Access tokens are short-lived; this module refreshes
     them inline if they're within OAUTH_REFRESH_BEFORE_EXPIRY of expiry.
     Refresh uses the stored encrypted refresh_token + client_secret to hit
     the provider's token_url, then writes the new tokens back to the DB.

  2. Static encrypted credentials (api_credentials table) -- used for APIs
     with simple long-lived tokens (e.g. "Authorization: Bearer ghp_xxx").
     Each credential row decrypts to a header name + value pair.

In both cases: decrypted values exist only in local variables inside this
module. They are never logged, never returned to the agent, never stored
in plaintext anywhere, never appear in tracebacks.

Security notes (see ssrf_guard.py for the full rationale):
  - Path parameter values are URL-encoded before being formatted into
    url_template, so an agent-supplied value like "../../internal" can't
    escape the path segment it's meant to fill.
  - The fully-resolved URL is re-validated against ssrf_guard immediately
    before the request fires (not just at registration time), because DNS
    can change between when an API was registered and when it's called.
  - Downstream response bodies are capped and, by default, NOT echoed back
    into error messages -- a downstream API's error body could contain
    data that shouldn't leak into the calling agent's context. Set
    EXECUTION_PROXY_INCLUDE_ERROR_BODY=true to opt back in (debug only).
"""

import os
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import httpx

import crypto
import registry
import ssrf_guard
from registry import RegisteredApi

MAX_RESPONSE_BYTES = 5 * 1024 * 1024  # 5 MB
INCLUDE_ERROR_BODY = os.environ.get("EXECUTION_PROXY_INCLUDE_ERROR_BODY", "").lower() == "true"

# Refresh the access token if it expires within this window. 5 minutes
# gives enough headroom for slow downstream APIs without being so long
# that we refresh unnecessarily on every other call.
OAUTH_REFRESH_BEFORE_EXPIRY = timedelta(minutes=5)


class ExecutionError(Exception):
    """Clean error type so call_tool can surface a readable message to the
    agent's LLM rather than leaking a raw Python traceback."""


# ---- OAuth token refresh ------------------------------------------------------

async def _get_fresh_access_token(api_id: str) -> str | None:
    """
    Returns a decrypted, ready-to-use access token for the given API, or
    None if no OAuth credentials are registered for it (meaning the API
    uses static header credentials instead).

    If the stored access token is still valid (more than
    OAUTH_REFRESH_BEFORE_EXPIRY away from expiry), it is decrypted and
    returned directly. If it's stale or missing, the refresh_token is used
    to get a new access token from the provider. The new tokens are
    encrypted and written back to the DB before being returned.

    Raises ExecutionError for all actionable failures (no refresh token,
    consent not yet completed, provider rejected the refresh).
    """
    oauth = await registry.get_oauth_token(api_id)
    if oauth is None:
        return None  # This API uses static credentials instead.

    # OAuth client registered but consent flow not yet completed.
    if oauth["encrypted_access_token"] is None:
        raise ExecutionError(
            f"OAuth not yet authorized for this API. "
            f"Visit /admin/oauth/authorize?api_id={api_id} to complete setup."
        )

    # Check whether the stored access token is still fresh enough.
    now = datetime.now(tz=timezone.utc)
    expiry = oauth["token_expiry"]
    if expiry is not None and expiry > now + OAUTH_REFRESH_BEFORE_EXPIRY:
        # Token is valid for long enough -- decrypt and return as-is.
        return crypto.decrypt(oauth["encrypted_access_token"])

    # Token is stale (or has no expiry recorded). Refresh it.
    if oauth["encrypted_refresh_token"] is None:
        raise ExecutionError(
            "OAuth access token is expired and no refresh token is stored. "
            "Re-authorize via /admin/oauth/authorize."
        )

    client_secret = crypto.decrypt(oauth["encrypted_client_secret"])
    refresh_token = crypto.decrypt(oauth["encrypted_refresh_token"])

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                oauth["token_url"],
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": oauth["client_id"],
                    "client_secret": client_secret,
                },
            )
    except httpx.RequestError as e:
        raise ExecutionError(f"OAuth token refresh request failed: {e}") from e
    finally:
        # Defensive: wipe plaintext secrets from local scope as early as
        # possible. Python doesn't guarantee immediate GC but this signals
        # intent and removes the reference from the frame.
        del client_secret
        del refresh_token

    if resp.status_code != 200:
        raise ExecutionError(
            f"OAuth token refresh failed: provider returned {resp.status_code}"
        )

    try:
        data = resp.json()
    except ValueError as e:
        raise ExecutionError("OAuth token refresh: provider returned non-JSON response") from e

    new_access_token = data.get("access_token")
    if not new_access_token:
        raise ExecutionError("OAuth token refresh: provider response missing access_token")

    # Compute new expiry. Providers return expires_in (seconds from now).
    expires_in = data.get("expires_in")
    new_expiry = (now + timedelta(seconds=int(expires_in))) if expires_in else None

    # Some providers rotate the refresh_token on each use; others don't.
    new_refresh_token_plain = data.get("refresh_token")
    new_encrypted_refresh = (
        crypto.encrypt(new_refresh_token_plain)
        if new_refresh_token_plain
        else None
    )

    new_encrypted_access = crypto.encrypt(new_access_token)

    # Write back to DB before returning -- if this write fails, we still
    # have the valid token in-hand for this call, but the next call would
    # try to refresh again. That's acceptable: we raise ExecutionError
    # so the admin is aware rather than silently swallowing the failure.
    try:
        await registry.update_oauth_tokens(
            api_id,
            new_encrypted_access,
            new_encrypted_refresh,
            new_expiry,
        )
    except Exception as e:
        raise ExecutionError(
            f"OAuth token refreshed successfully but failed to save new tokens: {e}"
        ) from e

    return new_access_token


# ---- Main entry point ---------------------------------------------------------

async def execute(api: RegisteredApi, arguments: dict) -> dict:
    # Route arguments to the correct HTTP layer (path / query / body).
    path_values = {k: arguments[k] for k in api.path_params if k in arguments}
    query_values = {k: arguments[k] for k in api.query_params if k in arguments}
    body_values = {k: arguments[k] for k in api.body_params if k in arguments}

    # URL-encode path values before formatting -- an agent-supplied value
    # containing "/", "..", or "@" must not be able to change which path
    # segment (or host) the request actually hits.
    encoded_path_values = {k: quote(str(v), safe="") for k, v in path_values.items()}

    try:
        url = api.url_template.format(**encoded_path_values)
    except KeyError as e:
        raise ExecutionError(f"Missing required path parameter: {e}") from e

    try:
        ssrf_guard.validate_url_resolved(url)
    except ssrf_guard.SsrfBlockedError as e:
        raise ExecutionError("Request blocked: destination not allowed") from e

    # Start with static (non-secret) headers from the API definition.
    headers: dict[str, str] = dict(api.static_headers)

    # Credential injection. OAuth takes priority; falls back to static
    # header credentials. An API should use one or the other, not both.
    access_token = await _get_fresh_access_token(api.id)

    if access_token is not None:
        headers["Authorization"] = f"Bearer {access_token}"
        del access_token  # Remove from scope once injected.
    else:
        # Static encrypted credentials (e.g. long-lived bearer tokens).
        cred_rows = await registry.get_credentials(api.id)
        for cred in cred_rows:
            headers[cred["header_name"]] = crypto.decrypt(cred["encrypted_value"])

    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            response = await client.request(
                method=api.method,
                url=url,
                params=query_values or None,
                json=body_values or None,
                headers=headers or None,
            )
        except httpx.RequestError as e:
            raise ExecutionError(f"Request to downstream API failed: {e}") from e

    content_length = response.headers.get("content-length")
    if content_length is not None and int(content_length) > MAX_RESPONSE_BYTES:
        raise ExecutionError("Downstream response exceeded the size limit")
    if len(response.content) > MAX_RESPONSE_BYTES:
        raise ExecutionError("Downstream response exceeded the size limit")

    if response.status_code >= 400:
        if INCLUDE_ERROR_BODY:
            raise ExecutionError(
                f"Downstream API returned {response.status_code}: {response.text[:500]}"
            )
        raise ExecutionError(f"Downstream API returned {response.status_code}")

    try:
        return response.json()
    except ValueError:
        return {"raw_response": response.text}