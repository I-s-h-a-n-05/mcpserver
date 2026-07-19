"""
Auth layer. Responsibilities:
  - Generate raw API keys (shown once at creation, never stored)
  - Hash keys for storage (SHA-256 -- high-entropy random input means
    SHA-256 is fine here; bcrypt is for low-entropy passwords)
  - Resolve a raw incoming key → tenant_id via DB lookup
  - Verify the admin API key (single shared secret, env-var based) used to
    gate all /admin/* endpoints
  - Provide the tenant_id contextvar that threads through the async chain

The contextvar is set in handle_streamable_http (main.py) before the MCP
session manager runs, so list_tools and call_tool can read it without
needing HTTP request access. Never set it anywhere else.
"""

import hashlib
import hmac
import os
import secrets
from contextvars import ContextVar
from typing import Optional

from db_pool import get_pool

# Set once per request in handle_streamable_http; read in list_tools/call_tool.
tenant_id_var: ContextVar[str] = ContextVar("tenant_id")


def verify_admin_key(raw_key: str) -> bool:
    """
    Constant-time comparison against ADMIN_API_KEY. There's exactly one
    admin key (env var, not DB-backed) -- this gateway doesn't have a
    concept of multiple admin operators yet. Fails closed: if
    ADMIN_API_KEY isn't set, every admin call is rejected rather than
    silently allowed.
    """
    expected = os.environ.get("ADMIN_API_KEY", "")
    if not expected or not raw_key:
        return False
    return hmac.compare_digest(raw_key, expected)


def generate_api_key() -> str:
    """
    Returns a new raw key. Call this once, show it to the user, throw away
    the plaintext. The prefix makes keys identifiable in logs/config files.
    """
    return "lgfmcp_" + secrets.token_hex(32)


def hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


async def resolve_api_key(raw_key: str) -> Optional[str]:
    """
    Returns tenant_id as a string if the key is valid and not revoked.
    Returns None if the key is unknown or revoked.
    """
    if not raw_key:
        return None
    pool = get_pool()
    row = await pool.fetchrow(
        """
        SELECT tenant_id FROM api_keys
        WHERE key_hash = $1 AND revoked_at IS NULL
        """,
        hash_key(raw_key),
    )
    return str(row["tenant_id"]) if row else None