"""
Database connection pool setup. One pool, shared across the whole app,
created at startup and closed at shutdown via FastAPI's lifespan.
"""

import os

import asyncpg

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL environment variable is not set.\n"
        "This used to silently fall back to postgres:devpassword@localhost --\n"
        "that fallback has been removed. A missing env var should fail the\n"
        "server startup, not quietly point it at a well-known dev password.\n"
        "Source set_env.ps1 or set DATABASE_URL explicitly."
    )

_pool: asyncpg.Pool | None = None


async def init_pool() -> None:
    global _pool
    _pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=10)


async def close_pool() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


def get_pool() -> asyncpg.Pool:
    if _pool is None:
        raise RuntimeError("DB pool not initialized -- init_pool() must run at startup")
    return _pool
