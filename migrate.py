# C:\MCP\migrate.py
import asyncio
import os
import pathlib
import sys
import asyncpg

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
if not DATABASE_URL:
    sys.exit(
        "DATABASE_URL environment variable is not set.\n"
        "This used to silently fall back to a hardcoded local password --\n"
        "that fallback has been removed because it's a real risk if this\n"
        "script (or the server) ever runs somewhere DATABASE_URL wasn't\n"
        "actually configured. Source set_env.ps1 or set it explicitly."
    )

SCHEMA_FILES = ["db/schema.sql", "db/schema_v2.sql", "db/schema_v3.sql", "db/schema_v4.sql", "db/schema_v5.sql", "db/schema_v6.sql"]


async def main():
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        for schema_file in SCHEMA_FILES:
            path = pathlib.Path(schema_file)
            if path.exists():
                sql = path.read_text()
                await conn.execute(sql)
                print(f"Applied {schema_file}")
            else:
                print(f"Skipped {schema_file} (not found)")
    finally:
        await conn.close()

asyncio.run(main())