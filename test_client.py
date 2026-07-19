# C:\MCP\test_client.py
import asyncio
import json
import os
import sys

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

API_KEY = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("MCP_API_KEY", "")

if not API_KEY:
    print("Usage: python test_client.py <api_key>")
    print("   or: set MCP_API_KEY=<key> && python test_client.py")
    sys.exit(1)

async def main():
    async with streamablehttp_client(
        "http://127.0.0.1:8000/mcp",
        headers={"X-API-Key": API_KEY},
    ) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("✓ initialize OK")

            tools = await session.list_tools()
            tool_names = [t.name for t in tools.tools]
            print(f"✓ list_tools → {tool_names}")

            if "get_github_repo" in tool_names:
                result = await session.call_tool(
                    "get_github_repo",
                    {"owner": "anthropics", "repo": "anthropic-sdk-python"},
                )
                raw = result.content[0].text
                # Could be an error string or JSON depending on rate limit
                try:
                    data = json.loads(raw)
                    print(f"✓ call_tool → stars={data.get('stargazers_count')} language={data.get('language')}")
                except json.JSONDecodeError:
                    print(f"✓ call_tool → (execution proxy relayed): {raw[:120]}")
            else:
                print("  (no get_github_repo tool found — register it first)")

asyncio.run(main())