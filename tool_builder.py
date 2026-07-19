"""
Converts a RegisteredApi (DB row) into an MCP Tool definition.

MCP concept: a Tool's inputSchema is plain JSON Schema describing the
arguments the agent must supply. We build it by merging path, query, and
body param definitions into one flat object schema -- the agent doesn't
need to know which params go where in the actual HTTP request, that's the
execution proxy's job, not the agent's.
"""

import mcp.types as types

from registry import RegisteredApi


def build_tool(api: RegisteredApi) -> types.Tool:
    properties: dict = {}
    required: list[str] = []

    for param_group in (api.path_params, api.query_params, api.body_params):
        for param_name, param_def in param_group.items():
            properties[param_name] = {
                "type": param_def.get("type", "string"),
                "description": param_def.get("description", ""),
            }
            if param_def.get("required", True):
                required.append(param_name)

    input_schema = {
        "type": "object",
        "properties": properties,
        "required": required,
    }

    return types.Tool(
        name=api.name,
        description=api.description,
        inputSchema=input_schema,
    )