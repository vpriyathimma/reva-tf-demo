"""Every outbound call this app makes goes through TrueFoundry.

That is the whole point of the module. Amit's instruction was to wire TrueFoundry
in as the gateway first and worry about authorization second: once the LLM calls,
the MCP calls, and the agent-to-agent calls all traverse the gateway, they appear
in AI Monitoring -> Metrics, and *then* the Reva guardrail plugin can intercept
them. So nothing here talks to OpenAI directly and nothing here talks to an MCP
server directly. Both go through TrueFoundry, and both are therefore authorizable.

Identity travels in the `X-TFY-METADATA` header. TrueFoundry copies it into the
guardrail payload as `context.metadata`, which is where the Reva plugin reads
`agent_id` to decide which Agent entity is making the call. That header is the
only reason a rogue agent can be told apart from the billing agent -- see
reva-truefoundry-plugin/guardrail/reva_auth.py:_agent_id.
"""

from __future__ import annotations

import json
import os
from typing import Any

from dotenv import load_dotenv
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from openai import AsyncOpenAI

load_dotenv()

TFY_API_KEY = os.environ.get("TFY_API_KEY", "")
# The OpenAI-compatible endpoint. Requests here land on /chat/completions in the
# metrics dashboard and count toward "Total LLM Calls".
TFY_LLM_URL = os.environ.get("TFY_LLM_URL", "https://reva-demo.truefoundry.cloud/api/llm")
# The MCP gateway. Each registered server hangs off this as /<server-name>/server.
TFY_MCP_URL = os.environ.get("TFY_MCP_URL", "https://gateway.truefoundry.ai/reva-demo/mcp")
TFY_MODEL = os.environ.get("TFY_MODEL", "openai/gpt-4o")


def _require_key() -> str:
    if not TFY_API_KEY:
        raise RuntimeError("TFY_API_KEY is unset — copy .env.example to .env and fill it in")
    return TFY_API_KEY


async def chat(
    messages: list[dict[str, Any]],
    *,
    agent_id: str,
    tools: list[dict[str, Any]] | None = None,
    user: str | None = None,
    model: str | None = None,
) -> Any:
    """One LLM turn, routed through TrueFoundry.

    `agent_id` becomes the Agent entity in Reva's eval request; `user` becomes the
    principal the agent acts on behalf of. Both ride in X-TFY-METADATA rather than
    in the body, because TrueFoundry only forwards metadata (not the body) into
    guardrail context.

    `model` overrides TFY_MODEL for one call. Reva sees the bare name with the
    provider prefix stripped, so "openai/gpt-4o" is authorized as "gpt-4o".
    """
    metadata = {"agent_id": agent_id}
    if user:
        metadata["reva_user"] = user

    client = AsyncOpenAI(
        api_key=_require_key(),
        base_url=TFY_LLM_URL,
        default_headers={"X-TFY-METADATA": json.dumps(metadata)},
    )
    kwargs: dict[str, Any] = {"model": model or TFY_MODEL, "messages": messages}
    if tools:
        kwargs["tools"] = tools
    return await client.chat.completions.create(**kwargs)


def _mcp_client(server: str) -> Client:
    return Client(
        StreamableHttpTransport(
            url=f"{TFY_MCP_URL}/{server}/server",
            headers={"Authorization": f"Bearer {_require_key()}"},
        )
    )


async def list_tools(server: str) -> list[dict[str, Any]]:
    """Discover a registered MCP server's tools, shaped for the OpenAI tools param.

    Tool names are prefixed with the server so the orchestrator can route a
    tool_call back to the right server later. The separator is `__` because
    OpenAI rejects `/` in function names -- and `/` is what Reva's resource ids
    use, so the two conventions have to be translated at this boundary.
    """
    async with _mcp_client(server) as c:
        return [
            {
                "type": "function",
                "function": {
                    "name": f"{server}__{t.name}",
                    "description": t.description or "",
                    "parameters": t.inputSchema,
                },
            }
            for t in await c.list_tools()
        ]


async def call_tool(server: str, tool: str, arguments: dict[str, Any]) -> Any:
    """Invoke one MCP tool through the gateway.

    Raises whatever the gateway raises. A Reva denial surfaces here as an
    exception mentioning MCPGuardrailError -- the tool's code never runs. Callers
    should catch it and tell the user they were not authorized, rather than
    letting it read as a crash.
    """
    async with _mcp_client(server) as c:
        result = await c.call_tool(tool, arguments)
        return result.structured_content or result.content
