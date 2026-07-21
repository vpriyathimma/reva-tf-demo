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
import secrets
import sys
from typing import Any

from dotenv import load_dotenv
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from openai import AsyncOpenAI

load_dotenv()

# .strip() defensively: a key pasted into a hosting dashboard often picks up a
# trailing newline, which makes httpx reject the "Bearer <key>\n" Authorization
# header with "Illegal header value". Stripping here fixes it at the source for
# both the LLM client and the MCP client.
TFY_API_KEY = os.environ.get("TFY_API_KEY", "").strip()
# The OpenAI-compatible endpoint. Requests here land on /chat/completions in the
# metrics dashboard and count toward "Total LLM Calls".
TFY_LLM_URL = os.environ.get("TFY_LLM_URL", "https://reva-demo.truefoundry.cloud/api/llm")
# The MCP gateway. Each registered server hangs off this as /<server-name>/server.
TFY_MCP_URL = os.environ.get("TFY_MCP_URL", "https://gateway.truefoundry.ai/reva-demo/mcp")
TFY_MODEL = os.environ.get("TFY_MODEL", "openai/gpt-4o")


def _log(msg: str) -> None:
    # Structured per-hop logging (mirrors guardrail.reva_auth._log). Each LLM and MCP
    # hop is logged with the turn's traceparent, so a request can be followed end to
    # end in the logs by grepping its trace id — the observability half of traceparent.
    print(f"[reva_tf gateway] {msg}", file=sys.stderr, flush=True)


def _tp(traceparent: str | None) -> str:
    return (traceparent or "-")[:50]


def _require_key() -> str:
    if not TFY_API_KEY:
        raise RuntimeError("TFY_API_KEY is unset — copy .env.example to .env and fill it in")
    return TFY_API_KEY


def mint_traceparent() -> str:
    """A W3C Trace Context id: 00-<32 hex trace id>-<16 hex span id>-01.

    Minted once per chat turn (see agents.orchestrate) and forwarded on the
    `traceparent` header of every LLM and MCP hop, so all hops of one request
    share a single trace id. That is what lets the PDP decision logs be filtered
    down to the exact path a single request took, rather than isolated calls.
    """
    return f"00-{secrets.token_hex(16)}-{secrets.token_hex(8)}-01"


async def chat(
    messages: list[dict[str, Any]],
    *,
    agent_id: str,
    tools: list[dict[str, Any]] | None = None,
    user: str | None = None,
    model: str | None = None,
    traceparent: str | None = None,
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

    default_headers = {"X-TFY-METADATA": json.dumps(metadata)}
    if traceparent:
        default_headers["traceparent"] = traceparent
    client = AsyncOpenAI(
        api_key=_require_key(),
        base_url=TFY_LLM_URL,
        default_headers=default_headers,
    )
    kwargs: dict[str, Any] = {"model": model or TFY_MODEL, "messages": messages}
    if tools:
        kwargs["tools"] = tools
    _log(f"llm → agent={agent_id} user={user or '-'} model={model or TFY_MODEL} "
         f"tools={len(tools or [])} msgs={len(messages)} tp={_tp(traceparent)}")
    resp = await client.chat.completions.create(**kwargs)
    try:
        n_tools = len(resp.choices[0].message.tool_calls or []) if resp.choices else 0
    except Exception:  # noqa: BLE001
        n_tools = 0
    _log(f"llm ← ok agent={agent_id} model={model or TFY_MODEL} tool_calls={n_tools}")
    return resp


def _mcp_client(server: str, *, agent_id: str | None = None, user: str | None = None,
                traceparent: str | None = None) -> Client:
    # Forward the acting agent + on-behalf-of user in X-TFY-METADATA, exactly like
    # the LLM client does. Without this, TrueFoundry fills the MCP guardrail context
    # with the API key's owner, so Reva sees the wrong user and on-behalf-of tool
    # policies (e.g. "bob@intern cannot pull billing reports") never match.
    headers = {"Authorization": f"Bearer {_require_key()}"}
    if agent_id or user:
        meta: dict[str, str] = {}
        if agent_id:
            meta["agent_id"] = agent_id
        if user:
            meta["reva_user"] = user
        headers["X-TFY-METADATA"] = json.dumps(meta)
    # Same turn-level trace id as the LLM hop, so this MCP call joins the same trace.
    if traceparent:
        headers["traceparent"] = traceparent
    return Client(
        StreamableHttpTransport(
            url=f"{TFY_MCP_URL}/{server}/server",
            headers=headers,
        )
    )


# Servers that are themselves reasoning agents: invoking them makes a nested
# model call, so the turn's traceparent + on-behalf-of user must reach them for
# that hop to join the same trace and act for the right user.
SUBAGENT_SERVERS = {"ticketing-agent", "booking-agent"}
# Params the app injects into sub-agent tool calls. Hidden from the model's tool
# schema (below) so it never tries to fill them; injected in call_tool instead.
_INJECTED_PARAMS = ("traceparent", "on_behalf_of")


def _strip_injected(schema: dict[str, Any] | None) -> dict[str, Any] | None:
    """Remove the app-injected params from a tool's JSON schema so the model
    doesn't see (or try to supply) them."""
    if not isinstance(schema, dict):
        return schema
    props = schema.get("properties")
    if isinstance(props, dict):
        for k in _INJECTED_PARAMS:
            props.pop(k, None)
    req = schema.get("required")
    if isinstance(req, list):
        schema["required"] = [r for r in req if r not in _INJECTED_PARAMS]
    return schema


async def list_tools(server: str, *, agent_id: str | None = None, user: str | None = None,
                     traceparent: str | None = None) -> list[dict[str, Any]]:
    """Discover a registered MCP server's tools, shaped for the OpenAI tools param.

    Tool names are prefixed with the server so the orchestrator can route a
    tool_call back to the right server later. The separator is `__` because
    OpenAI rejects `/` in function names -- and `/` is what Reva's resource ids
    use, so the two conventions have to be translated at this boundary.

    Sub-agent tools carry app-injected params (traceparent, on_behalf_of); those
    are stripped from the schema so the model never sees them.
    """
    async with _mcp_client(server, agent_id=agent_id, user=user, traceparent=traceparent) as c:
        tools = [
            {
                "type": "function",
                "function": {
                    "name": f"{server}__{t.name}",
                    "description": t.description or "",
                    "parameters": _strip_injected(t.inputSchema),
                },
            }
            for t in await c.list_tools()
        ]
    _log(f"mcp discover server={server} → {len(tools)} tools tp={_tp(traceparent)}")
    return tools


async def call_tool(server: str, tool: str, arguments: dict[str, Any],
                    *, agent_id: str | None = None, user: str | None = None,
                    traceparent: str | None = None) -> Any:
    """Invoke one MCP tool through the gateway.

    Raises whatever the gateway raises. A Reva denial surfaces here as an
    exception mentioning MCPGuardrailError -- the tool's code never runs. Callers
    should catch it and tell the user they were not authorized, rather than
    letting it read as a crash.
    """
    _log(f"mcp → server={server} tool={tool} agent={agent_id or '-'} user={user or '-'} tp={_tp(traceparent)}")
    # A sub-agent reasons with its own model call; inject the turn's trace + user
    # so that nested hop joins the same trace. The model never chose these (they
    # were stripped from its schema) — we add them here.
    args = dict(arguments or {})
    if server in SUBAGENT_SERVERS:
        args["traceparent"] = traceparent or ""
        args["on_behalf_of"] = user or ""
    async with _mcp_client(server, agent_id=agent_id, user=user, traceparent=traceparent) as c:
        result = await c.call_tool(tool, args)
        _log(f"mcp ← ok server={server} tool={tool}")
        return result.structured_content or result.content
