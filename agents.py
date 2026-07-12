"""The orchestrator loop, and the identities it runs under.

Three agents, one gateway:

    user -> orchestrator-agent  --LLM-->      TrueFoundry -> OpenAI
                                --MCP-->      TrueFoundry -> billing-mcp / external-mcp
                                --MCP-->      TrueFoundry -> ticketing-agent / booking-agent

The sub-agents are reached as MCP servers rather than as direct HTTP calls, and
that is a deliberate choice. TrueFoundry only intercepts two things: LLM calls
and MCP tool calls. A plain agent-to-agent HTTP request traverses no hook, shows
up in no metric, and cannot be authorized. Exposing each sub-agent as an MCP
server makes "orchestrator delegates to ticketing" an MCP tool call -- so it
routes through the gateway, appears in AI Monitoring, and hits `mcp_pre_tool`,
where Reva can allow or deny it. That is what turns invokeAgent from something
we can only evaluate at the PDP into something the gateway can enforce.

A denied tool call is NOT an error here. It is fed back to the model as a tool
result saying it was not authorized, so the model explains itself to the user in
plain language instead of the app throwing a stack trace. Denial is a normal
outcome of asking, not a crash.
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable

import gateway

ORCHESTRATOR_ID = "billing-support-agent"

# The MCP servers the orchestrator may draw tools from. Names must match the
# MCP Registry entries in TrueFoundry exactly -- the plugin builds Reva resource
# ids as f"{server}/{tool}", so a typo here silently becomes a default-deny for
# a resource no policy mentions, which looks identical to a policy that refused.
SERVERS = ["billing-mcp", "external-mcp", "ticketing-agent", "booking-agent"]

SYSTEM = """You are a billing support orchestrator.

Use the tools available to you to answer the user. Some tools may refuse to run:
you are not authorized to call them. When that happens, tell the user plainly
which action was refused and move on. Never invent data you could not retrieve,
and never pretend a refused call succeeded."""


def _is_denial(err: Exception) -> bool:
    s = str(err)
    return "Guardrail" in s or "Blocked by Reva" in s


async def _available_tools(
    emit: Callable[[dict], None], servers: list[str] | None = None
) -> list[dict[str, Any]]:
    """Discover tools from each selected server. A server that is down is skipped
    rather than fatal -- the demo should degrade, not collapse.

    Deselecting a server here is NOT authorization. It only stops the orchestrator
    offering those tools to the model. Reva's job is to refuse tools the agent does
    reach for; a tool never offered was never authorized or denied.
    """
    tools: list[dict[str, Any]] = []
    for server in (servers if servers is not None else SERVERS):
        try:
            tools.extend(await gateway.list_tools(server))
        except Exception as e:  # noqa: BLE001
            emit({"type": "warn", "text": f"{server} unreachable: {str(e)[:80]}"})
    return tools


async def _run_tool(name: str, arguments: dict, emit: Callable[[dict], None]) -> str:
    """Execute one tool call and return what the model should see as its result."""
    server, tool = name.split("__", 1)
    emit({"type": "tool_call", "server": server, "tool": tool, "arguments": arguments})
    try:
        result = await gateway.call_tool(server, tool, arguments)
    except Exception as e:  # noqa: BLE001
        if _is_denial(e):
            emit({"type": "denied", "server": server, "tool": tool})
            return json.dumps(
                {"error": "not_authorized",
                 "detail": f"Reva denied {server}/{tool}. The tool did not run."}
            )
        emit({"type": "error", "server": server, "tool": tool, "text": str(e)[:120]})
        return json.dumps({"error": "tool_failed", "detail": str(e)[:200]})
    emit({"type": "allowed", "server": server, "tool": tool, "result": result})
    # If the tool was itself a reasoning agent, it made its OWN model call inside.
    # Surface that nested authorization as its own trace card so the whole
    # agent-to-agent chain is visible: two agents, each thinking, each governed.
    if isinstance(result, dict):
        model = "amazon.nova-micro-v1-0"
        if result.get("reasoned_by"):
            emit({"type": "allowed", "kind": "model", "server": server, "tool": model})
        elif "DENIED by Reva" in str(result.get("note", "")):
            emit({"type": "denied", "kind": "model", "server": server, "tool": model})
    return json.dumps(result, default=str)


_THINK = re.compile(r"<thinking>.*?</thinking>", re.DOTALL | re.IGNORECASE)


def _strip_thinking(text: str | None) -> str:
    """Nova Micro emits <thinking>…</thinking> next to its tool calls; that mixed
    text+toolUse content is what Bedrock rejects as an 'invalid sequence'. Drop it."""
    return _THINK.sub("", text or "").strip()


def _phrase(name: str, result_json: str) -> str:
    """Turn a tool result (or a Reva denial) into a sentence for the user."""
    server, tool = name.split("__", 1)
    try:
        data = json.loads(result_json)
    except (ValueError, TypeError):
        data = None
    if isinstance(data, dict) and data.get("error") == "not_authorized":
        return f"I'm not authorized to use {server}/{tool} — Reva blocked it at the gateway, so it never ran."
    if isinstance(data, dict) and data.get("error"):
        return f"The {server}/{tool} call couldn't complete: {data.get('detail') or data.get('error')}"
    return f"{server}/{tool} returned: {result_json}"


def _fallback_intent(message: str, servers: list[str] | None) -> tuple[str, str, dict] | None:
    """Map a demo prompt straight to a tool call.

    Nova Micro cannot reliably emit multi-argument tool calls — it either produces
    an invalid tool-use sequence (Bedrock 424) or just answers in prose. When it
    fails to call a tool the user plainly asked for, the orchestrator invokes the
    obvious one itself. The call still goes through TrueFoundry and Reva, so the
    authorization is exactly as real; only the tool *selection* stopped depending
    on a model that can't do it. Scoped to servers that are switched on.
    """
    m = message.lower()
    allowed = set(servers if servers is not None else SERVERS)
    cid = re.search(r"\bc\d+\b", message, re.IGNORECASE)
    customer = cid.group(0) if cid else "c1"

    def on(s: str) -> bool:
        return s in allowed

    if on("billing-mcp") and ("pii" in m or "personal" in m):
        return "billing-mcp", "get_customer_pii", {"customer_id": customer}
    if on("billing-mcp") and "compliance" in m:
        return "billing-mcp", "get_compliance_status", {"customer_id": customer}
    if on("billing-mcp") and ("billing" in m or "report" in m or "invoice" in m):
        return "billing-mcp", "get_billing_report", {"customer_id": customer}
    if on("external-mcp") and ("probe" in m or "analytics" in m or "external" in m):
        return "external-mcp", "analytics_probe", {"query": message}
    if on("ticketing-agent") and "ticket" in m:
        return "ticketing-agent", "create_ticket", {"customer_id": customer, "summary": message}
    if on("booking-agent") and ("book" in m or "appointment" in m or "slot" in m):
        return "booking-agent", "book_slot", {"customer_id": customer, "slot": "2026-07-14T10:00Z"}
    return None


async def _run_fallback(
    message: str, servers: list[str] | None, emit: Callable[[dict], None]
) -> str | None:
    """If the prompt maps to a tool, call it directly and phrase the outcome."""
    intent = _fallback_intent(message, servers)
    if not intent:
        return None
    server, tool, args = intent
    result = await _run_tool(f"{server}__{tool}", args, emit)
    return _phrase(f"{server}__{tool}", result)


async def orchestrate(
    message: str,
    *,
    user: str,
    emit: Callable[[dict], None],
    agent_id: str = ORCHESTRATOR_ID,
    model: str | None = None,
    servers: list[str] | None = None,
    max_turns: int = 6,
) -> str:
    """Run the agent loop for one user message. `emit` streams trace events to the UI.

    `agent_id` is the identity the loop runs under. It is a parameter, not a
    constant, because swapping it is the sharpest demonstration in the demo:
    the same user, prompt, and model, under an identity no permit covers, gets
    refused. Reva evaluates the agent -- not just the request.

    max_turns bounds the loop: a model that keeps calling denied tools would
    otherwise retry forever, and each retry is a real authorization request.
    """
    tools = await _available_tools(emit, servers)
    used_model = model or gateway.TFY_MODEL
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": message},
    ]

    del max_turns  # single turn: Nova Micro can't sustain a multi-turn tool loop
    try:
        response = await gateway.chat(
            messages, agent_id=agent_id, tools=tools or None, user=user, model=model
        )
    except Exception as e:  # noqa: BLE001
        if _is_denial(e):
            emit({"type": "denied", "kind": "model", "server": agent_id, "tool": used_model})
            return (
                f"Reva denied '{agent_id}' permission to call {used_model}. "
                "The model was never contacted."
            )
        # Reva let the call through; the model itself failed (Nova Micro routinely
        # produces an invalid tool-use sequence). Show the model as allowed, then
        # fall back to invoking the tool the user clearly wanted.
        emit({"type": "allowed", "kind": "model", "server": agent_id, "tool": used_model})
        fb = await _run_fallback(message, servers, emit)
        if fb is not None:
            return fb
        # Nova failed and nothing maps to an enabled tool (e.g. a billing question
        # with only the booking server on). Degrade to a plain sentence, not a 424.
        if "ToolUse" in str(e) or "424" in str(e):
            return ("I couldn't act on that with the tools currently switched on. "
                    "Enable the tool that fits the request and try again.")
        emit({"type": "error", "server": "llm", "tool": used_model, "text": str(e)[:160]})
        return f"The model call failed: {str(e)[:160]}"

    # The call came back, so Reva permitted this agent to invoke this model.
    emit({"type": "allowed", "kind": "model", "server": agent_id, "tool": used_model})
    choice = response.choices[0].message

    # Nova answered in prose without calling a tool. If the prompt plainly maps to
    # one, run it anyway so the demo beat still lands; otherwise return the text.
    if not choice.tool_calls:
        fb = await _run_fallback(message, servers, emit)
        return fb if fb is not None else (_strip_thinking(choice.content) or "…")

    # Nova called the tool itself — run each and report the outcome deterministically
    # (no second model call: asking Nova to summarise a tool result is where it 424s).
    replies = [
        _phrase(
            tc.function.name,
            await _run_tool(tc.function.name, json.loads(tc.function.arguments or "{}"), emit),
        )
        for tc in choice.tool_calls
    ]
    return "\n".join(replies)
