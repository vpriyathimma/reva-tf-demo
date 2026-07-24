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
    emit: Callable[[dict], None], servers: list[str] | None = None,
    *, agent_id: str | None = None, user: str | None = None,
    traceparent: str | None = None,
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
            tools.extend(await gateway.list_tools(server, agent_id=agent_id, user=user,
                                                  traceparent=traceparent))
        except Exception as e:  # noqa: BLE001
            emit({"type": "warn", "text": f"{server} unreachable: {str(e)[:80]}"})
    return tools


async def _run_tool(name: str, arguments: dict, emit: Callable[[dict], None],
                    *, agent_id: str | None = None, user: str | None = None,
                    traceparent: str | None = None,
                    conversation: list[dict[str, Any]] | None = None,
                    thoughts: str | None = None) -> str:
    """Execute one tool call and return what the model should see as its result.

    `conversation` is the turn's history so far; forwarded so the tool-call eval
    carries chatHistory + hops instead of an empty list. `thoughts` is the agent's
    reasoning for this call → transmission.thoughts in the eval (intent detection)."""
    server, tool = name.split("__", 1)
    emit({"type": "tool_call", "server": server, "tool": tool, "arguments": arguments})
    try:
        result = await gateway.call_tool(server, tool, arguments, agent_id=agent_id, user=user,
                                         traceparent=traceparent, conversation=conversation,
                                         thoughts=thoughts)
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


def _fallback_intents(message: str, servers: list[str] | None) -> list[tuple[str, str, dict]]:
    """Every tool the prompt maps to, in a sensible order.

    Nova Micro cannot reliably emit multi-argument tool calls — it either produces
    an invalid tool-use sequence (Bedrock 424) or just answers in prose. When it
    fails to call the tools the user plainly asked for, the orchestrator invokes
    them itself. The calls still go through TrueFoundry and Reva, so the
    authorization is exactly as real; only the tool *selection* stopped depending
    on a model that can't do it.

    Returns a LIST, not a single match — a compound prompt ("get the billing
    report, then open a ticket") must fire BOTH tools so the agent-to-agent chain
    (billing agent -> ticketing sub-agent -> its own model call) actually runs.
    Scoped to servers that are switched on.
    """
    m = message.lower()
    allowed = set(servers if servers is not None else SERVERS)
    cid = re.search(r"\bc\d+\b", message, re.IGNORECASE)
    customer = cid.group(0) if cid else "c1"

    def on(s: str) -> bool:
        return s in allowed

    out: list[tuple[str, str, dict]] = []
    if on("billing-mcp") and ("pii" in m or "personal" in m):
        out.append(("billing-mcp", "get_customer_pii", {"customer_id": customer}))
    if on("billing-mcp") and "compliance" in m:
        out.append(("billing-mcp", "get_compliance_status", {"customer_id": customer}))
    if on("billing-mcp") and ("billing" in m or "report" in m or "invoice" in m):
        out.append(("billing-mcp", "get_billing_report", {"customer_id": customer}))
    if on("external-mcp") and ("probe" in m or "analytics" in m or "external" in m):
        out.append(("external-mcp", "analytics_probe", {"query": message}))
    if on("ticketing-agent") and "ticket" in m:
        out.append(("ticketing-agent", "create_ticket", {"customer_id": customer, "summary": message}))
    if on("booking-agent") and ("book" in m or "appointment" in m or "slot" in m):
        out.append(("booking-agent", "book_slot", {"customer_id": customer, "slot": "2026-07-14T10:00Z"}))
    return out


async def _run_fallback(
    message: str, servers: list[str] | None, emit: Callable[[dict], None],
    *, agent_id: str | None = None, user: str | None = None,
    traceparent: str | None = None,
) -> str | None:
    """Run EVERY tool the prompt maps to, in order, and phrase each outcome.

    Running all matches (not just the first) is what makes a compound prompt
    exercise the A2A chain: get_billing_report AND create_ticket, the latter
    delegating to the ticketing sub-agent."""
    intents = _fallback_intents(message, servers)
    if not intents:
        return None
    replies: list[str] = []
    # Running conversation, so each successive tool's eval shows the history that
    # led to it (the user prompt + prior tool results) — chatHistory + hops fill
    # progressively, the same way LiteLLM's loop builds them.
    convo: list[dict[str, Any]] = [{"role": "user", "content": message}]
    for server, tool, args in intents:
        # No live model reasoning here (this path runs when the model can't tool-call),
        # so synthesize the agent's intent from the prompt + planned action. The user's
        # own words ride along, so a prompt-injection/exfil ask is visible to the intent
        # engine in transmission.thoughts.
        thought = (f"To handle the user request {message!r}, I will call "
                   f"{server}/{tool} with arguments {json.dumps(args, default=str)}.")
        result = await _run_tool(f"{server}__{tool}", args, emit, agent_id=agent_id, user=user,
                                 traceparent=traceparent, conversation=list(convo),
                                 thoughts=thought)
        replies.append(_phrase(f"{server}__{tool}", result))
        convo.append({"role": "tool", "content": f"{server}/{tool} returned: {result[:600]}"})
    return "\n".join(replies)


async def orchestrate(
    message: str,
    *,
    user: str,
    emit: Callable[[dict], None],
    agent_id: str = ORCHESTRATOR_ID,
    model: str | None = None,
    servers: list[str] | None = None,
    history: list[dict[str, Any]] | None = None,
    max_turns: int = 6,
    traceparent: str | None = None,
) -> str:
    """Run the agent loop for one user message. `emit` streams trace events to the UI.

    `agent_id` is the identity the loop runs under. It is a parameter, not a
    constant, because swapping it is the sharpest demonstration in the demo:
    the same user, prompt, and model, under an identity no permit covers, gets
    refused. Reva evaluates the agent -- not just the request.

    max_turns bounds the loop: a model that keeps calling denied tools would
    otherwise retry forever, and each retry is a real authorization request.
    """
    # One W3C trace id for the whole turn: mint it once (or reuse an ingress one the
    # caller forwarded), emit it to the UI, then forward it on every LLM + MCP hop so
    # all of this turn's calls land in the PDP logs under the same trace.
    if not traceparent:
        traceparent = gateway.mint_traceparent()
    emit({"type": "trace", "traceparent": traceparent})

    tools = await _available_tools(emit, servers, agent_id=agent_id, user=user,
                                   traceparent=traceparent)
    used_model = model or gateway.TFY_MODEL
    # Nova can't do OpenAI-style tool-calling: handing it `tools` makes the gateway
    # return 424 (failed dependency) on the malformed tool_use block it emits, so the
    # chat-completion span looks broken. Withhold tools from Nova — the deterministic
    # keyword→tool fallback below still runs the tool (and still routes through Reva),
    # so the model call stays a clean 200. Tool-capable models (gpt-4o) keep tools.
    tool_capable = "nova" not in (used_model or "").lower()
    send_tools = tools if tool_capable else None
    # Carry prior turns so the payload BUILDS context across a session — the
    # requestBody.messages array grows [system, u1, a1, u2, a2, …, current]. This
    # is what lets TrueFoundry run intent guardrails over the whole conversation.
    messages: list[dict[str, Any]] = [{"role": "system", "content": SYSTEM}]
    if history:
        messages.extend(
            {"role": m["role"], "content": m["content"]}
            for m in history
            if isinstance(m, dict) and m.get("role") and m.get("content")
        )
    messages.append({"role": "user", "content": message})

    del max_turns  # single turn: Nova Micro can't sustain a multi-turn tool loop
    try:
        response = await gateway.chat(
            messages, agent_id=agent_id, tools=send_tools or None, user=user, model=model,
            traceparent=traceparent,
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
        fb = await _run_fallback(message, servers, emit, agent_id=agent_id, user=user,
                                 traceparent=traceparent)
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
        fb = await _run_fallback(message, servers, emit, agent_id=agent_id, user=user,
                                 traceparent=traceparent)
        return fb if fb is not None else (_strip_thinking(choice.content) or "…")

    # The model called the tool itself — run each and report the outcome deterministically
    # (no second model call: asking Nova to summarise a tool result is where it 424s).
    # choice.content is the model's OWN reasoning next to the tool call (for gpt-4o it's
    # the plan; for Nova the <thinking> block). Forward it as the tool call's thoughts so
    # the intent engine sees the agent's real reasoning, not just the tool name/args.
    reasoning = (choice.content or "").strip()
    replies = [
        _phrase(
            tc.function.name,
            await _run_tool(tc.function.name, json.loads(tc.function.arguments or "{}"), emit,
                            agent_id=agent_id, user=user, traceparent=traceparent,
                            thoughts=reasoning or None),
        )
        for tc in choice.tool_calls
    ]
    return "\n".join(replies)
