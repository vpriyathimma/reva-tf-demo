"""ticketing-agent — a sub-agent the orchestrator delegates to, exposed as MCP.

Why MCP and not a plain HTTP endpoint: TrueFoundry hooks LLM calls and MCP tool
calls, and nothing else. If the orchestrator called this over raw HTTP the
request would traverse no gateway, appear in no metric, and be unauthorizable.
As an MCP server it becomes a tool call -- routed, logged, and eligible for the
`mcp_pre_tool` hook, which is where Reva decides whether one agent may invoke
another.

⚠️ REGISTER IT IN TRUEFOUNDRY AS `ticketing-agent` — exactly. The plugin builds
the Reva resource id as f"{mcp_server_name}/{tool_name}", so the registered name
IS part of the policy's resource id. Register it as anything else and the policy
store will not recognise the resource; the call will still be denied, but by
default-deny rather than by a rule anyone wrote.

Run:
    .venv/bin/python ticketing_agent_server.py       # http://127.0.0.1:8003/mcp
Expose it (TrueFoundry must reach it):
    cloudflared tunnel --url http://localhost:8003 --protocol http2
"""

import os

from fastmcp import FastMCP

import gateway

mcp = FastMCP("ticketing-agent")

# This sub-agent is itself an agent: when asked to open a ticket it does its own
# reasoning by calling a model through TrueFoundry under its OWN identity
# ("ticketing-agent"). That second model call is authorized by Reva separately
# from the orchestrator's — which is what makes this genuine agent-to-agent:
# two agents, each reasoning, each governed. It needs its own model permit in the
# policy store; without one, Reva denies its thinking and it degrades gracefully.
AGENT_ID = "ticketing-agent"
_TICKETS: dict[str, dict] = {}


async def _triage(summary: str, *, traceparent: str | None = None,
                  on_behalf_of: str | None = None) -> dict:
    """Ask a model (as this agent) to classify the issue. Returns triage or a note.

    traceparent / on_behalf_of are injected by the calling app so this nested
    model call joins the same trace and acts for the same end user."""
    try:
        r = await gateway.chat(
            [
                {"role": "system", "content": "You are a support ticketing agent. Reply in one short "
                 "line: a priority (LOW, MEDIUM, or HIGH) and a five-word triage note."},
                {"role": "user", "content": summary},
            ],
            agent_id=AGENT_ID,
            user=on_behalf_of or None,
            traceparent=traceparent or None,
        )
        return {"triage": (r.choices[0].message.content or "").strip(),
                "reasoned_by": f"{AGENT_ID} (own model call via TrueFoundry)"}
    except Exception as e:  # noqa: BLE001
        s = str(e)
        if "Guardrail" in s or "Blocked by Reva" in s:
            return {"triage": None,
                    "note": f"{AGENT_ID}'s own model call was DENIED by Reva — ticket opened without triage."}
        return {"triage": None, "note": f"{AGENT_ID} could not reason: {s[:100]}"}


@mcp.tool
async def create_ticket(customer_id: str, summary: str,
                        traceparent: str = "", on_behalf_of: str = "") -> dict:
    """Open a support ticket. The ticketing-agent triages it via its own model call.

    traceparent / on_behalf_of are injected by the calling app (stripped from the
    model's view) so the triage model call joins the same trace."""
    ticket_id = f"TKT-{1000 + len(_TICKETS)}"
    _TICKETS[ticket_id] = {"customer_id": customer_id, "summary": summary, "status": "open"}
    result = {"ticket_id": ticket_id, "status": "open", "customer_id": customer_id}
    result.update(await _triage(summary, traceparent=traceparent or None,
                                on_behalf_of=on_behalf_of or None))
    return result


@mcp.tool
def close_ticket(ticket_id: str) -> dict:
    """Close an open support ticket. Privileged: a policy may forbid this."""
    if ticket_id not in _TICKETS:
        return {"error": "no such ticket", "ticket_id": ticket_id}
    _TICKETS[ticket_id]["status"] = "closed"
    return {"ticket_id": ticket_id, "status": "closed"}


if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=int(os.environ.get("PORT", "8003")))
