"""booking-agent — the second sub-agent, exposed as MCP for the same reason.

Companion to ticketing_agent_server.py. Two sub-agents rather than one because
Amit asked for agent-to-agent traffic, and one sub-agent only demonstrates
orchestrator-to-agent. With two, the orchestrator has to choose, and a policy
can permit one delegation while forbidding the other -- which is the whole point
of authorizing agent-to-agent calls rather than merely observing them.

⚠️ REGISTER IT IN TRUEFOUNDRY AS `booking-agent` — exactly. See the note in
ticketing_agent_server.py about why the registered name is load-bearing.

Run:
    .venv/bin/python booking_agent_server.py         # http://127.0.0.1:8004/mcp
Expose it (TrueFoundry must reach it):
    cloudflared tunnel --url http://localhost:8004 --protocol http2
"""

import os

from fastmcp import FastMCP

mcp = FastMCP("booking-agent")

_SLOTS = ["2026-07-14T10:00Z", "2026-07-14T14:00Z", "2026-07-15T09:00Z"]


@mcp.tool
def list_slots() -> dict:
    """List available callback slots for a customer support call."""
    return {"slots": _SLOTS}


@mcp.tool
def book_slot(customer_id: str, slot: str) -> dict:
    """Book a callback slot for a customer."""
    if slot not in _SLOTS:
        return {"error": "slot unavailable", "slot": slot}
    return {"booked": True, "customer_id": customer_id, "slot": slot}


if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=int(os.environ.get("PORT", "8004")))
