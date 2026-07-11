"""billing-mcp — a demo MCP server whose tools exist as Tool entities in the
Reva policy store.

Purpose: make the tool-authorization story demonstrable *through TrueFoundry*
rather than by hand-crafting the guardrail payload. Register this server in
TF's MCP Registry, attach the Reva guardrail to the mcp_pre_tool hook, and the
gateway will ask Reva before it runs any tool below.

Expected decisions (store: TrueFoundry Integration):

    get_billing_report      ALLOW   permit, no forbid
    get_compliance_status   ALLOW   permit, no forbid
    get_customer_pii        DENY    permitted, but a forbid overrides it
    analytics_probe         DENY    forbid (lives on external-mcp; see note)

⚠️ NAME IT `billing-mcp` IN TRUEFOUNDRY. The plugin builds the Reva resource id
as f"{mcp_server_name}/{tool_name}", and the store's Tool entities are
server-qualified ("billing-mcp/get_customer_pii"). Register it under any other
name and every tool resolves to an unknown entity, so every call denies for the
wrong reason — the same class of bug as the invokeModel/unknown-model one.

`analytics_probe` is deliberately NOT served here: its Tool entity is
"external-mcp/analytics_probe", so it needs a server registered as
`external-mcp` to resolve. Serving it here would evaluate it as
"billing-mcp/analytics_probe", which no policy mentions — it would still deny,
but by accident rather than by the forbid we wrote.

Run:
    .venv/bin/python billing_mcp_server.py          # http://127.0.0.1:8001/mcp
Then expose it (TrueFoundry must reach it):
    cloudflared tunnel --url http://localhost:8001 --protocol http2

The tool bodies return canned data. Nothing here is a real billing system —
the point is which calls Reva permits, not what they return.
"""

import os

from fastmcp import FastMCP

mcp = FastMCP("billing-mcp")


@mcp.tool
def get_billing_report(customer_id: str) -> dict:
    """Summarised, non-sensitive billing totals for a customer."""
    return {
        "customerId": customer_id,
        "invoices": 3,
        "outstanding": "1240.00",
        "currency": "USD",
        "note": "ALLOWED by Reva — permitted tool, no forbid.",
    }


@mcp.tool
def get_compliance_status(customer_id: str) -> dict:
    """Whether a customer's account is in good compliance standing."""
    return {
        "customerId": customer_id,
        "kyc": "verified",
        "standing": "good",
        "note": "ALLOWED by Reva — permitted tool, no forbid.",
    }


@mcp.tool
def get_customer_pii(customer_id: str) -> dict:
    """Full customer PII. A Reva forbid blocks this before it ever runs.

    If you are reading this payload, the guardrail did NOT fire — the tool was
    invoked. Check that the mcp_pre_tool rule targets this server.
    """
    return {
        "customerId": customer_id,
        "ssn": "000-00-0000",
        "dob": "1990-01-01",
        "note": "If you can see this, the PII forbid did not fire.",
    }


if __name__ == "__main__":
    # Render (and any PaaS) injects $PORT and needs 0.0.0.0; locally falls back to 8001.
    mcp.run(transport="http", host="0.0.0.0", port=int(os.environ.get("PORT", "8001")))
