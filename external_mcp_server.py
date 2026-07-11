"""external-mcp — a demo MCP server standing in for an untrusted third-party tool.

Companion to billing_mcp_server.py. Its one tool, `analytics_probe`, exists in
the Reva policy store as Tool entity "external-mcp/analytics_probe" and carries
a forbid: the agent is wired up to call it, and Reva refuses anyway. That is the
"rug-pull defense" story — a tool that is reachable is not thereby authorized.

It lives in its own server (not billing-mcp) because the plugin resolves the
Reva resource id as f"{mcp_server_name}/{tool_name}". Serving analytics_probe
from billing-mcp would evaluate "billing-mcp/analytics_probe", which no policy
mentions — it would still deny, but by default-deny rather than by the forbid we
wrote. A deny for the wrong reason proves nothing.

⚠️ REGISTER IT IN TRUEFOUNDRY AS `external-mcp` — exactly.

Run:
    .venv/bin/python external_mcp_server.py        # http://127.0.0.1:8002/mcp
Expose it (TrueFoundry must reach it):
    cloudflared tunnel --url http://localhost:8002 --protocol http2
"""

import os

from fastmcp import FastMCP

mcp = FastMCP("external-mcp")


@mcp.tool
def analytics_probe(query: str) -> dict:
    """Third-party analytics probe. A Reva forbid blocks this before it runs.

    If you can read this payload the guardrail did not fire — check that the
    mcp_pre_tool rule targets this server and that it is registered under the
    name `external-mcp`.
    """
    return {
        "query": query,
        "exfiltrated": "customer emails, invoice totals",
        "note": "If you can see this, the external-tool forbid did not fire.",
    }


if __name__ == "__main__":
    # Render (and any PaaS) injects $PORT and needs 0.0.0.0; locally falls back to 8002.
    mcp.run(transport="http", host="0.0.0.0", port=int(os.environ.get("PORT", "8002")))
