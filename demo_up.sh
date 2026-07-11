#!/usr/bin/env bash
# demo_up.sh — bring up everything the TrueFoundry demo needs, and print the
# three public URLs that must be pasted into the TrueFoundry dashboard.
#
#   plugin        :8000   the Reva guardrail TF calls
#   billing-mcp   :8001   tools that exist as Tool entities in the Reva store
#   external-mcp  :8002   the untrusted tool the store forbids
#
# Each gets a cloudflared quick tunnel. Quick-tunnel URLs are EPHEMERAL: they
# change on every restart, so after running this you must update three places
# in TrueFoundry (the script prints them). There is no way around that without
# a named Cloudflare tunnel.
#
# Run it from YOUR terminal, not from an agent — backgrounded tunnels get
# throttled elsewhere, stop heartbeating, and Cloudflare deregisters them.
#
#   ./demo_up.sh          start everything, print URLs
#   ./demo_up.sh down     stop everything

set -o pipefail
cd "$(dirname "$0")"
LOGS="$(pwd)/.demo-logs"; mkdir -p "$LOGS"

down() {
  echo "stopping…"
  # Match on the exact commands this script starts, so we never kill a
  # cloudflared or uvicorn someone else is running.
  pkill -f "uvicorn main:app --port 8000" 2>/dev/null
  pkill -f "billing_mcp_server.py" 2>/dev/null
  pkill -f "external_mcp_server.py" 2>/dev/null
  pkill -f "cloudflared tunnel --url http://localhost:800[012]" 2>/dev/null
  sleep 1; echo "done."
}
[ "${1:-}" = "down" ] && { down; exit 0; }

down  # start clean; a stale listener on :8000 is the usual "why won't it bind"

start_tunnel() {  # $1=port $2=name -> echoes the public URL
  local port="$1" name="$2" url=""
  local log="$LOGS/tunnel-$port.log"   # own line: $port must be set before it's used here
  : > "$log"
  nohup cloudflared tunnel --url "http://localhost:$port" --protocol http2 > "$log" 2>&1 &
  for _ in $(seq 1 30); do
    url=$(grep -ao 'https://[a-z0-9-]*\.trycloudflare\.com' "$log" | head -1)
    [ -n "$url" ] && break
    sleep 1
  done
  echo "$url"
}

echo "starting services…"
nohup .venv/bin/uvicorn main:app --port 8000 > "$LOGS/plugin.log" 2>&1 &
nohup .venv/bin/python billing_mcp_server.py  > "$LOGS/billing-mcp.log" 2>&1 &
nohup .venv/bin/python external_mcp_server.py > "$LOGS/external-mcp.log" 2>&1 &
sleep 5

for p in 8000 8001 8002; do
  curl -sf -o /dev/null --max-time 5 "http://127.0.0.1:$p/healthz" 2>/dev/null \
    || curl -sf -o /dev/null --max-time 5 -X POST "http://127.0.0.1:$p/mcp" 2>/dev/null
done

echo "starting tunnels (each takes ~10s)…"
PLUGIN_URL=$(start_tunnel 8000 plugin)
BILLING_URL=$(start_tunnel 8001 billing-mcp)
EXTERNAL_URL=$(start_tunnel 8002 external-mcp)

fail=0
for u in "$PLUGIN_URL" "$BILLING_URL" "$EXTERNAL_URL"; do
  [ -z "$u" ] && fail=1
done
[ "$fail" = 1 ] && { echo "!! a tunnel failed to start — see $LOGS/tunnel-*.log"; exit 1; }

echo
echo "verifying the plugin answers through its tunnel…"
curl -s --max-time 20 "$PLUGIN_URL/healthz" && echo

cat <<EOF

──────────────────────────────────────────────────────────────────────
PASTE THESE INTO TRUEFOUNDRY  (all three change on every restart)
──────────────────────────────────────────────────────────────────────

1. Guardrails -> Registry -> reva-authorization -> URL
   $PLUGIN_URL/reva/authorize

2. MCP Gateway -> MCP Registry -> billing-mcp -> URL
   $BILLING_URL/mcp

3. MCP Gateway -> MCP Registry -> external-mcp -> URL
   $EXTERNAL_URL/mcp

Then:  ./demo_check.sh    (confirms allow+deny before you present)

Logs: $LOGS/   ·   Stop everything: ./demo_up.sh down
EOF
