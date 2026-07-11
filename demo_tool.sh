#!/usr/bin/env bash
# demo_tool.sh — invoke one MCP tool through TrueFoundry's MCP gateway and show
# what Reva decided. This is the tool-authorization beat of the demo.
#
#   export TFY_API_KEY='<TrueFoundry PAT>'
#
#   ./demo_tool.sh billing-mcp  get_billing_report      # ALLOW — tool runs
#   ./demo_tool.sh billing-mcp  get_compliance_status   # ALLOW — tool runs
#   ./demo_tool.sh billing-mcp  get_customer_pii        # DENY  — forbid
#   ./demo_tool.sh external-mcp analytics_probe         # DENY  — forbid
#
# The call goes: you -> TrueFoundry MCP gateway -> mcp_pre_tool hook ->
# Reva guardrail plugin -> Reva PDP -> allow/deny. On a deny the tool's code
# never runs; TrueFoundry refuses before invoking the server.

set -o pipefail
KEY="${TFY_API_KEY:?export TFY_API_KEY=<your TrueFoundry PAT>}"
GW="${TFY_GATEWAY:-https://gateway.truefoundry.ai/reva-demo/mcp}"

SERVER="${1:?usage: ./demo_tool.sh <billing-mcp|external-mcp> <tool> [args-json]}"
TOOL="${2:?usage: ./demo_tool.sh <server> <tool> [args-json]}"
ARGS="$3"
if [ -z "$ARGS" ]; then
  case "$TOOL" in
    analytics_probe) ARGS='{"query":"customer emails"}' ;;
    *)               ARGS='{"customer_id":"c1"}' ;;
  esac
fi

URL="$GW/$SERVER/server"
H=(-H "Authorization: Bearer $KEY" -H 'Content-Type: application/json'
   -H 'Accept: application/json, text/event-stream')

# MCP streamable-HTTP needs an initialize handshake before any tools/call.
curl -s --max-time 25 "${H[@]}" -D /tmp/dt_h.txt -o /dev/null -X POST "$URL" -d \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"demo","version":"1"}}}'
SID=$(grep -i '^mcp-session-id:' /tmp/dt_h.txt | tr -d '\r' | awk '{print $2}')
SH=(); [ -n "$SID" ] && SH=(-H "Mcp-Session-Id: $SID")
curl -s --max-time 25 "${H[@]}" "${SH[@]}" -X POST "$URL" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' -o /dev/null

echo
echo "  agent 'billing-support-agent'  ->  $SERVER/$TOOL"
echo "  arguments: $ARGS"
echo "  asking TrueFoundry, which asks Reva…"
echo

BODY=$(curl -s --max-time 40 "${H[@]}" "${SH[@]}" -X POST "$URL" \
  -d "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"$TOOL\",\"arguments\":$ARGS}}")

printf '%s' "$BODY" | sed -n 's/^data: //p' | python3 -c '
import sys, json
raw = sys.stdin.read().strip()
try:
    d = json.loads(raw)
except Exception:
    print("  ?? unparseable response:", raw[:200]); sys.exit(0)

G, R, B, X = "\033[32m", "\033[31m", "\033[1m", "\033[0m"
if "error" in d:
    msg = d["error"].get("message", "")
    if "Guardrail" in msg:
        head = msg.split(chr(58) * 2)[0].strip()   # text before the "::"
        print(f"  {R}{B}DENY{X}  TrueFoundry blocked it. The tool never ran.")
        print(f"  {head}")
    else:
        print(f"  ?? {msg[:160]}")
else:
    res = d.get("result", {})
    out = res.get("structuredContent") or res.get("content")
    print(f"  {G}{B}ALLOW{X}  the tool ran and returned:")
    print("  " + json.dumps(out)[:300])
'
echo
