#!/usr/bin/env bash
# demo_check.sh — pre-flight. Run this AFTER updating the three URLs in
# TrueFoundry and BEFORE presenting. It fires the exact calls the demo makes,
# through TrueFoundry's real gateway, and asserts each decision.
#
#   export TFY_API_KEY='<TrueFoundry PAT>'
#   ./demo_check.sh
#
# Every check asserts an ALLOW as well as a DENY. A stack that denies
# everything looks like a working policy and proves nothing — the allows are
# what show Reva is actually reading the rules.

set -o pipefail
cd "$(dirname "$0")"
KEY="${TFY_API_KEY:?export TFY_API_KEY=<your TrueFoundry PAT>}"
GW="${TFY_GATEWAY:-https://gateway.truefoundry.ai/reva-demo/mcp}"

pass=0; fail=0
ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; fail=$((fail+1)); }

# One MCP tool call through the gateway; echoes "allow" or "deny".
call() { # $1=server $2=tool $3=args-json
  local url="$GW/$1/server" h=(-H "Authorization: Bearer $KEY"
        -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream')
  curl -s --max-time 25 "${h[@]}" -X POST "$url" -d \
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}' \
    -D /tmp/dc_h.txt -o /dev/null
  local sid; sid=$(grep -i '^mcp-session-id:' /tmp/dc_h.txt | tr -d '\r' | awk '{print $2}')
  local sh=(); [ -n "$sid" ] && sh=(-H "Mcp-Session-Id: $sid")
  curl -s --max-time 25 "${h[@]}" "${sh[@]}" -X POST "$url" \
    -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' -o /dev/null
  local body
  body=$(curl -s --max-time 40 "${h[@]}" "${sh[@]}" -X POST "$url" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"$2\",\"arguments\":$3}}")
  case "$body" in
    *MCPGuardrailError*) echo deny ;;
    *'"isError":false'*|*'"result"'*) echo allow ;;
    *) echo "error: ${body:0:120}" ;;
  esac
}

echo "MCP tool authorization (through TrueFoundry's MCP gateway)"
[ "$(call billing-mcp  get_billing_report    '{"customer_id":"c1"}')" = allow ] \
  && ok "billing-mcp/get_billing_report   -> allow" || bad "get_billing_report should ALLOW"
[ "$(call billing-mcp  get_compliance_status '{"customer_id":"c1"}')" = allow ] \
  && ok "billing-mcp/get_compliance_status -> allow" || bad "get_compliance_status should ALLOW"
[ "$(call billing-mcp  get_customer_pii     '{"customer_id":"c1"}')" = deny ] \
  && ok "billing-mcp/get_customer_pii     -> DENY (forbid)" || bad "get_customer_pii should DENY"
[ "$(call external-mcp analytics_probe      '{"query":"emails"}')"   = deny ] \
  && ok "external-mcp/analytics_probe     -> DENY (forbid)" || bad "analytics_probe should DENY"

echo
echo "Model + agent authorization (straight at the plugin, as TF shapes it)"
PLUGIN="${PLUGIN_URL:-http://127.0.0.1:8000}"
model() { # $1=model $2=agent_id
  curl -s --max-time 20 -X POST "$PLUGIN/reva/authorize" -H 'Content-Type: application/json' \
    -d "{\"requestBody\":{\"model\":\"$1\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]},
         \"context\":{\"user\":{\"subjectId\":\"alice@analyst\",\"subjectSlug\":\"alice@analyst\"},
                      \"metadata\":{\"agent_id\":\"$2\"}}}" \
  | grep -q '"verdict":true' && echo allow || echo deny
}
[ "$(model gpt-4o      billing-support-agent)" = allow ] && ok "gpt-4o      + billing-support-agent -> allow" || bad "gpt-4o should ALLOW"
[ "$(model gpt-4o-mini billing-support-agent)" = deny ]  && ok "gpt-4o-mini + billing-support-agent -> DENY (no permit)" || bad "gpt-4o-mini should DENY"
[ "$(model gpt-4o      rogue-agent)"          = deny ]  && ok "gpt-4o      + rogue-agent          -> DENY (no permit)" || bad "rogue-agent should DENY"

echo
echo "Agent invocation (Reva PDP — never traverses the gateway)"
[ "$(./agentic_eval_demo.sh activeuser 2>/dev/null | grep -o 'decision: [A-Z]*' | awk '{print $2}')" = ALLOW ] \
  && ok "alice@analyst -> agent -> allow" || bad "alice should ALLOW"
[ "$(./agentic_eval_demo.sh inactive   2>/dev/null | grep -o 'decision: [A-Z]*' | awk '{print $2}')" = DENY ] \
  && ok "carol@free    -> agent -> DENY (inactive)" || bad "carol should DENY"

echo
echo "──────────────────────────────────────────"
printf 'passed %d, failed %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && echo "Ready to demo." || echo "Fix the failures before presenting."
exit $((fail > 0))
