#!/usr/bin/env bash
# agentic_eval_demo.sh — Fire ONE agentic authorization decision at the live
# Reva PDP (the AGENTIC / V5 store), by hand.
#
# Every call here creates one row in the store's Decision Logs tab — the same
# thing the TrueFoundry plugin does per request. Running it yourself lets you
# show Amit exactly where each Allow/Deny comes from.
#
# Two kinds of DENY show up here, and they mean different things:
#   * "no permit"  -> nothing ever authorized it (Cedar's default deny)
#   * "forbid"     -> it WAS permitted, but a forbid overrides the permit
#
# USAGE:
#   ./agentic_eval_demo.sh model       # agent -> gpt-4o                 -> ALLOW
#   ./agentic_eval_demo.sh badmodel    # agent -> gpt-4o-mini            -> DENY (no permit)
#   ./agentic_eval_demo.sh rogueagent  # rogue-agent -> gpt-4o           -> DENY (no permit: unknown agent)
#   ./agentic_eval_demo.sh allowtool   # agent -> get_billing_report     -> ALLOW
#   ./agentic_eval_demo.sh compliance  # agent -> get_compliance_status  -> ALLOW
#   ./agentic_eval_demo.sh pii         # agent -> get_customer_pii       -> DENY (forbid: PII)
#   ./agentic_eval_demo.sh external    # agent -> analytics_probe        -> DENY (forbid: external tool)
#   ./agentic_eval_demo.sh activeuser  # alice@analyst -> agent          -> ALLOW
#   ./agentic_eval_demo.sh inactive    # carol@free -> agent             -> DENY (forbid: inactive user)
#
# Then refresh the Decision Logs tab to see the entry.
#
# Credentials are read from .env (REVA_AUTH_TOKEN / REVA_PDP_URL /
# REVA_POLICYSTORE_ID). If the token has expired, regenerate it in the Reva
# console (Settings -> Connect to Reva) and paste it into .env.

set -euo pipefail
cd "$(dirname "$0")"

# --- load creds from .env ---
set -a; [ -f .env ] && . ./.env; set +a
TOKEN="${REVA_AUTH_TOKEN:?Set REVA_AUTH_TOKEN in .env}"
URL="${REVA_PDP_URL:?Set REVA_PDP_URL in .env}"
STORE="${REVA_POLICYSTORE_ID:?Set REVA_POLICYSTORE_ID in .env}"
AGENT="${REVA_AGENT_ID:-billing-support-agent}"

CASE="${1:-pii}"
NOW="$(python3 -c 'import datetime;print(datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))')"
RID="$(python3 -c 'import uuid;print(uuid.uuid4().hex)')"
SID="$(python3 -c 'import uuid;print(uuid.uuid4().hex)')"

# Build the request body for the chosen scenario.
# subject   = who is acting (the Agent, or a User for the invokeAgent hop)
# action    = invokeModel | invokeTool | invokeAgent
# resource  = the model / tool / agent being accessed
# context   = onBehalfOf (the human) + environment
case "$CASE" in
  pii)        USER="alice@analyst"; ACTION="invokeTool";  RTYPE="Tool";  RID_="billing-mcp/get_customer_pii"; EXPECT="DENY (forbid: PII)";;
  external)   USER="alice@analyst"; ACTION="invokeTool";  RTYPE="Tool";  RID_="external-mcp/analytics_probe"; EXPECT="DENY (forbid: external)";;
  allowtool)  USER="alice@analyst"; ACTION="invokeTool";  RTYPE="Tool";  RID_="billing-mcp/get_billing_report"; EXPECT="ALLOW";;
  compliance) USER="alice@analyst"; ACTION="invokeTool";  RTYPE="Tool";  RID_="billing-mcp/get_compliance_status"; EXPECT="ALLOW";;
  model)      USER="alice@analyst"; ACTION="invokeModel"; RTYPE="Model"; RID_="gpt-4o"; EXPECT="ALLOW";;
  badmodel)   USER="alice@analyst"; ACTION="invokeModel"; RTYPE="Model"; RID_="gpt-4o-mini"; EXPECT="DENY (no permit)";;
  # Same model, same prompt — but an agent identity no permit covers.
  rogueagent) USER="alice@analyst"; AGENT="rogue-agent"; ACTION="invokeModel"; RTYPE="Model"; RID_="gpt-4o"; EXPECT="DENY (no permit: unknown agent)";;
  activeuser) USER="alice@analyst"; ACTION="invokeAgent"; RTYPE="Agent"; RID_="$AGENT"; EXPECT="ALLOW";;
  inactive)   USER="carol@free";    ACTION="invokeAgent"; RTYPE="Agent"; RID_="$AGENT"; EXPECT="DENY (forbid: inactive user)";;
  *) echo "unknown scenario '$CASE'. Try: model | badmodel | rogueagent | allowtool | compliance | pii | external | activeuser | inactive"; exit 1;;
esac

# For invokeAgent the actor IS the user; for model/tool hops the actor is the agent.
if [ "$ACTION" = "invokeAgent" ]; then
  SUBJECT="{\"type\":\"User\",\"id\":\"$USER\",\"name\":\"$USER\"}"
else
  SUBJECT="{\"type\":\"Agent\",\"id\":\"$AGENT\",\"name\":\"$AGENT\"}"
fi

BODY=$(cat <<JSON
{
  "subject":  $SUBJECT,
  "action":   {"name":"$ACTION"},
  "resource": {"type":"$RTYPE","id":"$RID_","name":"$RID_"},
  "principal":{"type":"User","id":"$USER"},
  "context":  {"onBehalfOf":{"type":"User","id":"$USER"},
               "environment":{"requestId":"$RID","time":"$NOW"}},
  "transmission":{"promptKey":"content","role":"user","contentType":"text/plain","content":"demo"},
  "session":  {"id":"$SID","turn":1,"startedAt":"$NOW"}
}
JSON
)

echo "-> Asking Reva: can $AGENT $ACTION $RTYPE::$RID_ (on behalf of $USER)?"
echo "   expected: $EXPECT"
echo

# The AI Evaluation API returns 200 for allow and 403 for deny; both carry a
# JSON body with "decision". We print the raw decision so you can see it.
RESP=$(curl -s -w $'\n__HTTP__%{http_code}' -X POST "$URL" \
  -H "Content-Type: application/json" \
  -H "policyStoreId: $STORE" \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-ms-correlation-id: $RID" \
  -d "$BODY")

CODE="${RESP##*__HTTP__}"
JSON_BODY="${RESP%$'\n'__HTTP__*}"
DECISION=$(printf '%s' "$JSON_BODY" | python3 -c 'import sys,json;d=json.load(sys.stdin);d=d[0] if isinstance(d,list) and d else d;print("ALLOW" if d.get("decision") in (True,"allow","Allow") else "DENY")' 2>/dev/null || echo "?")

echo "<- Reva decision: $DECISION   (HTTP $CODE)"
echo
echo "Now refresh the store's Decision Logs tab — you'll see this exact call."
