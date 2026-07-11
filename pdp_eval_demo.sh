#!/usr/bin/env bash
# pdp_eval_demo.sh — Fire ONE authorization decision at the live Reva PDP.
#
# Every call you make here creates one entry in the store's Decision Logs tab.
# This is what the TrueFoundry plugin does automatically per request; running it
# by hand lets you demonstrate exactly where the logs come from.
#
# USAGE:
#   export REVA_TOKEN='<paste a fresh PDP Auth Token from the store's
#                       Developer Integration / Connect to Reva panel>'
#   ./pdp_eval_demo.sh deny     # carol@free asking for a premium model -> DENY
#   ./pdp_eval_demo.sh allow    # alice@analyst asking for gpt-4o       -> ALLOW
#
# Then refresh the Decision Logs tab in the Reva console to see the entry.

set -euo pipefail

STORE_ID="43ae73b1-e267-42d6-a7fb-c453d7372671"          # litellm-gateway-authz
PDP_URL="https://api.pr06.preview.reva.ai/pdp/access/v1/evaluation"
ORIGIN="https://demo.preview.reva.ai"

: "${REVA_TOKEN:?Set REVA_TOKEN first — grab a fresh PDP Auth Token from the store settings}"

CASE="${1:-deny}"
if [ "$CASE" = "allow" ]; then
  USER_ID="alice@analyst"; TEAM="analyst-team"; TIER="paid"
  ALLOWED='["gpt-4o","gpt-4-turbo","gpt-4o-mini"]'
else
  USER_ID="carol@free"; TEAM="free-team"; TIER="free"
  ALLOWED='["gpt-4o","gpt-4o-mini"]'
fi
MODEL="gpt-4o"          # premium tier — free users are forbidden from it

# A traceparent so you can correlate this exact call in the logs.
TRACE=$(python3 -c "import uuid;print(uuid.uuid4().hex)")
TRACEPARENT="00-${TRACE}-$(python3 -c "import uuid;print(uuid.uuid4().hex[:16])")-01"

echo "→ Asking Reva: can ${USER_ID} (${TEAM}/${TIER}) CallModel ${MODEL}?"

# The request body IS the authorization question:
#   subject  = who is asking (+ their entitlements)
#   action   = what they want to do
#   resource = what they want to do it to (+ its attributes)
#   context  = extra facts the policy can use
RESPONSE=$(curl -s -X POST "$PDP_URL" \
  -H "Content-Type: application/json" \
  -H "policyStoreId: ${STORE_ID}" \
  -H "Authorization: Bearer ${REVA_TOKEN}" \
  -H "origin: ${ORIGIN}" \
  -H "traceparent: ${TRACEPARENT}" \
  -d "{
    \"subject\":  {\"type\":\"User\",\"id\":\"${USER_ID}\",
                   \"properties\":{\"team\":\"${TEAM}\",\"tier\":\"${TIER}\",
                     \"allowedModels\":${ALLOWED},\"blockedTools\":[],
                     \"approvedMcpTools\":[\"get_billing_report\"]}},
    \"action\":   {\"name\":\"CallModel\"},
    \"resource\": {\"type\":\"Model\",\"id\":\"${MODEL}\",
                   \"properties\":{\"name\":\"${MODEL}\",\"tier\":\"premium\",\"provider\":\"openai\"}},
    \"context\":  {\"tools\":[],\"messages_len\":1,\"hour\":14}
  }")

echo "← Reva decision: ${RESPONSE}"
echo "  (true = allow, false = deny)"
echo "  Trace id to find in Decision Logs: ${TRACE}"
