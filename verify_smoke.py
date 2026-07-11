"""End-to-end smoke test: drives the real FastAPI app in-process.

Covers the three behaviors that matter:
  1. No PDP configured  -> allow-by-default (verdict True, HTTP 200)
  2. PDP returns deny    -> verdict False, still HTTP 200 (mocked PDP)
  3. PDP transport error -> fail mode (enforce=>closed=deny, log=>open=allow)

Uses httpx.MockTransport so we exercise the whole stack except the network.
"""
import asyncio
import json

import httpx
from starlette.testclient import TestClient

import main
from guardrail.reva_auth import RevaConfig

client = TestClient(main.app)

LLM_BODY = {
    "requestBody": {"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}],
                    "tools": [{"function": {"name": "get_customer_pii"}}]},
    "context": {"user": {"subjectId": "u1", "subjectSlug": "bob@intern"},
                "metadata": {"reva_team": "intern-team", "reva_tier": "paid"}},
}

results = []

def check(name, cond, detail=""):
    results.append((name, cond, detail))
    print(f"{'PASS' if cond else 'FAIL'}  {name}  {detail}")


# 1) allow-by-default: no PDP config anywhere
r = client.post("/reva/authorize", json={**LLM_BODY, "config": {}})
check("healthz", client.get("/healthz").json() == {"status": "ok"})
check("no-pdp -> 200", r.status_code == 200, f"status={r.status_code}")
check("no-pdp -> allow", r.json()["verdict"] is True, r.json().get("message", ""))


def install_mock_pdp(handler):
    """Point the authorizer's shared client at a MockTransport."""
    main.authorizer._http = httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5.0)


CONFIG = {"reva_pdp_url": "https://pdp.example/pdp/access/v1/evaluation",
          "reva_policystore_id": "ps_123", "reva_auth_token": "tok_abc"}

# capture what we POST to the PDP so we can assert the eval shape
captured = {}

# 2) PDP deny (enforce)
def deny_handler(request: httpx.Request) -> httpx.Response:
    captured["body"] = json.loads(request.content)
    captured["headers"] = dict(request.headers)
    return httpx.Response(200, json={"decision": False,
                                     "determiningPolicies": [{"policyId": "forbid-intern-premium-models"}]})

install_mock_pdp(deny_handler)
r = client.post("/reva/authorize", json={**LLM_BODY, "config": {**CONFIG, "mode": "enforce"}})
check("deny -> 200", r.status_code == 200, f"status={r.status_code}")
check("deny -> verdict False", r.json()["verdict"] is False, r.json().get("message", ""))
# assert the converter built the eval correctly
b = captured["body"]
check("eval subject.id = slug", b["subject"]["id"] == "bob@intern", b["subject"]["id"])
check("eval bare type User", b["subject"]["type"] == "User", b["subject"]["type"])
check("eval action CallModel", b["action"]["name"] == "CallModel")
check("eval resource.id = model", b["resource"]["id"] == "gpt-4o")
check("eval tools carried", b["context"]["tools"] == ["get_customer_pii"], str(b["context"]["tools"]))
check("eval entitlements from TEAM_CONFIG",
      b["subject"]["properties"]["allowedModels"] == ["gpt-4o-mini"],
      str(b["subject"]["properties"]["allowedModels"]))
check("headers policyStoreId", captured["headers"].get("policystoreid") == "ps_123")
check("headers traceparent shape", captured["headers"].get("traceparent", "").startswith("00-"))

# 3) PDP allow (enforce) — decision True
def allow_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"decision": True, "determiningPolicies": [{"policyId": "permit-x"}]})
install_mock_pdp(allow_handler)
r = client.post("/reva/authorize", json={**LLM_BODY, "config": {**CONFIG, "mode": "enforce"}})
check("allow -> verdict True", r.json()["verdict"] is True, r.json().get("message", ""))

# 4) PDP transport error -> enforce => fail-closed (deny)
def boom_handler(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("boom")
install_mock_pdp(boom_handler)
r = client.post("/reva/authorize", json={**LLM_BODY, "config": {**CONFIG, "mode": "enforce"}})
check("error+enforce -> 200", r.status_code == 200)
check("error+enforce -> deny (fail-closed)", r.json()["verdict"] is False, r.json().get("message", ""))

# 5) PDP transport error -> log mode => fail-open (allow)
install_mock_pdp(boom_handler)
r = client.post("/reva/authorize", json={**LLM_BODY, "config": {**CONFIG, "mode": "log"}})
check("error+log -> allow (fail-open)", r.json()["verdict"] is True, r.json().get("message", ""))

# 6) log mode with a real deny decision => allow but message records would_deny
install_mock_pdp(deny_handler)
r = client.post("/reva/authorize", json={**LLM_BODY, "config": {**CONFIG, "mode": "log"}})
check("log+deny -> allow", r.json()["verdict"] is True)
check("log+deny -> message says would_deny", "would_deny" in r.json().get("message", ""),
      r.json().get("message", ""))

# ============================================================================
# agent_v5 schema mode — the agentic policy store vocabulary
# ============================================================================
v5_captured = {}

def v5_deny_handler(request: httpx.Request) -> httpx.Response:
    v5_captured["body"] = json.loads(request.content)
    v5_captured["headers"] = dict(request.headers)
    # AI Evaluation API: single object, deny reason at context.reason
    return httpx.Response(200, json={"decision": False,
                                     "context": {"reason": "authorization denied by policy"}})

install_mock_pdp(v5_deny_handler)
V5_BODY = {
    "requestBody": {"model": "gpt-4o", "messages": [{"role": "user", "content": "read the billing report"}]},
    "context": {"user": {"subjectId": "u1", "subjectSlug": "alice@analyst"},
                "metadata": {"team": "analyst-team", "tier": "paid", "agent_id": "billing-support-agent"}},
    "config": {**CONFIG, "mode": "enforce", "reva_schema_mode": "agent_v5"},
}
r = client.post("/reva/authorize", json=V5_BODY)
check("ai-eval deny -> verdict False", r.json()["verdict"] is False, r.json().get("message", ""))
check("ai-eval reason from context.reason", r.json().get("message") == "authorization denied by policy",
      r.json().get("message", ""))
ev = v5_captured["body"]
check("ai-eval posts single OBJECT", isinstance(ev, dict), type(ev).__name__)
check("ai-eval subject type Agent", ev["subject"]["type"] == "Agent", ev["subject"]["type"])
check("ai-eval subject id = agent_id", ev["subject"]["id"] == "billing-support-agent", ev["subject"]["id"])
check("ai-eval action invokeModel", ev["action"]["name"] == "invokeModel", ev["action"]["name"])
check("ai-eval resource Model gpt-4o", ev["resource"]["id"] == "gpt-4o")
check("ai-eval has principal User", ev["principal"]["type"] == "User" and ev["principal"]["id"] == "alice@analyst",
      str(ev.get("principal")))
check("ai-eval context.onBehalfOf", ev["context"]["onBehalfOf"]["id"] == "alice@analyst", str(ev["context"].get("onBehalfOf")))
check("ai-eval context.environment", "requestId" in ev["context"]["environment"], str(ev["context"].get("environment")))
check("ai-eval transmission carries PROMPT", ev["transmission"]["content"] == "read the billing report",
      ev["transmission"].get("content", ""))
check("ai-eval has session", "id" in ev.get("session", {}), str(ev.get("session")))
check("ai-eval Bearer auth header", v5_captured["headers"].get("authorization", "").startswith("Bearer "),
      v5_captured["headers"].get("authorization", "")[:12])
check("ai-eval x-ms-correlation-id", "x-ms-correlation-id" in v5_captured["headers"])

# v5 tool path
def v5_tool_handler(request: httpx.Request) -> httpx.Response:
    v5_captured["tool_body"] = json.loads(request.content)
    return httpx.Response(200, json={"decision": True})
install_mock_pdp(v5_tool_handler)
r = client.post("/reva/authorize-tool", json={
    "name": "get_customer_pii", "arguments": {"id": 1}, "server_id": "s1",
    "context": {"user": {"subjectId": "u1", "subjectSlug": "alice@analyst"}, "metadata": {"agent_id": "billing-support-agent"}},
    "config": {**CONFIG, "reva_schema_mode": "agent_v5"}})
tb = v5_captured["tool_body"]
check("ai-eval tool action invokeTool", tb["action"]["name"] == "invokeTool")
check("ai-eval tool resource Tool", tb["resource"]["type"] == "Tool" and tb["resource"]["id"] == "get_customer_pii")
check("ai-eval tool has principal+inputValues", tb["principal"]["id"] == "alice@analyst" and "inputValues" in tb,
      str(tb.get("inputValues")))

print("\n" + ("ALL PASS" if all(c for _, c, _ in results) else "SOME FAILED"))
raise SystemExit(0 if all(c for _, c, _ in results) else 1)
