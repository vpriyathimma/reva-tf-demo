# Reva ↔ TrueFoundry Authorization Plugin

A custom-guardrail plugin (FastAPI) for **TrueFoundry AI Gateway** that
delegates allow/deny to the **Reva Cedar PDP**. When an LLM request flows
through TrueFoundry, this plugin intercepts it, builds a Cedar eval request,
calls `/pdp/access/v1/evaluation`, and returns an allow/deny verdict — before
the prompt reaches the model.

It is the TrueFoundry sibling of the working LiteLLM integration in
[`../reva-litellm-demo/litellm/reva_auth_hook.py`](../reva-litellm-demo/litellm/reva_auth_hook.py).
The Reva eval-request shape is identical, so **one Reva policy store serves
both gateways with no policy changes**.

The plugin is a *pure converter*. All decisions are made by Cedar policies in
the Reva store; this code only translates between the two contracts.

---

## Request flow

```
TrueFoundry AI Gateway
      │  POST /reva/authorize   (InputGuardrailRequest)
      ▼
  this plugin ── build CallModel eval ──► Reva PDP /pdp/access/v1/evaluation
      │                                        │
      │  ◄──────── decision + policies ────────┘
      ▼
  ValidateGuardrailResponse { verdict, message }   (always HTTP 200)
```

## Endpoints

| Method | Path                   | Purpose                                              | Contract status |
|--------|------------------------|------------------------------------------------------|-----------------|
| POST   | `/reva/authorize`      | Authorize an LLM call **and** an MCP tool call       | ✅ Verified against live TF traffic |
| POST   | `/reva/authorize-tool` | Tool-only endpoint for non-TF callers                | ✅ Reachable, but TF does not route here by default |
| GET    | `/healthz`             | Liveness                                             | — |

> **TrueFoundry sends *both* hooks to one URL.** A guardrail config in the TF
> Registry binds exactly one URL, and that URL is reused for every hook the
> config is attached to. So attaching `reva-authorization` to both `llm_input`
> and `mcp_pre_tool` means the tool payload also lands on `/reva/authorize`.
> `main.py:_mcp_tool_call` dispatches on `context.metadata.tool_name`.
>
> To use `/reva/authorize-tool` instead, register a **second** guardrail config
> pointing at it and attach *that* one to the MCP hook.

## MCP tool authorization (`mcp_pre_tool`) — verified

This closes **M0** of the engineering spec ("de-risk the MCP payload") and the
§09 risk *"MCP pre_tool payload lacks tool identity"* — it does not lack it.

**How to enable it in TrueFoundry** (Guardrails → Policies → Add Rule):

| Field | Value |
|-------|-------|
| When Request Goes To | target type **MCP Servers** → pick your server |
| Apply On Hooks | **MCP Tool Pre-Invoke** → your guardrail |

The MCP hooks are greyed out unless the rule's target type is **MCP Servers**.

**What TF actually POSTs** (gateway v0.157.1, verified against live traffic):

```jsonc
{
  "requestBody": {"repoName": "tiangolo/fastapi"},   // the TOOL ARGUMENTS — no `model` key
  "context": {
    "user": { "subjectSlug": "alice@analyst", ... },
    "metadata": {
      "tool_name":       "read_wiki_structure",
      "mcp_server_name": "deepwiki",
      "mcp_server":      "reva-demo:mcp-server:deepwiki",
      "claims":          { ... }                      // caller's JWT claims
    }
  }
}
```

Mapping into the Reva AI eval:

| Reva AI-eval field | TrueFoundry source |
|--------------------|--------------------|
| `action.name = invokeTool` | presence of `context.metadata.tool_name` |
| `resource.id` (Tool) | `mcp_server_name` + `/` + `tool_name` |
| tool arguments | `requestBody` (the whole object) |

Resource ids are **server-qualified** (`billing-mcp/get_customer_pii`) to match
the store's Tool entities; `resource.id` reaches the PDP verbatim.

> **The bug this uncovered.** `requestBody` on a tool call carries the tool's
> *arguments*, so it has no `model` key. Before the dispatch existed,
> `build_model_eval` read `model = "unknown-model"` and asked the PDP *"may this
> agent invoke the model `unknown-model`?"* — which denied. Tool calls were
> blocked for the wrong reason and logged as `Model` resources. A deny that is
> right by accident is still wrong.

## Contract (verified)

**TrueFoundry → plugin** (`InputGuardrailRequest`):
- `requestBody` — OpenAI-format request (`model`, `messages`, `tools`, …)
- `context.user` — `subjectId`, `subjectType`, `subjectSlug`, `subjectDisplayName`
- `context.metadata` — optional `dict[str,str]`
- `config` — plugin settings from the TF dashboard integration form

**plugin → TrueFoundry** (`ValidateGuardrailResponse`):
- `verdict: bool` — `true` = allow, `false` = deny
- `message: str?` — reason (logs/UI only)
- **Always HTTP 200.** Denials are `verdict:false`, never a non-2xx status.

## Schema modes — vanilla vs agent_v5

The plugin speaks two Cedar vocabularies, selected by `config.reva_schema_mode`
(or `REVA_SCHEMA_MODE`):

| | `vanilla` (default) | `agent_v5` |
|---|---|---|
| Backing store | LiteLLM demo's store | agentic store ([`../reva-tf-demo-agent-authorization`](../reva-tf-demo-agent-authorization)) |
| LLM-call subject | `User` (team/tier/entitlements) | `Agent` (id from `metadata.agent_id`) |
| LLM-call action/resource | `CallModel` / `Model` | `invokeModel` / `Model` |
| Tool-call | `User` / `InvokeTool` / `Tool` | `Agent` / `invokeTool` / `Tool` |
| Context | `{tools, messages_len, hour}` | `SharedContext` — **requires** `chain{depth,ancestors}` + `timestamp` |
| PDP body | bare object | single-element list `[eval]` (matches reva-langchain's PdpClient) |

**agent_v5 design note (confirm with Amit):** an LLM call maps to *Agent →
invokeModel → Model* — the principal is the **Agent**, not the human user. The
user→agent check is a separate `invokeAgent` decision, not this hot-path model
call. If per-user model limits are required, they belong on that entry policy.

## Mapping: TrueFoundry → Reva eval

| TrueFoundry field                          | Reva eval field                    |
|--------------------------------------------|------------------------------------|
| `context.user.subjectSlug` / `subjectId`   | `subject.id`                       |
| `context.metadata.reva_team` / `team`      | `subject.properties.team` *(+ TEAM_CONFIG lookup)* |
| `context.metadata.reva_tier` / `tier`      | `subject.properties.tier`          |
| `requestBody.model`                        | `resource.id`, `resource.properties.name` |
| `requestBody.tools[].function.name`        | `context.tools`                    |
| `config.reva_pdp_url`                      | PDP endpoint URL                   |
| `config.reva_policystore_id`               | `policyStoreId` header             |
| `config.reva_auth_token`                   | `Authorization` header             |

Bare Cedar type names (`User`/`Model`/`Tool`) are sent in the eval body — the
`policyStoreId` header selects the namespace, matching the LiteLLM hook.

## Config (TF dashboard, per-request `config`)

| Key                     | Meaning                                   | Default |
|-------------------------|-------------------------------------------|---------|
| `reva_pdp_url`          | PDP evaluation endpoint                   | — |
| `reva_policystore_id`   | `policyStoreId` header                     | — |
| `reva_auth_token`       | `Authorization` header                     | — |
| `reva_pdp_origin`       | `origin` header                            | `https://demo.preview.reva.ai` |
| `reva_pdp_timeout`      | PDP call timeout (s)                        | `5.0` |
| `mode`                  | `enforce` \| `log` \| `monitor`            | `enforce` |
| `reva_fail_mode`        | `open` \| `closed` on PDP error            | derived from `mode` |

Env vars (`REVA_PDP_URL`, …; see `.env.example`) are a **local-dev fallback**;
the dashboard `config` wins.

### Modes & failure handling
- **`enforce`** — allow/deny as the PDP decides. On PDP error → **fail-closed**
  (deny) by default.
- **`log` / `monitor`** — never block; `message` records what enforce *would*
  do. On PDP error → **fail-open** (allow).
- `reva_fail_mode` overrides the derived behavior explicitly.

## Local run

```bash
cp .env.example .env          # fill in staging PDP creds from Amit
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Smoke test (allow-by-default, since no PDP configured → verdict:true):

```bash
curl -s localhost:8000/reva/authorize -H 'content-type: application/json' -d '{
  "requestBody": {"model": "gpt-4o", "messages": [{"role":"user","content":"hi"}]},
  "context": {"user": {"subjectId": "u1", "subjectSlug": "bob@intern"},
              "metadata": {"reva_team": "intern-team", "reva_tier": "paid"}},
  "config": {}
}'
```

## Docker

```bash
docker build -t reva-tf-plugin .
docker run -p 8000:8000 --env-file .env reva-tf-plugin
```

## How the user's team/tier reaches the plugin

TrueFoundry's `context.user` (Subject) carries **only** `subjectId` / `subjectType`
/ `subjectSlug` / `subjectDisplayName` — **no team or tier**. Those attributes
reach the plugin only if the calling agent app attaches them as request
metadata via the **`X-TFY-METADATA`** header, which TrueFoundry forwards into
`context.metadata`. This mirrors the LiteLLM version, where the agent sets
`reva_team` in `extra_body`.

The agent app sends (value is a **stringified JSON** object, string values,
max 128 chars each):

```python
client.chat.completions.create(
    model="gpt-4o",
    messages=[...],
    extra_headers={
        "X-TFY-METADATA": '{"team":"intern-team","tier":"paid"}',
    },
)
```

The plugin reads `team` / `tier` (and the `reva_`-prefixed aliases) from
`context.metadata` in `_resolve_identity()`. If they're absent, team resolves
to `"unknown-team"`, entitlements are empty, and the PDP denies anything
requiring a positive grant — a loud failure, not a silent hollow allow.

### Confirming it end-to-end (`REVA_DEBUG`)

Set `REVA_DEBUG=1` and the plugin logs the full incoming payload + the exact
`context.metadata` keys it received. Use this on the **first** real TF request
to verify the header made it through and the key names match. Turn it off
afterward — the dump includes the prompt.

```
[reva_tf DEBUG] /reva/authorize metadata keys=['ip_address', 'session_id', 'team', 'tier']
[reva_tf INFO]  CallModel user=bob@intern team=intern-team model=gpt-4o
```

