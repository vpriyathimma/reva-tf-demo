"""Reva authorization core for the TrueFoundry custom-guardrail plugin.

This is the *converter*: it turns a TrueFoundry ``InputGuardrailRequest`` into
a Reva Cedar eval request, calls the PDP, and turns the PDP decision back into
a TrueFoundry allow/deny verdict. No business logic lives here beyond that
translation — Cedar policies in the Reva store make the actual decisions.

The eval-request shape, the tier/provider/category heuristics, the
traceparent format, and the decision-parsing are ported verbatim (in intent)
from reva-litellm-demo/litellm/reva_auth_hook.py so a single Reva policy store
serves both gateways unchanged.

Design decisions (confirmed with the team):
  * User entitlements (team/tier/allowedModels/…) come from TrueFoundry
    request metadata, falling back to a ported TEAM_CONFIG map. This mirrors
    the LiteLLM hook and is DEMO-ONLY — production resolves these from an
    IDP / the Reva entity store. See _resolve_identity().
  * Failure handling is fail-open, mode-controlled: on any PDP/transport
    error we allow, EXCEPT when the effective fail mode is "closed"
    (which `mode="enforce"` selects by default). See _fail_verdict().
"""

from __future__ import annotations

import datetime as _dt
import os
import re
import sys
import time
import uuid
from typing import Any

import httpx


# ---------------------------------------------------------------------------
# Logging — straight to stderr so the container's log driver captures it
# regardless of any framework logger reconfiguration.
# ---------------------------------------------------------------------------
def _log(level: str, msg: str) -> None:
    print(f"[reva_tf {level}] {msg}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Team-level entitlements inlined onto the User entity at request time.
# Ported from reva_auth_hook.TEAM_CONFIG / authorisation/entities.json and
# kept in sync by hand for the demo. In production this is an IDP attribute
# lookup, NOT a hard-coded map.
# ---------------------------------------------------------------------------
TEAM_CONFIG: dict[str, dict[str, list[str]]] = {
    "analyst-team": {
        "allowedModels": ["gpt-4o", "gpt-4-turbo", "gpt-4o-mini"],
        "blockedTools": [],
        "approvedMcpTools": ["get_billing_report", "get_compliance_status", "get_customer_pii"],
    },
    "intern-team": {
        "allowedModels": ["gpt-4o-mini"],
        "blockedTools": ["delete_invoice", "send_invoice_email"],
        "approvedMcpTools": ["get_billing_report", "get_compliance_status"],
    },
    "free-team": {
        "allowedModels": ["gpt-4o", "gpt-4o-mini"],
        "blockedTools": [],
        "approvedMcpTools": ["get_billing_report"],
    },
    "finance-team": {
        "allowedModels": ["gpt-4o", "gpt-4-turbo", "gpt-4o-mini"],
        "blockedTools": [],
        "approvedMcpTools": ["get_billing_report", "get_compliance_status"],
    },
}
_DEFAULT_TEAM = {"allowedModels": [], "blockedTools": [], "approvedMcpTools": []}


# ---------------------------------------------------------------------------
# Config resolution — every request carries `config` from the TrueFoundry
# dashboard; env vars are a local-dev fallback only.
# ---------------------------------------------------------------------------
class RevaConfig:
    """Effective plugin settings for one request.

    Precedence: request `config` (TrueFoundry dashboard) > environment > default.
    """

    def __init__(self, config: dict[str, Any] | None) -> None:
        cfg = config or {}
        # TrueFoundry wraps our settings: it sends {"url": ..., "config": {...our
        # keys...}}. Unwrap so the real settings are read (and env stays the
        # fallback). Our own demo/curl sends config flat, which has no nested
        # "config" dict, so this is a no-op there.
        if isinstance(cfg.get("config"), dict):
            cfg = cfg["config"]

        # Demo pin: when REVA_PIN_TO_ENV is set, the plugin's own .env wins over
        # whatever `config` TrueFoundry forwards per request. This exists because
        # a stale guardrail config left over from the vanilla demo (it carries
        # reva_schema_mode=vanilla) was overriding env and forcing the wrong
        # Cedar vocabulary — vanilla User/CallModel against the agentic store —
        # which default-denies. With the pin on, env is authoritative for every
        # key. Leave it off for true multi-tenant use where TF config should win.
        pin_env = str(os.getenv("REVA_PIN_TO_ENV", "")).lower() in ("1", "true", "yes", "on")

        def pick(key: str, env: str, default: str = "") -> str:
            if pin_env:
                env_val = os.getenv(env)
                if env_val not in (None, ""):
                    return str(env_val)
            val = cfg.get(key)
            if val is None or val == "" or val == "<fresh PDP token>":
                val = os.getenv(env, default)
            return str(val)

        self.pdp_url = pick("reva_pdp_url", "REVA_PDP_URL").rstrip("/")
        self.policy_store_id = pick("reva_policystore_id", "REVA_POLICYSTORE_ID")
        self.auth_token = pick("reva_auth_token", "REVA_AUTH_TOKEN")
        self.origin = pick("reva_pdp_origin", "REVA_PDP_ORIGIN", "https://demo.preview.reva.ai")
        self.mode = pick("mode", "REVA_HOOK_MODE", "enforce").lower()

        # Which Cedar vocabulary to speak to the PDP:
        #   "vanilla"  — User / CallModel / Model, User / InvokeTool / Tool
        #                (matches the LiteLLM demo's policy store)
        #   "agent_v5" — Agent / invokeModel / Model, Agent / invokeTool / Tool
        #                with a V5 SharedContext (matches the agentic policy store
        #                generated from reva-tf-demo-agent). See the agentic store's
        #                DISCOVERY-REPORT for the mapping rationale.
        self.schema_mode = pick("reva_schema_mode", "REVA_SCHEMA_MODE", "vanilla").lower()
        # In agent_v5 mode the request principal is the Agent making the model/
        # tool call. Its id comes from request metadata (agent_id), else this
        # config default. (Design note for Amit: the human user maps to a
        # separate invokeAgent check, not this hot-path model call.)
        self.agent_id = pick("reva_agent_id", "REVA_AGENT_ID", "")
        self.environment = pick("reva_environment", "REVA_ENVIRONMENT", "")
        # Which AI gateway produced this eval (truefoundry / kong / litellm).
        # Multiple gateways can share one policy store, so we stamp the gateway
        # into every eval's context AND the gateway-side decision log, so a
        # decision can be traced back to the gateway that made it. (The Reva
        # Decision Logs UI does not yet surface this field; correlate by trace.)
        self.gateway_id = pick("reva_gateway_id", "REVA_GATEWAY_ID", "truefoundry")

        try:
            self.timeout_s = float(cfg.get("reva_pdp_timeout") or os.getenv("REVA_PDP_TIMEOUT", "5.0"))
        except (TypeError, ValueError):
            self.timeout_s = 5.0

        # Debug: when on, the handler logs the full incoming TrueFoundry
        # payload (context + metadata) so we can see exactly what TF forwards
        # — the fastest way to confirm team/tier arrive and under which keys.
        # OFF by default: payloads include the prompt, so never leave this on
        # in production.
        self.debug = str(cfg.get("reva_debug") or os.getenv("REVA_DEBUG", "")).lower() in (
            "1", "true", "yes", "on"
        )

        # Fail mode: explicit config wins; otherwise "enforce" ⇒ closed,
        # any other mode (log/monitor) ⇒ open. Matches the team decision:
        # fail-open by default, flip to fail-closed when enforcing.
        fail = str(cfg.get("reva_fail_mode") or os.getenv("REVA_FAIL_MODE", "")).lower()
        if fail in ("open", "closed"):
            self.fail_mode = fail
        else:
            self.fail_mode = "closed" if self.mode == "enforce" else "open"

    @property
    def pdp_configured(self) -> bool:
        return bool(self.pdp_url and self.policy_store_id and self.auth_token)


# ---------------------------------------------------------------------------
# Attribute heuristics — ported from reva_auth_hook.py so both gateways ship
# identical Model/Tool attributes to the PDP.
# ---------------------------------------------------------------------------
def _model_tier(model: str) -> str:
    m = (model or "").lower()
    if "mini" in m or "haiku" in m or "3.5" in m:
        return "standard"
    return "premium"


def _model_provider(model: str) -> str:
    m = (model or "").lower()
    if m.startswith("gpt") or m.startswith("openai/"):
        return "openai"
    if "claude" in m or m.startswith("anthropic/"):
        return "anthropic"
    if m.startswith("bedrock/"):
        return "bedrock"
    return "unknown"


def _tool_category(tool_name: str) -> str:
    n = (tool_name or "").lower()
    if "pii" in n or "customer" in n or "personal" in n:
        return "pii"
    if "compliance" in n or "audit" in n:
        return "compliance"
    if "billing" in n or "invoice" in n or "report" in n:
        return "billing"
    return "general"


def _v5_tool_classification(tool_name: str) -> str:
    """Best-effort V5 dataClassification from a tool name. Authoritative values
    live on the Tool entity in the policy store; this is only used when the
    plugin ships tool attributes inline (agent_v5 mode)."""
    n = (tool_name or "").lower()
    if "pii" in n or "customer" in n or "personal" in n:
        return "PII"
    if "compliance" in n or "audit" in n:
        return "CONFIDENTIAL"
    return "INTERNAL"


# Mock "Reva MCP scanner" baseline — see reva_auth_hook.py for the full
# rationale. A real deployment fetches the live per-tool risk score.
_BASELINE_TOOL_RISK: dict[str, int] = {
    "get_billing_report": 10,
    "get_compliance_status": 15,
    "get_customer_pii": 40,
    "analytics_diagnostic_probe": 80,
}


def _tool_risk_score(tool_name: str) -> int:
    return _BASELINE_TOOL_RISK.get(tool_name, 0)


def _build_traceparent(trace_id: str | None = None) -> str:
    tid = (trace_id or uuid.uuid4().hex).replace("-", "")[:32].ljust(32, "0")
    sid = uuid.uuid4().hex[:16]
    return f"00-{tid}-{sid}-01"


def _trace_id_of(traceparent: str) -> str:
    """The 32-hex trace-id from a W3C traceparent (00-<trace>-<span>-01).

    The value the Reva console shows as "Trace ID" and groups Decision Logs by,
    so every hop of a turn must send it as the correlation id."""
    parts = (traceparent or "").split("-")
    return parts[1] if len(parts) >= 2 and parts[1] else uuid.uuid4().hex


def _span_id_of(traceparent: str) -> str:
    """The 16-hex span-id (3rd field) of a W3C traceparent."""
    parts = (traceparent or "").split("-")
    return parts[2] if len(parts) >= 3 and parts[2] else uuid.uuid4().hex[:16]

# ---------------------------------------------------------------------------
# The authorizer
# ---------------------------------------------------------------------------
class Decision:
    """Normalized PDP outcome the FastAPI layer turns into a verdict."""

    __slots__ = ("allow", "reason", "trace_id", "errored")

    def __init__(self, allow: bool, reason: str, trace_id: str, errored: bool = False) -> None:
        self.allow = allow
        self.reason = reason
        self.trace_id = trace_id
        self.errored = errored


class RevaAuthorizer:
    """Owns the shared httpx client and the PDP call."""

    def __init__(self) -> None:
        self._http: httpx.AsyncClient | None = None

    async def _client(self, timeout_s: float) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(timeout=timeout_s)
        return self._http

    async def aclose(self) -> None:
        if self._http is not None and not self._http.is_closed:
            await self._http.aclose()

    # -- identity -----------------------------------------------------------
    @staticmethod
    def _resolve_identity(
        user: dict[str, Any], metadata: dict[str, str] | None
    ) -> tuple[str, str, str, dict[str, Any]]:
        """Return (user_id, team, tier, user_properties).

        user_id  ← subjectSlug (email-style, matches Reva demo entity ids)
                   or subjectId.
        team/tier ← TrueFoundry metadata (several key aliases accepted),
                   defaulting to unknown.
        entitlements ← TEAM_CONFIG[team] (DEMO-ONLY fallback).

        NOTE (open item, Amit 17:14): this assumes TrueFoundry forwards team/
        tier in `context.metadata`. If it does not, team resolves to
        "unknown-team", entitlements are empty, and the PDP will deny anything
        that requires a positive entitlement — a loud, correct failure rather
        than a silent hollow allow. Verify what TF actually passes and adjust
        the key names below.
        """
        meta = metadata or {}
        user_id = user.get("subjectSlug") or user.get("subjectId") or "anonymous"
        team = meta.get("reva_team") or meta.get("team") or "unknown-team"
        tier = meta.get("reva_tier") or meta.get("tier") or "unknown"

        team_cfg = TEAM_CONFIG.get(team, _DEFAULT_TEAM)
        user_properties = {
            "team": team,
            "tier": tier,
            "allowedModels": team_cfg["allowedModels"],
            "blockedTools": team_cfg["blockedTools"],
            "approvedMcpTools": team_cfg.get("approvedMcpTools", []),
        }
        return user_id, team, tier, user_properties

    # -- AI Evaluation API envelope helpers ---------------------------------
    # These build the request shape documented at the Agent Authorization
    # Evaluation API (POST /pdp/access/v1/ai/evaluation): a single JSON
    # envelope with subject/action/resource/principal/context/transmission/
    # session. The PDP resolves entity *attributes* (dataClassification,
    # ceilings, …) from the published store by uid — so we send type+id+name
    # and only the dynamic bits here. Modeled on the deployed copilot service.
    def _agent_id(self, meta: dict[str, Any], cfg: "RevaConfig") -> str:
        return meta.get("agent_id") or cfg.agent_id or "unknown-agent"

    @staticmethod
    def _iso_now() -> str:
        return _dt.datetime.utcnow().isoformat() + "Z"

    @staticmethod
    def _extract_prompt(request_body: dict[str, Any]) -> str:
        """Last user message content → transmission.content. This is the
        prompt the PDP authorizes against — the field the LiteLLM/vanilla
        contract never sent."""
        for m in reversed(request_body.get("messages") or []):
            if isinstance(m, dict) and m.get("role") == "user":
                c = m.get("content")
                if isinstance(c, str):
                    return c[:4000]
                if isinstance(c, list):  # OpenAI content-parts form
                    return " ".join(
                        p.get("text", "") for p in c if isinstance(p, dict)
                    )[:4000]
        return ""

    @staticmethod
    def _on_behalf_of(user_id: str, meta: dict[str, Any]) -> dict[str, Any]:
        """context.onBehalfOf — the delegating end user + any attributes the
        agent forwarded (team/tier). Authoritative attributes come from the
        store's entity data; these are supplementary/dynamic."""
        props: dict[str, Any] = {}
        for src, dst in (("team", "team"), ("reva_team", "team"),
                         ("tier", "tier"), ("reva_tier", "tier"),
                         ("riskTier", "riskTier")):
            v = meta.get(src)
            if v and dst not in props:
                props[dst] = str(v)
        ob: dict[str, Any] = {"type": "User", "id": user_id}
        if props:
            ob["properties"] = props
        return ob

    def _ai_context(self, user_id: str, meta: dict[str, Any]) -> dict[str, Any]:
        ctx: dict[str, Any] = {
            "onBehalfOf": self._on_behalf_of(user_id, meta),
            # `gateway` tags which AI gateway forwarded this eval, so evals from
            # TF / Kong / LiteLLM sharing one policy store can be told apart. The
            # PDP receives it now (forward-compatible with future decision-log
            # display); today it is correlated via the gateway-side log + trace.
            "environment": {"requestId": uuid.uuid4().hex, "time": self._iso_now(),
                            "gateway": os.getenv("REVA_GATEWAY_ID", "truefoundry")},
        }
        # Break-glass token + any guardrail signals the agent forwarded.
        approval = meta.get("approval_token") or meta.get("approvalToken")
        if approval:
            ctx["approvalToken"] = str(approval)
        for sig in ("blockedTermInUserMessage", "blockedTermInInput", "isBlockedTool"):
            if sig in meta:
                ctx[sig] = meta[sig]
        return ctx

    @staticmethod
    def _session(meta: dict[str, Any], now: str, turn: int = 1) -> dict[str, Any]:
        return {"id": meta.get("session_id") or uuid.uuid4().hex, "turn": turn, "startedAt": now}

    @staticmethod
    def _turn(messages: list[Any] | None) -> int:
        """Turn number = how many user messages the session has seen (incl. the
        current one). New contract wants the real turn; the old code pinned it to 1."""
        n = sum(1 for m in (messages or []) if isinstance(m, dict) and m.get("role") == "user")
        return n or 1

    @staticmethod
    def _conversation(messages: list[Any] | None, now: str,
                      keep_current_prompt: bool = False) -> dict[str, Any]:
        """context.conversation.messages[] — the accumulated history, EXCLUDING the
        system instruction and the current prompt (the last user message, which goes
        to transmission). Each entry is {seq, role, content, timestamp}.

        This is the field the intent engine reads to judge drift across a session.
        The vanilla/agent_v5 contract never sent it, so older messages were invisible
        to the engine — the gap Amit flagged. Per-message timestamps aren't in the
        TrueFoundry payload, so we stamp receipt time and note it."""
        msgs = messages or []
        last_user = None
        if not keep_current_prompt:
            for i in range(len(msgs) - 1, -1, -1):
                if isinstance(msgs[i], dict) and msgs[i].get("role") == "user":
                    last_user = i
                    break
        out: list[dict[str, Any]] = []
        for i, m in enumerate(msgs):
            if not isinstance(m, dict) or m.get("role") == "system":
                continue
            if last_user is not None and i == last_user:
                continue  # skip only the current prompt; keep intra-turn results
            c = m.get("content")
            if isinstance(c, list):  # OpenAI content-parts form
                c = " ".join(p.get("text", "") for p in c if isinstance(p, dict))
            out.append({
                "seq": len(out) + 1,
                "role": m.get("role"),
                "content": str(c or "")[:4000],
                "timestamp": now,
            })
        return {"messages": out}

    # An orchestrator tool result reaches the model phrased as
    # "billing-mcp/get_billing_report returned: {...}" (see agents._phrase). That
    # server-qualified id is exactly the hop's Tool resource id.
    _TOOL_RESULT = re.compile(r"^([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)\s+returned:")

    @classmethod
    def _tool_from_result(cls, content: str) -> str | None:
        m = cls._TOOL_RESULT.match((content or "").strip())
        return m.group(1) if m else None

    @classmethod
    def _hops(cls, agent_id: str, conv_messages: list[dict[str, Any]],
              user_id: str, now: str) -> list[dict[str, Any]]:
        """context.hops[] — the delegation chain, seq-aligned to the conversation
        (Amit: "hop 1 = message 1 ... one, one, two, two"). ONE hop per conversation
        message, keyed on that message's seq:
          * a user message  -> user invoked the agent   (User -> invokeAgent -> Agent)
          * a tool result   -> agent invoked that tool   (Agent -> invokeTool -> Tool)
          * any other agent turn -> agent invoked its model (Agent -> invokeModel)
        The CURRENT action (this eval's tool/model) is NOT a hop — it lives in the
        top-level action/resource, exactly as in Karthik's payload.

        When the conversation is empty (turn 1), we still record the single
        User -> invokeAgent hop for the current invocation, matching the simple curl
        Amit sent (empty conversation, one hop)."""
        hops: list[dict[str, Any]] = []
        for m in conv_messages:
            seq = m.get("seq")
            t = m.get("timestamp") or now
            if m.get("role") == "user":
                hops.append({"seq": seq, "subject": {"type": "User", "id": user_id},
                             "action": "invokeAgent",
                             "resource": {"type": "Agent", "id": agent_id}, "time": t})
                continue
            tool = cls._tool_from_result(m.get("content", ""))
            if tool:
                hops.append({"seq": seq, "subject": {"type": "Agent", "id": agent_id},
                             "action": "invokeTool",
                             "resource": {"type": "Tool", "id": tool}, "time": t})
            else:
                hops.append({"seq": seq, "subject": {"type": "Agent", "id": agent_id},
                             "action": "invokeModel",
                             "resource": {"type": "Model", "id": "model"}, "time": t})
        if not hops:
            hops.append({"seq": 1, "subject": {"type": "User", "id": user_id},
                         "action": "invokeAgent",
                         "resource": {"type": "Agent", "id": agent_id}, "time": now})
        return hops

    # -- eval-request construction -----------------------------------------
    def build_model_eval(
        self, request_body: dict[str, Any], context: dict[str, Any], cfg: "RevaConfig"
    ) -> tuple[dict[str, Any], str]:
        """Construct a model-call eval request from a TrueFoundry LLM request.

        vanilla mode mirrors reva_auth_hook (User/CallModel/Model). agent_v5
        mode emits Agent/invokeModel/Model with a SharedContext.
        Returns (eval_request, principal_id) — principal_id echoed for logging.
        """
        user = context.get("user") or {}
        meta = context.get("metadata") or {}
        raw_model = request_body.get("model") or "unknown-model"
        # TrueFoundry sends provider-prefixed names ("openai/gpt-4o"); the policy
        # store's allowedModels use bare names ("gpt-4o"). Derive the provider
        # from the full name, then strip the prefix so model matching works.
        provider = _model_provider(raw_model)
        model = raw_model.split("/", 1)[1] if "/" in raw_model else raw_model

        if cfg.schema_mode == "agent_v5":
            agent_id = self._agent_id(meta, cfg)
            # The human the agent acts for (context.onBehalfOf + principal). Normally
            # the TrueFoundry caller, but a `reva_user` metadata field can override it
            # — this lets the TF Playground pick which demo user the agent acts on
            # behalf of (e.g. carol@free) to exercise on-behalf-of policies.
            user_id = (
                meta.get("reva_user") or meta.get("onBehalfOf") or meta.get("reva_onbehalf")
                or user.get("subjectSlug") or user.get("subjectId") or "anonymous"
            )
            now = self._iso_now()
            messages = request_body.get("messages")
            resource = {"type": "Model", "id": model, "name": model,
                        "properties": {"provider": provider}}
            context = self._ai_context(user_id, meta)
            context["conversation"] = self._conversation(messages, now, keep_current_prompt=True)
            # Console Decision Logs render history under `chatHistory`
            # (matches Sarthak's Kong payload); emit the same flat array.
            context["chatHistory"] = context["conversation"]["messages"]
            context["hops"] = self._hops(agent_id, context["conversation"]["messages"], user_id, now)
            eval_request = {
                "subject": {"type": "Agent", "id": agent_id, "name": meta.get("agent_name") or agent_id},
                "action": {"name": "invokeModel"},
                "resource": resource,
                "principal": {"type": "User", "id": user_id},
                "context": context,
                "transmission": {"promptKey": "content", "role": "user",
                                 "contentType": "text/plain",
                                 "content": self._extract_prompt(request_body)},
                "session": self._session(meta, now, self._turn(messages)),
            }
            _log("INFO", f"[ai-eval] invokeModel agent={agent_id} model={model} user={user_id} "
                         f"history={len(context['conversation']['messages'])} turn={eval_request['session']['turn']}")
            return eval_request, agent_id

        user_id, team, tier, user_properties = self._resolve_identity(user, meta)
        requested_tools = [
            t.get("function", {}).get("name")
            for t in (request_body.get("tools") or [])
            if isinstance(t, dict) and t.get("function", {}).get("name")
        ]
        messages_len = len(request_body.get("messages") or [])

        # Time-of-day for the off-hours policy; overridable for demos.
        sim_hour = meta.get("simulated_hour")
        try:
            hour = int(sim_hour) if sim_hour is not None else _dt.datetime.utcnow().hour
        except (TypeError, ValueError):
            hour = _dt.datetime.utcnow().hour

        eval_context: dict[str, Any] = {
            "tools": requested_tools,
            "messages_len": messages_len,
            "hour": hour,
        }
        approval_token = meta.get("approval_token")
        if approval_token:
            eval_context["approval_token"] = str(approval_token)

        eval_request = {
            "subject": {"type": "User", "id": user_id, "properties": user_properties},
            "action": {"name": "CallModel"},
            "resource": {
                "type": "Model",
                "id": model,
                "properties": {
                    "name": model,
                    "tier": _model_tier(model),
                    "provider": provider,
                },
            },
            "context": eval_context,
        }
        _log("INFO", f"CallModel user={user_id} team={team} tier={tier} model={model} tools={requested_tools}")
        return eval_request, user_id

    def build_tool_eval(
        self, tool_name: str, arguments: Any, server_id: str, context: dict[str, Any], cfg: "RevaConfig"
    ) -> tuple[dict[str, Any], str]:
        """Construct a tool-call eval request.

        vanilla mode mirrors reva_auth_hook._handle_mcp_call (User/InvokeTool/
        Tool). agent_v5 mode emits Agent/invokeTool/Tool with a SharedContext.

        `tool_name` must be the store-qualified id ("deepwiki/read_wiki_structure")
        because resource.id reaches the PDP verbatim; main.py:_mcp_tool_call does
        that qualification for TrueFoundry's mcp_pre_tool payload.
        """
        user = context.get("user") or {}
        meta = context.get("metadata") or {}

        if cfg.schema_mode == "agent_v5":
            agent_id = self._agent_id(meta, cfg)
            # The human the agent acts for (context.onBehalfOf + principal). Normally
            # the TrueFoundry caller, but a `reva_user` metadata field can override it
            # — this lets the TF Playground pick which demo user the agent acts on
            # behalf of (e.g. carol@free) to exercise on-behalf-of policies.
            user_id = (
                meta.get("reva_user") or meta.get("onBehalfOf") or meta.get("reva_onbehalf")
                or user.get("subjectSlug") or user.get("subjectId") or "anonymous"
            )
            now = self._iso_now()
            resource = {"type": "Tool", "id": tool_name, "name": tool_name}
            context = self._ai_context(user_id, meta)
            # Tool-call authorizations from TrueFoundry today carry NO message
            # history (the mcp_pre_tool payload is just the tool args), so the
            # intent engine can't judge a tool call against the conversation —
            # exactly the drift gap Amit described. Forward-compatible: if the new
            # deployment (or the orchestrator via metadata) supplies the transcript
            # under `conversation`/`messages`, map it; else send an empty list.
            history = meta.get("conversation") or meta.get("messages")
            # A tool call has no current user prompt to hold back (its transmission
            # is the tool args), so include the whole conversation.
            context["conversation"] = (
                self._conversation(history, now, keep_current_prompt=True)
                if history else {"messages": []}
            )
            context["chatHistory"] = context["conversation"]["messages"]
            context["hops"] = self._hops(agent_id, context["conversation"]["messages"], user_id, now)
            turn = self._turn(history) if history else int(meta.get("turn") or 1)
            eval_request = {
                "subject": {"type": "Agent", "id": agent_id, "name": meta.get("agent_name") or agent_id},
                "action": {"name": "invokeTool"},
                # Authoritative Tool attributes (dataClassification, riskTier,
                # requiresHumanApproval) are resolved by the PDP from the
                # published store entity; we send type+id+name.
                "resource": resource,
                "principal": {"type": "User", "id": user_id},
                "context": context,
                "transmission": {"promptKey": "content", "role": "user",
                                 "contentType": "text/plain",
                                 "content": str(arguments or "")[:2000]},
                "inputValues": arguments if isinstance(arguments, dict) else {},
                "session": self._session(meta, now, turn),
            }
            _log("INFO", f"[ai-eval] invokeTool agent={agent_id} tool={tool_name} user={user_id} "
                         f"history={len(context['conversation']['messages'])}")
            return eval_request, agent_id

        user_id, team, _tier, user_properties = self._resolve_identity(user, meta)

        sim_score = meta.get("simulated_risk_score")
        try:
            risk_score = int(sim_score) if sim_score is not None else _tool_risk_score(tool_name)
        except (TypeError, ValueError):
            risk_score = _tool_risk_score(tool_name)

        eval_request = {
            "subject": {"type": "User", "id": user_id, "properties": user_properties},
            "action": {"name": "InvokeTool"},
            "resource": {
                "type": "Tool",
                "id": tool_name,
                "properties": {
                    "name": tool_name,
                    "category": _tool_category(tool_name),
                    "server": server_id or "unknown",
                    "risk_score": risk_score,
                },
            },
            "context": {
                "tool_name": tool_name,
                "args_summary": str(arguments or {})[:240],
            },
        }
        _log("INFO", f"InvokeTool user={user_id} team={team} tool={tool_name} risk={risk_score}")
        return eval_request, user_id

    # -- PDP call -----------------------------------------------------------
    async def evaluate(self, eval_request: dict[str, Any], cfg: RevaConfig,
                       *, incoming_traceparent: str | None = None) -> Decision:
        """POST the eval request to the Reva PDP and normalize the outcome.

        On success returns a Decision with allow/deny from the PDP. On any
        transport/HTTP error returns a Decision flagged ``errored=True`` with
        allow left unset-appropriate; the FastAPI layer applies the fail mode.

        `incoming_traceparent` is the W3C traceparent TrueFoundry put on the
        request to us; per Amit we FORWARD the same one to the PDP so a session's
        calls share a trace, instead of minting a fresh id per hop.
        """
        trace_id = uuid.uuid4().hex

        if not cfg.pdp_configured:
            # Not an error — it's an explicit "not wired yet" state. Allow so
            # the demo can be staged before policies/creds are published,
            # exactly like the LiteLLM hook's allow-by-default.
            _log("WARN", "PDP not configured — allow-by-default")
            return Decision(True, "pdp not configured (allow-by-default)", trace_id)

        # Header shape differs by target. agent_v5 hits the AI Evaluation API,
        # which wants `Authorization: Bearer <token>` + policyStoreId +
        # x-ms-correlation-id (per docs.reva.ai Agent Authorization Evaluation
        # API). vanilla hits the generic PDP the LiteLLM hook used (raw token +
        # origin + traceparent).
        if cfg.schema_mode == "agent_v5":
            token = cfg.auth_token
            # The traceparent this call sends — TrueFoundry's inbound one when
            # present, else a minted one.
            traceparent = incoming_traceparent or _build_traceparent(trace_id)
            # The console reads the trace from the request BODY (Decision Logs
            # show trace_source: request-body), so put the shared turn id there —
            # else the PDP mints one per hop and the trace filter scatters them.
            eval_request["trace_id"] = _trace_id_of(traceparent)
            eval_request["parent_span_id"] = _span_id_of(traceparent)
            headers = {
                "Content-Type": "application/json",
                "policyStoreId": cfg.policy_store_id,
                "Authorization": token if token.lower().startswith("bearer ") else f"Bearer {token}",
                # The Reva console groups Decision Logs by the correlation id, so
                # it MUST be the shared turn id (the traceparent's trace-id part),
                # not a per-call uuid — else each hop lands under its own id and
                # the trace filter shows them scattered instead of one chain.
                "x-ms-correlation-id": _trace_id_of(traceparent),
                "traceparent": traceparent,
            }
        else:
            token = cfg.auth_token
            headers = {
                "Content-Type": "application/json",
                "policyStoreId": cfg.policy_store_id,
                # Bearer-normalize: the Reva preview PDP requires `Bearer <token>`.
                # Accept a token pasted with or without the prefix.
                "Authorization": token if token.lower().startswith("bearer ") else f"Bearer {token}",
                "origin": cfg.origin,
                "traceparent": _build_traceparent(trace_id),
            }
        # Both endpoints take a single JSON object (the AI Evaluation API docs
        # show `--data '{...}'` and a single-object response; the LiteLLM hook
        # posted a bare object too).
        body: Any = eval_request

        t0 = time.perf_counter()
        try:
            client = await self._client(cfg.timeout_s)
            resp = await client.post(cfg.pdp_url, json=body, headers=headers)
        except Exception as e:  # noqa: BLE001 — never let a transport error crash the hot path
            _log("WARN", f"PDP error: {type(e).__name__}: {e} trace={trace_id}")
            return Decision(False, f"pdp error: {type(e).__name__}", trace_id, errored=True)

        # DO NOT raise_for_status. The AI Evaluation API returns the decision
        # envelope on BOTH 200 (allow) and 403 (deny) — a 403 here is a *policy
        # denial*, not an infra failure. So we honor any body that carries a
        # `decision`, regardless of status. Only a response with no decision
        # (401 auth, 5xx, non-JSON) is a genuine error handed to the fail mode.
        # The vanilla PDP (200 + decision) flows through this unchanged.
        try:
            payload = resp.json()
        except Exception:  # noqa: BLE001 — non-JSON body ⇒ falls through to error path
            payload = None

        _elapsed = int((time.perf_counter() - t0) * 1000)
        result = payload[0] if isinstance(payload, list) and payload else payload
        result = result if isinstance(result, dict) else {}
        if "decision" not in result:
            _log(
                "WARN",
                f"PDP HTTP {resp.status_code} no-decision response={resp.text[:500]!r} "
                f"request_keys={sorted(eval_request.keys())} trace={trace_id}",
            )
            return Decision(False, f"pdp error: HTTP {resp.status_code}", trace_id, errored=True)
        raw_decision = result.get("decision")
        allow = raw_decision in (True, "allow", "Allow")

        # Reason: AI Evaluation API returns it at context.reason on deny; the
        # generic PDP returns determiningPolicies. Support both.
        reason = ""
        ctx = result.get("context")
        if isinstance(ctx, dict) and ctx.get("reason"):
            reason = str(ctx["reason"])
        if not reason:
            determining = result.get("determiningPolicies") or []
            reason = "; ".join(
                p.get("policyId") or p.get("policy_id") or "policy"
                for p in determining
                if isinstance(p, dict)
            )
        # Gateway-side correlation line: stamps WHICH gateway made this eval next
        # to the action + trace id, so a decision in the shared Reva store can be
        # traced to its source gateway by matching trace_id, even though the
        # Decision Logs UI does not (yet) show a gateway column.
        _act = eval_request.get("action")
        _action_id = _act.get("id") if isinstance(_act, dict) else _act
        _log("INFO",
             f"[reva-tf] gateway={cfg.gateway_id} action={_action_id} "
             f"decision={'allow' if allow else 'deny'} reason={reason!r} trace={trace_id}")
        return Decision(allow, reason or ("allow" if allow else "deny"), trace_id)
