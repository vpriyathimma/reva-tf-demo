"""FastAPI entrypoint for the Reva ↔ TrueFoundry custom-guardrail plugin.

Exposes input-guardrail endpoints TrueFoundry's AI Gateway calls before a
request reaches the model. Each endpoint is a pure converter: TrueFoundry
payload → Reva PDP eval → allow/deny verdict.

Contract invariant: **every response is HTTP 200.** A policy denial is
``verdict=False`` in the body, never a non-2xx status — TrueFoundry treats
non-2xx as infrastructure failure, not a block. The only path that can 500 is
a genuinely unexpected crash, and even that is caught and converted to a
fail-mode verdict so gateway traffic behaves predictably.

Endpoints (paths are referenced from the TrueFoundry integration form):
  * POST /reva/authorize        — CallModel: authorize an LLM request  (VERIFIED contract)
  * POST /reva/authorize-tool   — InvokeTool: authorize an MCP tool call (UNVERIFIED — see below)
  * POST /reva/authorize-output — CAPTURE-ONLY probe: record TF's OUTPUT payload (no policy)
  * GET  /healthz               — liveness
"""

from __future__ import annotations

import asyncio
import json
import os
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

from dotenv import load_dotenv

import agents
from entities import InputGuardrailRequest, ValidateGuardrailResponse
from guardrail.reva_auth import RevaAuthorizer, RevaConfig, _log

# Load the plugin's .env (agentic store id, PDP url, token, schema_mode) at
# import time so `uvicorn main:app` picks it up without an explicit --env-file.
# RevaConfig reads os.getenv() per request, so this must run before any request.
load_dotenv(Path(__file__).with_name(".env"))

authorizer = RevaAuthorizer()
_STATIC = Path(__file__).with_name("static")

# Ring buffer of the raw payloads TrueFoundry POSTs to /reva/*, so we can inspect
# exactly what the gateway forwards to the plugin (headers + full body). In-memory,
# last 25 only; served by GET /debug/payloads when REVA_DEBUG=1.
_PAYLOAD_CAPTURE: deque = deque(maxlen=25)


async def _capture_payload(request: "Request") -> None:
    try:
        raw = await request.body()  # FastAPI already read+cached it for the route
        try:
            body = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            body = {"_raw": raw.decode("utf-8", "replace")[:8000]}
        headers = {k: v for k, v in request.headers.items() if k.lower() != "authorization"}
        _PAYLOAD_CAPTURE.append({"path": request.url.path, "headers": headers, "body": body})
    except Exception as e:  # noqa: BLE001 — capture must never break authorization
        _log("WARN", f"payload capture failed: {type(e).__name__}: {e}")


def _debug_dump(where: str, payload: dict[str, Any], cfg: RevaConfig) -> None:
    """When debug is on, log the full incoming TrueFoundry payload so we can
    see exactly what TF forwards — especially whether team/tier show up in
    context.metadata, and under which keys. Off by default (payloads contain
    the prompt)."""
    if not cfg.debug:
        return
    ctx = payload.get("context") or {}
    _log("DEBUG", f"{where} raw context={json.dumps(ctx, default=str)}")
    _log("DEBUG", f"{where} metadata keys={sorted((ctx.get('metadata') or {}).keys())}")
    _log("DEBUG", f"{where} full payload={json.dumps(payload, default=str)[:2000]}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await authorizer.aclose()


app = FastAPI(title="Reva TrueFoundry Guardrail", version="0.1.0", lifespan=lifespan)


@app.middleware("http")
async def _trace_every_request(request: Request, call_next):
    """VERIFICATION AID: log method + path for every inbound request.

    Answers "does TrueFoundry ever call us for an MCP tool invocation, and on
    which path?" — see /reva/authorize-tool's UNVERIFIED note. Path/method only;
    bodies are logged by the route handlers (they contain prompts)."""
    _log("TRACE", f"--> {request.method} {request.url.path}")
    return await call_next(request)


@app.exception_handler(RequestValidationError)
async def _log_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    """DIAGNOSTIC: when TrueFoundry's payload doesn't match our model, log the
    RAW body + which fields failed so we can see the real TF contract. Returns
    a permissive 200 verdict so TF doesn't treat it as an infra failure while
    we're inspecting."""
    raw = (await request.body()).decode("utf-8", "replace")
    _log("WARN", f"422 on {request.url.path} — validation errors: {exc.errors()}")
    _log("WARN", f"422 RAW BODY: {raw[:3000]}")
    return JSONResponse(status_code=200, content={"verdict": True, "message": "debug: payload logged"})


@app.get("/")
async def index() -> FileResponse:
    """The chat UI — the single front door for the demo. Same service also
    serves /reva/authorize (called by TrueFoundry) and /chat (called by this
    page's JS), so there is exactly one URL and one UI."""
    return FileResponse(_STATIC / "index.html")


class ChatRequest(BaseModel):
    message: str
    user: str = "alice@analyst"
    # Identity the orchestrator runs under. Client-chosen on purpose: swap it
    # mid-demo and watch the Reva verdict flip.
    agent_id: str = agents.ORCHESTRATOR_ID
    model: str | None = None  # None -> whatever TFY_MODEL says.
    servers: list[str] | None = None
    # Prior turns [{role, content}, …] the client carries so the payload builds
    # context across a session (grows requestBody.messages each turn).
    history: list[dict[str, Any]] | None = None


@app.post("/chat")
async def chat(req: ChatRequest, request: Request) -> StreamingResponse:
    """Server-sent events: trace events as they happen, then the final reply.

    The orchestrator loop runs as a task while events drain from a queue, so a
    slow tool call doesn't hold the trace back — the denial lands in real time.
    """
    queue: asyncio.Queue = asyncio.Queue()
    # Reuse a W3C traceparent if the caller already started a trace; otherwise the
    # orchestrator mints one for this turn. Either way every hop shares one trace id.
    ingress_traceparent = request.headers.get("traceparent")

    async def run() -> None:
        try:
            reply = await agents.orchestrate(
                req.message, user=req.user, agent_id=req.agent_id,
                model=req.model, servers=req.servers, history=req.history,
                emit=queue.put_nowait, traceparent=ingress_traceparent,
            )
            queue.put_nowait({"type": "reply", "text": reply})
        except Exception as e:  # noqa: BLE001
            queue.put_nowait({"type": "error", "text": str(e)[:200]})
        finally:
            queue.put_nowait(None)

    async def stream():
        task = asyncio.create_task(run())
        try:
            while (event := await queue.get()) is not None:
                yield f"data: {json.dumps(event, default=str)}\n\n"
        finally:
            task.cancel()

    return StreamingResponse(stream(), media_type="text/event-stream")


def _verdict_for(decision, cfg: RevaConfig) -> ValidateGuardrailResponse:
    """Turn a normalized PDP Decision + config into a TrueFoundry verdict.

      * PDP errored     → apply fail mode (open=allow, closed=deny).
      * log/monitor mode → always allow, but surface the would-be decision.
      * enforce mode     → allow/deny as the PDP decided.
    """
    if decision.errored:
        allow = cfg.fail_mode == "open"
        msg = f"{decision.reason} — failing {'open (allow)' if allow else 'closed (deny)'}"
        return ValidateGuardrailResponse(verdict=allow, message=msg)

    if cfg.mode in ("log", "monitor"):
        # Observe-only: never block, but record what enforce mode would do.
        return ValidateGuardrailResponse(
            verdict=True,
            message=f"[{cfg.mode}] would_{'allow' if decision.allow else 'deny'}: {decision.reason}",
        )

    return ValidateGuardrailResponse(verdict=decision.allow, message=decision.reason)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/debug/payloads")
async def debug_payloads() -> JSONResponse:
    """Return the raw payloads TrueFoundry recently POSTed to /reva/* — headers +
    full unparsed body — so we can see exactly which fields (user, prompt, history,
    metadata) the gateway forwards to the plugin. Gated behind REVA_DEBUG because
    the bodies contain prompts."""
    if os.getenv("REVA_DEBUG", "0") != "1":
        return JSONResponse(status_code=404,
                            content={"detail": "set REVA_DEBUG=1 on the service to enable"})
    return JSONResponse(content={"count": len(_PAYLOAD_CAPTURE), "payloads": list(_PAYLOAD_CAPTURE)})


@app.get("/debug/outbound")
async def debug_outbound() -> JSONResponse:
    """The subject/resource of the last eval we POSTed to the PDP — proves whether
    origin/endpoint actually go out on the wire. Gated behind REVA_DEBUG."""
    if os.getenv("REVA_DEBUG", "0") != "1":
        return JSONResponse(status_code=404,
                            content={"detail": "set REVA_DEBUG=1 on the service to enable"})
    from guardrail.reva_auth import _LAST_OUTBOUND
    return JSONResponse(content={"last_outbound": list(_LAST_OUTBOUND)})


def _mcp_tool_call(context: dict[str, Any], request_body: dict[str, Any]) -> tuple[str, Any] | None:
    """Detect an MCP tool invocation and return (qualified_tool_id, arguments).

    VERIFIED against live TrueFoundry traffic (mcp_pre_tool hook, gateway
    v0.157.1). A guardrail config binds exactly ONE url, so TF posts BOTH the
    llm_input and mcp_pre_tool payloads to the same endpoint. They are told
    apart by ``context.metadata.tool_name``, which is present only for tools::

        context.metadata.tool_name       "read_wiki_structure"
        context.metadata.mcp_server_name "deepwiki"
        requestBody                      {"repoName": "tiangolo/fastapi"}  <- the tool args

    Note requestBody carries the tool's *arguments*, not an OpenAI request —
    so it has no ``model`` key. Without this check build_model_eval would read
    model="unknown-model" and ask the PDP the wrong question.

    Returns None for a normal LLM request.
    """
    meta = context.get("metadata") or {}
    tool_name = meta.get("tool_name")
    if not tool_name:
        return None
    # Store entities are server-qualified ("billing-mcp/get_customer_pii"), so
    # qualify unless TF already handed us a path-shaped name.
    server = meta.get("mcp_server_name") or meta.get("mcp_server") or ""
    tool_id = str(tool_name) if "/" in str(tool_name) or not server else f"{server}/{tool_name}"
    return tool_id, request_body


@app.post("/reva/authorize", response_model=ValidateGuardrailResponse)
async def authorize(body: InputGuardrailRequest, request: Request) -> ValidateGuardrailResponse:
    """Authorize an LLM request (llm_input) or an MCP tool call (mcp_pre_tool).

    Both hooks arrive here because TrueFoundry binds one URL per guardrail
    config; we dispatch on the payload. VERIFIED against TF's contract.
    """
    await _capture_payload(request)
    cfg = RevaConfig(body.config)
    _debug_dump("/reva/authorize", body.model_dump(mode="json"), cfg)
    try:
        context = body.context.model_dump()
        mcp = _mcp_tool_call(context, body.requestBody)
        if mcp is not None:
            tool_id, arguments = mcp
            server = (context.get("metadata") or {}).get("mcp_server_name") or "unknown"
            eval_request, _user_id = authorizer.build_tool_eval(
                tool_id, arguments, server, context, cfg
            )
        else:
            eval_request, _user_id = authorizer.build_model_eval(
                body.requestBody, context, cfg
            )
        # The turn's traceparent rides in X-TFY-METADATA (context.metadata), which
        # TF forwards; the raw request header is TF's own PER-CALL id, which would
        # scatter every hop under a different trace. Prefer the app's, fall back to
        # the header only if absent.
        app_traceparent = (context.get("metadata") or {}).get("traceparent")
        decision = await authorizer.evaluate(
            eval_request, cfg,
            incoming_traceparent=app_traceparent or request.headers.get("traceparent"),
        )
    except Exception as e:  # noqa: BLE001 — a plugin bug must not 500 the gateway
        _log("WARN", f"unexpected error in /reva/authorize: {type(e).__name__}: {e}")
        allow = cfg.fail_mode == "open"
        return ValidateGuardrailResponse(
            verdict=allow,
            message=f"plugin error: {type(e).__name__} — failing {'open' if allow else 'closed'}",
        )
    return _verdict_for(decision, cfg)


@app.post("/reva/authorize-tool", response_model=ValidateGuardrailResponse)
async def authorize_tool(request: Request) -> ValidateGuardrailResponse:
    """Authorize an MCP tool (InvokeTool) call.

    TrueFoundry does not actually route here: a guardrail config binds one URL,
    so its mcp_pre_tool payload lands on /reva/authorize, which dispatches on
    ``context.metadata.tool_name`` (see _mcp_tool_call). This endpoint is kept
    for non-TF callers and for pointing a second TF guardrail config at a
    tool-only URL. It reads several key aliases because its payload shape is
    caller-defined, unlike the verified TF one.
    """
    raw: dict[str, Any] = await request.json()
    cfg = RevaConfig(raw.get("config"))
    _debug_dump("/reva/authorize-tool", raw, cfg)
    try:
        # Accept a few plausible shapes: explicit tool fields at top level, or
        # nested under requestBody. Adjust once the real payload is known.
        rb = raw.get("requestBody") or {}
        tool_name = raw.get("name") or rb.get("name") or rb.get("tool_name")
        if not tool_name:
            # Nothing to authorize — allow rather than block an unknown shape.
            return ValidateGuardrailResponse(verdict=True, message="no tool name in payload — allow")

        arguments = raw.get("arguments") or rb.get("arguments") or {}
        server_id = raw.get("server_id") or rb.get("server_id") or "unknown"
        context = raw.get("context") or {}

        eval_request, _user_id = authorizer.build_tool_eval(tool_name, arguments, server_id, context, cfg)
        decision = await authorizer.evaluate(eval_request, cfg)
    except Exception as e:  # noqa: BLE001
        _log("WARN", f"unexpected error in /reva/authorize-tool: {type(e).__name__}: {e}")
        allow = cfg.fail_mode == "open"
        return ValidateGuardrailResponse(
            verdict=allow,
            message=f"plugin error: {type(e).__name__} — failing {'open' if allow else 'closed'}",
        )
    return _verdict_for(decision, cfg)


@app.post("/reva/authorize-output")
async def authorize_output(request: Request) -> JSONResponse:
    """CAPTURE-ONLY output-guardrail probe — no policy, never blocks.

    Purpose: capture the EXACT payload TrueFoundry sends on the OUTPUT side
    (its ``OutputGuardrailRequest``: requestBody + responseBody + context +
    config) so we can analyse what information is available on the way back —
    especially ``responseBody`` (the model's completion / tool_calls).

    How to use: register THIS url as an *output* guardrail in the TF gateway,
    set REVA_DEBUG=1, send one request through the gateway, then read
    GET /debug/payloads to see the real bytes.

    This is a read-only probe for analysis, NOT an output filter — it always
    returns verdict=True (never blocks, never mutates). Turning Reva into a
    real output filter (validate/mutate on responseBody) is a later change.
    """
    await _capture_payload(request)
    try:
        raw: dict[str, Any] = await request.json()
    except Exception:  # noqa: BLE001 — probe must never break gateway traffic
        raw = {}
    resp = raw.get("responseBody")
    _log(
        "INFO",
        f"/reva/authorize-output captured — top-level keys={sorted(raw.keys())} "
        f"responseBody_present={resp is not None} "
        f"responseBody_keys={sorted(resp.keys()) if isinstance(resp, dict) else None}",
    )
    return JSONResponse(
        status_code=200,
        content={"verdict": True, "message": "output payload captured (probe — no policy)"},
    )


# Registered last: FastAPI matches routes in definition order, so every route
# above still wins. Only genuinely unknown paths land here.
@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def _catch_all(request: Request, full_path: str) -> JSONResponse:
    """VERIFICATION AID: capture any request TrueFoundry sends to a path we
    didn't anticipate — e.g. an MCP tool-invocation hook under a name we never
    guessed. Without this it would 404, which TF reads as an infra failure and
    which looks identical to "TF never called us at all".

    Returns a permissive 200 so gateway traffic keeps flowing while we inspect.
    """
    try:
        body = (await request.body()).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        body = "<unreadable>"
    _log("WARN", f"UNKNOWN PATH {request.method} /{full_path}")
    _log("WARN", f"UNKNOWN PATH headers={dict(request.headers)}")
    _log("WARN", f"UNKNOWN PATH body={body[:3000]}")
    return JSONResponse(status_code=200, content={"verdict": True, "message": "unknown path — logged"})
