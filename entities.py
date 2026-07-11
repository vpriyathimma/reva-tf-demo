"""Pydantic models for the Reva ↔ TrueFoundry custom-guardrail plugin.

Two contracts meet in this file:

  1. The **TrueFoundry custom-guardrail contract** — what the AI Gateway POSTs
     to us and what we must POST back. Field names mirror TrueFoundry's
     published template (github.com/truefoundry/custom-guardrails-template),
     verified against https://www.truefoundry.com/docs/ai-gateway/custom-guardrails.

  2. The **Reva PDP evaluation contract** — the Cedar eval request we send to
     /pdp/access/v1/evaluation. Shape is copied from the working LiteLLM hook
     (reva-litellm-demo/litellm/reva_auth_hook.py) so the same Reva policy
     store serves both gateways with no policy changes.

Only the fields we actually read are typed strictly; everything else is left
permissive (`extra="allow"`) because TrueFoundry evolves the payload and we
must not 500 on an unexpected key.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# TrueFoundry → plugin  (what the gateway sends us)
# ---------------------------------------------------------------------------
class Subject(BaseModel):
    """The identity TrueFoundry attributes the request to.

    `subjectSlug` is the human-readable id (typically the email); the Reva
    demo entities are keyed by ids like ``alice@analyst`` so we prefer the
    slug and fall back to the opaque `subjectId`.
    """

    model_config = ConfigDict(extra="allow")

    subjectId: str
    subjectType: Optional[str] = None  # "user" | "team" | "serviceaccount"
    subjectSlug: Optional[str] = None
    subjectDisplayName: Optional[str] = None


class RequestContext(BaseModel):
    model_config = ConfigDict(extra="allow")

    user: Subject
    # CONFIRMED against live TrueFoundry traffic: TF forwards the caller's
    # team/tier here (from the request's metadata). BUT it also stuffs
    # non-string values in — a nested `subject` object, a `teamName` array,
    # `tfy_gateway_region`, etc. So metadata is dict[str, Any], NOT
    # dict[str, str] (that mismatch was a 422). See reva_auth.py:_resolve_identity.
    metadata: Optional[dict[str, Any]] = None


class InputGuardrailRequest(BaseModel):
    """Body of the POST TrueFoundry makes to our input-guardrail endpoint."""

    model_config = ConfigDict(extra="allow")

    # OpenAI-format request (model, messages, tools, …). Left as a raw dict
    # rather than a strict CompletionCreateParams model so provider-specific
    # params never cause a validation 500 in the hot path.
    requestBody: dict[str, Any] = Field(default_factory=dict)
    context: RequestContext
    config: Optional[dict[str, Any]] = None


# ---------------------------------------------------------------------------
# plugin → TrueFoundry  (what we must return; ALWAYS HTTP 200)
# ---------------------------------------------------------------------------
class ValidateGuardrailResponse(BaseModel):
    """Validate-operation response. `verdict=False` denies the request.

    Non-2xx is reserved for infrastructure failure, so denials ride on a 200
    with ``verdict=False`` — see main.py, which never raises for a policy deny.
    """

    verdict: bool
    message: Optional[str] = None
