"""Relay-compatible routes."""

from __future__ import annotations

import hmac

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from n4ughtyllm_gate.adapters.openai_compat.router import (
    _execute_chat_once,
    _execute_chat_stream_once,
)
from n4ughtyllm_gate.adapters.openai_compat.upstream import (
    _effective_gateway_headers,
    _header_value,
    _resolve_gateway_key,
)
from n4ughtyllm_gate.adapters.relay_compat.mapper import relay_to_chat_payload
from n4ughtyllm_gate.config.settings import settings
from n4ughtyllm_gate.util.logger import logger


router = APIRouter()


@router.post("/generate")
async def relay_generate(payload: dict, request: Request):
    headers = _effective_gateway_headers(request)
    upstream_base = (_header_value(headers, settings.upstream_base_header) or "").strip()
    gateway_key = _resolve_gateway_key(headers).strip()
    if not upstream_base:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_parameters", "detail": "missing upstream base header"},
        )
    if not settings.gateway_key:
        return JSONResponse(status_code=500, content={"error": "gateway_misconfigured"})
    if not hmac.compare_digest(gateway_key.encode("utf-8"), settings.gateway_key.encode("utf-8")):
        return JSONResponse(status_code=401, content={"error": "gateway_auth_failed"})

    mapped_payload = relay_to_chat_payload(payload)
    boundary = getattr(request.state, "security_boundary", {})
    logger.info(
        "relay generate request_id=%s model=%s stream=%s routed_to=/v1/chat/completions",
        mapped_payload.get("request_id"),
        mapped_payload.get("model"),
        bool(mapped_payload.get("stream")),
    )

    if bool(mapped_payload.get("stream")):
        return await _execute_chat_stream_once(
            payload=mapped_payload,
            request_headers=headers,
            request_path="/v1/chat/completions",
            boundary=boundary,
            forced_upstream_base=None,
        )

    return await _execute_chat_once(
        payload=mapped_payload,
        request_headers=headers,
        request_path="/v1/chat/completions",
        boundary=boundary,
        skip_confirmation=False,
        forced_upstream_base=None,
    )
