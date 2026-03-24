"""Streaming SSE helpers and chunk builders (split from router for tests and maintenance)."""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator
from typing import Any, AsyncIterable, Iterable

from fastapi.responses import StreamingResponse

from n4ughtyllm_gate.core.context import RequestContext


def _flatten_stream_content(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "".join(_flatten_stream_content(item) for item in value)
    if isinstance(value, dict):
        if isinstance(value.get("text"), str):
            return value["text"]
        for key in ("content", "delta", "output_text", "text"):
            if key in value:
                text = _flatten_stream_content(value[key])
                if text:
                    return text
    return ""


def _extract_stream_text_from_event(data_payload: str) -> str:
    try:
        event = json.loads(data_payload)
    except json.JSONDecodeError:
        return ""

    if not isinstance(event, dict):
        return ""

    # For Responses typed streams, only incremental assistant text deltas should
    # contribute to stream cache. Any other typed event (summary/tool/completed/etc.)
    # would cause duplicate or noisy replay text when upstream closes early.
    event_type = str(event.get("type") or "").strip().lower()
    if event_type:
        if event_type != "response.output_text.delta":
            return ""
        text = _flatten_stream_content(event.get("delta"))
        return text if text else ""

    choices = event.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0]
        if isinstance(first, dict):
            delta = first.get("delta")
            text = _flatten_stream_content(delta)
            if text:
                return text
            message = first.get("message")
            text2 = _flatten_stream_content(message)
            if text2:
                return text2

    for key in ("delta", "output_text", "text", "output"):
        if key in event:
            text = _flatten_stream_content(event[key])
            if text:
                return text
    return ""


def _extract_stream_event_type(data_payload: str) -> str:
    """Return normalized stream event type, or empty string if unavailable."""
    try:
        event = json.loads(data_payload)
    except json.JSONDecodeError:
        return ""
    if not isinstance(event, dict):
        return ""
    event_type = event.get("type")
    if not isinstance(event_type, str):
        return ""
    return event_type.strip().lower()


def _stream_block_reason(ctx: RequestContext) -> str | None:
    # Command-like high risk output should always require confirmation in stream mode.
    if "response_anomaly_high_risk_command" in ctx.security_tags:
        return "response_high_risk_command"

    if ctx.response_disposition == "block":
        if ctx.disposition_reasons:
            return ctx.disposition_reasons[-1]
        return "response_blocked"
    if ctx.response_disposition == "sanitize":
        return "response_sanitized"
    # tool_call_violation: only block the stream when the policy action is block, not review
    if "tool_call_violation" in ctx.security_tags:
        has_block_action = any(
            a.endswith(":block") and a.startswith("tool_call_guard:")
            for a in ctx.enforcement_actions
        )
        if has_block_action:
            return "response_tool_call_violation"
    if ctx.requires_human_review and any(tag.startswith("response_") for tag in ctx.security_tags):
        return "response_human_review_required"

    high_risk_tags = {
        "response_privilege_abuse",
        "response_injection_system_exfil",
        "response_injection_unicode_bidi",
        "response_semantic_leak",
        "response_semantic_privilege",
    }
    for tag in high_risk_tags:
        if tag in ctx.security_tags:
            return tag
    if ctx.risk_score >= max(ctx.risk_threshold, 0.9):
        return "response_high_risk"
    return None


def _stream_block_message(reason: str) -> str:
    return f"[N4ughtyLLM Gate] stream blocked by security policy: {reason}"


def _stream_block_sse_chunk(ctx: RequestContext, model: str, reason: str, route: str) -> bytes:
    if route == "/v1/responses":
        payload: dict[str, Any] = {
            "id": ctx.request_id,
            "object": "response.chunk",
            "model": model,
            "type": "response.output_text.delta",
            "delta": _stream_block_message(reason),
            "n4ughtyllm_gate": {
                "action": "block",
                "risk_score": round(ctx.risk_score, 4),
                "reason": reason,
                "security_tags": sorted(ctx.security_tags),
            },
        }
        return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n".encode("utf-8")

    payload = {
        "id": ctx.request_id,
        "object": "chat.completion.chunk",
        "model": model,
        "choices": [
            {
                "index": 0,
                "delta": {"role": "assistant", "content": _stream_block_message(reason)},
                "finish_reason": "stop",
            }
        ],
        "n4ughtyllm_gate": {
            "action": "block",
            "risk_score": round(ctx.risk_score, 4),
            "reason": reason,
            "security_tags": sorted(ctx.security_tags),
        },
    }
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n".encode("utf-8")


def _stream_error_sse_chunk(message: str, code: str | None = None) -> bytes:
    """SSE chunk carrying upstream failure; compatible with error.message / error.code."""
    detail = (message or "upstream_error").strip() or "upstream_error"
    error_code = (code or "upstream_error").strip() or "upstream_error"
    payload: dict[str, Any] = {
        "type": "error",
        "error": {
            "message": detail,
            "type": "n4ughtyllm_gate_error",
            "code": error_code,
        },
        "n4ughtyllm_gate": {
            "action": "block",
            "reason": error_code,
        },
    }
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n".encode("utf-8")


def _stream_done_sse_chunk() -> bytes:
    return b"data: [DONE]\n\n"


def _stream_confirmation_sse_chunk(
    ctx: RequestContext,
    model: str,
    route: str,
    content: str,
    confirmation_meta: dict[str, Any] | None,
) -> bytes:
    """Stream one assistant delta for confirmation-style notice or hard block; omit meta when None."""
    n4ughtyllm_gate_meta: dict[str, Any] = {}
    if confirmation_meta is not None:
        n4ughtyllm_gate_meta["confirmation"] = confirmation_meta
        n4ughtyllm_gate_meta["action"] = "awaiting_confirmation"
    else:
        n4ughtyllm_gate_meta["action"] = "blocked"
    if route == "/v1/responses":
        payload: dict[str, Any] = {
            "id": ctx.request_id,
            "object": "response.chunk",
            "model": model,
            "type": "response.output_text.delta",
            "delta": content,
            "n4ughtyllm_gate": n4ughtyllm_gate_meta,
        }
    else:
        payload = {
            "id": ctx.request_id,
            "object": "chat.completion.chunk",
            "model": model,
            "choices": [
                {"index": 0, "delta": {"role": "assistant", "content": content}, "finish_reason": "stop"}
            ],
            "n4ughtyllm_gate": n4ughtyllm_gate_meta,
        }
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n".encode("utf-8")


def _extract_sse_data_payload(line: bytes) -> str | None:
    if not line:
        return None
    stripped = line.strip()
    if not stripped.startswith(b"data:"):
        return None
    return stripped[5:].strip().decode("utf-8", errors="replace")


def _extract_sse_data_payload_from_chunk(chunk: bytes) -> str | None:
    normalized = chunk.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    payload_lines: list[str] = []
    for raw_line in normalized.split(b"\n"):
        payload = _extract_sse_data_payload(raw_line)
        if payload is not None:
            payload_lines.append(payload)
    if not payload_lines:
        return None
    return "\n".join(payload_lines)


def _build_sse_frame(lines: list[bytes]) -> bytes:
    frame = b"".join(lines)
    if not frame.endswith(b"\n"):
        frame += b"\n"
    if not frame.endswith(b"\n\n"):
        frame += b"\n"
    return frame


async def _iter_sse_frames(chunks: AsyncIterable[bytes]) -> AsyncGenerator[bytes, None]:
    buffer = b""
    async for chunk in chunks:
        if not chunk:
            continue
        buffer += chunk.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        while True:
            split_at = buffer.find(b"\n\n")
            if split_at < 0:
                break
            frame_body = buffer[:split_at]
            buffer = buffer[split_at + 2 :]
            if not frame_body:
                continue
            frame_lines = [line + b"\n" for line in frame_body.split(b"\n") if line]
            if frame_lines:
                yield _build_sse_frame(frame_lines)
    if buffer.strip():
        frame_lines = [line + b"\n" for line in buffer.split(b"\n") if line]
        if frame_lines:
            yield _build_sse_frame(frame_lines)


def _build_streaming_response(generator: Iterable[bytes] | AsyncIterable[bytes]) -> StreamingResponse:
    return StreamingResponse(
        generator,
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
