"""Relay protocol mapper.

Converts relay-format payloads to InternalRequest (for the filter pipeline)
and to OpenAI chat-completion dicts (for the chat executor).

Relay format fields
-------------------
request_id   : str  – unique request identifier (auto-generated if absent)
session_id   : str  – session identifier (defaults to request_id)
model        : str  – model name
prompt       : str  – simple single-turn text prompt (alternative to ``messages``)
messages     : list – OpenAI-style messages list; takes precedence over ``prompt``
system       : str  – optional system prompt prepended to the message list
stream       : bool – enable SSE streaming
policy       : str  – security policy name (defaults to gateway default_policy)
max_tokens   : int  – maximum tokens to generate
temperature  : float
top_p        : float
stop         : str | list[str] – stop sequence(s)
n            : int  – number of completions
presence_penalty  : float
frequency_penalty : float
logit_bias   : dict
user         : str  – end-user identifier forwarded to upstream
metadata     : dict – arbitrary caller-supplied metadata stored in InternalRequest
source       : str  – attribution label placed on the synthetic user message
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from n4ughtyllm_gate.config.settings import settings
from n4ughtyllm_gate.core.models import InternalMessage, InternalRequest
from n4ughtyllm_gate.util.logger import logger

# ------------------------------------------------------------------
# Field sets
# ------------------------------------------------------------------
_GENERATION_PARAMS: tuple[str, ...] = (
    "max_tokens",
    "temperature",
    "top_p",
    "stop",
    "n",
    "presence_penalty",
    "frequency_penalty",
    "logit_bias",
    "user",
    "seed",
    "logprobs",
    "top_logprobs",
    "response_format",
)

_BASE64_LIKE_RE = re.compile(r"[A-Za-z0-9+/]{256,}={0,2}")
_BINARY_PLACEHOLDER = "[BINARY_CONTENT]"
_IMAGE_PLACEHOLDER = "[IMAGE_CONTENT]"
_NON_TEXT_PLACEHOLDER = "[NON_TEXT_PART]"
_TRUNCATED_SUFFIX = " [TRUNCATED]"


# ------------------------------------------------------------------
# Content helpers (replicate the subset needed without circular import)
# ------------------------------------------------------------------

def _cap_text(text: str, limit: int) -> str:
    if limit <= 0:
        return text
    if len(text) <= limit:
        return text
    return f"{text[:limit]}{_TRUNCATED_SUFFIX}"


def _looks_like_data_url(value: str) -> bool:
    lowered = value.strip().lower()
    return (
        lowered.startswith("data:image/")
        or lowered.startswith("data:audio/")
        or lowered.startswith("data:video/")
    )


def _is_binary_dict_part(part: dict) -> bool:
    ptype = str(part.get("type", "")).lower()
    if any(tok in ptype for tok in ("image", "audio", "video", "file")):
        return True
    return any(
        key in part for key in ("image_url", "image", "file", "audio", "video", "input_image", "input_audio")
    )


def _flatten_part(part: object) -> str:
    if isinstance(part, dict):
        if _is_binary_dict_part(part):
            if "image" in str(part.get("type", "")).lower() or "image_url" in part:
                return _IMAGE_PLACEHOLDER
            return _BINARY_PLACEHOLDER
        text = part.get("text")
        if isinstance(text, str):
            return text
        content = part.get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            merged = " ".join(_flatten_part(item) for item in content).strip()
            return merged or _NON_TEXT_PLACEHOLDER
        return _NON_TEXT_PLACEHOLDER

    if isinstance(part, str):
        if _looks_like_data_url(part):
            return _IMAGE_PLACEHOLDER
        if len(part) > 1024 and _BASE64_LIKE_RE.search(part):
            return _BINARY_PLACEHOLDER
        return part

    return str(part)


def _flatten_content(content: object) -> str:
    if isinstance(content, list):
        merged = " ".join(_flatten_part(part) for part in content)
        return " ".join(merged.split())
    if isinstance(content, dict):
        return _flatten_part(content)
    return str(content)


# ------------------------------------------------------------------
# Normalisation helpers
# ------------------------------------------------------------------

def _normalise_messages(payload: dict) -> list[dict]:
    """Return a normalised messages list from a relay payload.

    Priority:
    1. ``payload["messages"]`` if it is a non-empty list
    2. A synthetic user message built from ``payload["prompt"]``

    If ``payload["system"]`` is present it is prepended as a system message
    when the incoming messages list does not already start with one.
    """
    raw_messages: Any = payload.get("messages")
    if isinstance(raw_messages, list) and raw_messages:
        messages: list[dict] = [
            m if isinstance(m, dict) else {"role": "user", "content": str(m)}
            for m in raw_messages
        ]
    else:
        prompt = str(payload.get("prompt") or "")
        messages = [{"role": "user", "content": prompt}]

    system_text = str(payload.get("system") or "").strip()
    if system_text:
        has_leading_system = (
            messages
            and isinstance(messages[0], dict)
            and str(messages[0].get("role", "")).strip().lower() == "system"
        )
        if not has_leading_system:
            messages = [{"role": "system", "content": system_text}, *messages]

    return messages


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------

def relay_to_internal(payload: dict) -> InternalRequest:
    """Map a relay-format payload to an :class:`InternalRequest`.

    Handles all relay protocol fields: message list or single prompt,
    optional system prompt, content flattening, binary placeholder
    substitution, per-message content length cap, and generation parameters
    preserved in metadata for downstream use.
    """
    request_id = str(payload.get("request_id") or uuid.uuid4())
    session_id = str(payload.get("session_id") or request_id)
    model = str(payload.get("model") or "relay-model")
    source_label = str(payload.get("source") or "user")

    raw_messages = _normalise_messages(payload)

    internal_messages: list[InternalMessage] = []
    for item in raw_messages:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role") or "user").strip().lower()
        source = (
            item.get("source")
            or ("system" if role == "system" else source_label)
        )
        content = _flatten_content(item.get("content", ""))
        content = _cap_text(content, settings.max_content_length_per_message)
        internal_messages.append(
            InternalMessage(
                role=role,
                content=content,
                source=str(source),
                metadata=item.get("metadata") or {},
            )
        )

    generation_params: dict[str, Any] = {}
    for param in _GENERATION_PARAMS:
        if param in payload:
            generation_params[param] = payload[param]

    caller_meta: dict[str, Any] = payload.get("metadata") or {}

    logger.debug(
        "relay_to_internal request_id=%s model=%s messages=%d stream=%s",
        request_id,
        model,
        len(internal_messages),
        bool(payload.get("stream")),
    )

    return InternalRequest(
        request_id=request_id,
        session_id=session_id,
        route="/relay/generate",
        model=model,
        messages=internal_messages,
        metadata={
            "raw": payload,
            "generation_params": generation_params,
            "caller_metadata": caller_meta,
        },
    )


def relay_to_chat_payload(payload: dict) -> dict:
    """Map a relay-format payload to an OpenAI chat-completion dict.

    This is the canonical conversion used by the relay router to build the
    ``payload`` dict expected by :func:`_execute_chat_once` and
    :func:`_execute_chat_stream_once`.  All relay-specific generation
    parameters (``max_tokens``, ``temperature``, ``top_p``, ``stop``, …)
    are forwarded so they reach the upstream model unchanged.
    """
    request_id = str(payload.get("request_id") or uuid.uuid4())
    session_id = str(payload.get("session_id") or request_id)
    model = str(payload.get("model") or "relay-model")

    messages = _normalise_messages(payload)

    mapped: dict[str, Any] = {
        "request_id": request_id,
        "session_id": session_id,
        "model": model,
        "messages": messages,
    }

    if "stream" in payload:
        mapped["stream"] = bool(payload["stream"])
    if "policy" in payload and payload["policy"] is not None:
        mapped["policy"] = str(payload["policy"])

    for param in _GENERATION_PARAMS:
        if param in payload and payload[param] is not None:
            mapped[param] = payload[param]

    logger.debug(
        "relay_to_chat_payload request_id=%s model=%s messages=%d stream=%s",
        request_id,
        model,
        len(messages),
        bool(mapped.get("stream")),
    )

    return mapped
