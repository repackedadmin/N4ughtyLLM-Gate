"""Confirmation workflow helpers.

NOTE: The yes/no approval flow has been removed. All dangerous content is now
automatically sanitized (redacted or split with ---). The confirmation template
is informational only — it tells the user what was detected and how the content
was processed, but does NOT offer a release/approve option.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from typing import Any


# YES_WORDS is intentionally empty — approval is no longer supported.
YES_WORDS: set[str] = set()

NO_WORDS = {
    "no",
    "n",
    "cancel",
    "stop",
    "reject",
}


@dataclass(slots=True)
class ConfirmationDecision:
    value: str
    has_yes: bool
    has_no: bool


def make_confirm_id() -> str:
    return f"cfm-{uuid.uuid4().hex[:12]}"


def payload_hash(payload: dict[str, Any]) -> str:
    body = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def make_action_bind_token(seed: str) -> str:
    raw = str(seed or "").encode("utf-8")
    return f"act-{hashlib.sha256(raw).hexdigest()[:16]}"


def _tokenize_text(text: str) -> set[str]:
    normalized = text.strip().lower()
    if not normalized:
        return set()
    tokens = re.split(r"[\s,，。.!！？;；:/\\\|\(\)\[\]{}\"'`<>：（）【】「」『』《》]+", normalized)
    return {token for token in tokens if token}


def parse_confirmation_decision(text: str) -> ConfirmationDecision:
    tokens = _tokenize_text(text)
    has_yes = any(token in YES_WORDS for token in tokens)
    has_no = any(token in NO_WORDS for token in tokens)
    if has_no and not has_yes:
        return ConfirmationDecision(value="no", has_yes=False, has_no=True)
    if has_yes and not has_no:
        return ConfirmationDecision(value="yes", has_yes=True, has_no=False)
    if has_yes and has_no:
        return ConfirmationDecision(value="ambiguous", has_yes=True, has_no=True)
    return ConfirmationDecision(value="unknown", has_yes=False, has_no=False)


def confirmation_template(confirm_id: str, reason: str, summary: str, action_token: str = "") -> str:
    """Informational-only template. No yes/no approval options."""
    return (
        f"⚠️ [N4ughtyLLM Gate] Security interception notice\n"
        f"---\n"
        f"Reason: {reason}\n"
        f"Summary: {summary}\n"
        f"Action: Dangerous fragments were auto-redacted or split; approval is not available\n"
        f"Event ID: {confirm_id}\n"
        f"---\n"
        f"Dangerous content has been automatically processed (redacted or split with ---). "
        f"Contact your security administrator to review the original content."
    )
