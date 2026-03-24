"""
Unified framework for risk-aware interception messaging.

Interceptions that surface a structured notice to the user (request or response side)
share reason codes, human-readable descriptions, and metadata shape here.
Callers persist pending state and return responses; this module only formats copy and structs.
"""

from __future__ import annotations

from typing import Any

from n4ughtyllm_gate.core.confirmation import confirmation_template

PHASE_REQUEST = "request"
PHASE_RESPONSE = "response"

# reason_key -> (human-readable reason, summary prefix / template)
REASON_DESCRIPTIONS: dict[str, tuple[str, str]] = {
    "request_secret_exfiltration": (
        "Request appears to solicit leaking prompts, secrets, or internal information",
        "Signal: request_secret_exfiltration",
    ),
    "request_leak_check_failed": (
        "Request matched leak-detection rules",
        "Signal: request_leak_check_failed",
    ),
    "request_privilege_abuse": (
        "Request appears to seek privilege escalation or abuse",
        "Signal: request_privilege_abuse",
    ),
    "request_rule_bypass": (
        "Request appears to attempt bypassing safety rules",
        "Signal: request_rule_bypass",
    ),
    "request_strong_intent_attack": (
        "Request appears to contain strong attack intent",
        "Signal: request_strong_intent_attack",
    ),
    "request_shape_anomaly": (
        "Request structure looks anomalous (possible poisoning or injection)",
        "Signal: request_shape_anomaly",
    ),
    "request_blocked": (
        "Request blocked by security policy",
        "Signal: request_blocked",
    ),
    "response_high_risk": (
        "High-risk model output",
        "High-risk command or poisoning signal detected",
    ),
    "response_high_risk_command": (
        "High-risk command-like output",
        "High-risk command output signal detected",
    ),
    "response_forbidden_command": (
        "Matched strict command block rule",
        "Signal: response_forbidden_command",
    ),
    "response_tool_call_violation": (
        "Tool call hit high-risk guardrails",
        "Signal: response_tool_call_violation",
    ),
    "response_system_prompt_leak": (
        "Possible system prompt leak",
        "Signal: response_system_prompt_leak",
    ),
    "response_unicode_bidi": (
        "Possible Unicode bidirectional text poisoning",
        "Signal: response_unicode_bidi",
    ),
    "response_post_restore_masked": (
        "Sensitive exfiltration suspected after restoration",
        "Signal: response_post_restore_masked",
    ),
    "response_post_restore_blocked": (
        "High-risk exfiltration blocked after restoration",
        "Signal: response_post_restore_blocked",
    ),
    "response_sanitized": (
        "Response triggered safety sanitization",
        "Signal: response_sanitized",
    ),
    "awaiting_user_confirmation": (
        "Awaiting user confirmation",
        "Would require confirmation to proceed (legacy; approval disabled)",
    ),
}


def get_reason_and_summary(
    phase: str,
    disposition_reasons: list[str],
    security_tags: set[str],
) -> tuple[str, str]:
    """
    Derive unified reason text and summary from phase and context.
    phase: PHASE_REQUEST | PHASE_RESPONSE
    """
    reason_key = disposition_reasons[0] if disposition_reasons else (
        "request_blocked" if phase == PHASE_REQUEST else "response_high_risk"
    )
    reason_text, summary_prefix = REASON_DESCRIPTIONS.get(
        reason_key, (reason_key, f"Signal: {reason_key}")
    )
    if phase == PHASE_RESPONSE:
        tags = [t for t in sorted(security_tags) if t.startswith("response_")]
        summary = f"{summary_prefix}" + (
            f" ({', '.join(tags[:3])})" if tags else ""
        )
    else:
        summary = summary_prefix
    return reason_text, summary


def build_confirmation_message(
    confirm_id: str,
    reason: str,
    summary: str,
    phase: str = PHASE_RESPONSE,
    note: str = "",
    action_token: str = "",
) -> str:
    """
    Build the standard security notice body (informational only; no approval flow).
    phase is reserved for future differentiation; same template for now.
    """
    base = confirmation_template(confirm_id=confirm_id, reason=reason, summary=summary, action_token=action_token)
    if note:
        return f"{note}\n\n{base}"
    return base


def build_confirmation_metadata(
    confirm_id: str,
    status: str,
    reason: str,
    summary: str,
    phase: str = PHASE_RESPONSE,
    payload_omitted: bool = False,
    action_token: str = "",
) -> dict[str, Any]:
    """
    Build the `n4ughtyllm_gate.confirmation` object for JSON/SSE responses (client parsing).
    """
    pending = str(status or "").strip().lower() == "pending"
    return {
        "required": pending,
        "confirm_id": confirm_id,
        "status": status,
        "reason": reason,
        "summary": summary,
        "phase": phase,
        "payload_omitted": payload_omitted,
        "action_token": action_token,
    }
