"""UI configuration field definitions, docs catalog, and env file helpers."""

from __future__ import annotations

import tempfile
from pathlib import Path

from n4ughtyllm_gate.config.settings import settings
from n4ughtyllm_gate.util.logger import logger

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_ENV_PATH = (Path.cwd() / "config" / ".env").resolve()

_EXCLUDED_ROOT_DOCS: frozenset[str] = frozenset(
    {
        "AGENTS.md",
        "CHANGELOG.md",
        "PRODUCTION_READINESS_TEST_REPORT.md",
        "OPEN_SOURCE_CHECKLIST.md",
        "PR_DESCRIPTION_2026-02-26-security-hardening.md",
    }
)

_DOC_FRIENDLY_TITLES: dict[str, str] = {
    "README.md": "README",
    "WEBUI-QUICKSTART.md": "Web UI quick start",
    "CLIPROXY-QUICKSTART.md": "CLIProxy quick start",
    "SUB2API-QUICKSTART.md": "Sub2API quick start",
    "AICLIENT2API-QUICKSTART.md": "AIClient-2-API quick start",
    "OTHER_TERMINAL_CLIENTS_USAGE.md": "Other terminal clients",
    "SKILL.md": "Agent skill",
}

_DOC_ORDER: tuple[str, ...] = (
    "README.md",
    "WEBUI-QUICKSTART.md",
    "CLIPROXY-QUICKSTART.md",
    "SUB2API-QUICKSTART.md",
    "AICLIENT2API-QUICKSTART.md",
    "OTHER_TERMINAL_CLIENTS_USAGE.md",
    "SKILL.md",
)


def _docs_catalog() -> list[dict[str, str]]:
    """Return UI docs catalog sorted by _DOC_ORDER (existing files only)."""
    available: set[str] = {
        p.name for p in _PROJECT_ROOT.glob("*.md") if p.name not in _EXCLUDED_ROOT_DOCS
    }
    docs: list[dict[str, str]] = []
    seen: set[str] = set()
    for name in _DOC_ORDER:
        if name in available:
            docs.append(
                {
                    "id": name,
                    "title": _DOC_FRIENDLY_TITLES.get(
                        name, name.replace("-", " ").replace("_", " ").rstrip(".md")
                    ),
                    "path": name,
                }
            )
            seen.add(name)
    for name in sorted(available - seen):
        docs.append(
            {
                "id": name,
                "title": _DOC_FRIENDLY_TITLES.get(
                    name, name.replace("-", " ").replace("_", " ")
                ),
                "path": name,
            }
        )
    return docs


def _resolve_doc_path(doc_id: str) -> Path | None:
    safe_id = Path(doc_id).name
    if safe_id != doc_id:
        return None
    if safe_id in _EXCLUDED_ROOT_DOCS:
        return None
    candidate = (_PROJECT_ROOT / safe_id).resolve()
    if (
        candidate.is_file()
        and candidate.suffix == ".md"
        and candidate.parent == _PROJECT_ROOT
    ):
        return candidate
    return None


# ---------------------------------------------------------------------------
# UI config field metadata
# ---------------------------------------------------------------------------
_UI_CONFIG_FIELDS: tuple[dict[str, object], ...] = (
    # ---- general ----
    {
        "env": "N4UGHTYLLM_GATE_HOST",
        "field": "host",
        "label": "Listen host",
        "type": "string",
        "section": "general",
    },
    {
        "env": "N4UGHTYLLM_GATE_PORT",
        "field": "port",
        "label": "Listen port",
        "type": "int",
        "section": "general",
    },
    {
        "env": "N4UGHTYLLM_GATE_UPSTREAM_BASE_URL",
        "field": "upstream_base_url",
        "label": "Direct upstream base URL",
        "type": "string",
        "section": "general",
    },
    {
        "env": "N4UGHTYLLM_GATE_LOG_LEVEL",
        "field": "log_level",
        "label": "Log level",
        "type": "enum",
        "section": "general",
        "options": ["debug", "info", "warning", "error"],
    },
    {
        "env": "N4UGHTYLLM_GATE_LOG_FULL_REQUEST_BODY",
        "field": "log_full_request_body",
        "label": "Log full request body",
        "type": "bool",
        "section": "general",
    },
    {
        "env": "N4UGHTYLLM_GATE_STORAGE_BACKEND",
        "field": "storage_backend",
        "label": "Storage backend",
        "type": "enum",
        "section": "general",
        "options": ["sqlite", "redis", "postgres"],
    },
    {
        "env": "N4UGHTYLLM_GATE_SQLITE_DB_PATH",
        "field": "sqlite_db_path",
        "label": "SQLite path",
        "type": "string",
        "section": "general",
    },
    {
        "env": "N4UGHTYLLM_GATE_REDIS_URL",
        "field": "redis_url",
        "label": "Redis URL",
        "type": "string",
        "section": "general",
    },
    {
        "env": "N4UGHTYLLM_GATE_UPSTREAM_TIMEOUT_SECONDS",
        "field": "upstream_timeout_seconds",
        "label": "Upstream timeout (seconds)",
        "type": "int",
        "section": "general",
    },
    {
        "env": "N4UGHTYLLM_GATE_UPSTREAM_MAX_CONNECTIONS",
        "field": "upstream_max_connections",
        "label": "Max concurrent connections",
        "type": "int",
        "section": "general",
    },
    {
        "env": "N4UGHTYLLM_GATE_UPSTREAM_MAX_KEEPALIVE_CONNECTIONS",
        "field": "upstream_max_keepalive_connections",
        "label": "Keepalive pool size",
        "type": "int",
        "section": "general",
    },
    {
        "env": "N4UGHTYLLM_GATE_ENABLE_THREAD_OFFLOAD",
        "field": "enable_thread_offload",
        "label": "Thread-pool offload",
        "type": "bool",
        "section": "general",
    },
    {
        "env": "N4UGHTYLLM_GATE_FILTER_PIPELINE_TIMEOUT_S",
        "field": "filter_pipeline_timeout_s",
        "label": "Filter pipeline timeout (seconds)",
        "type": "int",
        "section": "general",
    },
    {
        "env": "N4UGHTYLLM_GATE_MAX_REQUEST_BODY_BYTES",
        "field": "max_request_body_bytes",
        "label": "Max request body (bytes)",
        "type": "int",
        "section": "general",
    },
    {
        "env": "N4UGHTYLLM_GATE_MAX_MESSAGES_COUNT",
        "field": "max_messages_count",
        "label": "Max messages count",
        "type": "int",
        "section": "general",
    },
    {
        "env": "N4UGHTYLLM_GATE_MAX_CONTENT_LENGTH_PER_MESSAGE",
        "field": "max_content_length_per_message",
        "label": "Max chars per message",
        "type": "int",
        "section": "general",
    },
    {
        "env": "N4UGHTYLLM_GATE_MAX_PENDING_PAYLOAD_BYTES",
        "field": "max_pending_payload_bytes",
        "label": "Max pending payload (bytes)",
        "type": "int",
        "section": "general",
    },
    {
        "env": "N4UGHTYLLM_GATE_MAX_RESPONSE_LENGTH",
        "field": "max_response_length",
        "label": "Max response chars",
        "type": "int",
        "section": "general",
    },
    {
        "env": "N4UGHTYLLM_GATE_AUDIT_LOG_PATH",
        "field": "audit_log_path",
        "label": "Audit log path",
        "type": "string",
        "section": "general",
    },
    {
        "env": "N4UGHTYLLM_GATE_ENABLE_DANGEROUS_RESPONSE_LOG",
        "field": "enable_dangerous_response_log",
        "label": "Save dangerous response samples",
        "type": "bool",
        "section": "general",
    },
    {
        "env": "N4UGHTYLLM_GATE_DANGEROUS_RESPONSE_LOG_PATH",
        "field": "dangerous_response_log_path",
        "label": "Dangerous response log path",
        "type": "string",
        "section": "general",
    },
    {
        "env": "N4UGHTYLLM_GATE_TRUSTED_PROXY_IPS",
        "field": "trusted_proxy_ips",
        "label": "Trusted proxy IPs (comma-separated)",
        "type": "string",
        "section": "general",
    },
    {
        "env": "N4UGHTYLLM_GATE_ENABLE_LOCAL_PORT_ROUTING",
        "field": "enable_local_port_routing",
        "label": "Local port auto-routing",
        "type": "bool",
        "section": "general",
    },
    {
        "env": "N4UGHTYLLM_GATE_LOCAL_PORT_ROUTING_HOST",
        "field": "local_port_routing_host",
        "label": "Port routing target host",
        "type": "string",
        "section": "general",
    },
    {
        "env": "N4UGHTYLLM_GATE_ENABLE_RELAY_ENDPOINT",
        "field": "enable_relay_endpoint",
        "label": "Relay compatibility endpoint",
        "type": "bool",
        "section": "general",
    },
    # ---- security ----
    {
        "env": "N4UGHTYLLM_GATE_SECURITY_LEVEL",
        "field": "security_level",
        "label": "Security level",
        "type": "enum",
        "section": "security",
        "options": ["low", "medium", "high"],
    },
    {
        "env": "N4UGHTYLLM_GATE_DEFAULT_POLICY",
        "field": "default_policy",
        "label": "Default policy",
        "type": "enum",
        "section": "security",
        "options": ["default", "permissive", "strict"],
    },
    {
        "env": "N4UGHTYLLM_GATE_STRICT_COMMAND_BLOCK_ENABLED",
        "field": "strict_command_block_enabled",
        "label": "Strict command block",
        "type": "bool",
        "section": "security",
    },
    {
        "env": "N4UGHTYLLM_GATE_RISK_SCORE_THRESHOLD",
        "field": "risk_score_threshold",
        "label": "Risk score threshold (0-1)",
        "type": "string",
        "section": "security",
    },
    {
        "env": "N4UGHTYLLM_GATE_REQUEST_PIPELINE_TIMEOUT_ACTION",
        "field": "request_pipeline_timeout_action",
        "label": "Request pipeline timeout action",
        "type": "enum",
        "section": "security",
        "options": ["block", "pass"],
    },
    {
        "env": "N4UGHTYLLM_GATE_ADMIN_RATE_LIMIT_PER_MINUTE",
        "field": "admin_rate_limit_per_minute",
        "label": "Admin rate limit (per minute)",
        "type": "int",
        "section": "security",
    },
    {
        "env": "N4UGHTYLLM_GATE_ENFORCE_LOOPBACK_ONLY",
        "field": "enforce_loopback_only",
        "label": "Loopback only",
        "type": "bool",
        "section": "security",
    },
    {
        "env": "N4UGHTYLLM_GATE_ENABLE_SEMANTIC_MODULE",
        "field": "enable_semantic_module",
        "label": "Semantic module",
        "type": "bool",
        "section": "security",
    },
    {
        "env": "N4UGHTYLLM_GATE_SEMANTIC_GRAY_LOW",
        "field": "semantic_gray_low",
        "label": "Semantic low-risk threshold",
        "type": "string",
        "section": "security",
    },
    {
        "env": "N4UGHTYLLM_GATE_SEMANTIC_GRAY_HIGH",
        "field": "semantic_gray_high",
        "label": "Semantic high-risk threshold",
        "type": "string",
        "section": "security",
    },
    {
        "env": "N4UGHTYLLM_GATE_SEMANTIC_TIMEOUT_MS",
        "field": "semantic_timeout_ms",
        "label": "Semantic timeout (ms)",
        "type": "int",
        "section": "security",
    },
    {
        "env": "N4UGHTYLLM_GATE_SEMANTIC_CACHE_TTL_SECONDS",
        "field": "semantic_cache_ttl_seconds",
        "label": "Semantic cache TTL (seconds)",
        "type": "int",
        "section": "security",
    },
    {
        "env": "N4UGHTYLLM_GATE_SEMANTIC_SERVICE_URL",
        "field": "semantic_service_url",
        "label": "Semantic service URL",
        "type": "string",
        "section": "security",
    },
    {
        "env": "N4UGHTYLLM_GATE_ENABLE_EXACT_VALUE_REDACTION",
        "field": "enable_exact_value_redaction",
        "label": "Exact-value redaction",
        "type": "bool",
        "section": "security",
    },
    {
        "env": "N4UGHTYLLM_GATE_ENABLE_REDACTION",
        "field": "enable_redaction",
        "label": "PII redaction",
        "type": "bool",
        "section": "security",
    },
    {
        "env": "N4UGHTYLLM_GATE_ENABLE_RESTORATION",
        "field": "enable_restoration",
        "label": "Redaction restoration",
        "type": "bool",
        "section": "security",
    },
    {
        "env": "N4UGHTYLLM_GATE_ENABLE_INJECTION_DETECTOR",
        "field": "enable_injection_detector",
        "label": "Injection detection",
        "type": "bool",
        "section": "security",
    },
    {
        "env": "N4UGHTYLLM_GATE_ENABLE_PRIVILEGE_GUARD",
        "field": "enable_privilege_guard",
        "label": "Privilege guard",
        "type": "bool",
        "section": "security",
    },
    {
        "env": "N4UGHTYLLM_GATE_ENABLE_ANOMALY_DETECTOR",
        "field": "enable_anomaly_detector",
        "label": "Anomaly detection",
        "type": "bool",
        "section": "security",
    },
    {
        "env": "N4UGHTYLLM_GATE_ENABLE_REQUEST_SANITIZER",
        "field": "enable_request_sanitizer",
        "label": "Request sanitizer",
        "type": "bool",
        "section": "security",
    },
    {
        "env": "N4UGHTYLLM_GATE_ENABLE_OUTPUT_SANITIZER",
        "field": "enable_output_sanitizer",
        "label": "Output sanitizer",
        "type": "bool",
        "section": "security",
    },
    {
        "env": "N4UGHTYLLM_GATE_ENABLE_POST_RESTORE_GUARD",
        "field": "enable_post_restore_guard",
        "label": "Post-restore guard",
        "type": "bool",
        "section": "security",
    },
    {
        "env": "N4UGHTYLLM_GATE_ENABLE_UNTRUSTED_CONTENT_GUARD",
        "field": "enable_untrusted_content_guard",
        "label": "Untrusted content guard",
        "type": "bool",
        "section": "security",
    },
    {
        "env": "N4UGHTYLLM_GATE_ENABLE_TOOL_CALL_GUARD",
        "field": "enable_tool_call_guard",
        "label": "Tool call guard",
        "type": "bool",
        "section": "security",
    },
    {
        "env": "N4UGHTYLLM_GATE_ENABLE_RAG_POISON_GUARD",
        "field": "enable_rag_poison_guard",
        "label": "RAG poison guard",
        "type": "bool",
        "section": "security",
    },
    {
        "env": "N4UGHTYLLM_GATE_ENABLE_SYSTEM_PROMPT_GUARD",
        "field": "enable_system_prompt_guard",
        "label": "System prompt guard",
        "type": "bool",
        "section": "security",
    },
    # ---- v2 proxy ----
    {
        "env": "N4UGHTYLLM_GATE_ENABLE_V2_PROXY",
        "field": "enable_v2_proxy",
        "label": "Enable v2 proxy",
        "type": "bool",
        "section": "v2",
    },
    {
        "env": "N4UGHTYLLM_GATE_V2_ENABLE_REQUEST_REDACTION",
        "field": "v2_enable_request_redaction",
        "label": "v2 request redaction",
        "type": "bool",
        "section": "v2",
    },
    {
        "env": "N4UGHTYLLM_GATE_V2_ENABLE_RESPONSE_COMMAND_FILTER",
        "field": "v2_enable_response_command_filter",
        "label": "v2 response command filter",
        "type": "bool",
        "section": "v2",
    },
    {
        "env": "N4UGHTYLLM_GATE_V2_RESPONSE_FILTER_OBVIOUS_ONLY",
        "field": "v2_response_filter_obvious_only",
        "label": "v2 obvious-only response filter",
        "type": "bool",
        "section": "v2",
    },
    {
        "env": "N4UGHTYLLM_GATE_V2_BLOCK_INTERNAL_TARGETS",
        "field": "v2_block_internal_targets",
        "label": "v2 SSRF protection",
        "type": "bool",
        "section": "v2",
    },
    {
        "env": "N4UGHTYLLM_GATE_V2_TARGET_ALLOWLIST",
        "field": "v2_target_allowlist",
        "label": "v2 target host allowlist",
        "type": "string",
        "section": "v2",
    },
    {
        "env": "N4UGHTYLLM_GATE_V2_RESPONSE_FILTER_BYPASS_HOSTS",
        "field": "v2_response_filter_bypass_hosts",
        "label": "v2 response filter bypass hosts",
        "type": "string",
        "section": "v2",
    },
    {
        "env": "N4UGHTYLLM_GATE_V2_RESPONSE_FILTER_MAX_CHARS",
        "field": "v2_response_filter_max_chars",
        "label": "v2 response filter max chars",
        "type": "int",
        "section": "v2",
    },
)


def _ui_config_field_map() -> dict[str, dict[str, object]]:
    return {str(item["field"]): dict(item) for item in _UI_CONFIG_FIELDS}


def _field_default(field_name: str) -> object:
    field_info = settings.__class__.model_fields[field_name]
    return field_info.default


def _serialize_env_value(kind: str, value: object) -> str:
    if kind == "bool":
        return "true" if bool(value) else "false"
    return str(value)


def _parse_bool_value(value: object) -> bool:
    if isinstance(value, bool):
        return value
    normalized = str(value or "").strip().lower()
    return normalized in {"1", "true", "yes", "on"}


def _coerce_config_value(meta: dict[str, object], raw_value: object) -> object:
    kind = str(meta["type"])
    if kind == "bool":
        return _parse_bool_value(raw_value)
    if kind == "int":
        try:
            return int(str(raw_value).strip())
        except ValueError as exc:
            raise ValueError(f"invalid integer for {meta['field']}") from exc
    value = str(raw_value or "").strip()
    if kind == "enum":
        raw_options = meta.get("options")
        options = (
            {str(item) for item in raw_options}
            if isinstance(raw_options, list)
            else set()
        )
        if value not in options:
            raise ValueError(f"invalid option for {meta['field']}")
    return value


def _read_env_lines() -> list[str]:
    if not _ENV_PATH.exists():
        return []
    return _ENV_PATH.read_text(encoding="utf-8").splitlines()


def _write_env_updates(updates: dict[str, str]) -> None:
    existing_lines = _read_env_lines()
    consumed: set[str] = set()
    new_lines: list[str] = []
    for line in existing_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            new_lines.append(line)
            continue
        key, _, _value = line.partition("=")
        key = key.strip()
        if key in updates:
            new_lines.append(f"{key}={updates[key]}")
            consumed.add(key)
        else:
            new_lines.append(line)
    if new_lines and new_lines[-1].strip():
        new_lines.append("")
    for key in updates:
        if key not in consumed:
            new_lines.append(f"{key}={updates[key]}")
    try:
        _ENV_PATH.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", delete=False, dir=str(_ENV_PATH.parent)
        ) as tmp:
            tmp.write("\n".join(new_lines).rstrip() + "\n")
            tmp_path = Path(tmp.name)
        tmp_path.replace(_ENV_PATH)
    except OSError as exc:
        logger.error("config env write failed path=%s error=%s", _ENV_PATH, exc)
        raise RuntimeError(f"cannot write {_ENV_PATH}: {exc}") from exc


def _ui_config_payload() -> dict[str, object]:
    items: list[dict[str, object]] = []
    for meta in _UI_CONFIG_FIELDS:
        field_name = str(meta["field"])
        current_value = getattr(settings, field_name)
        default_value = _field_default(field_name)
        items.append({**meta, "value": current_value, "default": default_value})
    return {"items": items}
