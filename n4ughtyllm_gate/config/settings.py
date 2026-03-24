"""Runtime settings."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="N4UGHTYLLM_GATE_",
        extra="ignore",
        env_file="config/.env",
        env_file_encoding="utf-8",
    )

    app_name: str = "N4ughtyLLM Gate"
    env: str = "dev"
    log_level: str = "info"
    # In DEBUG, log full request bodies; when False log method/path/route/headers + body_size only
    log_full_request_body: bool = False
    host: str = "127.0.0.1"
    port: int = 18080
    enable_relay_endpoint: bool = False

    upstream_timeout_seconds: float = 600.0
    upstream_max_connections: int = 300
    upstream_max_keepalive_connections: int = 100
    # Thread offload for store I/O defaults off: on some Python 3.13 setups asyncio.to_thread can stall
    # loop shutdown (pytest / short-lived scripts). Enable via env when validated in your runtime.
    enable_thread_offload: bool = False
    # Max time (seconds) for request/response filter pipelines. On timeout the request is rejected
    # (response: block, request: pass-through) so the event loop is not wedged. 0 = unlimited (not recommended).
    filter_pipeline_timeout_s: float = 90.0
    upstream_base_header: str = "x-upstream-base"
    # Optional default upstream: set to call /v1/... without port routing or token registration
    upstream_base_url: str = ""
    upstream_whitelist_url_list: str = ""
    # Directory for compose files in the UI editor; empty = config/compose/
    compose_dir: str = ""
    storage_backend: str = "sqlite"  # sqlite | redis | postgres
    sqlite_db_path: str = (
        "logs/n4ughtyllm_gate.db"  # In Docker if logs/ is not writable, use e.g. /tmp/n4ughtyllm_gate.db
    )
    redis_url: str = "redis://127.0.0.1:6379/0"
    redis_key_prefix: str = "n4ughtyllm_gate"
    redis_pending_scan_batch_size: int = 200
    redis_pending_scan_max_entries: int = (
        0  # <=0: no scan cap (can miss older pending under very high concurrency)
    )
    postgres_dsn: str = ""
    postgres_schema: str = "public"
    max_request_body_bytes: int = 12_000_000
    max_messages_count: int = 300
    max_content_length_per_message: int = 250_000
    max_pending_payload_bytes: int = 1_200_000
    max_response_length: int = 2_000_000
    gateway_key_header: str = "gateway-key"
    gateway_key: str = ""  # Loaded from config/n4ughtyllm_gate_gateway.key at startup
    tenant_id_header: str = "x-tenant-id"
    confirmation_ttl_seconds: int = 600
    confirmation_executing_timeout_seconds: int = 120
    pending_data_ttl_seconds: int = 86400
    # Whether confirmation copy may include a redacted hit preview (legacy UI)
    confirmation_show_hit_preview: bool = True
    # Deprecated: yes/no approval removed; dangerous output is auto-redacted/split regardless of this flag.
    require_confirmation_on_block: bool = False
    # When true, strict command rules block immediately (ignore security_level / risk threshold)
    strict_command_block_enabled: bool = False
    # high: full detection | medium (default): high-risk + redaction | low: mostly redact + extreme blocks
    security_level: str = "medium"
    enable_semantic_module: bool = True  # Built-in TF-IDF classifier, no GPU
    semantic_gray_low: float = 0.25
    semantic_gray_high: float = 0.75
    semantic_timeout_ms: int = 150
    semantic_cache_ttl_seconds: int = 300
    semantic_cache_max_entries: int = 5000
    semantic_service_url: str = ""
    semantic_circuit_failure_threshold: int = 3
    semantic_circuit_open_seconds: int = 30
    default_policy: str = "default"
    security_rules_path: str = "n4ughtyllm_gate/policies/rules/security_filters.yaml"
    # Token map path (config/gw_tokens.json); loaded at startup, updated on register/remove
    gw_tokens_path: str = "config/gw_tokens.json"
    # Numeric token (1024-65535) routes to local_port_routing_host:{port}/v1
    # e.g. /v1/__gw__/t/8080/chat/completions → http://host.docker.internal:8080/v1/chat/completions
    enable_local_port_routing: bool = False
    # Host for numeric port routing (Docker: host.docker.internal; bare metal: 127.0.0.1)
    local_port_routing_host: str = "host.docker.internal"
    # Auto-register token → Docker service at startup (comma-separated token:service[:port]; default port = token)
    # Example: 8317:cli-proxy-api,8080:sub2api,3000:aiclient2api → token 8317 → http://cli-proxy-api:8317/v1
    docker_upstreams: str = ""
    enforce_loopback_only: bool = True
    # Trusted reverse-proxy IPs (comma-separated); only these may set X-Forwarded-For.
    # Empty = trust direct client IP only (safest default).
    trusted_proxy_ips: str = ""
    local_ui_session_ttl_seconds: int = 43_200
    local_ui_login_rate_limit_per_minute: int = 10
    local_ui_secure_cookie: bool = True
    local_ui_allow_internal_network: bool = False
    # Block internal/private IPs as v2 target URL (SSRF protection)
    v2_block_internal_targets: bool = True

    enable_request_hmac_auth: bool = False
    request_hmac_secret: str = ""
    request_signature_header: str = "x-n4ughtyllm-gate-signature"
    request_timestamp_header: str = "x-n4ughtyllm-gate-timestamp"
    request_nonce_header: str = "x-n4ughtyllm-gate-nonce"
    request_replay_window_seconds: int = 300
    request_nonce_cache_size: int = 50000
    nonce_cache_backend: str = "memory"  # memory | redis

    # v2 generic HTTP proxy (independent from v1 OpenAI-compatible filter chain)
    enable_v2_proxy: bool = True
    v2_enable_request_redaction: bool = True
    v2_enable_response_command_filter: bool = True
    v2_response_filter_obvious_only: bool = True
    v2_target_allowlist: str = ""
    v2_response_filter_bypass_hosts: str = ""
    v2_response_filter_max_chars: int = 200_000
    v2_sse_filter_probe_max_chars: int = 4_000

    enable_pending_prune_task: bool = True
    pending_prune_interval_seconds: int = 60
    clear_pending_on_startup: bool = False
    audit_log_path: str = (
        "logs/audit.jsonl"  # Empty string disables audit file; Docker may use /tmp/audit.jsonl
    )
    enable_dangerous_response_log: bool = (
        False  # Persist risky response samples; rotated daily; prunes older than ~10 days
    )
    dangerous_response_log_path: str = "logs/dangerous_response_samples.jsonl"  # Base path for samples log; Docker may redirect under /tmp

    enable_redaction: bool = True
    enable_restoration: bool = True
    enable_injection_detector: bool = True
    enable_privilege_guard: bool = True
    enable_anomaly_detector: bool = True
    enable_request_sanitizer: bool = True
    enable_output_sanitizer: bool = True
    enable_post_restore_guard: bool = True
    enable_system_prompt_guard: bool = False
    enable_untrusted_content_guard: bool = True
    enable_tool_call_guard: bool = True
    enable_rag_poison_guard: bool = True
    enable_exact_value_redaction: bool = True

    risk_score_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    # Request pipeline timeout action: "block" (safe default) or "pass" (legacy)
    request_pipeline_timeout_action: str = "block"
    # Admin endpoint rate limit: max requests per minute per client IP
    admin_rate_limit_per_minute: int = 30


settings = Settings()
