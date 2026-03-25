"""FastAPI app entry — assembly module.

This file imports from sub-modules and wires the application together.
The actual logic lives in:
- gateway_keys.py     — key & proxy token management
- gateway_network.py  — trusted proxy, loopback, internal IP checks
- gateway_auth.py     — UI session, CSRF, admin auth, blocked response
- gateway_ui_config.py — config field data, docs catalog, env helpers
- gateway_ui_routes.py — UI / keys / rules / compose endpoints
"""

from __future__ import annotations

import hmac
import json
import re
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path
from threading import Lock
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles

from n4ughtyllm_gate.adapters.openai_compat.router import (
    clear_pending_confirmations_on_startup,
    close_runtime_dependencies,
    close_semantic_async_client,
    prune_pending_confirmations,
    reload_runtime_dependencies,
    router as openai_router,
)
from n4ughtyllm_gate.adapters.openai_compat.offload import shutdown_payload_transform_executor
from n4ughtyllm_gate.adapters.openai_compat.upstream import close_upstream_async_client
from n4ughtyllm_gate.adapters.relay_compat.router import router as relay_router
from n4ughtyllm_gate.adapters.v2_proxy.router import (
    close_v2_async_client,
    router as v2_proxy_router,
)
from n4ughtyllm_gate.config.settings import settings
from n4ughtyllm_gate.core.audit import shutdown_audit_worker
from n4ughtyllm_gate.core.dangerous_response_log import shutdown_dangerous_response_log_worker
from n4ughtyllm_gate.core.confirmation_cache_task import ConfirmationCacheTask
from n4ughtyllm_gate.core.hot_reload import HotReloader, build_watcher

# --- Re-exports from sub-modules (backward compatibility) ---
from n4ughtyllm_gate.core.gateway_keys import (  # noqa: F401
    _FORBIDDEN_UPSTREAM_BASE_EXAMPLES,
    _GATEWAY_KEY_FILE,
    _is_forbidden_upstream_base_example,
    _normalize_input_upstream_base,
    _PROXY_TOKEN_FILE,
    _PROXY_TOKEN_HEADER,
    _ensure_gateway_key,
    _ensure_proxy_token,
    _gateway_key_cached,
    _normalize_required_whitelist_list,
    get_proxy_token_value,
)
from n4ughtyllm_gate.core.gateway_network import (  # noqa: F401
    _LOOPBACK_HOSTS,
    _is_internal_ip,
    _is_loopback_ip,
    _is_trusted_proxy,
    _parse_trusted_proxy_ips,
    _real_client_ip,
)
import n4ughtyllm_gate.core.gateway_network as _gw_net  # noqa: F401 — used by tests
from n4ughtyllm_gate.core.gateway_auth import (  # noqa: F401
    _UI_SESSION_COOKIE,
    _apply_ui_security_headers,
    _blocked_response,
    _create_ui_session_token,
    _gateway_token_base_url,
    _is_passthrough_read_path,
    _is_public_ui_path,
    _is_ui_authenticated,
    _is_valid_ui_session,
    _public_base_url,
    _sanitize_public_host,
    _string_field,
    _ui_client_fingerprint,
    _ui_csrf_token,
    _ui_session_signature,
    _verify_admin_gateway_key,
    _verify_ui_csrf,
)
from n4ughtyllm_gate.core.gateway_ui_config import (  # noqa: F401
    _coerce_config_value,
    _docs_catalog,
    _field_default,
    _parse_bool_value,
    _read_env_lines,
    _resolve_doc_path,
    _serialize_env_value,
    _ui_config_field_map,
    _ui_config_payload,
    _write_env_updates,
    _UI_CONFIG_FIELDS,
)
from n4ughtyllm_gate.core.gateway_ui_routes import (  # noqa: F401
    register_ui_routes,
    _ui_bootstrap_payload,
)

from n4ughtyllm_gate.core.gw_tokens import (
    find_token as gw_tokens_find_token,
    get as gw_tokens_get,
    inject_docker_upstreams as gw_tokens_inject_docker_upstreams,
    load as gw_tokens_load,
    register as gw_tokens_register,
    unregister as gw_tokens_unregister,
    update as gw_tokens_update,
)
from n4ughtyllm_gate.core.upstream_registry import (
    check_provider_health,
    delete_provider,
    delete_model_group_policy,
    get_provider,
    get_model_group_policy,
    get_provider_health_state,
    list_provider_health_states,
    list_providers,
    list_model_group_policies,
    load_providers,
    load_routing_policies,
    reset_provider_circuit,
    resolve_provider_for_model_group,
    resolve_provider_route,
    upsert_model_group_policy,
    upsert_provider,
)
from n4ughtyllm_gate.init_config import assert_security_bootstrap_ready, ensure_config_dir
from n4ughtyllm_gate.observability.logging import configure_logging
from n4ughtyllm_gate.observability.metrics import inc_request, observe_request_duration
from n4ughtyllm_gate.observability.metrics import get_metrics_app
from n4ughtyllm_gate.observability.tracing import trace_span
from n4ughtyllm_gate.observability.tracing import init_tracing
from n4ughtyllm_gate.storage.crypto import ensure_key as _ensure_fernet_key
from n4ughtyllm_gate.core.security_boundary import (
    build_nonce_cache,
    build_signature_payload,
    now_ts,
    verify_hmac_signature,
)
from n4ughtyllm_gate.storage.offload import run_store_io, shutdown_store_io_executor
from n4ughtyllm_gate.util.logger import logger
from n4ughtyllm_gate.util.redaction_whitelist import normalize_whitelist_keys

# /v1/__gw__/t/{token}/chat/completions -> /v1/chat/completions
# /v1/__gw__/t/{token}__redact/chat/completions -> redact-only mode
# /v1/__gw__/t/{token}__passthrough/chat/completions -> passthrough mode
# /v2/__gw__/t/{token}/proxy -> /v2/proxy
_GW_TOKEN_PATH_RE = re.compile(r"^/(v1|v2)/__gw__/t/([^/]+?)(?:__([a-z]+))?(?:/(.*))?$")
_GW_PROVIDER_PATH_RE = re.compile(r"^/(v1|v2)/__gw__/p/([^/]+?)(?:__([a-z]+))?(?:/(.*))?$")
_VALID_FILTER_MODES = frozenset({"redact", "passthrough"})

_confirmation_cache_task: ConfirmationCacheTask | None = None
_hot_reloader: HotReloader | None = None


def _initialize_observability() -> None:
    configure_logging(settings.log_level)
    init_tracing(settings.app_name)


def _mount_metrics_endpoint(target_app: FastAPI) -> None:
    metrics_app = get_metrics_app()
    if metrics_app is not None:
        target_app.mount("/metrics", metrics_app)


def _observability_route_label(path: str) -> str:
    matched = _GW_TOKEN_PATH_RE.match(path)
    if matched:
        return f"token_{matched.group(1)}"
    provider_match = _GW_PROVIDER_PATH_RE.match(path)
    if provider_match:
        return f"provider_{provider_match.group(1)}"
    if path == "/":
        return "root"
    if path == "/health":
        return "health"
    if path == "/robots.txt":
        return "robots"
    if path == "/favicon.ico":
        return "favicon"
    if path == "/metrics":
        return "metrics"
    if path.startswith("/__ui__/assets"):
        return "ui_assets"
    if path == "/__ui__/login":
        return "ui_login_page"
    if path == "/__ui__/api/login":
        return "ui_login_api"
    if path.startswith("/__ui__/api/"):
        return "ui_api"
    if path.startswith("/__ui__"):
        return "ui_page"
    if path.startswith("/__gw__/"):
        return f"gw_{path.rsplit('/', 1)[-1]}"
    if path == "/v1/chat/completions":
        return "v1_chat_completions"
    if path == "/v1/responses":
        return "v1_responses"
    if path.startswith("/v1/") or path == "/v1":
        return "v1_passthrough"
    if path == "/v2/proxy":
        return "v2_proxy"
    if path.startswith("/v2/") or path == "/v2":
        return "v2"
    if path == "/relay/generate":
        return "relay_generate"
    if path.startswith("/relay/") or path == "/relay":
        return "relay"
    return "other"


def _record_request_observability(
    *,
    method: str,
    route_label: str,
    started_at: float,
    status_code: int,
    reject_reason: str | None,
    span: object,
) -> None:
    setter = getattr(span, "set_attribute", None)
    if callable(setter):
        setter("http.method", method)
        setter("http.route", route_label)
        setter("http.status_code", status_code)
        if reject_reason:
            setter("n4ughtyllm_gate.rejected_reason", reject_reason)
    inc_request(route_label, status_code)
    observe_request_duration(route_label, max(time.perf_counter() - started_at, 0.0))


def _observe_response(
    response: Response,
    *,
    method: str,
    route_label: str,
    started_at: float,
    reject_reason: str | None,
    span: object,
) -> Response:
    _record_request_observability(
        method=method,
        route_label=route_label,
        started_at=started_at,
        status_code=response.status_code,
        reject_reason=reject_reason,
        span=span,
    )
    return response


# ---------------------------------------------------------------------------
# Simple in-memory rate limiter for admin endpoints
# ---------------------------------------------------------------------------
class _AdminRateLimiter:
    _EVICT_INTERVAL = 300.0  # Evict expired rate-limit buckets every 5 minutes
    _MAX_BUCKETS = 50_000  # Cap unique IPs tracked for admin rate limiting

    def __init__(self, max_per_minute: int = 30) -> None:
        self._max = max(1, max_per_minute)
        self._buckets: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()
        self._last_evict: float = 0.0

    def is_allowed(self, client_ip: str) -> bool:
        now = time.monotonic()
        cutoff = now - 60.0
        with self._lock:
            # Periodically evict stale buckets to prevent unbounded memory growth
            if now - self._last_evict > self._EVICT_INTERVAL:
                self._buckets = defaultdict(
                    list,
                    {k: v for k, v in self._buckets.items() if v and v[-1] > cutoff},
                )
                self._last_evict = now
            # Hard cap: reject if too many distinct IPs tracked (DoS mitigation)
            if client_ip not in self._buckets and len(self._buckets) >= self._MAX_BUCKETS:
                return False
            bucket = self._buckets[client_ip]
            self._buckets[client_ip] = [t for t in bucket if t > cutoff]
            if len(self._buckets[client_ip]) >= self._max:
                return False
            self._buckets[client_ip].append(now)
            return True


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ARG001
    # --- startup ---
    try:
        ensure_config_dir()
        assert_security_bootstrap_ready()
        logger.info("security policy bootstrap ready")
    except Exception as exc:  # pragma: no cover
        logger.error("init_config on startup failed: %s", exc)
        raise

    _initialize_observability()
    _ensure_gateway_key()
    _ensure_proxy_token()
    _ensure_fernet_key()
    # Rebuild runtime dependencies at startup so test lifespans and hot-reload
    # shutdowns never reuse a store backend that has already been closed.
    reload_runtime_dependencies()

    upstream = (settings.upstream_base_url or "").strip()
    logger.info(
        "gateway config: upstream=%s security_level=%s enforce_loopback=%s v2_proxy=%s",
        upstream or "(none — token path required)",
        settings.security_level,
        settings.enforce_loopback_only,
        settings.enable_v2_proxy,
    )

    try:
        gw_tokens_load()
    except Exception as exc:  # pragma: no cover
        logger.warning("gw_tokens load on startup failed: %s", exc)
    try:
        load_providers()
    except Exception as exc:  # pragma: no cover
        logger.warning("upstream providers load on startup failed: %s", exc)
    try:
        load_routing_policies()
    except Exception as exc:  # pragma: no cover
        logger.warning("upstream routing policies load on startup failed: %s", exc)
    try:
        gw_tokens_inject_docker_upstreams()
    except Exception as exc:  # pragma: no cover
        logger.warning("docker_upstreams inject failed: %s", exc)
    if settings.clear_pending_on_startup:
        try:
            n = await run_store_io(clear_pending_confirmations_on_startup)
            if n:
                logger.info("cleared %d pending confirmation(s) on startup", n)
        except Exception as exc:  # pragma: no cover
            logger.warning("clear pending confirmations on startup failed: %s", exc)
    global _confirmation_cache_task, _hot_reloader
    if settings.enable_pending_prune_task and _confirmation_cache_task is None:
        _confirmation_cache_task = ConfirmationCacheTask(
            prune_func=prune_pending_confirmations
        )
        await _confirmation_cache_task.start()

    if _hot_reloader is None:
        _hot_reloader = build_watcher()
        await _hot_reloader.start()

    yield

    # --- shutdown ---
    if _hot_reloader is not None:
        await _hot_reloader.stop()
        _hot_reloader = None
    if _confirmation_cache_task is not None:
        await _confirmation_cache_task.stop()
        _confirmation_cache_task = None
    close_runtime_dependencies()
    shutdown_store_io_executor()
    shutdown_payload_transform_executor()
    await close_upstream_async_client()
    await close_v2_async_client()
    await close_semantic_async_client()
    shutdown_audit_worker()
    shutdown_dangerous_response_log_worker()
    from n4ughtyllm_gate.core.stats import flush as flush_stats

    flush_stats()


app = FastAPI(title=settings.app_name, lifespan=lifespan)
_mount_metrics_endpoint(app)
app.include_router(openai_router, prefix="/v1")
if settings.enable_v2_proxy:
    app.include_router(v2_proxy_router)
if settings.enable_relay_endpoint:
    app.include_router(relay_router, prefix="/relay")
_WWW_DIR = (Path(__file__).resolve().parents[2] / "www").resolve()
_UI_ASSETS_DIR = (_WWW_DIR / "assets").resolve()
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_UI_LOGIN_RATE_LIMITER = _AdminRateLimiter(
    max_per_minute=settings.local_ui_login_rate_limit_per_minute
)
if _UI_ASSETS_DIR.is_dir():
    app.mount(
        "/__ui__/assets", StaticFiles(directory=str(_UI_ASSETS_DIR)), name="ui-assets"
    )
_nonce_cache = build_nonce_cache()
_admin_rate_limiter = _AdminRateLimiter(
    max_per_minute=settings.admin_rate_limit_per_minute
)
_ADMIN_ENDPOINTS = frozenset(
    {
        "/__gw__/register",
        "/__gw__/lookup",
        "/__gw__/unregister",
        "/__gw__/add",
        "/__gw__/remove",
    }
)
_PASSTHROUGH_PATHS = frozenset({"/", "/health", "/robots.txt", "/favicon.ico"})


# ---------------------------------------------------------------------------
# GWTokenRewriteMiddleware
# ---------------------------------------------------------------------------
class GWTokenRewriteMiddleware:
    """Rewrite token paths before route matching."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        path = str(scope.get("path") or "/")
        token_match = _GW_TOKEN_PATH_RE.match(path)
        provider_match = _GW_PROVIDER_PATH_RE.match(path)
        if not token_match and not provider_match:
            await self.app(scope, receive, send)
            return

        route_label = _observability_route_label(path)
        started_at = time.perf_counter()
        method = str(scope.get("method") or "GET").upper()

        if token_match:
            version, principal, filter_mode, rest = (
                token_match.group(1),
                token_match.group(2),
                token_match.group(3),
                token_match.group(4),
            )
            principal_kind = "token"
        else:
            assert provider_match is not None
            version, principal, filter_mode, rest = (
                provider_match.group(1),
                provider_match.group(2),
                provider_match.group(3),
                provider_match.group(4),
            )
            principal_kind = "provider"

        # Validate filter_mode suffix
        if filter_mode and filter_mode not in _VALID_FILTER_MODES:
            with trace_span(
                "gateway.request",
                http_method=method,
                http_route=route_label,
            ) as span:
                response = JSONResponse(
                    status_code=400,
                    content={
                        "error": "invalid_filter_mode",
                        "detail": f"unknown mode '{filter_mode}', valid: {sorted(_VALID_FILTER_MODES)}",
                    },
                )
                _record_request_observability(
                    method=method,
                    route_label=route_label,
                    started_at=started_at,
                    status_code=response.status_code,
                    reject_reason="invalid_filter_mode",
                    span=span,
                )
                await response(scope, receive, send)
                return

        mapping: dict[str, Any] | None = None
        provider_headers: dict[str, str] = {}
        if principal_kind == "token":
            mapping = gw_tokens_get(principal)
            if not mapping:
                logger.warning("gw_token not found token=%s path=%s", principal, path)
                with trace_span(
                    "gateway.request",
                    http_method=method,
                    http_route=route_label,
                ) as span:
                    response = JSONResponse(
                        status_code=404,
                        content={
                            "error": "token_not_found",
                            "detail": "token invalid or expired",
                        },
                    )
                    _record_request_observability(
                        method=method,
                        route_label=route_label,
                        started_at=started_at,
                        status_code=response.status_code,
                        reject_reason="token_not_found",
                        span=span,
                    )
                    await response(scope, receive, send)
                    return
        else:
            try:
                base, provider_headers = resolve_provider_route(principal)
                mapping = {"upstream_base": base, "whitelist_key": []}
            except KeyError:
                with trace_span(
                    "gateway.request",
                    http_method=method,
                    http_route=route_label,
                ) as span:
                    response = JSONResponse(
                        status_code=404,
                        content={"error": "provider_not_found", "detail": "unknown upstream provider id"},
                    )
                    _record_request_observability(
                        method=method,
                        route_label=route_label,
                        started_at=started_at,
                        status_code=response.status_code,
                        reject_reason="provider_not_found",
                        span=span,
                    )
                    await response(scope, receive, send)
                    return
            except PermissionError as exc:
                with trace_span(
                    "gateway.request",
                    http_method=method,
                    http_route=route_label,
                ) as span:
                    response = JSONResponse(
                        status_code=403,
                        content={"error": str(exc), "detail": "provider is disabled or restricted"},
                    )
                    _record_request_observability(
                        method=method,
                        route_label=route_label,
                        started_at=started_at,
                        status_code=response.status_code,
                        reject_reason=str(exc),
                        span=span,
                    )
                    await response(scope, receive, send)
                    return

        new_path = f"/{version}/{rest}" if rest else f"/{version}"
        logger.debug(
            "gw_rewrite kind=%s path=%s -> %s principal=%s… mode=%s",
            principal_kind,
            path,
            new_path,
            principal[:6],
            filter_mode or "default",
        )

        assert mapping is not None
        ub = mapping["upstream_base"]
        wk = normalize_whitelist_keys(mapping.get("whitelist_key"))
        new_scope = dict(scope)
        new_scope["path"] = new_path
        new_scope["root_path"] = ""
        new_scope["raw_path"] = new_path.encode("utf-8")
        new_scope["n4ughtyllm_gate_token_authenticated"] = True
        new_scope["n4ughtyllm_gate_gateway_token"] = principal if principal_kind == "token" else ""
        new_scope["n4ughtyllm_gate_provider_id"] = principal if principal_kind == "provider" else ""
        new_scope["n4ughtyllm_gate_upstream_base"] = ub
        if provider_headers:
            new_scope["n4ughtyllm_gate_upstream_headers"] = provider_headers
        new_scope["n4ughtyllm_gate_redaction_whitelist_keys"] = wk
        new_scope["n4ughtyllm_gate_filter_mode"] = filter_mode  # None | "redact" | "passthrough"

        headers = list(new_scope.get("headers") or [])
        ub_name = settings.upstream_base_header.encode("latin-1")
        gk_name = settings.gateway_key_header.encode("latin-1")
        rk_name = b"x-n4ughtyllm-gate-redaction-whitelist"
        ub_alt = settings.upstream_base_header.replace("-", "_").encode("latin-1")
        gk_alt = settings.gateway_key_header.replace("-", "_").encode("latin-1")
        skip = (
            ub_name.lower(),
            gk_name.lower(),
            rk_name.lower(),
            ub_alt.lower(),
            gk_alt.lower(),
        )
        headers = [(k, v) for k, v in headers if k.lower() not in skip]
        new_scope["headers"] = headers

        await self.app(new_scope, receive, send)


# ---------------------------------------------------------------------------
# Security boundary middleware
# ---------------------------------------------------------------------------


async def _drain_and_reject(
    request: Request,
    boundary: dict[str, object],
    reason: str,
    status_code: int,
    detail: str | None = None,
) -> JSONResponse:
    """Consume request body (prevent Starlette warnings) and return a blocked response."""
    await request.body()
    boundary["rejected_reason"] = reason
    return _blocked_response(status_code=status_code, reason=reason, detail=detail)


@app.middleware("http")
async def security_boundary_middleware(request: Request, call_next):
    boundary: dict[str, object] = {
        "loopback_only": settings.enforce_loopback_only,
        "auth_required": settings.enable_request_hmac_auth,
        "auth_verified": False,
        "replay_checked": False,
        "max_request_body_bytes": settings.max_request_body_bytes,
    }
    request.state.security_boundary = boundary
    route_label = _observability_route_label(request.url.path)
    started_at = time.perf_counter()
    method = request.method.upper()

    with trace_span(
        "gateway.request",
        http_method=method,
        http_route=route_label,
    ) as span:

        def finish(response: Response) -> Response:
            reject_reason = boundary.get("rejected_reason")
            return _observe_response(
                response,
                method=method,
                route_label=route_label,
                started_at=started_at,
                reject_reason=reject_reason if isinstance(reject_reason, str) else None,
                span=span,
            )

        async def finish_drain(
            reason: str,
            status_code: int,
            detail: str | None = None,
        ) -> Response:
            response = await _drain_and_reject(
                request,
                boundary,
                reason,
                status_code,
                detail,
            )
            return finish(response)

        if request.url.path.startswith("/__ui__"):
            client_ip = _real_client_ip(request)
            ui_allowed = (
                _is_internal_ip(client_ip)
                if settings.local_ui_allow_internal_network
                else _is_loopback_ip(client_ip)
            )
            if not ui_allowed:
                boundary["rejected_reason"] = "local_ui_network_restricted"
                logger.warning(
                    "boundary reject local ui host=%s path=%s",
                    client_ip,
                    request.url.path,
                )
                detail = (
                    "local ui only allowed from internal network"
                    if settings.local_ui_allow_internal_network
                    else "local ui only allowed from loopback"
                )
                return finish(
                    _apply_ui_security_headers(
                        _blocked_response(
                            status_code=403,
                            reason="local_ui_network_restricted",
                            detail=detail,
                        )
                    )
                )
            if request.url.path == "/__ui__/api/login" and method == "POST":
                if not _UI_LOGIN_RATE_LIMITER.is_allowed(client_ip):
                    boundary["rejected_reason"] = "ui_login_rate_limited"
                    return finish(
                        _apply_ui_security_headers(
                            JSONResponse(
                                status_code=429,
                                content={
                                    "error": "ui_login_rate_limited",
                                    "detail": "too many login attempts",
                                },
                            )
                        )
                    )
            if _is_public_ui_path(request.url.path):
                response = await call_next(request)
                return finish(_apply_ui_security_headers(response))
            if not _is_ui_authenticated(request):
                boundary["rejected_reason"] = "ui_auth_required"
                if request.url.path.startswith("/__ui__/api/"):
                    return finish(
                        _apply_ui_security_headers(
                            JSONResponse(
                                status_code=401,
                                content={"error": "ui_auth_required"},
                            )
                        )
                    )
                from fastapi.responses import RedirectResponse

                return finish(
                    _apply_ui_security_headers(
                        RedirectResponse(url="/__ui__/login", status_code=303)
                    )
                )
            if method not in {"GET", "HEAD", "OPTIONS"} and request.url.path.startswith(
                "/__ui__/api/"
            ):
                if request.url.path != "/__ui__/api/login" and not _verify_ui_csrf(
                    request
                ):
                    boundary["rejected_reason"] = "ui_csrf_invalid"
                    return finish(
                        _apply_ui_security_headers(
                            JSONResponse(
                                status_code=403,
                                content={
                                    "error": "ui_csrf_invalid",
                                    "detail": "missing or invalid csrf token",
                                },
                            )
                        )
                    )
            response = await call_next(request)
            return finish(_apply_ui_security_headers(response))

        if request.url.path in _PASSTHROUGH_PATHS and method in {"GET", "HEAD"}:
            return finish(await call_next(request))

        logger.debug(
            "boundary enter method=%s path=%s", request.method, request.url.path
        )

        if settings.enforce_loopback_only:
            client_host = request.client.host if request.client else ""
            if client_host not in _LOOPBACK_HOSTS:
                logger.warning(
                    "boundary reject non-loopback host=%s path=%s",
                    client_host,
                    request.url.path,
                )
                return await finish_drain("loopback_only_reject", 403)

        is_admin_api = (
            request.url.path in _ADMIN_ENDPOINTS
            or request.url.path.startswith("/__gw__/providers")
            or request.url.path.startswith("/__gw__/routing")
            or request.url.path.startswith("/__gw__/circuit")
        )
        if is_admin_api and method in {"POST", "PUT", "PATCH", "DELETE", "GET"}:
            client_ip = _real_client_ip(request)
            if not _admin_rate_limiter.is_allowed(client_ip):
                logger.warning(
                    "boundary reject admin rate limit host=%s path=%s",
                    client_ip,
                    request.url.path,
                )
                return await finish_drain(
                    "admin_rate_limited",
                    429,
                    "too many requests",
                )
            if not _is_internal_ip(client_ip):
                logger.warning(
                    "boundary reject admin endpoint from non-internal host=%s path=%s",
                    client_ip,
                    request.url.path,
                )
                return await finish_drain(
                    "admin_endpoint_network_restricted",
                    403,
                    "admin endpoint only allowed from internal network",
                )

        if not bool(request.scope.get("n4ughtyllm_gate_token_authenticated")):
            provider_header = (request.headers.get("x-n4ughtyllm-gate-provider") or "").strip()
            if provider_header:
                model_hint = (request.headers.get("x-n4ughtyllm-gate-model") or "").strip()
                try:
                    resolved_base, provider_headers = resolve_provider_route(
                        provider_id=provider_header, model=model_hint
                    )
                    request.scope["n4ughtyllm_gate_upstream_base"] = resolved_base
                    request.scope["n4ughtyllm_gate_upstream_headers"] = provider_headers
                    request.scope["n4ughtyllm_gate_provider_id"] = provider_header
                    request.scope["n4ughtyllm_gate_token_authenticated"] = True
                except KeyError:
                    return await finish_drain(
                        "provider_not_found",
                        404,
                        "unknown upstream provider id",
                    )
                except PermissionError as exc:
                    return await finish_drain(
                        str(exc),
                        403,
                        "provider is disabled or model is not allowed",
                    )

        protected_v1 = request.url.path == "/v1" or request.url.path.startswith("/v1/")
        protected_v2 = request.url.path == "/v2" or request.url.path.startswith("/v2/")

        if not bool(request.scope.get("n4ughtyllm_gate_token_authenticated")) and (
            protected_v1 or protected_v2
        ):
            proxy_token = (request.headers.get(_PROXY_TOKEN_HEADER) or "").strip()
            proxy_token_value = get_proxy_token_value()
            if (
                proxy_token
                and proxy_token_value
                and hmac.compare_digest(proxy_token, proxy_token_value)
            ):
                default_base = (settings.upstream_base_url or "").strip()
                if default_base:
                    request.scope["n4ughtyllm_gate_upstream_base"] = default_base
                    request.scope["n4ughtyllm_gate_token_authenticated"] = True
                    boundary["auth_verified"] = True

        if protected_v1 and not bool(request.scope.get("n4ughtyllm_gate_token_authenticated")):
            default_base = (settings.upstream_base_url or "").strip()
            if default_base:
                request.scope["n4ughtyllm_gate_upstream_base"] = default_base
                request.scope["n4ughtyllm_gate_token_authenticated"] = True
                logger.debug("using default upstream for v1 path=%s", request.url.path)
            else:
                model_hint = await _extract_model_hint_from_body(request)
                try:
                    (
                        routed_provider_id,
                        routed_base,
                        routed_headers,
                        routing_meta,
                    ) = resolve_provider_for_model_group(
                        model=model_hint,
                        tenant_id="default",
                        request_id=(request.headers.get("x-n4ughtyllm-gate-request-id") or "").strip(),
                    )
                    request.scope["n4ughtyllm_gate_upstream_base"] = routed_base
                    request.scope["n4ughtyllm_gate_upstream_headers"] = routed_headers
                    request.scope["n4ughtyllm_gate_provider_id"] = routed_provider_id
                    request.scope["n4ughtyllm_gate_token_authenticated"] = True
                    request.scope["n4ughtyllm_gate_routing_group_id"] = routing_meta.get("group_id")
                    request.scope["n4ughtyllm_gate_routing_strategy"] = routing_meta.get("strategy")
                    logger.info(
                        "policy routing selected provider=%s model=%s group=%s strategy=%s path=%s",
                        routed_provider_id,
                        model_hint or "(empty)",
                        routing_meta.get("group_id"),
                        routing_meta.get("strategy"),
                        request.url.path,
                    )
                except KeyError:
                    pass
            if not bool(request.scope.get("n4ughtyllm_gate_token_authenticated")):
                client_ip = _real_client_ip(request)
                logger.warning(
                    "boundary reject non-token request path=%s client=%s hint=set N4UGHTYLLM_GATE_UPSTREAM_BASE_URL or use token path",
                    request.url.path,
                    client_ip,
                )
                return await finish_drain(
                    "token_route_required",
                    403,
                    "no default upstream configured; use /v1/__gw__/t/<token>/... or set N4UGHTYLLM_GATE_UPSTREAM_BASE_URL",
                )

        if protected_v2 and not bool(request.scope.get("n4ughtyllm_gate_token_authenticated")):
            logger.warning(
                "boundary reject non-token v2 request path=%s", request.url.path
            )
            return await finish_drain(
                "token_route_required",
                403,
                "use /v2/__gw__/t/<token>/... routes for v2 proxy access",
            )

        cached_body: bytes | None = None
        content_length_header = request.headers.get("content-length", "").strip()
        if (
            settings.max_request_body_bytes > 0
            and method in {"POST", "PUT", "PATCH"}
            and content_length_header
        ):
            try:
                content_length = int(content_length_header)
            except ValueError:
                logger.warning(
                    "boundary reject invalid content-length path=%s", request.url.path
                )
                return await finish_drain("invalid_content_length", 400)
            if content_length > settings.max_request_body_bytes:
                logger.warning(
                    "boundary reject oversize request content_length=%s max=%s path=%s",
                    content_length,
                    settings.max_request_body_bytes,
                    request.url.path,
                )
                return await finish_drain("request_body_too_large", 413)
            boundary["request_body_size"] = content_length
        elif settings.max_request_body_bytes > 0 and method in {"POST", "PUT", "PATCH"}:
            cached_body = await request.body()
            boundary["request_body_size"] = len(cached_body)
            if len(cached_body) > settings.max_request_body_bytes:
                boundary["rejected_reason"] = "request_body_too_large"
                logger.warning(
                    "boundary reject oversize request actual_size=%s max=%s path=%s",
                    len(cached_body),
                    settings.max_request_body_bytes,
                    request.url.path,
                )
                return finish(
                    _blocked_response(status_code=413, reason="request_body_too_large")
                )

        if settings.enable_request_hmac_auth:
            secret = settings.request_hmac_secret
            if not secret:
                logger.error("request hmac auth enabled but secret is empty")
                boundary["rejected_reason"] = "hmac_misconfigured"
                return finish(
                    _blocked_response(status_code=500, reason="hmac_misconfigured")
                )

            signature = request.headers.get(settings.request_signature_header)
            timestamp = request.headers.get(settings.request_timestamp_header)
            nonce = request.headers.get(settings.request_nonce_header)
            if not signature or not timestamp or not nonce:
                boundary["rejected_reason"] = "hmac_header_missing"
                return finish(
                    _blocked_response(status_code=401, reason="hmac_header_missing")
                )

            try:
                ts_int = int(timestamp)
            except ValueError:
                boundary["rejected_reason"] = "hmac_timestamp_invalid"
                return finish(
                    _blocked_response(status_code=401, reason="hmac_timestamp_invalid")
                )

            current_ts = now_ts()
            if abs(current_ts - ts_int) > settings.request_replay_window_seconds:
                boundary["rejected_reason"] = "hmac_timestamp_out_of_window"
                return finish(
                    _blocked_response(
                        status_code=401,
                        reason="hmac_timestamp_out_of_window",
                    )
                )

            replayed = _nonce_cache.check_and_store(
                nonce=nonce,
                now_ts=current_ts,
                window_seconds=settings.request_replay_window_seconds,
            )
            boundary["replay_checked"] = True
            if replayed:
                boundary["rejected_reason"] = "replay_nonce_detected"
                return finish(
                    _blocked_response(status_code=409, reason="replay_nonce_detected")
                )

            body = cached_body if cached_body is not None else await request.body()
            boundary["request_body_size"] = len(body)
            payload = build_signature_payload(
                timestamp=timestamp,
                nonce=nonce,
                body=body,
            )
            if not verify_hmac_signature(
                secret=secret,
                payload=payload,
                presented=signature,
            ):
                boundary["rejected_reason"] = "hmac_signature_invalid"
                return finish(
                    _blocked_response(status_code=401, reason="hmac_signature_invalid")
                )

            boundary["auth_verified"] = True
            logger.info("boundary hmac verified path=%s", request.url.path)

        try:
            response = await call_next(request)
        except Exception:  # pragma: no cover - fail-safe
            logger.exception("gateway unhandled exception path=%s", request.url.path)
            boundary["rejected_reason"] = "gateway_internal_error"
            return finish(
                _blocked_response(
                    status_code=500,
                    reason="gateway_internal_error",
                    detail="an internal error occurred",
                )
            )
        if boundary.get("auth_verified"):
            response.headers["x-n4ughtyllm-gate-auth-verified"] = "true"
        logger.debug(
            "boundary pass method=%s path=%s auth_verified=%s",
            request.method,
            request.url.path,
            bool(boundary.get("auth_verified")),
        )
        return finish(response)


# ---------------------------------------------------------------------------
# Admin API endpoints (register / add / remove / lookup / unregister)
# ---------------------------------------------------------------------------


@app.post("/__gw__/register")
async def gw_register(request: Request) -> JSONResponse:
    """One-shot register: return short token and baseUrl; persist to config/gw_tokens.json."""
    try:
        body = await request.json()
    except (ValueError, TypeError):
        return JSONResponse(status_code=400, content={"error": "invalid_json"})
    upstream_base = _normalize_input_upstream_base(body.get("upstream_base"))
    gateway_key = _string_field(body.get("gateway_key"))
    whitelist_present = "whitelist_key" in body
    requested_whitelist = (
        normalize_whitelist_keys(body.get("whitelist_key"))
        if whitelist_present
        else None
    )
    if not upstream_base or not gateway_key:
        return JSONResponse(
            status_code=400,
            content={
                "error": "missing_params",
                "detail": "upstream_base and gateway_key required",
            },
        )
    if not _verify_admin_gateway_key(body):
        logger.warning("register rejected: gateway_key mismatch")
        return JSONResponse(
            status_code=403,
            content={
                "error": "gateway_key_invalid",
                "detail": "gateway_key does not match the configured key",
            },
        )
    if _is_forbidden_upstream_base_example(upstream_base):
        return JSONResponse(
            status_code=400,
            content={
                "error": "example_upstream_forbidden",
                "detail": "upstream_base cannot be a documentation example URL; set your real upstream and retry.",
            },
        )
    if whitelist_present:
        token, already_registered = gw_tokens_register(
            upstream_base, whitelist_key=requested_whitelist
        )
    else:
        token, already_registered = gw_tokens_register(upstream_base)
    stored = gw_tokens_get(token) or {}
    effective_whitelist = (
        normalize_whitelist_keys(stored.get("whitelist_key"))
        if stored
        else (requested_whitelist or [])
    )
    base_url = _gateway_token_base_url(request, token)
    if already_registered:
        return JSONResponse(
            content={
                "already_registered": True,
                "detail": "This upstream_base is already registered; returning the existing token.",
                "token": token,
                "baseUrl": base_url,
                "whitelist_key": effective_whitelist,
            }
        )
    return JSONResponse(
        content={
            "token": token,
            "baseUrl": base_url,
            "whitelist_key": effective_whitelist,
        }
    )


@app.post("/__gw__/add")
async def gw_add(request: Request) -> JSONResponse:
    """Append whitelist_key to a token; optionally replace upstream_base."""
    try:
        body = await request.json()
    except (ValueError, TypeError):
        return JSONResponse(status_code=400, content={"error": "invalid_json"})
    token = _string_field(body.get("token"))
    gateway_key = _string_field(body.get("gateway_key"))
    whitelist_add = _normalize_required_whitelist_list(body.get("whitelist_key"))
    if not token or not gateway_key or whitelist_add is None or not whitelist_add:
        return JSONResponse(
            status_code=400,
            content={
                "error": "missing_params",
                "detail": "token, gateway_key and whitelist_key(list) required",
            },
        )
    if not _verify_admin_gateway_key(body):
        return JSONResponse(
            status_code=403,
            content={
                "error": "gateway_key_invalid",
                "detail": "gateway_key does not match",
            },
        )
    upstream_base_input = _normalize_input_upstream_base(body.get("upstream_base"))
    mapping = gw_tokens_get(token)
    if not mapping:
        return JSONResponse(status_code=404, content={"error": "token_not_found"})
    current_upstream_base = _normalize_input_upstream_base(mapping.get("upstream_base"))
    next_upstream_base = current_upstream_base
    if upstream_base_input:
        if _is_forbidden_upstream_base_example(upstream_base_input):
            return JSONResponse(
                status_code=400,
                content={
                    "error": "example_upstream_forbidden",
                    "detail": "upstream_base cannot be a documentation example URL; set your real upstream and retry.",
                },
            )
        existing = gw_tokens_find_token(upstream_base_input)
        if existing is not None and existing != token:
            return JSONResponse(
                status_code=409,
                content={
                    "error": "upstream_pair_conflict",
                    "detail": "target upstream_base already bound",
                },
            )
        next_upstream_base = upstream_base_input
    current = normalize_whitelist_keys(mapping.get("whitelist_key"))
    current_set = set(current)
    added = [k for k in whitelist_add if k not in current_set]
    next_whitelist = current + added
    updated = gw_tokens_update(
        token, upstream_base=next_upstream_base, whitelist_key=next_whitelist
    )
    if not updated:
        return JSONResponse(status_code=404, content={"error": "token_not_found"})
    latest = (gw_tokens_get(token) or {}).get("whitelist_key", current)
    base_url = _gateway_token_base_url(request, token)
    return JSONResponse(
        content={
            "token": token,
            "upstream_base": next_upstream_base,
            "baseUrl": base_url,
            "whitelist_key": normalize_whitelist_keys(latest),
            "added": added,
        }
    )


@app.post("/__gw__/remove")
async def gw_remove(request: Request) -> JSONResponse:
    """Remove whitelist_key entries for a token."""
    try:
        body = await request.json()
    except (ValueError, TypeError):
        return JSONResponse(status_code=400, content={"error": "invalid_json"})
    token = _string_field(body.get("token"))
    gateway_key = _string_field(body.get("gateway_key"))
    whitelist_remove = _normalize_required_whitelist_list(body.get("whitelist_key"))
    if not token or not gateway_key or whitelist_remove is None or not whitelist_remove:
        return JSONResponse(
            status_code=400,
            content={
                "error": "missing_params",
                "detail": "token, gateway_key and whitelist_key(list) required",
            },
        )
    if not _verify_admin_gateway_key(body):
        return JSONResponse(
            status_code=403,
            content={
                "error": "gateway_key_invalid",
                "detail": "gateway_key does not match",
            },
        )
    mapping = gw_tokens_get(token)
    if not mapping:
        return JSONResponse(status_code=404, content={"error": "token_not_found"})
    upstream_base = _normalize_input_upstream_base(mapping.get("upstream_base"))
    current = normalize_whitelist_keys(mapping.get("whitelist_key"))
    remove_set = set(whitelist_remove)
    removed = [k for k in current if k in remove_set]
    next_whitelist = [k for k in current if k not in remove_set]
    updated = gw_tokens_update(
        token, upstream_base=upstream_base, whitelist_key=next_whitelist
    )
    if not updated:
        return JSONResponse(status_code=404, content={"error": "token_not_found"})
    latest = (gw_tokens_get(token) or {}).get("whitelist_key", current)
    base_url = _gateway_token_base_url(request, token)
    return JSONResponse(
        content={
            "token": token,
            "baseUrl": base_url,
            "whitelist_key": normalize_whitelist_keys(latest),
            "removed": removed,
        }
    )


@app.post("/__gw__/lookup")
async def gw_lookup(request: Request) -> JSONResponse:
    """Look up the token registered for an upstream_base."""
    try:
        body = await request.json()
    except (ValueError, TypeError):
        return JSONResponse(status_code=400, content={"error": "invalid_json"})
    upstream_base = _normalize_input_upstream_base(body.get("upstream_base"))
    gateway_key = _string_field(body.get("gateway_key"))
    if not upstream_base or not gateway_key:
        return JSONResponse(
            status_code=400,
            content={
                "error": "missing_params",
                "detail": "upstream_base and gateway_key required",
            },
        )
    if not _verify_admin_gateway_key(body):
        return JSONResponse(
            status_code=403,
            content={
                "error": "gateway_key_invalid",
                "detail": "gateway_key does not match",
            },
        )
    if _is_forbidden_upstream_base_example(upstream_base):
        return JSONResponse(
            status_code=400,
            content={
                "error": "example_upstream_forbidden",
                "detail": "upstream_base cannot be a documentation example URL.",
            },
        )
    token = gw_tokens_find_token(upstream_base)
    if token is None:
        return JSONResponse(
            status_code=404,
            content={
                "error": "not_found",
                "detail": "This upstream_base is not registered; call /__gw__/register first.",
            },
        )
    base_url = _gateway_token_base_url(request, token)
    mapping = gw_tokens_get(token) or {}
    whitelist_key = normalize_whitelist_keys(mapping.get("whitelist_key"))
    return JSONResponse(
        content={"token": token, "baseUrl": base_url, "whitelist_key": whitelist_key}
    )


@app.post("/__gw__/unregister")
async def gw_unregister(request: Request) -> JSONResponse:
    """Delete a token mapping."""
    try:
        body = await request.json()
    except (ValueError, TypeError):
        return JSONResponse(status_code=400, content={"error": "invalid_json"})
    token = _string_field(body.get("token"))
    gateway_key = _string_field(body.get("gateway_key"))
    if not token or not gateway_key:
        return JSONResponse(
            status_code=400,
            content={
                "error": "missing_params",
                "detail": "token and gateway_key required",
            },
        )
    if not _verify_admin_gateway_key(body):
        return JSONResponse(
            status_code=403,
            content={
                "error": "gateway_key_invalid",
                "detail": "gateway_key does not match",
            },
        )
    mapping = gw_tokens_get(token)
    if not mapping:
        return JSONResponse(status_code=404, content={"error": "token_not_found"})
    if gw_tokens_unregister(token):
        return JSONResponse(content={"ok": True, "message": "token removed"})
    return JSONResponse(status_code=404, content={"error": "token_not_found"})


def _provider_payload_from_body(body: dict[str, Any]) -> dict[str, Any]:
    default_headers = body.get("default_headers")
    if not isinstance(default_headers, dict):
        default_headers = {}
    model_allowlist = body.get("model_allowlist")
    if not isinstance(model_allowlist, list):
        model_allowlist = []
    metadata = body.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    try:
        priority = int(body.get("priority") or 100)
    except (TypeError, ValueError):
        priority = 100
    try:
        timeout_seconds = float(body.get("timeout_seconds") or settings.upstream_timeout_seconds)
    except (TypeError, ValueError):
        timeout_seconds = float(settings.upstream_timeout_seconds)
    return {
        "provider_id": _string_field(body.get("provider_id")),
        "display_name": _string_field(body.get("display_name")),
        "upstream_base": _normalize_input_upstream_base(body.get("upstream_base")),
        "api_type": _string_field(body.get("api_type")) or "openai",
        "enabled": bool(body.get("enabled", True)),
        "priority": priority,
        "timeout_seconds": timeout_seconds,
        "health_path": _string_field(body.get("health_path")) or "/models",
        "default_headers": {str(k): str(v) for k, v in default_headers.items() if str(k).strip()},
        "model_allowlist": [str(x).strip() for x in model_allowlist if str(x).strip()],
        "metadata": metadata,
        "api_key": body.get("api_key"),
        "auth_mode": _string_field(body.get("auth_mode")) or "bearer",
        "auth_header_name": _string_field(body.get("auth_header_name")) or "authorization",
    }


def _routing_policy_payload_from_body(body: dict[str, Any]) -> dict[str, Any]:
    providers_raw = body.get("providers")
    providers: list[dict[str, Any]] = []
    if isinstance(providers_raw, list):
        for item in providers_raw:
            if not isinstance(item, dict):
                continue
            try:
                weight = int(item.get("weight") or 1)
            except (TypeError, ValueError):
                weight = 1
            try:
                priority = int(item.get("priority") or 100)
            except (TypeError, ValueError):
                priority = 100
            providers.append(
                {
                    "provider_id": _string_field(item.get("provider_id")),
                    "weight": max(1, weight),
                    "priority": max(0, priority),
                }
            )
    patterns_raw = body.get("model_patterns")
    model_patterns = [str(x).strip() for x in patterns_raw if str(x).strip()] if isinstance(patterns_raw, list) else ["*"]
    metadata = body.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    return {
        "group_id": _string_field(body.get("group_id")),
        "model_patterns": model_patterns,
        "strategy": _string_field(body.get("strategy")) or "failover",
        "providers": providers,
        "enabled": bool(body.get("enabled", True)),
        "metadata": metadata,
    }


async def _extract_model_hint_from_body(request: Request) -> str:
    if request.method.upper() not in {"POST", "PUT", "PATCH"}:
        return ""
    content_type = (request.headers.get("content-type") or "").lower()
    if "application/json" not in content_type:
        return ""
    try:
        raw = await request.body()
    except Exception:
        return ""
    if not raw:
        return ""
    try:
        parsed = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return ""
    if not isinstance(parsed, dict):
        return ""
    model = parsed.get("model")
    if isinstance(model, str):
        return model.strip()
    target_model = parsed.get("target_model")
    if isinstance(target_model, str):
        return target_model.strip()
    return ""


@app.get("/__gw__/providers")
async def gw_list_providers(request: Request) -> JSONResponse:
    gateway_key = _string_field(request.headers.get(settings.gateway_key_header))
    if not gateway_key:
        gateway_key = _string_field(request.query_params.get("gateway_key"))
    if not _verify_admin_gateway_key({"gateway_key": gateway_key}):
        return JSONResponse(
            status_code=403,
            content={"error": "gateway_key_invalid", "detail": "gateway_key does not match"},
        )
    include_disabled = str(request.query_params.get("include_disabled", "true")).strip().lower() not in {"0", "false", "no"}
    return JSONResponse(content={"providers": list_providers(include_disabled=include_disabled)})


@app.post("/__gw__/providers")
async def gw_upsert_provider(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except (TypeError, ValueError):
        return JSONResponse(status_code=400, content={"error": "invalid_json"})
    if not _verify_admin_gateway_key(body):
        return JSONResponse(
            status_code=403,
            content={"error": "gateway_key_invalid", "detail": "gateway_key does not match"},
        )
    payload = _provider_payload_from_body(body)
    if not payload["provider_id"] or not payload["upstream_base"]:
        return JSONResponse(
            status_code=400,
            content={"error": "missing_params", "detail": "provider_id and upstream_base are required"},
        )
    if _is_forbidden_upstream_base_example(payload["upstream_base"]):
        return JSONResponse(
            status_code=400,
            content={
                "error": "example_upstream_forbidden",
                "detail": "upstream_base cannot be a documentation example URL; set your real upstream and retry.",
            },
        )
    try:
        provider = upsert_provider(**payload)
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": "provider_persist_failed", "detail": str(exc)})
    return JSONResponse(content={"provider": provider})


@app.get("/__gw__/providers/{provider_id}")
async def gw_get_provider(provider_id: str, request: Request) -> JSONResponse:
    gateway_key = _string_field(request.headers.get(settings.gateway_key_header))
    if not gateway_key:
        gateway_key = _string_field(request.query_params.get("gateway_key"))
    if not _verify_admin_gateway_key({"gateway_key": gateway_key}):
        return JSONResponse(
            status_code=403,
            content={"error": "gateway_key_invalid", "detail": "gateway_key does not match"},
        )
    provider = get_provider(provider_id)
    if not provider:
        return JSONResponse(status_code=404, content={"error": "provider_not_found"})
    return JSONResponse(content={"provider": provider})


@app.delete("/__gw__/providers/{provider_id}")
async def gw_delete_provider(provider_id: str, request: Request) -> JSONResponse:
    gateway_key = _string_field(request.headers.get(settings.gateway_key_header))
    if not gateway_key:
        gateway_key = _string_field(request.query_params.get("gateway_key"))
    if not _verify_admin_gateway_key({"gateway_key": gateway_key}):
        return JSONResponse(
            status_code=403,
            content={"error": "gateway_key_invalid", "detail": "gateway_key does not match"},
        )
    if not delete_provider(provider_id):
        return JSONResponse(status_code=404, content={"error": "provider_not_found"})
    return JSONResponse(content={"ok": True})


@app.get("/__gw__/providers/{provider_id}/health")
async def gw_provider_health(provider_id: str, request: Request) -> JSONResponse:
    gateway_key = _string_field(request.headers.get(settings.gateway_key_header))
    if not gateway_key:
        gateway_key = _string_field(request.query_params.get("gateway_key"))
    if not _verify_admin_gateway_key({"gateway_key": gateway_key}):
        return JSONResponse(
            status_code=403,
            content={"error": "gateway_key_invalid", "detail": "gateway_key does not match"},
        )
    try:
        status = await check_provider_health(provider_id)
    except KeyError:
        return JSONResponse(status_code=404, content={"error": "provider_not_found"})
    return JSONResponse(content=status)


@app.get("/__gw__/routing-policies")
async def gw_list_routing_policies(request: Request) -> JSONResponse:
    gateway_key = _string_field(request.headers.get(settings.gateway_key_header))
    if not gateway_key:
        gateway_key = _string_field(request.query_params.get("gateway_key"))
    if not _verify_admin_gateway_key({"gateway_key": gateway_key}):
        return JSONResponse(
            status_code=403,
            content={"error": "gateway_key_invalid", "detail": "gateway_key does not match"},
        )
    include_disabled = str(request.query_params.get("include_disabled", "true")).strip().lower() not in {"0", "false", "no"}
    return JSONResponse(content={"model_groups": list_model_group_policies(include_disabled=include_disabled)})


@app.post("/__gw__/routing-policies")
async def gw_upsert_routing_policy(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except (TypeError, ValueError):
        return JSONResponse(status_code=400, content={"error": "invalid_json"})
    if not _verify_admin_gateway_key(body):
        return JSONResponse(
            status_code=403,
            content={"error": "gateway_key_invalid", "detail": "gateway_key does not match"},
        )
    payload = _routing_policy_payload_from_body(body)
    if not payload["group_id"] or not payload["providers"]:
        return JSONResponse(
            status_code=400,
            content={"error": "missing_params", "detail": "group_id and providers are required"},
        )
    try:
        policy = upsert_model_group_policy(**payload)
    except KeyError as exc:
        return JSONResponse(status_code=400, content={"error": "providers_not_found", "detail": str(exc)})
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": "routing_policy_persist_failed", "detail": str(exc)})
    return JSONResponse(content={"model_group": policy})


@app.get("/__gw__/routing-policies/{group_id}")
async def gw_get_routing_policy(group_id: str, request: Request) -> JSONResponse:
    gateway_key = _string_field(request.headers.get(settings.gateway_key_header))
    if not gateway_key:
        gateway_key = _string_field(request.query_params.get("gateway_key"))
    if not _verify_admin_gateway_key({"gateway_key": gateway_key}):
        return JSONResponse(
            status_code=403,
            content={"error": "gateway_key_invalid", "detail": "gateway_key does not match"},
        )
    policy = get_model_group_policy(group_id)
    if not policy:
        return JSONResponse(status_code=404, content={"error": "model_group_not_found"})
    return JSONResponse(content={"model_group": policy})


@app.delete("/__gw__/routing-policies/{group_id}")
async def gw_delete_routing_policy(group_id: str, request: Request) -> JSONResponse:
    gateway_key = _string_field(request.headers.get(settings.gateway_key_header))
    if not gateway_key:
        gateway_key = _string_field(request.query_params.get("gateway_key"))
    if not _verify_admin_gateway_key({"gateway_key": gateway_key}):
        return JSONResponse(
            status_code=403,
            content={"error": "gateway_key_invalid", "detail": "gateway_key does not match"},
        )
    if not delete_model_group_policy(group_id):
        return JSONResponse(status_code=404, content={"error": "model_group_not_found"})
    return JSONResponse(content={"ok": True})


@app.get("/__gw__/circuit")
async def gw_list_circuit_states(request: Request) -> JSONResponse:
    gateway_key = _string_field(request.headers.get(settings.gateway_key_header))
    if not gateway_key:
        gateway_key = _string_field(request.query_params.get("gateway_key"))
    if not _verify_admin_gateway_key({"gateway_key": gateway_key}):
        return JSONResponse(
            status_code=403,
            content={"error": "gateway_key_invalid", "detail": "gateway_key does not match"},
        )
    return JSONResponse(content={"circuit_states": list_provider_health_states()})


@app.get("/__gw__/circuit/{provider_id}")
async def gw_get_circuit_state(provider_id: str, request: Request) -> JSONResponse:
    gateway_key = _string_field(request.headers.get(settings.gateway_key_header))
    if not gateway_key:
        gateway_key = _string_field(request.query_params.get("gateway_key"))
    if not _verify_admin_gateway_key({"gateway_key": gateway_key}):
        return JSONResponse(
            status_code=403,
            content={"error": "gateway_key_invalid", "detail": "gateway_key does not match"},
        )
    state = get_provider_health_state(provider_id)
    if state is None:
        return JSONResponse(status_code=404, content={"error": "provider_not_found"})
    return JSONResponse(content={"circuit_state": state})


@app.post("/__gw__/circuit/{provider_id}/reset")
async def gw_reset_circuit(provider_id: str, request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except (TypeError, ValueError):
        body = {}
    if not _verify_admin_gateway_key(body):
        gateway_key = _string_field(request.headers.get(settings.gateway_key_header))
        if not gateway_key or not _verify_admin_gateway_key({"gateway_key": gateway_key}):
            return JSONResponse(
                status_code=403,
                content={"error": "gateway_key_invalid", "detail": "gateway_key does not match"},
            )
    if not reset_provider_circuit(provider_id):
        return JSONResponse(status_code=404, content={"error": "provider_not_found"})
    state = get_provider_health_state(provider_id) or {}
    return JSONResponse(content={"ok": True, "circuit_state": state})


@app.get("/__gw__/routing/resolve")
async def gw_preview_route_resolution(request: Request) -> JSONResponse:
    gateway_key = _string_field(request.headers.get(settings.gateway_key_header))
    if not gateway_key:
        gateway_key = _string_field(request.query_params.get("gateway_key"))
    if not _verify_admin_gateway_key({"gateway_key": gateway_key}):
        return JSONResponse(
            status_code=403,
            content={"error": "gateway_key_invalid", "detail": "gateway_key does not match"},
        )
    model = _string_field(request.query_params.get("model"))
    request_id = _string_field(request.query_params.get("request_id"))
    try:
        provider_id, upstream_base, _headers, meta = resolve_provider_for_model_group(
            model=model,
            tenant_id="default",
            request_id=request_id,
        )
    except KeyError:
        return JSONResponse(status_code=404, content={"error": "no_policy_provider_available"})
    return JSONResponse(
        content={
            "model": model,
            "provider_id": provider_id,
            "upstream_base": upstream_base,
            "routing": meta,
            "health": get_provider_health_state(provider_id) or {},
        }
    )


# ---------------------------------------------------------------------------
# Register UI routes
# ---------------------------------------------------------------------------
register_ui_routes(app)


# Backward-compat aliases for functions that tests call directly.
def local_ui_bootstrap(request: Request) -> dict[str, object]:
    return _ui_bootstrap_payload(request)


def local_ui_index() -> Response:
    index_path = (_WWW_DIR / "index.html").resolve()
    if not index_path.is_file():
        return PlainTextResponse("local ui assets not found", status_code=404)
    from fastapi.responses import FileResponse

    return FileResponse(index_path, media_type="text/html; charset=utf-8")


# ---------------------------------------------------------------------------
# Info / health / liveness endpoints
# ---------------------------------------------------------------------------
_BOOT_TIME = time.time()


@app.get("/health")
@app.head("/health")
def health() -> dict:
    """Liveness probe — lightweight, no logging."""
    return {"status": "ok"}


@app.api_route("/", methods=["GET", "HEAD"])
def gateway_root(request: Request) -> dict:
    """Gateway info — used by Caddy / ALB health checks and humans."""
    from n4ughtyllm_gate import __version__

    routes_summary = ["/v1/*"]
    if settings.enable_v2_proxy:
        routes_summary.append("/v2/*")
    if settings.enable_relay_endpoint:
        routes_summary.append("/relay/*")
    return {
        "name": settings.app_name,
        "version": __version__,
        "status": "ok",
        "uptime_seconds": int(time.time() - _BOOT_TIME),
        "routes": routes_summary,
    }


@app.get("/robots.txt")
def robots_txt() -> PlainTextResponse:
    """Block crawlers — this is an API gateway, not a website."""
    return PlainTextResponse("User-agent: *\nDisallow: /\n", media_type="text/plain")


@app.get("/favicon.ico")
def favicon() -> Response:
    return Response(status_code=204)


# Token path rewrite runs first: ASGI middleware mutates scope.path before routing.
app.add_middleware(GWTokenRewriteMiddleware)
