"""Native upstream provider registry with encrypted credentials."""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import time
import fnmatch
import hashlib
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx

from n4ughtyllm_gate.config.settings import settings
from n4ughtyllm_gate.storage.crypto import decrypt_mapping, encrypt_mapping
from n4ughtyllm_gate.util.logger import logger

_PROVIDERS_FILE = "upstream_providers.json"
_ROUTING_FILE = "upstream_routing.json"
_LOCK = threading.Lock()
_PROVIDERS: dict[str, "UpstreamProvider"] = {}
_ROUTING_POLICIES: dict[str, "ModelRoutingPolicy"] = {}
_PROVIDER_HEALTH: dict[str, dict[str, Any]] = {}


def _normalize_provider_id(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9_-]+", "-", str(value or "").strip().lower()).strip("-")
    if not normalized:
        raise ValueError("provider_id_required")
    if len(normalized) > 64:
        raise ValueError("provider_id_too_long")
    return normalized


def _normalize_upstream_base(raw_base: str) -> str:
    candidate = str(raw_base or "").strip()
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("invalid_upstream_scheme")
    if not parsed.netloc:
        raise ValueError("invalid_upstream_host")
    if parsed.query or parsed.fragment:
        raise ValueError("invalid_upstream_query_fragment")
    cleaned_path = parsed.path.rstrip("/")
    return urlunparse((parsed.scheme, parsed.netloc, cleaned_path, "", "", ""))


def _normalize_api_type(api_type: str) -> str:
    normalized = str(api_type or "openai").strip().lower()
    if normalized not in {"openai", "anthropic", "gemini", "custom"}:
        raise ValueError("invalid_api_type")
    return normalized


def _providers_path() -> Path:
    p = Path.cwd() / "config" / _PROVIDERS_FILE
    return p.resolve()


def _routing_path() -> Path:
    p = Path.cwd() / "config" / _ROUTING_FILE
    return p.resolve()


def _safe_int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value: object, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


@dataclass(slots=True)
class UpstreamProvider:
    provider_id: str
    display_name: str
    upstream_base: str
    api_type: str = "openai"
    api_key_encrypted: str = ""
    auth_mode: str = "bearer"  # bearer | x-api-key | none
    auth_header_name: str = "authorization"
    enabled: bool = True
    priority: int = 100
    timeout_seconds: float = 600.0
    health_path: str = "/models"
    default_headers: dict[str, str] = field(default_factory=dict)
    model_allowlist: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    updated_at: int = 0

    def to_record(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "display_name": self.display_name,
            "upstream_base": self.upstream_base,
            "api_type": self.api_type,
            "api_key_encrypted": self.api_key_encrypted,
            "auth_mode": self.auth_mode,
            "auth_header_name": self.auth_header_name,
            "enabled": self.enabled,
            "priority": self.priority,
            "timeout_seconds": self.timeout_seconds,
            "health_path": self.health_path,
            "default_headers": dict(self.default_headers),
            "model_allowlist": list(self.model_allowlist),
            "metadata": dict(self.metadata),
            "updated_at": self.updated_at,
        }

    def to_public_dict(self) -> dict[str, Any]:
        data = self.to_record()
        data.pop("api_key_encrypted", None)
        data["has_api_key"] = bool(self.api_key_encrypted)
        return data

    @classmethod
    def from_record(cls, payload: dict[str, Any]) -> "UpstreamProvider":
        provider_id = _normalize_provider_id(str(payload.get("provider_id", "")))
        display_name = str(payload.get("display_name") or provider_id).strip() or provider_id
        upstream_base = _normalize_upstream_base(str(payload.get("upstream_base", "")))
        api_type = _normalize_api_type(str(payload.get("api_type", "openai")))
        auth_mode = str(payload.get("auth_mode") or "bearer").strip().lower()
        if auth_mode not in {"bearer", "x-api-key", "none"}:
            auth_mode = "bearer"
        auth_header_name = str(payload.get("auth_header_name") or "authorization").strip().lower()
        if not auth_header_name:
            auth_header_name = "authorization"
        timeout_seconds = float(payload.get("timeout_seconds") or 600.0)
        if timeout_seconds <= 0:
            timeout_seconds = 600.0
        health_path = str(payload.get("health_path") or "/models").strip() or "/models"
        if not health_path.startswith("/"):
            health_path = f"/{health_path}"
        headers = payload.get("default_headers")
        default_headers: dict[str, str] = {}
        if isinstance(headers, dict):
            for k, v in headers.items():
                key = str(k or "").strip()
                if key:
                    default_headers[key] = str(v or "")
        allowlist = payload.get("model_allowlist")
        model_allowlist: list[str] = []
        if isinstance(allowlist, list):
            for item in allowlist:
                model = str(item or "").strip()
                if model:
                    model_allowlist.append(model)
        return cls(
            provider_id=provider_id,
            display_name=display_name,
            upstream_base=upstream_base,
            api_type=api_type,
            api_key_encrypted=str(payload.get("api_key_encrypted") or ""),
            auth_mode=auth_mode,
            auth_header_name=auth_header_name,
            enabled=bool(payload.get("enabled", True)),
            priority=max(0, _safe_int(payload.get("priority"), 100)),
            timeout_seconds=timeout_seconds,
            health_path=health_path,
            default_headers=default_headers,
            model_allowlist=model_allowlist,
            metadata=payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {},
            updated_at=max(0, _safe_int(payload.get("updated_at"), 0)),
        )


@dataclass(slots=True)
class PolicyProviderTarget:
    provider_id: str
    weight: int = 1
    priority: int = 100

    def to_record(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "weight": self.weight,
            "priority": self.priority,
        }

    @classmethod
    def from_record(cls, payload: dict[str, Any]) -> "PolicyProviderTarget":
        provider_id = _normalize_provider_id(str(payload.get("provider_id", "")))
        weight = max(1, _safe_int(payload.get("weight"), 1))
        priority = max(0, _safe_int(payload.get("priority"), 100))
        return cls(provider_id=provider_id, weight=weight, priority=priority)


@dataclass(slots=True)
class ModelRoutingPolicy:
    group_id: str
    enabled: bool = True
    model_patterns: list[str] = field(default_factory=list)
    strategy: str = "failover"  # failover | weighted
    providers: list[PolicyProviderTarget] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    updated_at: int = 0

    def to_record(self) -> dict[str, Any]:
        return {
            "group_id": self.group_id,
            "enabled": self.enabled,
            "model_patterns": list(self.model_patterns),
            "strategy": self.strategy,
            "providers": [p.to_record() for p in self.providers],
            "metadata": dict(self.metadata),
            "updated_at": self.updated_at,
        }

    def to_public_dict(self) -> dict[str, Any]:
        return self.to_record()

    @classmethod
    def from_record(cls, payload: dict[str, Any]) -> "ModelRoutingPolicy":
        group_id = _normalize_provider_id(str(payload.get("group_id", "")))
        strategy = str(payload.get("strategy") or "failover").strip().lower()
        if strategy not in {"failover", "weighted"}:
            raise ValueError("invalid_routing_strategy")
        raw_patterns = payload.get("model_patterns")
        patterns: list[str] = []
        if isinstance(raw_patterns, list):
            for item in raw_patterns:
                pat = str(item or "").strip()
                if pat:
                    patterns.append(pat)
        if not patterns:
            patterns = ["*"]
        raw_providers = payload.get("providers")
        providers: list[PolicyProviderTarget] = []
        if isinstance(raw_providers, list):
            for item in raw_providers:
                if not isinstance(item, dict):
                    continue
                providers.append(PolicyProviderTarget.from_record(item))
        if not providers:
            raise ValueError("routing_policy_requires_providers")
        return cls(
            group_id=group_id,
            enabled=bool(payload.get("enabled", True)),
            model_patterns=patterns,
            strategy=strategy,
            providers=providers,
            metadata=payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {},
            updated_at=max(0, _safe_int(payload.get("updated_at"), 0)),
        )


def _encrypt_api_key(api_key: str) -> str:
    key = str(api_key or "").strip()
    if not key:
        return ""
    return encrypt_mapping({"api_key": key})


def _decrypt_api_key(encrypted: str) -> str:
    value = str(encrypted or "").strip()
    if not value:
        return ""
    try:
        return str(decrypt_mapping(value).get("api_key") or "").strip()
    except Exception:
        logger.warning("upstream provider api_key decrypt failed")
        return ""


def _save_locked() -> None:
    path = _providers_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"providers": {k: v.to_record() for k, v in _PROVIDERS.items()}}
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            delete=False,
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
        ) as tmp:
            tmp.write(json.dumps(payload, ensure_ascii=False, indent=2))
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp_path = Path(tmp.name)
        tmp_path.replace(path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except OSError as exc:
        if tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
        raise RuntimeError(f"providers_persist_failed:{exc}") from exc


def _save_routing_locked() -> None:
    path = _routing_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"model_groups": {k: v.to_record() for k, v in _ROUTING_POLICIES.items()}}
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            delete=False,
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
        ) as tmp:
            tmp.write(json.dumps(payload, ensure_ascii=False, indent=2))
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp_path = Path(tmp.name)
        tmp_path.replace(path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except OSError as exc:
        if tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
        raise RuntimeError(f"routing_persist_failed:{exc}") from exc


def load_providers() -> None:
    path = _providers_path()
    with _LOCK:
        _PROVIDERS.clear()
        if not path.is_file():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("providers load failed path=%s error=%s", path, exc)
            return
        records = data.get("providers")
        if not isinstance(records, dict):
            return
        for _, raw in records.items():
            if not isinstance(raw, dict):
                continue
            try:
                provider = UpstreamProvider.from_record(raw)
            except Exception as exc:
                logger.warning("skip invalid provider record error=%s payload=%s", exc, raw)
                continue
            _PROVIDERS[provider.provider_id] = provider


def load_routing_policies() -> None:
    path = _routing_path()
    with _LOCK:
        _ROUTING_POLICIES.clear()
        if not path.is_file():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("routing policies load failed path=%s error=%s", path, exc)
            return
        records = data.get("model_groups")
        if not isinstance(records, dict):
            return
        for _, raw in records.items():
            if not isinstance(raw, dict):
                continue
            try:
                policy = ModelRoutingPolicy.from_record(raw)
            except Exception as exc:
                logger.warning("skip invalid routing policy error=%s payload=%s", exc, raw)
                continue
            _ROUTING_POLICIES[policy.group_id] = policy


def list_providers(*, include_disabled: bool = True) -> list[dict[str, Any]]:
    with _LOCK:
        values = [p for p in _PROVIDERS.values() if include_disabled or p.enabled]
        values.sort(key=lambda p: (p.priority, p.provider_id))
        return [p.to_public_dict() for p in values]


def get_provider(provider_id: str) -> dict[str, Any] | None:
    pid = _normalize_provider_id(provider_id)
    with _LOCK:
        provider = _PROVIDERS.get(pid)
        if not provider:
            return None
        return provider.to_public_dict()


def upsert_provider(
    *,
    provider_id: str,
    display_name: str,
    upstream_base: str,
    api_type: str = "openai",
    enabled: bool = True,
    priority: int = 100,
    timeout_seconds: float = 600.0,
    health_path: str = "/models",
    default_headers: dict[str, str] | None = None,
    model_allowlist: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
    api_key: str | None = None,
    auth_mode: str = "bearer",
    auth_header_name: str = "authorization",
) -> dict[str, Any]:
    pid = _normalize_provider_id(provider_id)
    now_ts = int(time.time())
    with _LOCK:
        existing = _PROVIDERS.get(pid)
        encrypted = existing.api_key_encrypted if existing else ""
        api_key_rotated = api_key is not None
        if api_key_rotated:
            encrypted = _encrypt_api_key(api_key)
        provider = UpstreamProvider.from_record(
            {
                "provider_id": pid,
                "display_name": display_name or pid,
                "upstream_base": upstream_base,
                "api_type": api_type,
                "api_key_encrypted": encrypted,
                "auth_mode": auth_mode,
                "auth_header_name": auth_header_name,
                "enabled": enabled,
                "priority": priority,
                "timeout_seconds": timeout_seconds,
                "health_path": health_path,
                "default_headers": default_headers or {},
                "model_allowlist": model_allowlist or [],
                "metadata": metadata or {},
                "updated_at": now_ts,
            }
        )
        # Reset circuit when provider is re-enabled after being disabled, or when
        # the API key is rotated (may resolve auth-error-induced trips).
        was_disabled = existing is not None and not existing.enabled
        if (was_disabled and enabled) or api_key_rotated:
            health_state = _PROVIDER_HEALTH.get(pid)
            if health_state is not None:
                health_state.update(
                    {
                        "healthy": True,
                        "circuit_state": _CIRCUIT_STATE_CLOSED,
                        "circuit_open_until": 0.0,
                        "consecutive_failures": 0,
                        "consecutive_successes": 0,
                        "circuit_tripped_at": 0.0,
                        "last_error": "",
                        "probe_in_flight": False,
                        "probe_started_at": 0.0,
                    }
                )
                reason = "re-enabled" if was_disabled and enabled else "api_key_rotated"
                logger.info("circuit_breaker auto-reset provider=%s reason=%s", pid, reason)
        _PROVIDERS[pid] = provider
        _save_locked()
        return provider.to_public_dict()


def delete_provider(provider_id: str) -> bool:
    pid = _normalize_provider_id(provider_id)
    with _LOCK:
        if pid not in _PROVIDERS:
            return False
        _PROVIDERS.pop(pid, None)
        _PROVIDER_HEALTH.pop(pid, None)
        _save_locked()
        return True


def list_model_group_policies(*, include_disabled: bool = True) -> list[dict[str, Any]]:
    with _LOCK:
        values = [p for p in _ROUTING_POLICIES.values() if include_disabled or p.enabled]
        values.sort(key=lambda p: p.group_id)
        return [p.to_public_dict() for p in values]


def get_model_group_policy(group_id: str) -> dict[str, Any] | None:
    gid = _normalize_provider_id(group_id)
    with _LOCK:
        policy = _ROUTING_POLICIES.get(gid)
        if not policy:
            return None
        return policy.to_public_dict()


def upsert_model_group_policy(
    *,
    group_id: str,
    model_patterns: list[str],
    strategy: str,
    providers: list[dict[str, Any]],
    enabled: bool = True,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    gid = _normalize_provider_id(group_id)
    now_ts = int(time.time())
    with _LOCK:
        provider_targets: list[dict[str, Any]] = []
        for item in providers:
            if not isinstance(item, dict):
                continue
            provider_targets.append(
                {
                    "provider_id": item.get("provider_id"),
                    "weight": max(1, _safe_int(item.get("weight"), 1)),
                    "priority": max(0, _safe_int(item.get("priority"), 100)),
                }
            )
        policy = ModelRoutingPolicy.from_record(
            {
                "group_id": gid,
                "model_patterns": model_patterns,
                "strategy": strategy,
                "providers": provider_targets,
                "enabled": enabled,
                "metadata": metadata or {},
                "updated_at": now_ts,
            }
        )
        missing = [target.provider_id for target in policy.providers if target.provider_id not in _PROVIDERS]
        if missing:
            raise KeyError(f"providers_not_found:{','.join(sorted(set(missing)))}")
        _ROUTING_POLICIES[gid] = policy
        _save_routing_locked()
        return policy.to_public_dict()


def delete_model_group_policy(group_id: str) -> bool:
    gid = _normalize_provider_id(group_id)
    with _LOCK:
        if gid not in _ROUTING_POLICIES:
            return False
        _ROUTING_POLICIES.pop(gid, None)
        _save_routing_locked()
        return True


def _provider_auth_headers(provider: UpstreamProvider) -> dict[str, str]:
    api_key = _decrypt_api_key(provider.api_key_encrypted)
    if not api_key or provider.auth_mode == "none":
        return {}
    if provider.auth_mode == "x-api-key":
        header = provider.auth_header_name or "x-api-key"
        return {header: api_key}
    return {"Authorization": f"Bearer {api_key}"}


def _model_matches_policy(model: str, policy: ModelRoutingPolicy) -> bool:
    current = str(model or "").strip()
    if not current:
        return any(pat in {"*", "*:*"} for pat in policy.model_patterns)
    lowered = current.lower()
    for pattern in policy.model_patterns:
        pat = str(pattern or "").strip()
        if not pat:
            continue
        if fnmatch.fnmatch(lowered, pat.lower()):
            return True
    return False


_CIRCUIT_STATE_CLOSED = "closed"
_CIRCUIT_STATE_OPEN = "open"
_CIRCUIT_STATE_HALF_OPEN = "half_open"


def _circuit_open_seconds(consecutive_failures: int) -> float:
    """Exponential backoff with per-settings caps for circuit open duration."""
    base = settings.circuit_breaker_base_open_seconds
    cap = settings.circuit_breaker_max_open_seconds
    threshold = max(1, settings.circuit_breaker_failure_threshold)
    excess = max(0, consecutive_failures - threshold)
    duration = min(cap, base * (2.0 ** excess))
    jitter_range = duration * max(0.0, min(1.0, settings.circuit_breaker_jitter_factor))
    return duration + random.uniform(0.0, jitter_range)


def _get_circuit_state(health: dict[str, Any], now_ts: float) -> str:
    open_until = _safe_float(health.get("circuit_open_until"), 0.0)
    if open_until <= 0.0:
        return _CIRCUIT_STATE_CLOSED
    if open_until > now_ts:
        return _CIRCUIT_STATE_OPEN
    return _CIRCUIT_STATE_HALF_OPEN


def _health_is_available(provider_id: str, now_ts: float) -> bool:
    """Return True if the provider should receive a request.

    In HALF_OPEN state only one probe is allowed at a time.  The probe slot is
    claimed atomically under _LOCK (callers must hold _LOCK).  A stale-probe
    guard (2 × upstream timeout) automatically releases the slot when the
    previous probe request was abandoned (e.g. client disconnect) so the
    circuit never deadlocks in HALF_OPEN indefinitely.
    """
    health = _PROVIDER_HEALTH.get(provider_id)
    if not isinstance(health, dict):
        return True
    if not settings.circuit_breaker_enabled:
        return health.get("healthy") is not False
    state = _get_circuit_state(health, now_ts)
    if state == _CIRCUIT_STATE_OPEN:
        return False
    if state == _CIRCUIT_STATE_HALF_OPEN:
        probe_in_flight = bool(health.get("probe_in_flight", False))
        probe_started_at = _safe_float(health.get("probe_started_at"), 0.0)
        stale_threshold = float(settings.upstream_timeout_seconds) * 2.0
        probe_is_stale = probe_in_flight and (now_ts - probe_started_at) > stale_threshold
        if probe_in_flight and not probe_is_stale:
            # Another probe is already in flight; block this request.
            return False
        # Claim the probe slot.
        health["probe_in_flight"] = True
        health["probe_started_at"] = now_ts
        return True
    return True


def report_provider_success(provider_id: str) -> None:
    """Record a successful upstream request. Resets failure counter and closes circuit."""
    if not provider_id or not settings.circuit_breaker_enabled:
        return
    pid = provider_id.strip()
    if not pid:
        return
    now_ts = time.time()
    with _LOCK:
        state = _PROVIDER_HEALTH.setdefault(pid, {})
        prev_failures = _safe_int(state.get("consecutive_failures"), 0)
        prev_state = _get_circuit_state(state, now_ts)
        consecutive_successes = _safe_int(state.get("consecutive_successes"), 0) + 1
        threshold = max(1, settings.circuit_breaker_success_threshold)
        if prev_state == _CIRCUIT_STATE_HALF_OPEN and consecutive_successes >= threshold:
            # Enough probe successes: fully close the circuit.
            state.update(
                {
                    "healthy": True,
                    "circuit_state": _CIRCUIT_STATE_CLOSED,
                    "circuit_open_until": 0.0,
                    "consecutive_failures": 0,
                    "consecutive_successes": consecutive_successes,
                    "last_success_at": now_ts,
                    "last_error": "",
                    "probe_in_flight": False,
                    "probe_started_at": 0.0,
                }
            )
            logger.info(
                "circuit_breaker closed provider=%s after %d probe success(es) (was open for %.1fs)",
                pid,
                consecutive_successes,
                now_ts - _safe_float(state.get("circuit_tripped_at"), now_ts),
            )
        elif prev_state == _CIRCUIT_STATE_HALF_OPEN:
            # Probe succeeded but not yet enough; keep half-open and release probe slot
            # so the next request can send another probe immediately.
            state.update(
                {
                    "healthy": False,
                    "circuit_state": _CIRCUIT_STATE_HALF_OPEN,
                    "consecutive_failures": 0,
                    "consecutive_successes": consecutive_successes,
                    "last_success_at": now_ts,
                    "probe_in_flight": False,
                    "probe_started_at": 0.0,
                }
            )
            logger.info(
                "circuit_breaker probe success provider=%s successes=%d/%d",
                pid,
                consecutive_successes,
                threshold,
            )
        elif prev_state == _CIRCUIT_STATE_CLOSED:
            state.update(
                {
                    "healthy": True,
                    "circuit_state": _CIRCUIT_STATE_CLOSED,
                    "circuit_open_until": 0.0,
                    "consecutive_failures": 0,
                    "consecutive_successes": consecutive_successes,
                    "last_success_at": now_ts,
                    "last_error": "",
                }
            )
            if prev_failures > 0:
                logger.info("circuit_breaker recovered provider=%s failures_cleared=%d", pid, prev_failures)


def report_provider_failure(provider_id: str, *, error: str = "", status_code: int = 0) -> None:
    """Record a failed upstream request. Trips or deepens the circuit if threshold is exceeded."""
    if not provider_id or not settings.circuit_breaker_enabled:
        return
    pid = provider_id.strip()
    if not pid:
        return
    now_ts = time.time()
    with _LOCK:
        state = _PROVIDER_HEALTH.setdefault(pid, {})
        prev_state = _get_circuit_state(state, now_ts)
        failures = _safe_int(state.get("consecutive_failures"), 0) + 1
        threshold = max(1, settings.circuit_breaker_failure_threshold)
        error_snippet = (str(error or "") or "")[:300]
        if prev_state == _CIRCUIT_STATE_HALF_OPEN:
            # Re-trip immediately on any failure during probe window; release probe slot.
            open_duration = _circuit_open_seconds(failures)
            open_until = now_ts + open_duration
            state.update(
                {
                    "healthy": False,
                    "circuit_state": _CIRCUIT_STATE_OPEN,
                    "circuit_open_until": open_until,
                    "consecutive_failures": failures,
                    "consecutive_successes": 0,
                    "last_failure_at": now_ts,
                    "last_error": error_snippet,
                    "last_status_code": status_code,
                    "circuit_tripped_at": state.get("circuit_tripped_at", now_ts),
                    "probe_in_flight": False,
                    "probe_started_at": 0.0,
                }
            )
            logger.warning(
                "circuit_breaker re-tripped provider=%s probe_failed failures=%d open_until=+%.0fs error=%s",
                pid,
                failures,
                open_duration,
                error_snippet[:80],
            )
        elif failures >= threshold:
            # First trip or worsening: calculate back-off and open circuit.
            open_duration = _circuit_open_seconds(failures)
            open_until = now_ts + open_duration
            tripped_at = state.get("circuit_tripped_at") or now_ts
            if prev_state == _CIRCUIT_STATE_CLOSED:
                tripped_at = now_ts
                logger.warning(
                    "circuit_breaker tripped provider=%s consecutive_failures=%d open_until=+%.0fs error=%s",
                    pid,
                    failures,
                    open_duration,
                    error_snippet[:80],
                )
            else:
                logger.warning(
                    "circuit_breaker deepened provider=%s consecutive_failures=%d open_until=+%.0fs",
                    pid,
                    failures,
                    open_duration,
                )
            state.update(
                {
                    "healthy": False,
                    "circuit_state": _CIRCUIT_STATE_OPEN,
                    "circuit_open_until": open_until,
                    "consecutive_failures": failures,
                    "consecutive_successes": 0,
                    "last_failure_at": now_ts,
                    "last_error": error_snippet,
                    "last_status_code": status_code,
                    "circuit_tripped_at": tripped_at,
                    "probe_in_flight": False,
                    "probe_started_at": 0.0,
                }
            )
        else:
            # Below threshold: mark degraded but keep circuit closed.
            state.update(
                {
                    "healthy": False,
                    "circuit_state": _CIRCUIT_STATE_CLOSED,
                    "consecutive_failures": failures,
                    "consecutive_successes": 0,
                    "last_failure_at": now_ts,
                    "last_error": error_snippet,
                    "last_status_code": status_code,
                }
            )
            logger.info(
                "circuit_breaker degraded provider=%s consecutive_failures=%d threshold=%d error=%s",
                pid,
                failures,
                threshold,
                error_snippet[:80],
            )


def _select_weighted_provider(
    candidates: list[tuple[PolicyProviderTarget, UpstreamProvider]],
    *,
    model: str,
    tenant_id: str,
    request_id: str,
) -> tuple[PolicyProviderTarget, UpstreamProvider]:
    if len(candidates) == 1:
        return candidates[0]
    seed_source = f"{tenant_id}|{model}|{request_id or time.time_ns()}"
    seed = int(hashlib.sha256(seed_source.encode("utf-8")).hexdigest()[:16], 16)
    rng = random.Random(seed)
    total = sum(max(1, target.weight) for target, _ in candidates)
    ticket = rng.randint(1, total)
    running = 0
    for target, provider in candidates:
        running += max(1, target.weight)
        if ticket <= running:
            return target, provider
    return candidates[-1]


def _provider_headers_for(provider: UpstreamProvider) -> dict[str, str]:
    headers = dict(provider.default_headers)
    headers.update(_provider_auth_headers(provider))
    return headers


def resolve_provider_route(
    provider_id: str,
    *,
    model: str = "",
) -> tuple[str, dict[str, str]]:
    pid = _normalize_provider_id(provider_id)
    with _LOCK:
        provider = _PROVIDERS.get(pid)
        if not provider:
            raise KeyError("provider_not_found")
        if not provider.enabled:
            raise PermissionError("provider_disabled")
        if provider.model_allowlist and model and model not in provider.model_allowlist:
            raise PermissionError("model_not_allowed_for_provider")
        base = provider.upstream_base
        return base, _provider_headers_for(provider)


def resolve_best_provider(*, model: str = "") -> tuple[str, str, dict[str, str]]:
    with _LOCK:
        candidates = [p for p in _PROVIDERS.values() if p.enabled]
        candidates.sort(key=lambda p: (p.priority, p.provider_id))
        for provider in candidates:
            if provider.model_allowlist and model and model not in provider.model_allowlist:
                continue
            return provider.provider_id, provider.upstream_base, _provider_headers_for(provider)
    raise KeyError("no_enabled_provider")


def resolve_provider_for_model_group(
    *,
    model: str,
    tenant_id: str = "default",
    request_id: str = "",
) -> tuple[str, str, dict[str, str], dict[str, Any]]:
    now_ts = time.time()
    with _LOCK:
        policies = [p for p in _ROUTING_POLICIES.values() if p.enabled and _model_matches_policy(model, p)]
        policies.sort(key=lambda p: p.group_id)
        for policy in policies:
            candidates: list[tuple[PolicyProviderTarget, UpstreamProvider]] = []
            ordered_targets = sorted(policy.providers, key=lambda t: (t.priority, t.provider_id))
            for target in ordered_targets:
                provider = _PROVIDERS.get(target.provider_id)
                if not provider or not provider.enabled:
                    continue
                if provider.model_allowlist and model and model not in provider.model_allowlist:
                    continue
                if not _health_is_available(provider.provider_id, now_ts):
                    continue
                candidates.append((target, provider))
            if not candidates:
                continue
            selected_target: PolicyProviderTarget
            selected_provider: UpstreamProvider
            if policy.strategy == "weighted":
                selected_target, selected_provider = _select_weighted_provider(
                    candidates,
                    model=model,
                    tenant_id=tenant_id,
                    request_id=request_id,
                )
            else:
                selected_target, selected_provider = candidates[0]
            headers = _provider_headers_for(selected_provider)
            return (
                selected_provider.provider_id,
                selected_provider.upstream_base,
                headers,
                {
                    "group_id": policy.group_id,
                    "strategy": policy.strategy,
                    "weight": selected_target.weight,
                    "priority": selected_target.priority,
                },
            )
    raise KeyError("no_policy_provider_available")


async def check_provider_health(provider_id: str) -> dict[str, Any]:
    pid = _normalize_provider_id(provider_id)
    with _LOCK:
        provider = _PROVIDERS.get(pid)
        if not provider:
            raise KeyError("provider_not_found")
        timeout = provider.timeout_seconds
        url = f"{provider.upstream_base}{provider.health_path}"
        headers = dict(provider.default_headers)
        headers.update(_provider_auth_headers(provider))
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
            response = await client.get(url, headers=headers)
        healthy = response.status_code < 500
        if healthy:
            report_provider_success(pid)
        else:
            report_provider_failure(pid, error=f"health_check_http_{response.status_code}", status_code=response.status_code)
        with _LOCK:
            state = dict(_PROVIDER_HEALTH.get(pid, {}))
            state["last_health_checked_at"] = time.time()
            state["health_status_code"] = response.status_code
        return {
            "provider_id": pid,
            "healthy": healthy,
            "status_code": response.status_code,
            "url": url,
            "circuit_state": state.get("circuit_state", _CIRCUIT_STATE_CLOSED),
            "consecutive_failures": state.get("consecutive_failures", 0),
        }
    except httpx.HTTPError as exc:
        report_provider_failure(pid, error=str(exc), status_code=0)
        with _LOCK:
            state = dict(_PROVIDER_HEALTH.get(pid, {}))
        return {
            "provider_id": pid,
            "healthy": False,
            "status_code": 0,
            "url": url,
            "error": str(exc),
            "circuit_state": state.get("circuit_state", _CIRCUIT_STATE_CLOSED),
            "consecutive_failures": state.get("consecutive_failures", 0),
        }


def get_provider_health_state(provider_id: str) -> dict[str, Any] | None:
    pid = _normalize_provider_id(provider_id)
    now_ts = time.time()
    with _LOCK:
        state = _PROVIDER_HEALTH.get(pid)
        if not state:
            return None
        result = dict(state)
    computed_state = _get_circuit_state(result, now_ts)
    result["circuit_state"] = computed_state
    open_until = _safe_float(result.get("circuit_open_until"), 0.0)
    result["circuit_open_remaining_seconds"] = max(0.0, open_until - now_ts) if open_until > 0 else 0.0
    return result


def reset_provider_circuit(provider_id: str) -> bool:
    """Manually close the circuit for a provider (admin override)."""
    pid = _normalize_provider_id(provider_id)
    with _LOCK:
        if pid not in _PROVIDERS:
            return False
        state = _PROVIDER_HEALTH.setdefault(pid, {})
        state.update(
            {
                "healthy": True,
                "circuit_state": _CIRCUIT_STATE_CLOSED,
                "circuit_open_until": 0.0,
                "consecutive_failures": 0,
                "consecutive_successes": 0,
                "circuit_tripped_at": 0.0,
                "last_error": "",
                "probe_in_flight": False,
                "probe_started_at": 0.0,
            }
        )
        logger.info("circuit_breaker manually reset provider=%s", pid)
        return True


def list_provider_health_states() -> list[dict[str, Any]]:
    """Return circuit breaker state for all known providers, sorted by provider_id."""
    now_ts = time.time()
    with _LOCK:
        pids = sorted(_PROVIDERS.keys())
        result: list[dict[str, Any]] = []
        for pid in pids:
            state = dict(_PROVIDER_HEALTH.get(pid, {}))
            state["provider_id"] = pid
            computed_state = _get_circuit_state(state, now_ts)
            state["circuit_state"] = computed_state
            open_until = _safe_float(state.get("circuit_open_until"), 0.0)
            state["circuit_open_remaining_seconds"] = max(0.0, open_until - now_ts) if open_until > 0 else 0.0
            result.append(state)
    return result
