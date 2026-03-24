"""
Gateway token map: registration returns a short token; traffic uses /v1/__gw__/t/{token}/... to resolve upstream.
Persisted in config/gw_tokens.json, loaded at startup, safe to edit manually.
"""

from __future__ import annotations

import copy
import json
import os
import secrets
import tempfile
import threading
from pathlib import Path
from typing import Any

from n4ughtyllm_gate.config.settings import settings
from n4ughtyllm_gate.util.logger import logger
from n4ughtyllm_gate.util.redaction_whitelist import normalize_whitelist_keys

# In-memory map: token -> {"upstream_base": str, "whitelist_key": list[str]}
_tokens: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()
_TOKEN_LEN = 24
_GW_TOKENS_KEY = "tokens"
_WHITELIST_UNSET = object()


def _generate_alnum_token(length: int) -> str:
    """Generate alphanumeric token (a-zA-Z0-9) without separators."""
    chars: list[str] = []
    while len(chars) < length:
        raw = secrets.token_urlsafe(length * 2)
        chars.extend(c for c in raw if c.isalnum())
    return "".join(chars[:length])


def _path() -> Path:
    p = settings.gw_tokens_path
    return Path(p) if os.path.isabs(p) else Path.cwd() / p


def load(*, replace: bool = False) -> None:
    """Load the token map from disk.

    With ``replace=False`` (default), a missing or invalid file only logs; in-memory state is kept.
    With ``replace=True``, disk is authoritative: missing/invalid data clears memory so hot reload
    cannot keep serving deleted tokens.
    """
    path = _path()
    with _lock:
        if not path.is_file():
            if replace:
                _tokens.clear()
                logger.info("gw_tokens file missing path=%s, cleared in-memory tokens", path)
            else:
                logger.debug("gw_tokens file not found path=%s, skip load", path)
            return
        try:
            raw = path.read_text(encoding="utf-8")
            data = json.loads(raw)
            tokens = data.get(_GW_TOKENS_KEY)
            if not isinstance(tokens, dict):
                if replace:
                    _tokens.clear()
                    logger.warning("gw_tokens load failed path=%s error=invalid tokens payload; in-memory tokens cleared", path)
                return
            _tokens.clear()
            for k, v in tokens.items():
                if isinstance(v, dict) and "upstream_base" in v:
                    _tokens[str(k)] = {
                        "upstream_base": str(v["upstream_base"]),
                        "whitelist_key": normalize_whitelist_keys(v.get("whitelist_key")),
                    }
            logger.info("gw_tokens loaded path=%s count=%d", path, len(_tokens))
        except (json.JSONDecodeError, OSError, ValueError, KeyError, TypeError) as exc:
            if replace:
                _tokens.clear()
            logger.warning("gw_tokens load failed path=%s error=%s", path, exc)


def _save() -> None:
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    data: dict[str, Any] = {_GW_TOKENS_KEY: dict(_tokens)}
    tmp_path: Path | None = None
    try:
        # Write to a sibling temp file first so readers never observe a
        # partially-written gw_tokens.json during concurrent reloads.
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            delete=False,
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
        ) as tmp:
            tmp.write(json.dumps(data, ensure_ascii=False, indent=2))
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp_path = Path(tmp.name)
        tmp_path.replace(path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        logger.debug("gw_tokens saved path=%s count=%d", path, len(_tokens))
    except OSError as exc:
        if tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
        logger.warning("gw_tokens: could not persist to %s: %s (in-memory state intact)", path, exc)


def get(token: str) -> dict[str, Any] | None:
    """Return mapping for token, or None.

    With ``settings.enable_local_port_routing`` and a numeric token in 1024-65535,
    synthesize a local port route without prior registration.
    """
    with _lock:
        mapping = _tokens.get(token)
        if mapping is not None:
            return copy.deepcopy(mapping)

    # Numeric local port routing fallback
    if settings.enable_local_port_routing and token.isdigit():
        port = int(token)
        if 1024 <= port <= 65535:
            host = (settings.local_port_routing_host or "host.docker.internal").strip()
            return {
                "upstream_base": f"http://{host}:{port}/v1",
                "whitelist_key": [],
            }
    return None


def _normalize_upstream(s: str) -> str:
    return (s or "").strip().rstrip("/")


def _find_token_holding_lock(ub: str) -> str | None:
    """Find token for normalized upstream_base while holding _lock."""
    for token, m in _tokens.items():
        if _normalize_upstream(m["upstream_base"]) == ub:
            return token
    return None


def find_token(upstream_base: str, gateway_key: str | None = None, **_kwargs: Any) -> str | None:
    """
    Find token for upstream_base using the same normalization as register; None if missing.

    .. deprecated:: gateway_key is ignored.
    """
    ub = _normalize_upstream(upstream_base)
    if not ub:
        return None
    with _lock:
        return _find_token_holding_lock(ub)


def register(upstream_base: str, gateway_key: Any = None, whitelist_key: Any = _WHITELIST_UNSET, **_kwargs: Any) -> tuple[str, bool]:
    """
    Register: at most one token per upstream_base.
    Returns (token, True) if it already existed, else (new_token, False).
    If whitelist_key is omitted on an existing row, whitelist_key is left unchanged.

    .. deprecated:: gateway_key is ignored.
    """
    # Backward compat: register(ub, ["key1"]) — positional list was whitelist_key
    if whitelist_key is _WHITELIST_UNSET and gateway_key is not None and not isinstance(gateway_key, str):
        whitelist_key = gateway_key
    upstream_base = _normalize_upstream(upstream_base)
    if not upstream_base:
        raise ValueError("upstream_base required")
    whitelist_provided = whitelist_key is not _WHITELIST_UNSET
    whitelist_keys = normalize_whitelist_keys(whitelist_key) if whitelist_provided else []
    with _lock:
        existing = _find_token_holding_lock(upstream_base)
        if existing is not None:
            if whitelist_provided:
                mapping = _tokens.get(existing) or {}
                current = normalize_whitelist_keys(mapping.get("whitelist_key"))
                if current != whitelist_keys:
                    mapping["whitelist_key"] = whitelist_keys
                    _tokens[existing] = mapping
                    _save()
            return existing, True
        for attempt in range(20):
            token = _generate_alnum_token(_TOKEN_LEN)
            if token not in _tokens:
                break
        else:
            raise RuntimeError("failed to generate unique gw_token after 20 attempts")
        _tokens[token] = {
            "upstream_base": upstream_base,
            "whitelist_key": whitelist_keys if whitelist_provided else [],
        }
        _save()
    return token, False


def unregister(token: str) -> bool:
    """Remove token mapping and persist; True if it existed."""
    with _lock:
        if token not in _tokens:
            return False
        del _tokens[token]
        _save()
        return True


def update(token: str, *, upstream_base: str | None = None, gateway_key: str | None = None, whitelist_key: Any = None, **_kwargs: Any) -> bool:
    """Update mapping by token and persist; False if token missing.

    .. deprecated:: gateway_key is ignored.
    """
    with _lock:
        mapping = _tokens.get(token)
        if mapping is None:
            return False
        next_mapping = dict(mapping)
        if upstream_base is not None:
            normalized_upstream = _normalize_upstream(upstream_base)
            if not normalized_upstream:
                raise ValueError("upstream_base required")
            next_mapping["upstream_base"] = normalized_upstream
        if whitelist_key is not None:
            next_mapping["whitelist_key"] = normalize_whitelist_keys(whitelist_key)
        _tokens[token] = next_mapping
        _save()
        return True


def update_and_rename(
    token: str,
    *,
    upstream_base: str | None = None,
    gateway_key: str | None = None,
    whitelist_key: Any = None,
    new_token: str | None = None,
    **_kwargs: Any,
) -> bool:
    """Atomically update fields and optionally rename token under one lock.
    False if token missing; ValueError if new_token collides or fields invalid.

    .. deprecated:: gateway_key is ignored.
    """
    with _lock:
        mapping = _tokens.get(token)
        if mapping is None:
            return False
        next_mapping = dict(mapping)
        if upstream_base is not None:
            normalized_upstream = _normalize_upstream(upstream_base)
            if not normalized_upstream:
                raise ValueError("upstream_base required")
            next_mapping["upstream_base"] = normalized_upstream
        if whitelist_key is not None:
            next_mapping["whitelist_key"] = normalize_whitelist_keys(whitelist_key)
        if new_token and new_token != token:
            if new_token in _tokens:
                raise ValueError(f"token already exists: {new_token}")
            _tokens[new_token] = next_mapping
            del _tokens[token]
        else:
            _tokens[token] = next_mapping
        _save()
        return True


def list_tokens() -> dict[str, dict[str, Any]]:
    """Snapshot of all token mappings."""
    with _lock:
        return copy.deepcopy(_tokens)


def inject_docker_upstreams() -> int:
    """Parse N4UGHTYLLM_GATE_DOCKER_UPSTREAMS and register Docker service upstreams.

    Comma-separated ``token:service[:port]``; default port is the token when omitted.
    Example: ``8317:cli-proxy-api`` → token ``8317`` → ``http://cli-proxy-api:8317/v1``.

    Existing tokens with the same name are overwritten so compose env stays authoritative.
    Returns number of entries applied.
    """
    raw = (settings.docker_upstreams or "").strip()
    if not raw:
        return 0
    pending: dict[str, dict[str, Any]] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        parts = entry.split(":")
        if len(parts) < 2:
            logger.warning("docker_upstreams: invalid entry %r (expected token:service[:port]), skipped", entry)
            continue
        token = parts[0].strip()
        service = parts[1].strip()
        port = parts[2].strip() if len(parts) >= 3 else token
        if not token or not service or not port:
            logger.warning("docker_upstreams: empty field in %r, skipped", entry)
            continue
        upstream_base = f"http://{service}:{port}/v1"
        pending[token] = {
            "upstream_base": upstream_base,
            "whitelist_key": [],
        }
    injected = len(pending)
    if injected:
        with _lock:
            _tokens.update(pending)
            _save()
        logger.info("docker_upstreams injected %d token(s): %s", injected, raw)
    return injected
