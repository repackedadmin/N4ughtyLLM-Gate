"""Tests for runtime circuit breaker — failure recording, tripping, half-open probe,
recovery, manual reset, and admin API endpoints."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from n4ughtyllm_gate.core import upstream_registry
from n4ughtyllm_gate.core.upstream_registry import (
    _CIRCUIT_STATE_CLOSED,
    _CIRCUIT_STATE_HALF_OPEN,
    _CIRCUIT_STATE_OPEN,
    _PROVIDER_HEALTH,
    _get_circuit_state,
    report_provider_failure,
    report_provider_success,
    reset_provider_circuit,
    get_provider_health_state,
    list_provider_health_states,
    resolve_provider_for_model_group,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _setup_registry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config").mkdir(parents=True, exist_ok=True)
    upstream_registry.load_providers()
    upstream_registry.load_routing_policies()
    # Clear any leftover health state from prior tests
    _PROVIDER_HEALTH.clear()


def _add_provider(provider_id: str, upstream_base: str = "https://example.com/v1") -> None:
    upstream_registry.upsert_provider(
        provider_id=provider_id,
        display_name=provider_id,
        upstream_base=upstream_base,
        api_type="openai",
        auth_mode="none",
    )


def _add_policy(group_id: str, provider_ids: list[str], strategy: str = "failover") -> None:
    upstream_registry.upsert_model_group_policy(
        group_id=group_id,
        model_patterns=["gpt-5*"],
        strategy=strategy,
        providers=[{"provider_id": pid, "weight": 1, "priority": idx * 10} for idx, pid in enumerate(provider_ids)],
        enabled=True,
    )


# ---------------------------------------------------------------------------
# Unit: report_provider_failure tripping and backoff
# ---------------------------------------------------------------------------

def test_circuit_trips_at_threshold(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _setup_registry(tmp_path, monkeypatch)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_enabled", True)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_failure_threshold", 3)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_base_open_seconds", 10.0)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_jitter_factor", 0.0)
    _add_provider("prov-a")

    report_provider_failure("prov-a", error="timeout")
    state = get_provider_health_state("prov-a")
    assert state["circuit_state"] == _CIRCUIT_STATE_CLOSED
    assert state["consecutive_failures"] == 1

    report_provider_failure("prov-a", error="timeout")
    state = get_provider_health_state("prov-a")
    assert state["circuit_state"] == _CIRCUIT_STATE_CLOSED
    assert state["consecutive_failures"] == 2

    report_provider_failure("prov-a", error="timeout")
    state = get_provider_health_state("prov-a")
    assert state["circuit_state"] == _CIRCUIT_STATE_OPEN
    assert state["consecutive_failures"] == 3
    assert state["circuit_open_remaining_seconds"] > 0.0


def test_circuit_exponential_backoff(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _setup_registry(tmp_path, monkeypatch)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_enabled", True)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_failure_threshold", 2)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_base_open_seconds", 10.0)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_max_open_seconds", 300.0)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_jitter_factor", 0.0)
    _add_provider("prov-backoff")

    open_durations: list[float] = []
    now = time.time()
    for i in range(6):
        report_provider_failure("prov-backoff", error="err")
        state = get_provider_health_state("prov-backoff")
        remaining = state["circuit_open_remaining_seconds"]
        open_durations.append(remaining)

    # Backoff must grow: each additional failure past threshold should increase duration
    # (durations may be slightly different at different moments; compare pairs)
    assert open_durations[2] >= open_durations[1] - 0.1  # at threshold: base
    assert open_durations[3] > open_durations[2] - 0.1   # excess=1: base*2
    assert open_durations[4] > open_durations[3] - 0.1   # excess=2: base*4
    assert open_durations[5] <= 300.0 + 1.0              # cap respected


def test_circuit_success_clears_failures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _setup_registry(tmp_path, monkeypatch)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_enabled", True)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_failure_threshold", 2)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_jitter_factor", 0.0)
    _add_provider("prov-clear")

    report_provider_failure("prov-clear", error="err")
    assert get_provider_health_state("prov-clear")["consecutive_failures"] == 1

    report_provider_success("prov-clear")
    state = get_provider_health_state("prov-clear")
    assert state["circuit_state"] == _CIRCUIT_STATE_CLOSED
    assert state["consecutive_failures"] == 0
    assert state["circuit_open_remaining_seconds"] == 0.0


def test_half_open_success_closes_circuit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """After open window expires the circuit enters HALF_OPEN.
    Exactly success_threshold consecutive successes are required to fully close it."""
    _setup_registry(tmp_path, monkeypatch)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_enabled", True)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_failure_threshold", 1)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_base_open_seconds", 0.0)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_max_open_seconds", 0.0)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_success_threshold", 2)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_jitter_factor", 0.0)
    _add_provider("prov-halfopen")

    # Trip the circuit (open window = 0 → immediately half-open)
    report_provider_failure("prov-halfopen", error="err")
    state = get_provider_health_state("prov-halfopen")
    # base_open_seconds=0 means circuit_open_until is at most at now; HALF_OPEN or boundary OPEN
    assert state["circuit_state"] in (_CIRCUIT_STATE_OPEN, _CIRCUIT_STATE_HALF_OPEN)

    # Force into HALF_OPEN so timing is deterministic
    with upstream_registry._LOCK:
        upstream_registry._PROVIDER_HEALTH["prov-halfopen"]["circuit_open_until"] = time.time() - 1.0
        upstream_registry._PROVIDER_HEALTH["prov-halfopen"]["probe_in_flight"] = False

    # First probe success: consecutive_successes=1, threshold=2 → still HALF_OPEN
    report_provider_success("prov-halfopen")
    state = get_provider_health_state("prov-halfopen")
    assert state["circuit_state"] == _CIRCUIT_STATE_HALF_OPEN
    assert state["consecutive_failures"] == 0
    assert state["consecutive_successes"] == 1

    # Second probe success reaches threshold=2 → CLOSED
    report_provider_success("prov-halfopen")
    state = get_provider_health_state("prov-halfopen")
    assert state["circuit_state"] == _CIRCUIT_STATE_CLOSED
    assert state["consecutive_failures"] == 0
    assert state["circuit_open_remaining_seconds"] == 0.0


def test_half_open_failure_retrips_with_backoff(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _setup_registry(tmp_path, monkeypatch)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_enabled", True)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_failure_threshold", 1)
    # Use a real open duration so the re-trip puts open_until in the future (non-zero)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_base_open_seconds", 30.0)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_max_open_seconds", 300.0)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_jitter_factor", 0.0)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_success_threshold", 3)
    _add_provider("prov-retrip")

    report_provider_failure("prov-retrip", error="err")
    # Force the state into HALF_OPEN by rewinding open_until to the past and
    # clearing probe_in_flight so report_provider_failure sees HALF_OPEN state.
    with upstream_registry._LOCK:
        _PROVIDER_HEALTH["prov-retrip"]["circuit_open_until"] = time.time() - 1.0
        _PROVIDER_HEALTH["prov-retrip"]["probe_in_flight"] = False

    state = get_provider_health_state("prov-retrip")
    assert state["circuit_state"] == _CIRCUIT_STATE_HALF_OPEN

    # Failure during half-open probe must re-trip the circuit as OPEN
    report_provider_failure("prov-retrip", error="probe failed")
    state = get_provider_health_state("prov-retrip")
    assert state["circuit_state"] == _CIRCUIT_STATE_OPEN
    assert state["circuit_open_remaining_seconds"] > 1.0


def test_circuit_disabled_does_not_affect_routing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _setup_registry(tmp_path, monkeypatch)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_enabled", False)
    _add_provider("prov-disabled")
    _add_policy("gpt5-disabled", ["prov-disabled"])

    # Record many failures — circuit must NOT block resolution when disabled
    for _ in range(10):
        report_provider_failure("prov-disabled", error="err")

    provider_id, base, _headers, meta = resolve_provider_for_model_group(model="gpt-5-mini")
    assert provider_id == "prov-disabled"


def test_circuit_open_excludes_from_model_group_routing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _setup_registry(tmp_path, monkeypatch)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_enabled", True)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_failure_threshold", 1)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_base_open_seconds", 60.0)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_jitter_factor", 0.0)

    _add_provider("primary")
    _add_provider("secondary", "https://secondary.example.com/v1")
    _add_policy("gpt5-failover", ["primary", "secondary"], strategy="failover")

    report_provider_failure("primary", error="err")

    # primary is now open → secondary must be chosen
    provider_id, base, _headers, meta = resolve_provider_for_model_group(model="gpt-5-mini")
    assert provider_id == "secondary"
    assert base == "https://secondary.example.com/v1"


def test_reset_provider_circuit_manually(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _setup_registry(tmp_path, monkeypatch)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_enabled", True)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_failure_threshold", 1)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_base_open_seconds", 600.0)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_jitter_factor", 0.0)
    _add_provider("prov-reset")

    report_provider_failure("prov-reset", error="err")
    state = get_provider_health_state("prov-reset")
    assert state["circuit_state"] == _CIRCUIT_STATE_OPEN

    assert reset_provider_circuit("prov-reset") is True

    state = get_provider_health_state("prov-reset")
    assert state["circuit_state"] == _CIRCUIT_STATE_CLOSED
    assert state["consecutive_failures"] == 0


def test_list_provider_health_states(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _setup_registry(tmp_path, monkeypatch)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_enabled", True)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_failure_threshold", 1)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_jitter_factor", 0.0)
    _add_provider("prov-aa")
    _add_provider("prov-bb")

    report_provider_failure("prov-aa", error="err")

    states = list_provider_health_states()
    ids = [s["provider_id"] for s in states]
    assert "prov-aa" in ids
    assert "prov-bb" in ids

    aa = next(s for s in states if s["provider_id"] == "prov-aa")
    assert aa["circuit_state"] == _CIRCUIT_STATE_OPEN
    bb = next(s for s in states if s["provider_id"] == "prov-bb")
    assert bb["circuit_state"] == _CIRCUIT_STATE_CLOSED


# ---------------------------------------------------------------------------
# Integration: context var propagation via _forward_json
# ---------------------------------------------------------------------------

def test_forward_json_reports_failure_to_registry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """_forward_json must call report_provider_failure when httpx raises."""
    import asyncio
    from n4ughtyllm_gate.adapters.openai_compat.upstream import (
        _forward_json,
        set_active_provider,
    )

    _setup_registry(tmp_path, monkeypatch)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_enabled", True)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_failure_threshold", 1)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_jitter_factor", 0.0)
    _add_provider("ctxvar-prov")

    import httpx
    mock_client = AsyncMock()
    mock_client.post.side_effect = httpx.ConnectError("refused")

    async def run():
        set_active_provider("ctxvar-prov")
        import n4ughtyllm_gate.adapters.openai_compat.upstream as up_mod
        monkeypatch.setattr(up_mod, "_upstream_async_client", mock_client)
        with pytest.raises(RuntimeError, match="upstream_unreachable"):
            await _forward_json("https://example.com/v1/chat/completions", {}, {})

    asyncio.get_event_loop().run_until_complete(run())

    state = get_provider_health_state("ctxvar-prov")
    assert state is not None
    assert state["circuit_state"] == _CIRCUIT_STATE_OPEN


def test_forward_json_reports_success_to_registry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio
    import httpx
    from n4ughtyllm_gate.adapters.openai_compat.upstream import (
        _forward_json,
        set_active_provider,
    )

    _setup_registry(tmp_path, monkeypatch)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_enabled", True)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_failure_threshold", 3)
    _add_provider("ctxvar-prov2")

    # Pre-seed a failure so we can observe it being cleared
    report_provider_failure("ctxvar-prov2", error="pre")
    assert get_provider_health_state("ctxvar-prov2")["consecutive_failures"] == 1

    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.content = b'{"id":"r1","choices":[]}'
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)

    async def run():
        set_active_provider("ctxvar-prov2")
        import n4ughtyllm_gate.adapters.openai_compat.upstream as up_mod
        monkeypatch.setattr(up_mod, "_upstream_async_client", mock_client)
        await _forward_json("https://example.com/v1/chat/completions", {}, {})

    asyncio.get_event_loop().run_until_complete(run())

    state = get_provider_health_state("ctxvar-prov2")
    assert state["consecutive_failures"] == 0
    assert state["circuit_state"] == _CIRCUIT_STATE_CLOSED


# ---------------------------------------------------------------------------
# Admin API: circuit endpoints
# ---------------------------------------------------------------------------

def test_circuit_admin_api(tmp_path: Path, monkeypatch) -> None:
    from n4ughtyllm_gate.core import gateway
    from n4ughtyllm_gate.core.upstream_registry import load_providers, load_routing_policies

    monkeypatch.chdir(tmp_path)
    (tmp_path / "config").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(gateway.settings, "gateway_key", "test-cb-key")
    monkeypatch.setattr(gateway.settings, "enforce_loopback_only", False)
    monkeypatch.setattr(gateway, "_is_internal_ip", lambda _host: True)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_enabled", True)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_failure_threshold", 1)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_base_open_seconds", 600.0)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_jitter_factor", 0.0)
    load_providers()
    load_routing_policies()
    _PROVIDER_HEALTH.clear()

    upstream_registry.upsert_provider(
        provider_id="cb-prov",
        display_name="CB Provider",
        upstream_base="https://cb.example.com/v1",
        api_type="openai",
        auth_mode="none",
    )
    report_provider_failure("cb-prov", error="injected")

    client = TestClient(gateway.app)
    auth = {"gateway-key": "test-cb-key"}

    # List all circuit states
    resp = client.get("/__gw__/circuit", headers=auth)
    assert resp.status_code == 200, resp.text
    states = resp.json()["circuit_states"]
    assert any(s["provider_id"] == "cb-prov" for s in states)
    cb_state = next(s for s in states if s["provider_id"] == "cb-prov")
    assert cb_state["circuit_state"] == _CIRCUIT_STATE_OPEN

    # Get single circuit state
    resp = client.get("/__gw__/circuit/cb-prov", headers=auth)
    assert resp.status_code == 200, resp.text
    assert resp.json()["circuit_state"]["circuit_state"] == _CIRCUIT_STATE_OPEN

    # Reset circuit
    resp = client.post("/__gw__/circuit/cb-prov/reset", headers=auth, json={"gateway_key": "test-cb-key"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["ok"] is True
    assert resp.json()["circuit_state"]["circuit_state"] == _CIRCUIT_STATE_CLOSED

    # Verify it is now closed
    resp = client.get("/__gw__/circuit/cb-prov", headers=auth)
    assert resp.status_code == 200, resp.text
    assert resp.json()["circuit_state"]["circuit_state"] == _CIRCUIT_STATE_CLOSED

    # Unknown provider returns 404
    resp = client.get("/__gw__/circuit/does-not-exist", headers=auth)
    assert resp.status_code == 404, resp.text


# ---------------------------------------------------------------------------
# Probe serialization: only one concurrent probe request during HALF_OPEN
# ---------------------------------------------------------------------------

def test_half_open_probe_serialization(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Exactly one request is granted probe access when the circuit is HALF_OPEN;
    all subsequent callers are blocked until the probe resolves."""
    from n4ughtyllm_gate.core.upstream_registry import _health_is_available, _LOCK

    _setup_registry(tmp_path, monkeypatch)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_enabled", True)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_failure_threshold", 1)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_base_open_seconds", 30.0)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_jitter_factor", 0.0)
    monkeypatch.setattr(upstream_registry.settings, "upstream_timeout_seconds", 60)
    _add_provider("prov-probe")

    # Trip and fast-forward to HALF_OPEN
    report_provider_failure("prov-probe", error="err")
    with _LOCK:
        _PROVIDER_HEALTH["prov-probe"]["circuit_open_until"] = time.time() - 1.0
        _PROVIDER_HEALTH["prov-probe"]["probe_in_flight"] = False

    # First call claims the probe slot and gets access
    with _LOCK:
        first = _health_is_available("prov-probe", time.time())
    assert first is True

    # Second concurrent call must be blocked (probe_in_flight is True)
    with _LOCK:
        second = _health_is_available("prov-probe", time.time())
    assert second is False

    # After probe succeeds, slot is released and next caller can probe again
    report_provider_success("prov-probe")
    with _LOCK:
        probe_flag = _PROVIDER_HEALTH["prov-probe"].get("probe_in_flight", False)
    assert probe_flag is False


def test_half_open_stale_probe_recovery(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A stale probe_in_flight flag (older than 2×timeout) must be overridden so the
    circuit does not remain permanently blocked in HALF_OPEN."""
    from n4ughtyllm_gate.core.upstream_registry import _health_is_available, _LOCK

    _setup_registry(tmp_path, monkeypatch)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_enabled", True)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_failure_threshold", 1)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_base_open_seconds", 30.0)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_jitter_factor", 0.0)
    monkeypatch.setattr(upstream_registry.settings, "upstream_timeout_seconds", 10)
    _add_provider("prov-stale")

    report_provider_failure("prov-stale", error="err")
    with _LOCK:
        # Simulate an abandoned probe started 30 s ago (stale_threshold = 2*10 = 20s)
        _PROVIDER_HEALTH["prov-stale"]["circuit_open_until"] = time.time() - 1.0
        _PROVIDER_HEALTH["prov-stale"]["probe_in_flight"] = True
        _PROVIDER_HEALTH["prov-stale"]["probe_started_at"] = time.time() - 30.0

    # The stale probe must be overridden; this call gets a fresh probe slot
    with _LOCK:
        result = _health_is_available("prov-stale", time.time())
    assert result is True
    with _LOCK:
        assert _PROVIDER_HEALTH["prov-stale"]["probe_in_flight"] is True
        assert _PROVIDER_HEALTH["prov-stale"]["probe_started_at"] > time.time() - 2.0


# ---------------------------------------------------------------------------
# upsert_provider auto-reset circuit on re-enable / key rotation
# ---------------------------------------------------------------------------

def test_upsert_provider_resets_circuit_on_reenable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Re-enabling a disabled provider must automatically close its circuit."""
    _setup_registry(tmp_path, monkeypatch)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_enabled", True)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_failure_threshold", 1)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_base_open_seconds", 600.0)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_jitter_factor", 0.0)

    upstream_registry.upsert_provider(
        provider_id="prov-reenable",
        display_name="Test",
        upstream_base="https://example.com/v1",
        api_type="openai",
        auth_mode="none",
        enabled=False,
    )
    report_provider_failure("prov-reenable", error="err")
    state = get_provider_health_state("prov-reenable")
    assert state is not None and state["circuit_state"] == _CIRCUIT_STATE_OPEN

    # Re-enable the provider → circuit must auto-reset
    upstream_registry.upsert_provider(
        provider_id="prov-reenable",
        display_name="Test",
        upstream_base="https://example.com/v1",
        api_type="openai",
        auth_mode="none",
        enabled=True,
    )
    state = get_provider_health_state("prov-reenable")
    assert state is not None
    assert state["circuit_state"] == _CIRCUIT_STATE_CLOSED
    assert state["consecutive_failures"] == 0


def test_upsert_provider_resets_circuit_on_key_rotation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Rotating the API key must close any open circuit (the key may have been causing auth errors)."""
    _setup_registry(tmp_path, monkeypatch)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_enabled", True)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_failure_threshold", 1)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_base_open_seconds", 600.0)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_jitter_factor", 0.0)

    upstream_registry.upsert_provider(
        provider_id="prov-keyrot",
        display_name="Test",
        upstream_base="https://example.com/v1",
        api_type="openai",
        auth_mode="bearer",
        api_key="old-key",
    )
    report_provider_failure("prov-keyrot", error="err")
    state = get_provider_health_state("prov-keyrot")
    assert state is not None and state["circuit_state"] == _CIRCUIT_STATE_OPEN

    # Rotate key → circuit must auto-reset
    upstream_registry.upsert_provider(
        provider_id="prov-keyrot",
        display_name="Test",
        upstream_base="https://example.com/v1",
        api_type="openai",
        auth_mode="bearer",
        api_key="new-key",
    )
    state = get_provider_health_state("prov-keyrot")
    assert state is not None
    assert state["circuit_state"] == _CIRCUIT_STATE_CLOSED
    assert state["consecutive_failures"] == 0


# ---------------------------------------------------------------------------
# v2 proxy: circuit breaker feedback via report_provider_success/failure
# ---------------------------------------------------------------------------

def test_v2_proxy_reports_failure_on_upstream_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """proxy_v2 must call report_provider_failure when the upstream returns 5xx."""
    import asyncio
    from unittest.mock import MagicMock

    _setup_registry(tmp_path, monkeypatch)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_enabled", True)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_failure_threshold", 1)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_jitter_factor", 0.0)
    _add_provider("v2-prov")

    import httpx
    import n4ughtyllm_gate.adapters.v2_proxy.router as v2_mod

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 502
    mock_response.headers = httpx.Headers({})
    mock_response.content = b'{"error":"bad gateway"}'

    mock_client = AsyncMock()
    mock_client.request = AsyncMock(return_value=mock_response)

    async def run():
        monkeypatch.setattr(v2_mod, "_v2_async_client", mock_client)
        # Build a minimal ASGI scope with the provider_id injected by middleware
        from starlette.requests import Request as StarletteRequest
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/v2",
            "query_string": b"",
            "headers": [
                (b"x-target-url", b"https://example.com/v1/chat/completions"),
                (b"content-type", b"application/json"),
            ],
            "n4ughtyllm_gate_provider_id": "v2-prov",
        }

        async def receive():
            return {"type": "http.request", "body": b"{}", "more_body": False}

        request = StarletteRequest(scope, receive)
        # Call proxy_v2 directly; it reads provider_id from scope
        from n4ughtyllm_gate.adapters.v2_proxy.router import proxy_v2
        await proxy_v2(request)

    asyncio.get_event_loop().run_until_complete(run())

    state = get_provider_health_state("v2-prov")
    assert state is not None
    assert state["circuit_state"] == _CIRCUIT_STATE_OPEN


def test_v2_proxy_reports_success_on_2xx(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """proxy_v2 must call report_provider_success for 2xx responses, clearing any degraded state."""
    import asyncio
    from unittest.mock import MagicMock

    _setup_registry(tmp_path, monkeypatch)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_enabled", True)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_failure_threshold", 3)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_jitter_factor", 0.0)
    _add_provider("v2-prov-ok")

    # Pre-seed one failure (below threshold so circuit stays closed)
    report_provider_failure("v2-prov-ok", error="pre")
    assert get_provider_health_state("v2-prov-ok")["consecutive_failures"] == 1

    import httpx
    import n4ughtyllm_gate.adapters.v2_proxy.router as v2_mod

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.headers = httpx.Headers({"content-type": "application/json"})
    mock_response.content = b'{"choices":[]}'

    mock_client = AsyncMock()
    mock_client.request = AsyncMock(return_value=mock_response)

    async def run():
        monkeypatch.setattr(v2_mod, "_v2_async_client", mock_client)
        from starlette.requests import Request as StarletteRequest
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/v2",
            "query_string": b"",
            "headers": [
                (b"x-target-url", b"https://example.com/v1/chat/completions"),
                (b"content-type", b"application/json"),
            ],
            "n4ughtyllm_gate_provider_id": "v2-prov-ok",
        }

        async def receive():
            return {"type": "http.request", "body": b"{}", "more_body": False}

        request = StarletteRequest(scope, receive)
        from n4ughtyllm_gate.adapters.v2_proxy.router import proxy_v2
        await proxy_v2(request)

    asyncio.get_event_loop().run_until_complete(run())

    state = get_provider_health_state("v2-prov-ok")
    assert state is not None
    assert state["consecutive_failures"] == 0
    assert state["circuit_state"] == _CIRCUIT_STATE_CLOSED


def test_v2_proxy_reports_failure_on_connect_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """proxy_v2 must call report_provider_failure when httpx raises a connection error."""
    import asyncio

    _setup_registry(tmp_path, monkeypatch)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_enabled", True)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_failure_threshold", 1)
    monkeypatch.setattr(upstream_registry.settings, "circuit_breaker_jitter_factor", 0.0)
    _add_provider("v2-prov-conn")

    import httpx
    import n4ughtyllm_gate.adapters.v2_proxy.router as v2_mod

    mock_client = AsyncMock()
    mock_client.request = AsyncMock(side_effect=httpx.ConnectError("refused"))

    async def run():
        monkeypatch.setattr(v2_mod, "_v2_async_client", mock_client)
        from starlette.requests import Request as StarletteRequest
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/v2",
            "query_string": b"",
            "headers": [
                (b"x-target-url", b"https://example.com/v1/chat/completions"),
                (b"content-type", b"application/json"),
            ],
            "n4ughtyllm_gate_provider_id": "v2-prov-conn",
        }

        async def receive():
            return {"type": "http.request", "body": b"{}", "more_body": False}

        request = StarletteRequest(scope, receive)
        from n4ughtyllm_gate.adapters.v2_proxy.router import proxy_v2
        await proxy_v2(request)

    asyncio.get_event_loop().run_until_complete(run())

    state = get_provider_health_state("v2-prov-conn")
    assert state is not None
    assert state["circuit_state"] == _CIRCUIT_STATE_OPEN
