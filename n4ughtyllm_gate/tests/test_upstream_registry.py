from __future__ import annotations

from pathlib import Path

import pytest

from n4ughtyllm_gate.core import upstream_registry


def test_upstream_registry_crud_and_resolve(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config").mkdir(parents=True, exist_ok=True)
    upstream_registry.load_providers()
    upstream_registry.load_routing_policies()

    provider = upstream_registry.upsert_provider(
        provider_id="openai-main",
        display_name="OpenAI Main",
        upstream_base="https://api.openai.com/v1",
        api_type="openai",
        api_key="sk-test-123",
        auth_mode="bearer",
        default_headers={"x-test": "1"},
        model_allowlist=["gpt-5.4"],
    )
    assert provider["provider_id"] == "openai-main"
    assert provider["has_api_key"] is True

    base, headers = upstream_registry.resolve_provider_route("openai-main", model="gpt-5.4")
    assert base == "https://api.openai.com/v1"
    assert headers["x-test"] == "1"
    assert headers["Authorization"] == "Bearer sk-test-123"

    with pytest.raises(PermissionError):
        upstream_registry.resolve_provider_route("openai-main", model="gpt-5.5")

    listed = upstream_registry.list_providers()
    assert len(listed) == 1
    assert listed[0]["provider_id"] == "openai-main"

    reloaded = upstream_registry.get_provider("openai-main")
    assert reloaded is not None
    assert reloaded["display_name"] == "OpenAI Main"

    assert upstream_registry.delete_provider("openai-main") is True
    assert upstream_registry.get_provider("openai-main") is None


@pytest.mark.asyncio
async def test_upstream_registry_health_check(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config").mkdir(parents=True, exist_ok=True)
    upstream_registry.load_providers()
    upstream_registry.load_routing_policies()

    upstream_registry.upsert_provider(
        provider_id="bad-provider",
        display_name="Bad Provider",
        upstream_base="https://127.0.0.1:1/v1",
        api_type="custom",
        api_key="",
        auth_mode="none",
    )
    result = await upstream_registry.check_provider_health("bad-provider")
    assert result["provider_id"] == "bad-provider"
    assert result["healthy"] is False


def test_upstream_registry_model_group_weighted_and_failover(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config").mkdir(parents=True, exist_ok=True)
    upstream_registry.load_providers()
    upstream_registry.load_routing_policies()

    upstream_registry.upsert_provider(
        provider_id="provider-a",
        display_name="Provider A",
        upstream_base="https://a.example.com/v1",
        api_type="openai",
        auth_mode="none",
    )
    upstream_registry.upsert_provider(
        provider_id="provider-b",
        display_name="Provider B",
        upstream_base="https://b.example.com/v1",
        api_type="openai",
        auth_mode="none",
    )

    upstream_registry.upsert_model_group_policy(
        group_id="gpt5-weighted",
        model_patterns=["gpt-5*"],
        strategy="weighted",
        providers=[
            {"provider_id": "provider-a", "weight": 9, "priority": 100},
            {"provider_id": "provider-b", "weight": 1, "priority": 100},
        ],
        enabled=True,
    )
    upstream_registry.upsert_model_group_policy(
        group_id="gpt5-failover",
        model_patterns=["gpt-5-failover*"],
        strategy="failover",
        providers=[
            {"provider_id": "provider-a", "weight": 1, "priority": 10},
            {"provider_id": "provider-b", "weight": 1, "priority": 20},
        ],
        enabled=True,
    )

    chosen: dict[str, int] = {"provider-a": 0, "provider-b": 0}
    for idx in range(120):
        provider_id, _, _, meta = upstream_registry.resolve_provider_for_model_group(
            model="gpt-5-mini",
            tenant_id="default",
            request_id=f"req-{idx}",
        )
        assert meta["group_id"] == "gpt5-weighted"
        chosen[provider_id] += 1
    assert chosen["provider-a"] > chosen["provider-b"]

    # Trip provider-a's circuit so it is excluded from failover routing
    for _ in range(3):
        upstream_registry.report_provider_failure("provider-a", error="test-induced failure")
    provider_id, base, _headers, meta = upstream_registry.resolve_provider_for_model_group(
        model="gpt-5-failover-1",
        tenant_id="default",
        request_id="failover-case",
    )
    assert provider_id == "provider-b"
    assert base == "https://b.example.com/v1"
    assert meta["group_id"] == "gpt5-failover"
