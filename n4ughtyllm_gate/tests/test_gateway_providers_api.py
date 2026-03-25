from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from n4ughtyllm_gate.core import gateway
from n4ughtyllm_gate.core.upstream_registry import load_providers, load_routing_policies


def test_provider_api_crud(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(gateway.settings, "gateway_key", "test-admin-key")
    monkeypatch.setattr(gateway.settings, "enforce_loopback_only", False)
    monkeypatch.setattr(gateway, "_is_internal_ip", lambda _host: True)
    load_providers()
    load_routing_policies()

    client = TestClient(gateway.app)
    headers = {"gateway-key": "test-admin-key"}

    create_resp = client.post(
        "/__gw__/providers",
        headers=headers,
        json={
            "provider_id": "openai-main",
            "display_name": "OpenAI Main",
            "upstream_base": "https://api.openai.com/v1",
            "api_type": "openai",
            "auth_mode": "bearer",
            "api_key": "sk-test-xyz",
            "default_headers": {"x-test": "1"},
            "gateway_key": "test-admin-key",
        },
    )
    assert create_resp.status_code == 200, create_resp.text
    payload = create_resp.json()["provider"]
    assert payload["provider_id"] == "openai-main"
    assert payload["has_api_key"] is True

    list_resp = client.get("/__gw__/providers", headers=headers)
    assert list_resp.status_code == 200, list_resp.text
    providers = list_resp.json()["providers"]
    assert providers and providers[0]["provider_id"] == "openai-main"

    get_resp = client.get("/__gw__/providers/openai-main", headers=headers)
    assert get_resp.status_code == 200, get_resp.text
    assert get_resp.json()["provider"]["display_name"] == "OpenAI Main"

    health_resp = client.get("/__gw__/providers/openai-main/health", headers=headers)
    assert health_resp.status_code == 200, health_resp.text
    assert "healthy" in health_resp.json()

    delete_resp = client.delete("/__gw__/providers/openai-main", headers=headers)
    assert delete_resp.status_code == 200, delete_resp.text

    missing_resp = client.get("/__gw__/providers/openai-main", headers=headers)
    assert missing_resp.status_code == 404, missing_resp.text


def test_routing_policy_api_crud_and_preview(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(gateway.settings, "gateway_key", "test-admin-key")
    monkeypatch.setattr(gateway.settings, "enforce_loopback_only", False)
    monkeypatch.setattr(gateway, "_is_internal_ip", lambda _host: True)
    load_providers()
    load_routing_policies()

    client = TestClient(gateway.app)
    headers = {"gateway-key": "test-admin-key"}

    provider_resp = client.post(
        "/__gw__/providers",
        headers=headers,
        json={
            "provider_id": "openai-main",
            "display_name": "OpenAI Main",
            "upstream_base": "https://api.openai.com/v1",
            "auth_mode": "none",
            "gateway_key": "test-admin-key",
        },
    )
    assert provider_resp.status_code == 200, provider_resp.text

    policy_resp = client.post(
        "/__gw__/routing-policies",
        headers=headers,
        json={
            "group_id": "gpt5-main",
            "model_patterns": ["gpt-5*"],
            "strategy": "failover",
            "providers": [{"provider_id": "openai-main", "priority": 10, "weight": 1}],
            "gateway_key": "test-admin-key",
        },
    )
    assert policy_resp.status_code == 200, policy_resp.text
    assert policy_resp.json()["model_group"]["group_id"] == "gpt5-main"

    list_resp = client.get("/__gw__/routing-policies", headers=headers)
    assert list_resp.status_code == 200, list_resp.text
    groups = list_resp.json()["model_groups"]
    assert groups and groups[0]["group_id"] == "gpt5-main"

    resolve_resp = client.get("/__gw__/routing/resolve?model=gpt-5.4", headers=headers)
    assert resolve_resp.status_code == 200, resolve_resp.text
    resolved = resolve_resp.json()
    assert resolved["provider_id"] == "openai-main"
    assert resolved["routing"]["group_id"] == "gpt5-main"

    delete_resp = client.delete("/__gw__/routing-policies/gpt5-main", headers=headers)
    assert delete_resp.status_code == 200, delete_resp.text
