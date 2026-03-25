# Config directory (mounted volume)

Docker mounts this directory at runtime. Some files support polled hot-reload; for production, plan a graceful restart after changes to avoid stale connections or threads.

## First start (auto-generated)

**No manual copy required:** on first Docker or local start, if policy YAML is missing here (or in the mounted rules path inside the container), the app copies built-in defaults without overwriting existing files. If `config/.env` is missing, a default is generated from `config/.env.example`.

## Two kinds of configuration

### 1. Policies and rules (YAML)

Host `./config` is mounted as the container rules directory. Missing YAML on first start is auto-filled; you can edit files manually.

| File | Purpose |
|------|---------|
| `default.yaml` | Default policy (enabled filters, `risk_threshold`) |
| `security_filters.yaml` | Per-filter rules and `action_map` |
| `strict.yaml` / `permissive.yaml` | Optional policies selected via `policy` on requests |

Default policy notes:

- `untrusted_content_guard` is enabled: wraps and scores untrusted sources (`retrieval` / `web` / `tool` / `document`, etc.).
- `tool_call_guard` is enabled: unknown tool names default to `review`; dangerous parameters default to `block`; `tool_whitelist` starts empty to avoid breaking custom tools. Tighten with an explicit whitelist if needed.

### 2. Runtime parameters (`.env`)

Controls **settings**: log level, security level, gateway key, upstream timeouts, etc.

- **Single file source:** N4ughtyLLM Gate reads `config/.env` only; a repo-root `.env` is not used at runtime.
- **First use:** copy `config/.env.example` to `config/.env`. If missing, Compose can still start with defaults (`env_file` is optional):

  ```bash
  cp config/.env.example config/.env
  ```

- Edit `config/.env`; see `config/.env.example` for all tunables.

Common variables:

| Variable | Purpose | Examples |
|----------|---------|----------|
| `N4UGHTYLLM_GATE_LOG_LEVEL` | Log level | `info` / `debug` |
| `N4UGHTYLLM_GATE_LOG_FULL_REQUEST_BODY` | Log full bodies in DEBUG | `false` / `true` |
| `N4UGHTYLLM_GATE_SECURITY_LEVEL` | `medium` (default): strict on high risk only; `low`: mostly redact; `high`: full detection | `low` / `medium` / `high` |
| `N4UGHTYLLM_GATE_ENABLE_SEMANTIC_MODULE` | Built-in TF-IDF classifier (no GPU) | `true` / `false` |
| `N4UGHTYLLM_GATE_REQUIRE_CONFIRMATION_ON_BLOCK` | **Deprecated** — approval flow removed; always auto-redact/split | `false` |
| `N4UGHTYLLM_GATE_STRICT_COMMAND_BLOCK_ENABLED` | Force block on command match | `false` / `true` |
| `N4UGHTYLLM_GATE_GATEWAY_KEY` | Optional override; default loaded from `config/n4ughtyllm_gate_gateway.key` (auto-created) | file |
| `N4UGHTYLLM_GATE_DEFAULT_POLICY` | Default policy name | `default` |
| `N4UGHTYLLM_GATE_UPSTREAM_TIMEOUT_SECONDS` | Upstream timeout | `600` |
| `N4UGHTYLLM_GATE_MAX_REQUEST_BODY_BYTES` | Max body size | `12000000` |

See the main README “Configuration” section and `config/.env.example` for the full list.

**Warning:** with `N4UGHTYLLM_GATE_LOG_LEVEL=debug` and `N4UGHTYLLM_GATE_LOG_FULL_REQUEST_BODY=true`, full bodies (including tool outputs in `responses`) are logged. Keep `false` in production.

### Observability (optional)

- With `.[observability]`, `/metrics` is exposed for Prometheus.
- OpenTelemetry provider/exporter initializes at startup; HTTP auto-instrumentation for spans is off by default.
- Configure OTLP with `OTEL_EXPORTER_OTLP_*`.
- `/metrics` has no separate auth; it follows normal network/HMAC/loopback controls.
- Without the extra, metrics and tracing no-op safely.

### 3. Token map (`gw_tokens.json`)

Tokens from `POST /__gw__/register` are stored here (override path with `N4UGHTYLLM_GATE_GW_TOKENS_PATH`). Loaded at startup; editable on disk. **Prefer one entry per `upstream_base`.** Restart to apply.

- **Default Docker Compose:** `N4UGHTYLLM_GATE_GW_TOKENS_PATH=/app/n4ughtyllm_gate/policies/rules/gw_tokens.json` with `./config` mounted there → persists as `./config/gw_tokens.json` on the host.
- Paths under `/tmp` may lose data on container restart.

### 4. Native provider registry (`upstream_providers.json`)

The gateway can manage first-party upstream providers directly (no external wrapper required).

- File path: `config/upstream_providers.json` (schema example: `config/upstream_providers.json.example`).
- Runtime APIs:
  - `POST /__gw__/providers` (create/update)
  - `GET /__gw__/providers`
  - `GET /__gw__/providers/{provider_id}`
  - `DELETE /__gw__/providers/{provider_id}`
  - `GET /__gw__/providers/{provider_id}/health`
- Route binding:
  - `/v1/__gw__/p/{provider_id}/...`
  - `/v2/__gw__/p/{provider_id}/...`
  - or header `x-n4ughtyllm-gate-provider: <provider_id>`

Provider `api_key` values are encrypted before persistence.

### 5. Model-group routing policies (`upstream_routing.json`)

Model-group policies provide automatic provider selection for direct `/v1/*` traffic when no token route, no explicit provider header, and no default upstream are set.

- File path: `config/upstream_routing.json` (schema example: `config/upstream_routing.json.example`).
- Runtime APIs:
  - `POST /__gw__/routing-policies` (create/update)
  - `GET /__gw__/routing-policies`
  - `GET /__gw__/routing-policies/{group_id}`
  - `DELETE /__gw__/routing-policies/{group_id}`
  - `GET /__gw__/routing/resolve?model=...` (preview selected provider)
- Strategies:
  - `failover`: priority-based first healthy provider wins.
  - `weighted`: weighted random selection across healthy providers.

---

### Hot reload

- Watcher polls: `config/.env`, `security_filters.yaml`, policy YAML, `gw_tokens.json`, `upstream_providers.json`, `upstream_routing.json`.
- Rules YAML changes clear caches; the next request rebuilds the filter pipeline.
- Only **some** `.env` fields hot-reload. Security-critical fields (`gateway_key`, `security_level`, `enforce_loopback_only`, HMAC settings, `trusted_proxy_ips`, `v2_block_internal_targets`, `local_ui_allow_internal_network`, etc.) require restart.
- After changes in Compose or for long-lived streams, run `docker compose restart n4ughtyllm_gate` to be safe.
