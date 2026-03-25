# N4ughtyLLM Gate — Core Capabilities

*Last updated: March 24, 2026.*

---

## API Endpoints

### OpenAI-Compatible (full security pipeline)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/v1/chat/completions` | Chat completions with full request + response security pipeline |
| `POST` | `/v1/responses` | Responses API with full request + response security pipeline |

**Cross-format compatibility:**
- A Responses-style payload (`input`) sent to `/v1/chat/completions` is forwarded upstream as `/v1/responses` and the result is converted back to Chat Completions format.
- A Chat-style payload (`messages`) sent to `/v1/responses` is converted to Responses format before forwarding, and the response is converted back.

### Provider & Token Routes

| Pattern | Description |
|---------|-------------|
| `/v1/__gw__/p/{provider_id}/...` | Route to a registered provider by id (with full security pipeline) |
| `/v2/__gw__/p/{provider_id}/...` | Same, for v2 generic proxy paths |
| `/v1/__gw__/t/{token}/...` | Legacy token-bound route (backward compatible) |
| `/v2/__gw__/t/{token}/...` | Legacy token-bound v2 proxy route |

Filter mode suffixes append `__redact` (redaction-only) or `__passthrough` (bypass all filters) to the provider/token segment.

### Generic Pass-through

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/v1/{subpath}` | Forward any other `/v1/` path to upstream without running the security filter pipeline. Use for non-OpenAI providers (e.g. `/v1/messages` for Claude). |
| `ANY` | `/v2/__gw__/t/{token}/proxy` | Generic HTTP proxy requiring `x-target-url` header |

### Info & Health

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Liveness probe (no auth, no logging) |
| `GET` | `/` | Gateway info: name, version, status, uptime, routes |
| `GET` | `/metrics` | Prometheus metrics (requires `observability` extra) |

---

## Admin API

All admin endpoints require the gateway key (from `config/n4ughtyllm_gate_gateway.key`) in either a `gateway-key` request header or the JSON body field `gateway_key`. They are restricted to internal network clients (loopback or private IP range).

### Token Management (Legacy)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/__gw__/register` | Register a new upstream → token mapping |
| `POST` | `/__gw__/lookup` | Look up a token by upstream URL |
| `POST` | `/__gw__/unregister` | Unregister by upstream URL |
| `POST` | `/__gw__/add` | Add/update token with allowlist keys |
| `POST` | `/__gw__/remove` | Remove a token directly |

### Provider Registry

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/__gw__/providers` | Create or update a provider (encrypted credential storage) |
| `GET` | `/__gw__/providers` | List all providers (`?include_disabled=false` to filter) |
| `GET` | `/__gw__/providers/{provider_id}` | Fetch one provider (api_key is never returned) |
| `DELETE` | `/__gw__/providers/{provider_id}` | Delete a provider |
| `GET` | `/__gw__/providers/{provider_id}/health` | Run a live health probe against the provider |

**Provider fields:**

| Field | Description |
|-------|-------------|
| `provider_id` | Unique identifier (slugified, max 64 chars) |
| `display_name` | Human-readable label |
| `upstream_base` | Base URL (e.g. `https://api.openai.com/v1`) |
| `api_type` | `openai` \| `anthropic` \| `gemini` \| `custom` |
| `api_key` | API key (write-only; stored encrypted) |
| `auth_mode` | `bearer` \| `x-api-key` \| `none` |
| `auth_header_name` | Header name override (default: `authorization`) |
| `model_allowlist` | List of model names this provider accepts (empty = all) |
| `default_headers` | Extra headers to inject on every request |
| `priority` | Lower = higher priority in failover selection |
| `timeout_seconds` | Per-request timeout override |
| `health_path` | Health probe path (default: `/models`) |

### Model-Group Routing Policies

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/__gw__/routing-policies` | Create or update a model-group routing policy |
| `GET` | `/__gw__/routing-policies` | List all policies |
| `GET` | `/__gw__/routing-policies/{group_id}` | Fetch one policy |
| `DELETE` | `/__gw__/routing-policies/{group_id}` | Delete a policy |
| `GET` | `/__gw__/routing/resolve?model=...` | Preview which provider would be selected for a model |

**Policy fields:**

| Field | Description |
|-------|-------------|
| `group_id` | Unique identifier |
| `model_patterns` | Glob patterns matched against the request model name (e.g. `gpt-5*`, `o*`) |
| `strategy` | `failover` \| `weighted` |
| `providers` | List of `{provider_id, weight, priority}` objects |
| `enabled` | Whether the policy is active |

**Strategies:**
- `failover` — pick the highest-priority provider whose circuit is closed and model is allowed
- `weighted` — distribute requests across healthy providers by weight; selection is deterministic per (tenant, model, request_id) to minimize session splits

### Circuit Breaker

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/__gw__/circuit` | List circuit state for all registered providers |
| `GET` | `/__gw__/circuit/{provider_id}` | Single provider circuit state |
| `POST` | `/__gw__/circuit/{provider_id}/reset` | Force-close a tripped circuit (admin override) |

**Circuit states:** `closed` → `open` → `half_open` → `closed`

---

## Native Upstream Engine

### Credential Security
- Provider API keys are encrypted at rest using Fernet symmetric encryption before writing to `config/upstream_providers.json`.
- The `api_key` field is write-only; it is never returned in API responses (`has_api_key: true/false` is returned instead).

### Circuit Breaker (Runtime Failure Feedback)

Every upstream HTTP call updates the provider's circuit state automatically via a `ContextVar` threaded through the async forwarding pipeline — no code changes at call sites.

| Condition | Action |
|-----------|--------|
| HTTP `< 500` response | `report_provider_success` → resets failure counter; may close circuit |
| HTTP `>= 500` response | `report_provider_failure` → increments failure counter |
| `httpx.HTTPError` (connect/timeout) | `report_provider_failure` → increments failure counter |
| Failures reach threshold | Circuit **trips open**; provider excluded from routing pools |
| Open window expires | Circuit enters **half-open**; one probe request allowed |
| Probe succeeds (≥ success_threshold times) | Circuit **closes** |
| Probe fails | Circuit **re-trips** with extended exponential backoff |

**Backoff formula:** `open_seconds = min(max, base × 2^(failures − threshold)) + jitter`

Health-check calls (`GET /__gw__/providers/{id}/health`) also feed into the same circuit state.

### Hot Reload
File-based watcher polls every 30 seconds for changes to:
- `config/upstream_providers.json`
- `config/upstream_routing.json`
- `config/.env`
- `config/security_filters.yaml`
- `config/gw_tokens.json`
- All policy YAML files

On change, providers and routing policies reload atomically without restart.

---

## Security Pipeline

### Request Pipeline (in order)

1. **PII Redaction** — 50+ pattern categories; replaces matched values with placeholder tokens
2. **Exact-Value Redaction** — hash-keyed exact-match redaction for arbitrary secrets registered via API
3. **Request Sanitizer** — prompt injection detection (regex + TF-IDF), system prompt guard, untrusted content guard
4. **RAG Poison Guard** — detects and blocks poisoned context injection in retrieval-augmented requests

### Response Pipeline (in order)

1. **Injection Detector** — multi-layer: regex patterns + TF-IDF semantic classifier
2. **Anomaly Detector** — encoding attacks, Unicode abuse, obfuscated payload detection
3. **Privilege Guard** — detects privilege escalation attempts in model output
4. **Tool Call Guard** — validates and sanitizes tool call parameters and invocations
5. **Restoration** — replaces redaction placeholders with original values where safe
6. **Post-Restore Guard** — re-scans restored content for injection or exfiltration patterns
7. **Output Sanitizer** — applies final block/sanitize/pass decision based on cumulative risk score

### Dangerous Content Actions

| Risk Level | Action | Examples |
|------------|--------|----------|
| **Safe** | Pass through | Normal conversation |
| **Low risk** | Chunked-hyphen obfuscation | `dev-elo-per mes-sag-e` |
| **High risk / dangerous commands** | Replace with safety marker | SQL injection, reverse shell, `rm -rf` |
| **Spam noise** | Replace with `[N4ughtyLLM Gate:spam-content-removed]` | Gambling/porn spam, fake tool calls |

### Filter Modes (per-request override)

| Mode | Behaviour |
|------|-----------|
| _(none)_ | Full security pipeline |
| `redact` (suffix `__redact` or header `x-n4ughtyllm-gate-filter-mode: redact`) | Redaction-only; no injection/command filters |
| `passthrough` (suffix `__passthrough` or header `x-n4ughtyllm-gate-filter-mode: passthrough`) | Skip all filters; forward verbatim |

### Security Levels

| Level | Behaviour |
|-------|-----------|
| `low` | Mostly redaction + extreme block only |
| `medium` (default) | High-risk patterns + redaction |
| `high` | Full detection at strictest thresholds |

---

## PII Redaction Coverage (50+ Categories)

| Category | Examples |
|----------|----------|
| **Credentials** | API keys (OpenAI, AWS, GitHub, Slack), JWT, cookies, PEM private keys |
| **Financial** | Credit cards, IBAN, SWIFT/BIC, bank routing & account numbers |
| **Network & Devices** | IPv4/IPv6, MAC, IMEI/IMSI, device serial numbers |
| **Identity & Compliance** | SSN, tax IDs, passport, driver's license, medical record numbers |
| **Crypto** | BTC/ETH/SOL/TRON wallet addresses, WIF/xprv/xpub, seed phrases, exchange API keys |
| **Infrastructure** (relaxed mode) | Hostnames, OS versions, container IDs, K8s resources, internal URLs |

---

## Configuration Reference

Full settings are in [`config/.env.example`](config/.env.example). All variable names use the `N4UGHTYLLM_GATE_` prefix.

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST` | `127.0.0.1` | Listen address |
| `PORT` | `18080` | Listen port |
| `UPSTREAM_BASE_URL` | _(empty)_ | Default upstream (single-provider fast path) |
| `SECURITY_LEVEL` | `medium` | `low` / `medium` / `high` |
| `RISK_SCORE_THRESHOLD` | `0.7` | Risk threshold 0–1; overridden by policy YAML |
| `STORAGE_BACKEND` | `sqlite` | `sqlite` / `redis` / `postgres` |
| `ENFORCE_LOOPBACK_ONLY` | `true` | Restrict to loopback; set `false` for Docker |

### Security Filters

| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLE_REDACTION` | `true` | PII redaction |
| `ENABLE_INJECTION_DETECTOR` | `true` | Prompt injection detection |
| `ENABLE_PRIVILEGE_GUARD` | `true` | Privilege escalation detection |
| `ENABLE_TOOL_CALL_GUARD` | `true` | Tool call validation |
| `ENABLE_RAG_POISON_GUARD` | `true` | RAG context injection detection |
| `STRICT_COMMAND_BLOCK_ENABLED` | `false` | Hard-block on dangerous command match |
| `FILTER_PIPELINE_TIMEOUT_S` | `90.0` | Max seconds for filter pipeline |
| `REQUEST_PIPELINE_TIMEOUT_ACTION` | `block` | `block` or `pass` on timeout |

### Upstream & Circuit Breaker

| Variable | Default | Description |
|----------|---------|-------------|
| `UPSTREAM_TIMEOUT_SECONDS` | `600.0` | Per-request upstream timeout |
| `UPSTREAM_MAX_CONNECTIONS` | `300` | HTTP connection pool size |
| `CIRCUIT_BREAKER_ENABLED` | `true` | Enable runtime circuit breaker |
| `CIRCUIT_BREAKER_FAILURE_THRESHOLD` | `3` | Consecutive failures before trip |
| `CIRCUIT_BREAKER_BASE_OPEN_SECONDS` | `10.0` | Minimum open window (backoff base) |
| `CIRCUIT_BREAKER_MAX_OPEN_SECONDS` | `300.0` | Maximum open window cap |
| `CIRCUIT_BREAKER_SUCCESS_THRESHOLD` | `2` | Probe successes to close in half-open |
| `CIRCUIT_BREAKER_JITTER_FACTOR` | `0.1` | Jitter fraction applied to open window |

### Auth & Rate Limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLE_REQUEST_HMAC_AUTH` | `false` | HMAC signature verification |
| `TRUSTED_PROXY_IPS` | _(empty)_ | Comma-separated IPs/CIDRs trusted to set `X-Forwarded-For` |
| `ADMIN_RATE_LIMIT_PER_MINUTE` | `30` | Admin endpoint rate limit per IP |

---

## Deployment

### Docker Compose

```bash
docker compose up -d --build
```

Service: `n4ughtyllm_gate` on port 18080. Volumes mount `./config` for persistent state.

### Local (no Docker)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,semantic]"
uvicorn n4ughtyllm_gate.core.gateway:app --host 127.0.0.1 --port 18080 --reload
```

### Public TLS (Caddy)

See [Caddyfile.example](Caddyfile.example). Block `/__gw__/*` externally; keep admin endpoints on internal/loopback only.

### Storage Backends

| Backend | Variable | Notes |
|---------|----------|-------|
| SQLite | `STORAGE_BACKEND=sqlite` | Default; zero-config; path in `SQLITE_DB_PATH` |
| Redis | `STORAGE_BACKEND=redis` | Configure `REDIS_URL` |
| PostgreSQL | `STORAGE_BACKEND=postgres` | Configure `POSTGRES_DSN` |

---

## Web UI

Built-in admin UI at `http://localhost:18080/__ui__`.

- Login with the gateway key from `config/n4ughtyllm_gate_gateway.key`
- Edit runtime settings, security rules, and Docker Compose files
- CRUD for tokens, key rotation (gateway / proxy / Fernet)
- Real-time service status and request statistics
- Browse in-repo Markdown documentation

See [WEBUI-QUICKSTART.md](WEBUI-QUICKSTART.md) for setup and remote access via SSH tunnel.

---

## Client Integration

N4ughtyLLM Gate works as a drop-in `baseUrl` replacement for any OpenAI-compatible client.

**Provider route (recommended):**
```text
http://127.0.0.1:18080/v1/__gw__/p/{provider_id}/
```

**Token route (legacy):**
```text
http://127.0.0.1:18080/v1/__gw__/t/{token}/
```

**Direct (single upstream configured):**
```text
http://127.0.0.1:18080/v1/
```

Claude `POST /v1/messages` streaming is supported via the generic pass-through path.

For AI coding agents (Cursor, Claude Code, Codex): see [SKILL.md](SKILL.md).

For terminal/desktop clients and Claude API setup: see [OTHER_TERMINAL_CLIENTS_USAGE.md](OTHER_TERMINAL_CLIENTS_USAGE.md).
