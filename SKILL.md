# N4ughtyLLM Gate Agent Skill

> **What is this document?** An agent-executable skill for N4ughtyLLM Gate — an open-source LLM security gateway. It covers installation, startup, token registration, upstream configuration, and client integration on a fresh machine.

Use this on a new machine to install N4ughtyLLM Gate, start it, register tokens or configure a direct upstream, and wire clients.

## 0) What N4ughtyLLM Gate does (read first)

- LLM security gateway: request-side redaction/cleanup; response-side detection and auto-sanitization. Structured `responses` `input` (including function/tool output) is redacted before forwarding upstream.
- **Two routing modes** (both can be enabled):
  - **Token routing** (multi-tenant): each token maps to its own upstream; management calls need the gateway key.
    - v1 (LLM): `http://<host>:18080/v1/__gw__/t/<TOKEN>/...`
    - v2 (generic HTTP proxy): `http://<host>:18080/v2/__gw__/t/<TOKEN>` with header `x-target-url: <full target URL>`
  - **Direct upstream** (single user / agents): set `N4UGHTYLLM_GATE_UPSTREAM_BASE_URL=<upstream>` and call `/v1/...` without a token. v2 still requires a token path.
- **Redaction whitelist (`whitelist_key`)**: when registering a token, pass comma-separated field names (e.g. `api_key,secret,token`). Values for those fields skip PII redaction and forward verbatim. Matches JSON `"field":"value"`, `field=value`, `field:value`, and query `?field=value`.
- Admin APIs (`/__gw__/register|lookup|unregister|add|remove`) must stay on intranet/admin hosts only.

## 1) Prerequisites

```bash
uname -a
cat /etc/os-release
which docker || true
which docker-compose || true
git --version || true
python3 --version || true
```

## 2) Install Docker (Ubuntu/Debian) if missing

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo $VERSION_CODENAME) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
docker --version
docker compose version
```

Optional (no sudo for Docker):

```bash
sudo usermod -aG docker "$USER"
newgrp docker
```

## 3) Get the source

### Git

```bash
git clone https://github.com/ax128/N4ughtyLLM-Gate.git
cd N4ughtyLLM-Gate
```

### Existing tree

```bash
cd /path/to/N4ughtyLLM-Gate
```

## 4) Start with Docker (recommended)

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f n4ughtyllm_gate
```

Health:

```bash
curl -sS http://127.0.0.1:18080/health
```

## 5) Run without Docker

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e .
uvicorn n4ughtyllm_gate.core.gateway:app --host 127.0.0.1 --port 18080
```

## 6) Connect upstream LLM providers

### 6.1 Token routing (multi-tenant)

Register upstream and get a token:

```bash
# gateway_key from: cat config/n4ughtyllm_gate_gateway.key
curl -X POST http://127.0.0.1:18080/__gw__/register \
  -H "Content-Type: application/json" \
  -d '{"upstream_base":"https://your-upstream.example.com/v1","gateway_key":"<N4UGHTYLLM_GATE_GATEWAY_KEY>"}'
```

Expected:

```json
{
  "token": "Ab3k9Qx7Yp",
  "baseUrl": "http://127.0.0.1:18080/v1/__gw__/t/Ab3k9Qx7Yp"
}
```

With whitelist fields:

```bash
curl -X POST http://127.0.0.1:18080/__gw__/register \
  -H "Content-Type: application/json" \
  -d '{"upstream_base":"https://your-upstream.example.com/v1","gateway_key":"<N4UGHTYLLM_GATE_GATEWAY_KEY>","whitelist_key":["api_key","secret"]}'
```

### 6.2 Direct upstream

In `config/.env`:

```env
N4UGHTYLLM_GATE_UPSTREAM_BASE_URL=https://your-upstream.example.com/v1
```

After restart, call `/v1/...` without a token. v2 still needs `/v2/__gw__/t/<TOKEN>/...`:

```bash
curl -X POST http://127.0.0.1:18080/v1/responses \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <UPSTREAM_API_KEY>" \
  -d '{"model":"gpt-4.1-mini","input":"hello"}'
```

## 7) Verify

### Token routing

```bash
curl -X POST "http://127.0.0.1:18080/v1/__gw__/t/<TOKEN>/responses" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <UPSTREAM_API_KEY>" \
  -d '{"model":"gpt-4.1-mini","input":"hello"}'
```

### Direct upstream

```bash
curl -X POST "http://127.0.0.1:18080/v1/responses" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <UPSTREAM_API_KEY>" \
  -d '{"model":"gpt-4.1-mini","input":"hello"}'
```

## 8) Client templates

### Token routing

```yaml
provider: openai_compatible
base_url: http://127.0.0.1:18080/v1/__gw__/t/<TOKEN>
api_key: <UPSTREAM_API_KEY>
model: gpt-4.1-mini
```

### Direct upstream

```yaml
provider: openai_compatible
base_url: http://127.0.0.1:18080/v1
api_key: <UPSTREAM_API_KEY>
model: gpt-4.1-mini
```

Notes:

- Streaming clients: the gateway recovers missing `[DONE]` where needed.
- Direct mode: `base_url` does not include the token path segment.

## 9) Common operations

Lookup token:

```bash
curl -X POST http://127.0.0.1:18080/__gw__/lookup \
  -H "Content-Type: application/json" \
  -d '{"token":"<TOKEN>"}'
```

Delete token:

```bash
curl -X POST http://127.0.0.1:18080/__gw__/unregister \
  -H "Content-Type: application/json" \
  -d '{"token":"<TOKEN>"}'
```

List tokens (needs gateway key):

```bash
curl http://127.0.0.1:18080/__ui__/api/tokens \
  -H "X-Gateway-Key: <N4UGHTYLLM_GATE_GATEWAY_KEY>"
```

Logs:

```bash
docker compose logs -f n4ughtyllm_gate
```

Restart:

```bash
docker compose restart n4ughtyllm_gate
```

Upgrade:

```bash
git pull
docker compose up -d --build
```

## 10) Troubleshooting

1. Is `health` OK? `curl http://127.0.0.1:18080/health`
2. Which mode: token path `/v1/__gw__/t/<TOKEN>/...` vs direct `N4UGHTYLLM_GATE_UPSTREAM_BASE_URL`?
3. Token mode: token exists (`/__gw__/lookup`)? Upstream URL and API key correct?
4. Direct mode: `N4UGHTYLLM_GATE_UPSTREAM_BASE_URL` in `config/.env` and service restarted?
5. Check `docker compose logs -f n4ughtyllm_gate` for upstream errors, auto-sanitize, block reasons.

## 11) Security baseline

- Expose only the data plane publicly; keep admin APIs internal.
- Prefer binding to `127.0.0.1` and use a reverse proxy for external access.
- Never paste secrets (keys, tokens, cookies, private keys, mnemonics) into logs or tickets.
- Rotate `config/n4ughtyllm_gate_gateway.key` in production (replace file, restart).
- Use `whitelist_key` only for fields that truly must skip redaction.
