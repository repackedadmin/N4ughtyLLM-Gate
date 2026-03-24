# N4ughtyLLM Gate Web UI

The gateway ships with a local Web UI for a lightweight control plane on a single machine or intranet.

## When to use it

- You run N4ughtyLLM Gate locally and want status, config, and tokens in a browser.
- You prefer not to edit `config/.env` or admin HTTP APIs by hand every time.
- You reach a remote server via SSH port forwarding.

## Starting

Use the repo launcher:

```bash
python3 n4ughtyllm_gate-local.py install
python3 n4ughtyllm_gate-local.py init-config
python3 n4ughtyllm_gate-local.py start
```

Defaults:

- Gateway: `http://127.0.0.1:18080`
- UI login: `http://127.0.0.1:18080/__ui__/login`

Common commands: `status`, `stop`, `logs`.

Manual dev run:

```bash
uvicorn n4ughtyllm_gate.core.gateway:app --host 127.0.0.1 --port 18080
```

## Login

- URL: `http://127.0.0.1:18080/__ui__/login`
- Password: contents of `config/n4ughtyllm_gate_gateway.key`

There is no default placeholder password; the file is created on first start.

Show the key:

```bash
cat config/n4ughtyllm_gate_gateway.key
```

## What the UI can do

- Service status, listen address, security level, default upstream.
- Edit main runtime settings (general, security, v2, flags, rate limits).
- CRUD security rules in `security_filters.yaml` (hot-reload on save).
- Token CRUD; key rotation for gateway / proxy / Fernet.
- Edit Docker Compose files from the UI.
- Restart the gateway (SIGTERM; with `restart: unless-stopped` in Compose it comes back).
- Browse in-repo Markdown docs.

## Security

- The UI is loopback-only by default; do not expose `__ui__` on the public internet without tight controls.
- Login uses the same gateway key as admin APIs—protect `config/n4ughtyllm_gate_gateway.key`.

## Remote access

SSH tunnel:

```bash
ssh -N -L 127.0.0.1:18080:127.0.0.1:18080 user@server
```

Then open `http://127.0.0.1:18080/__ui__` locally.

## Troubleshooting

- Blank page: check `http://127.0.0.1:18080/health`.
- Login fails: confirm `config/n4ughtyllm_gate_gateway.key` exists and paste without extra spaces.
- Remote: ensure you use the forwarded localhost URL, not the server’s public IP for `__ui__`.
