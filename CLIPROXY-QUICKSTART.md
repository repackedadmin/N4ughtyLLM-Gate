# CLIProxyAPI with N4ughtyLLM Gate

**Prerequisite:** Install and run [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) per its docs (default port **8317**).

## Same host as the gateway

Set the client base URL to:

```text
http://<gateway-host>:18080/v1/__gw__/t/8317
```

Pass `Authorization: Bearer <key>` as you would to CLIProxyAPI; the gateway forwards it upstream.

## Remote CLIProxyAPI

Register a token pointing at the remote upstream:

```bash
curl -X POST http://127.0.0.1:18080/__gw__/register \
  -H "Content-Type: application/json" \
  -d '{"upstream_base":"http://<remote-ip>:8317/v1","gateway_key":"<YOUR_GATEWAY_KEY>"}'
```

Use `gateway_key` from `cat config/n4ughtyllm_gate_gateway.key`.

Client base URL:

```text
http://<gateway-host>:18080/v1/__gw__/t/<token>
```

## Public HTTPS

See [README.md](README.md) (Caddy + public exposure).
