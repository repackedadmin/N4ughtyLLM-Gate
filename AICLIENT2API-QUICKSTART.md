# AIClient-2-API with N4ughtyLLM Gate

**Prerequisite:** Install [AIClient-2-API](https://github.com/justlovemaki/AIClient-2-API) and confirm it works (default port **3000**).

## Same host as the gateway

Client base URL:

```text
http://<gateway-ip>:18080/v1/__gw__/t/3000
```

Forward `Authorization` as usual.

## Remote AIClient-2-API

```bash
curl -X POST http://127.0.0.1:18080/__gw__/register \
  -H "Content-Type: application/json" \
  -d '{"upstream_base":"http://<remote-ip>:3000/v1","gateway_key":"<YOUR_GATEWAY_KEY>"}'
```

`gateway_key` is from `cat config/n4ughtyllm_gate_gateway.key`.

Client:

```text
http://<gateway-ip>:18080/v1/__gw__/t/<token>
```

## Caddy / public access

See [README.md](README.md). Prefer a separate hostname for the AIClient admin UI (port 3000) if you do not want it behind the gateway.
