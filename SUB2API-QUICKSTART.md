# Sub2API with N4ughtyLLM Gate

**Prerequisite:** Install and run [Sub2API](https://github.com/Wei-Shaw/sub2api) (default port **8080**).

## Same host as the gateway

Client base URL:

```text
http://<gateway-host>:18080/v1/__gw__/t/8080
```

## Remote Sub2API

```bash
curl -X POST http://127.0.0.1:18080/__gw__/register \
  -H "Content-Type: application/json" \
  -d '{"upstream_base":"http://<remote-ip>:8080/v1","gateway_key":"<YOUR_GATEWAY_KEY>"}'
```

Then:

```text
http://<gateway-host>:18080/v1/__gw__/t/<token>
```

## Public HTTPS

See [README.md](README.md).
