#!/bin/sh
# Read auto-generated proxy token from shared config volume.
# N4ughtyLLM Gate generates this file on first boot; Caddy injects it into
# X-N4ughtyLLM-Gate-Proxy-Token header so the gateway auto-authenticates requests.
TOKEN_FILE="/config/n4ughtyllm_gate_proxy_token.key"

# Wait for N4ughtyLLM Gate to generate the token (depends_on only waits for start).
for i in 1 2 3 4 5; do
    [ -f "$TOKEN_FILE" ] && break
    echo "caddy-entrypoint: waiting for $TOKEN_FILE ..."
    sleep 1
done

if [ -f "$TOKEN_FILE" ]; then
    export N4UGHTYLLM_GATE_PROXY_TOKEN
    N4UGHTYLLM_GATE_PROXY_TOKEN=$(cat "$TOKEN_FILE")
    echo "caddy-entrypoint: proxy token loaded"
else
    export N4UGHTYLLM_GATE_PROXY_TOKEN=""
    echo "caddy-entrypoint: WARNING - $TOKEN_FILE not found, proxy token disabled"
fi

exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
