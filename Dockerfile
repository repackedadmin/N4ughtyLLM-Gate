FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    N4UGHTYLLM_GATE_INIT_STRICT=true \
    N4UGHTYLLM_GATE_BOOTSTRAP_RULES_DIR=/app/bootstrap/rules

WORKDIR /app

COPY pyproject.toml README.md /app/
# Root Markdown files for the built-in UI docs catalog (_EXCLUDED_ROOT_DOCS filters some out).
COPY *.md /app/
COPY n4ughtyllm_gate /app/n4ughtyllm_gate
# init_config copies .env and policy YAML from here into the mounted config on first start if missing.
COPY config/.env.example /app/config/.env.example
# Read-only policy templates in the image if the mounted rules dir is empty.
COPY n4ughtyllm_gate/policies/rules /app/bootstrap/rules

COPY n4ughtyllm_gate/models /app/n4ughtyllm_gate/models
COPY www /app/www

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir ".[semantic]" \
    && useradd --create-home --uid 10001 appuser \
    && mkdir -p /app/logs \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 18080

CMD ["sh", "-c", "python -m n4ughtyllm_gate.init_config && uvicorn n4ughtyllm_gate.core.gateway:app --host 0.0.0.0 --port 18080"]
