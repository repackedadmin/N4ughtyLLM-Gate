# Repository Guidelines

## Project Structure & Module Organization
- `n4ughtyllm_gate/core`: gateway entrypoint, middleware, auth boundary, confirmation flow, and audit integration.
- `n4ughtyllm_gate/adapters`: protocol-facing handlers (`openai_compat`, `v2_proxy`, `relay_compat`).
- `n4ughtyllm_gate/filters`: request/response safety filters and policy-driven enforcement.
- `n4ughtyllm_gate/policies/rules`: YAML policy/rule sources (`default.yaml`, `security_filters.yaml`, etc.).
- `n4ughtyllm_gate/tests`: pytest suites for routing, streaming, security boundary, token rewrite, and long-context behavior.
- `config/`: runtime config (`.env`) and persisted token map (`gw_tokens.json`).
- `scripts/`: development and deployment tooling.

## Build, Test, and Development Commands
- `python -m pip install -e .[dev]`: install project + development dependencies.
- `uvicorn n4ughtyllm_gate.core.gateway:app --host 127.0.0.1 --port 18080 --reload`: run local API gateway.
- `pytest -q`: run full test suite.
- `pytest -q n4ughtyllm_gate/tests/test_gateway_boundary_access.py`: run targeted suite during focused changes.
- `docker compose up -d --build`: start N4ughtyLLM Gate (Docker service name: `n4ughtyllm_gate`). Upstream services deploy independently.

## Coding Style & Naming Conventions
- Python 3.10+ conventions, 4-space indentation, PEP 8 style, and type hints for new/changed functions.
- Naming: `snake_case` for files/functions/variables, `PascalCase` for classes, `UPPER_SNAKE_CASE` for constants.
- Keep route handlers lean; extract reusable logic into `core/`, `filters/`, or adapter helper modules.
- Follow existing structured logging keys (`request_id`, `route`, `reason`) for traceability.

## Testing Guidelines
- Framework: `pytest`.
- Place tests under `n4ughtyllm_gate/tests` with `test_*.py` naming.
- For security or routing changes, cover both allow-path and block-path behavior.
- Before submitting, run targeted tests plus `pytest -q`; summarize commands/results in PR.

## Commit & Pull Request Guidelines
- Commit style follows repo history: `fix(scope): ...`, `feat(scope): ...`, `refactor(scope): ...`, `docs: ...`.
- Use clear scopes (for example: `v2`, `gateway`, `streaming`, `docs`).
- PRs should follow `.github/pull_request_template.md`: summary, security impact, config changes, tests run, observability impact, and rollback plan.

## Security & Configuration Tips
- Never commit secrets, API keys, or production hostnames.
- Add new config behind `N4UGHTYLLM_GATE_*` env vars and document defaults in `README.md` and `config/.env.example`.
- For public ingress, block `POST /__gw__/*` externally and enforce rate limiting/HMAC where applicable.
