# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Breaking Changes

- **Removed `gateway_key` from the token map**
  - `gw_tokens.json` no longer stores `gateway_key`; each token binds `upstream_base` + `whitelist_key` only
  - At most one token per `upstream_base` (previously deduped by `upstream_base` + `gateway_key`)
  - Admin routes such as `/__gw__/register`, `/__gw__/add`, `/__gw__/remove`, `/__gw__/lookup`, `/__gw__/unregister` no longer persist or match `gateway_key` from the JSON body (admin calls still authenticate with `gateway_key`)
  - `register()`, `find_token()`, `update()`, `update_and_rename()` ignore a passed `gateway_key` (deprecated)
  - UI token table and edit dialog drop the “gateway key” column

- **Removed default admin password `admin123`**
  - Local UI login always uses `config/n4ughtyllm_gate_gateway.key`; no one-time default password
  - Removed `_is_admin_initialized()` / `_mark_admin_initialized()` and the `.admin_initialized` marker file

### Added

- **Tighter local UI reachability**: `N4UGHTYLLM_GATE_LOCAL_UI_ALLOW_INTERNAL_NETWORK` (default `false`)
  - By default only loopback (127.0.0.1 / ::1) may use the UI; RFC1918 clients are rejected
  - Set `true` to restore the previous “allow internal network” behavior
  - Immutable at runtime; restart required

- **Stronger v2 SSRF protection: DNS resolution**
  - Added async `_resolve_target_ips()`; block hostnames that resolve to private/internal addresses
  - DNS failure is fail-closed (block) to mitigate DNS rebinding
  - `_is_ssrf_target()` and `_extract_target_url()` are async to avoid blocking the event loop on DNS

### Fixed

- **Upstream 400 when tool `name` contains invalid characters**
  - OpenAI Responses API expects `input[].name` to match `^[a-zA-Z0-9_-]+`; non-ASCII names are rejected
  - `_sanitize_responses_input_for_upstream` normalizes `name` on `function_call` / `function` / `function_call_output` entries (invalid chars → `_`)
  - Non-function `name` fields (e.g. usernames) are left unchanged

### Added

- **Filter mode suffixes on token paths**: `__redact` and `__passthrough`
  - `token__redact`: run redaction filters only (`exact_value_redaction` / `redaction` / `restoration`), skip safety scoring
  - `token__passthrough`: skip all filters; pass request/response through
  - Unknown mode → `400 invalid_filter_mode`
  - Audit logs tag `filter_mode:redact` / `filter_mode:passthrough`
  - Port routing supports the same: `/v1/__gw__/t/8317__redact/...`

- **Request stats dashboard**: `GET /__ui__/api/stats` and UI page
  - In-memory hourly buckets, 7-day retention, thread-safe collector
  - Tracks totals, redaction replacements, dangerous-content replacements, blocks, passthrough
  - UI: summary cards plus hourly/daily tables with refresh

### Changed

- **Token generation is alphanumeric only** (`a-zA-Z0-9`), no `-` / `_`, avoiding clashes with `__` filter-mode syntax

### Fixed

- **[Critical] `tool_call_guard` `review` treated as `block` in streaming**
  - `_stream_block_reason()` blocked the stream on any `tool_call_violation` tag, ignoring `block` vs `review`
  - Normal tool calls (e.g. `apply_patch`, `write`) were replaced wholesale with the danger placeholder
  - **Fix**: stream blocking only when a `tool_call_guard:*:block` enforcement action exists; `review` no longer stops the stream

- **False positives from `tool_call_guard` on coding-tool arguments**
  - Code/diff payloads can resemble shell commands
  - Added `_CODE_CONTENT_TOOLS` allowlist (25+ tools) skipping `dangerous_param_patterns`
  - `dangerous_param` default action `block` → `review`
  - DEBUG logs for hits: tool name, pattern, matched text

- **[Critical] SSE holdback leaked separators and broke client JSON**
  - Hold-back paths yielded blank SSE lines in the wrong order; `response.completed` could precede pending text deltas
  - Clients saw `Unexpected end of JSON input`
  - **Fix**: `_suppress_next_separator` defers separators until flush; chat and responses streaming paths aligned

- **[Critical] Blocked tool call `function.arguments` was not valid JSON**
  - Placeholder was bare non-JSON text
  - **Fix**: `json.dumps({"_blocked": "…"})` style payload

- **`info_log_sanitized` could log raw dangerous tool payloads**
  - Tool-call summaries from `_extract_chat_output_text` did not redact executable-looking content
  - **Fix**: run `_looks_executable_payload_dangerous` and substitute placeholders before logging

### Changed

- **Rule tuning (fewer false positives)**
  - `dangerous_param_patterns`: `&&` / `;` / `||` / backticks only when followed by a dangerous command
  - `python` / `perl` / `ruby` / `php` only with `-c`/`-e`-style inline execution
  - `semantic_approval_patterns`: bare `delete`/`drop` → phrases like `drop table`
  - `privilege_escalation`: narrowed “read config” style patterns toward system paths
  - `tool_call_injection`: severity 9→6, action `block`→`review`, removed from non-reducible set
  - `obfuscated`: removed from non-reducible (discussing encoding is allowed to down-rank)
  - Non-reducible categories: 5→3 (`system_exfil`, `unicode_bidi`, `spam_noise`)

### Added

- **Host/infra PII redaction (request side, lenient)**
  - Nine field-labeled patterns: SYS_HOSTNAME, SYS_USERNAME, SYS_OS_VERSION, SYS_KERNEL, SYS_HOME_PATH, SYS_ENV_VAR, SYS_DOCKER_ID, SYS_K8S_RESOURCE, SYS_INTERNAL_URL
  - Matches `field: value` / `field=value` shapes (e.g. `hostname: prod-web-01`) to avoid casual mentions
  - SYS_HOME_PATH and SYS_INTERNAL_URL match path/URL shapes without a label

---

## [Previous]

### Breaking Changes

- **Yes/no approval flow removed permanently**
  - Dangerous content is auto-redacted or split; manual release is not supported
  - `YES_WORDS` is empty; `parse_confirmation_decision("yes")` → `"unknown"`
  - `confirmation_template` is informational only (reason, handling, event id); no yes/no lines
  - `N4UGHTYLLM_GATE_REQUIRE_CONFIRMATION_ON_BLOCK` is deprecated and behaves like `false`
  - Sending `yes cfm-xxx--act-yyy` yields a “approval disabled” notice
  - Policy summary: clean → pass through; mild risk → hyphen chunking; severe → fixed placeholder; spam → `[N4ughtyLLM Gate:spam-content-removed]` (or localized equivalent in product copy)

### Added

- **Spam noise signal (`spam_noise`)**
  - Three spam families (gambling / adult / platform promo) with keyword lists (including non-English spam strings in rules)
  - `spam_noise` when ≥2 families hit in one message → `block`; not down-rankable as “research discussion”
  - Listed under `non_reducible_categories`

- **Structured tool-call argument scanning**
  - `InternalResponse.tool_call_content` aggregates OpenAI `function.arguments` and Anthropic `tool_use.input`
  - Response pipeline scans `output_text` + `tool_call_content` in `injection_detector` and `output_sanitizer`
  - Defensive `isinstance` handling for `choice` / `msg` / `tc` / `func` when upstream sends `null`

- **Spam + tool-injection combo rules**
  - `tool_call_with_spam` / `spam_with_tool_call` also match `functions.` namespaces
  - Rule `to_eq_functions` for forged `to=functions.xxx` calls
  - Window widened 30 → 60 characters

- **Message-level multi-script obfuscation**
  - `obfuscated` when ≥3 rare Unicode scripts appear in one message (e.g. Armenian + Gujarati + Georgian)
  - Common scripts (Latin, CJK, kana, Hangul, fullwidth digits) excluded

- **INFO logs for post-sanitize text**
  - `info_log_sanitized()` in `debug_excerpt.py` logs redacted/split summaries at INFO
  - Covers chat, responses, both stream modes, generic proxy/stream, and request-block paths
  - Default excerpt 800 chars; override with `N4UGHTYLLM_GATE_DEBUG_EXCERPT_MAX_LEN`

### Fixed

- **[Critical] Crash when upstream returns `tool_calls: null`**
  - `msg.get("tool_calls", [])` was `None` → iteration error
  - **Fix**: `msg.get("tool_calls") or []` plus nested `isinstance` guards

- **[Critical] Sanitize path did not persist rewritten response text**
  - `PostRestoreGuard` and `OutputSanitizer` computed sanitized text but did not write `resp.output_text`
  - **Fix**: both write back on sanitize disposition

- **[Critical] After “confirm”, upstream plaintext could bypass sanitization**
  - **Fix**: confirmation replay path still applies hit-fragment transforms for block/sanitize-class output

- **`disposition="sanitize"` incorrectly entered confirmation**
  - `_needs_confirmation()` treated `sanitize` like `block`
  - **Fix**: only `block` requires confirmation flow; `sanitize` returns the modified body

- **Generic proxy dropped sanitize results**
  - **Fix**: early return preserves `disposition == "sanitize"` output

### Added

- **`N4UGHTYLLM_GATE_REQUIRE_CONFIRMATION_ON_BLOCK` (later deprecated)**
  - Previously gated confirmation; now disabled everywhere
  - `_sanitize_hit_fragments()` remains the core auto-redaction helper

- **Tiered transforms for extreme commands**
  - ~45 high-risk patterns (`rm -rf`, SQLi, reverse shells, fork bombs, `curl|bash`, destructive `dd`, `mkfs`, `powershell -enc`, etc.) → full replacement placeholder; raw text not returned
  - Milder hits still use hyphen chunking
  - Sources: `anomaly_detector.command_patterns`, `sanitizer.force_block_command_patterns`, `privilege_guard.blocked_patterns`, plus hard-coded shell hazards

- **TF-IDF semantic module (phase 1)**
  - On-device TF-IDF + logistic regression (~166 KB), no GPU
  - Training: `deepset/prompt-injections` plus supplemental jailbreak/safe lines (`scripts/train_tfidf.py`)
  - Layered logic: high-confidence safe pass → high-confidence injection tag → gray zone with regex → TF-IDF dampening of regex FPs
  - `N4UGHTYLLM_GATE_ENABLE_SEMANTIC_MODULE` (default `true`)
  - Optional deps: `pip install ".[semantic]"` (scikit-learn, jieba, joblib)

### Security

- **Lowered thresholds (semantic assist, fewer false blocks)**
  - Default `security_level`: **`medium`** — most “maybe risky” phrases are not hard-blocked; focus on high severity + redaction
  - `injection_detector` scorer: `nonlinear_k` 2.2→2.0, `allow` 0.35→0.40, `review` 0.70→0.75
  - Signal severities adjusted (e.g. `direct` 7→5, `remote_content` 7→5, …)
  - `privilege_guard` floors: request 0.75→0.65, response 0.70→0.60
  - `anomaly_detector` repetition thresholds relaxed; scorer same k/allow/review shift as injection
  - `rag_poison_guard` scores lowered slightly on ingestion/retrieval/propagation
  - Level multipliers: medium ×1.30 threshold / ×0.85 floor; low ×1.60 / ×0.70
  - **Still hard-block**: `system_exfil` (10), `obfuscated` (9), `unicode_bidi` (10) regardless of level
  - `leak_check`: `block`→`review` so benign agent instructions mentioning “system prompt” / tools are not stopped outright

- **Earlier hardening (recorded)**
  - `privilege_guard`: tighter zh/en patterns so benign phrases survive
  - `output_sanitizer`: stop blocking read-only `docker ps/images/logs`
  - `request_sanitizer`: `rule_bypass` `block`→`review`

- **[Critical] `action=block` ignored under `low` security level**
  - Capped threshold prevented risk from reaching block cutoff
  - **Fix**: explicit `disposition=block` from filters that emit `block`, bypassing the soft threshold cap
  - Applies to `injection_detector` (per phase) and `privilege_guard` (request + response)

### Changed

- **Default `security_level` → `medium`**, TF-IDF on by default for fewer false positives while keeping hard blocks for exfil/obfuscation/bidi
- **`N4UGHTYLLM_GATE_ENABLE_THREAD_OFFLOAD`**: historically toggled for store I/O threading (see current `config/.env.example` / `Settings` for the default in your build)
- **`confirmation_ttl_seconds` 300→600** (legacy confirmation UX)
- **Stale `executing` confirmations**: background prune every 60s resets records stuck in `executing` >120s back to `pending` (SQLite / Redis / Postgres)

### Previous Security

- **[Critical] Fernet encryption** for redaction maps (replaces base64-only). Key at `config/n4ughtyllm_gate_fernet.key` (0600) or `N4UGHTYLLM_GATE_ENCRYPTION_KEY`; backward compatible reads
- **[Critical] Auto gateway key** when `N4UGHTYLLM_GATE_GATEWAY_KEY` unset: `secrets.token_urlsafe` persisted to `config/n4ughtyllm_gate_gateway.key` (0600); admin routes use `hmac.compare_digest`
- **Admin route auth** for register/lookup/add/remove/unregister + internal-network expectations
- **`N4UGHTYLLM_GATE_ADMIN_RATE_LIMIT_PER_MINUTE`** (default 30)
- **`N4UGHTYLLM_GATE_TRUSTED_PROXY_IPS`** (CIDR-aware XFF trust)
- **`N4UGHTYLLM_GATE_V2_BLOCK_INTERNAL_TARGETS`** blocks RFC1918, loopback, link-local, cloud metadata targets on v2
- **`N4UGHTYLLM_GATE_REQUEST_PIPELINE_TIMEOUT_ACTION`** default `block` on pipeline timeout
- **Longer random tokens** for gateway paths and bind tokens
- **Sanitized error bodies** (no stack traces to clients)
- **Regex escape fixes** in `security_rules.py` (~30 patterns)
- **`cryptography>=41`** dependency

### Changed

- **Docs aligned with implementation** (CLIProxy, v1 default upstream, v2 boundaries, bypass-host semantics, token paths, Caddy guidance)

- **Compose defaults**: base `docker-compose.yml` runs `n4ughtyllm_gate` only; `docker-compose.cliproxy.yml` adds Caddy + cli-proxy-api

### Fixed

- **[Critical] Gateway wedge: `_flatten_text` skipped Responses `function_call` items**
  - Empty flatten forced `json.dumps` of entire upstream bodies (huge `instructions`), melting CPU in filters
  - **Fix**: short summaries for `function_call` / `computer_call` / `bash` items; safe fallback extracts only `status`/`error` snippets

- **[Critical] Gateway wedge: synchronous filter pipelines on the event loop**
  - **Fix**: offload filter execution via `asyncio.to_thread` + `asyncio.wait_for` hard timeout (historically introduced at 30s; see `Settings.filter_pipeline_timeout_s` for the current default)

### Added

- **Per-filter timing logs** in `pipeline.py` (`slow_filter` warning >1s)

- **Debug excerpt controls**: `N4UGHTYLLM_GATE_DEBUG_EXCERPT_MAX_LEN`, diagnostic lines around `debug_log_original`, extra logging before `response_before_filters`

---

## Operations notes

### Pipeline / threading-related settings (check `Settings` for your version)

| Variable | Typical current default | Purpose |
|---|---|---|
| `N4UGHTYLLM_GATE_FILTER_PIPELINE_TIMEOUT_S` | `90.0` | Max seconds for filter pipelines; on timeout, response path blocks and request path may pass through (see `N4UGHTYLLM_GATE_REQUEST_PIPELINE_TIMEOUT_ACTION`) |
| `N4UGHTYLLM_GATE_ENABLE_THREAD_OFFLOAD` | `false` | When `true`, store I/O uses a thread pool to avoid blocking SQLite on the loop |
| `N4UGHTYLLM_GATE_REQUIRE_CONFIRMATION_ON_BLOCK` | `false` | **Deprecated** — approval UI removed; value ignored |

### Debug logging

- Full body logging: set `N4UGHTYLLM_GATE_DEBUG_EXCERPT_MAX_LEN=0` before start (in Docker, set in compose `environment` and restart).
- Partial increase: e.g. `N4UGHTYLLM_GATE_DEBUG_EXCERPT_MAX_LEN=20000`.
- If excerpts still truncate, inspect the `debug_excerpt` diagnostic line for `max_len_used` vs env.
