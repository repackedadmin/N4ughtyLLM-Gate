"""Request/response pipeline executor."""

from __future__ import annotations

import threading
import time
from collections.abc import Sequence
from typing import Any

from n4ughtyllm_gate.core.context import RequestContext
from n4ughtyllm_gate.core.errors import FilterRejectedError
from n4ughtyllm_gate.core.models import InternalRequest, InternalResponse
from n4ughtyllm_gate.filters.base import BaseFilter
from n4ughtyllm_gate.observability.metrics import inc_filter_hit, observe_pipeline_duration
from n4ughtyllm_gate.util.logger import logger

# Filters slower than this threshold (seconds) will emit a WARNING for diagnosis.
_SLOW_FILTER_WARN_S = 1.0

_init_log_lock = threading.Lock()
_init_logged: bool = False


def _should_log_filter_done(
    *, phase: str, is_stream: bool, report: dict[str, Any]
) -> bool:
    if phase != "request" and is_stream:
        return False
    return bool(report.get("hit"))


class Pipeline:
    def __init__(
        self,
        request_filters: Sequence[BaseFilter],
        response_filters: Sequence[BaseFilter],
    ) -> None:
        self.request_filters = list(request_filters)
        self.response_filters = list(response_filters)
        global _init_logged
        if not _init_logged:
            with _init_log_lock:
                if not _init_logged:
                    _init_logged = True
                    logger.info(
                        "pipeline initialized request_filters=%s response_filters=%s",
                        [p.name for p in self.request_filters],
                        [p.name for p in self.response_filters],
                    )

    def _run_phase(
        self,
        *,
        phase: str,
        current: Any,
        filters: list[BaseFilter],
        ctx: RequestContext,
        is_stream: bool = False,
    ) -> Any:
        phase_start = time.monotonic()
        for plugin in filters:
            if not plugin.enabled(ctx):
                continue
            t0 = time.monotonic()
            try:
                if phase == "request":
                    current = plugin.process_request(current, ctx)
                else:
                    current = plugin.process_response(current, ctx)
            except FilterRejectedError as rej:
                elapsed = time.monotonic() - t0
                reason = str(rej) or "filter_rejected"
                if phase == "request":
                    ctx.request_disposition = "block"
                else:
                    ctx.response_disposition = "block"
                ctx.disposition_reasons.append(reason)
                ctx.add_report({"filter": plugin.name, "hit": True, "action": "block", "reason": reason})
                inc_filter_hit(plugin.name, "block")
                logger.info(
                    "filter_rejected phase=%s filter=%s elapsed_s=%.3f request_id=%s reason=%s",
                    phase,
                    plugin.name,
                    elapsed,
                    ctx.request_id,
                    reason,
                )
                continue
            except Exception:
                elapsed = time.monotonic() - t0
                logger.exception(
                    "filter_error phase=%s filter=%s elapsed_s=%.3f request_id=%s",
                    phase,
                    plugin.name,
                    elapsed,
                    ctx.request_id,
                )
                ctx.add_report({"filter": plugin.name, "error": True, "hit": False})
                inc_filter_hit(plugin.name, "error")
                continue
            elapsed = time.monotonic() - t0
            report = plugin.report()
            ctx.add_report(report)
            if report.get("hit"):
                # Resolve the most severe action taken so far to label the metric.
                if ctx.request_disposition == "block" or ctx.response_disposition == "block":
                    action = "block"
                elif ctx.request_disposition == "sanitize" or ctx.response_disposition == "sanitize":
                    action = "sanitize"
                else:
                    action = "flag"
                inc_filter_hit(plugin.name, action)
            if elapsed >= _SLOW_FILTER_WARN_S:
                extra = (
                    f" output_len={len(getattr(current, 'output_text', ''))}"
                    if phase == "response"
                    else ""
                )
                logger.warning(
                    "slow_filter phase=%s filter=%s elapsed_s=%.3f request_id=%s%s",
                    phase,
                    plugin.name,
                    elapsed,
                    ctx.request_id,
                    extra,
                )
            elif _should_log_filter_done(
                phase=phase, is_stream=is_stream, report=report
            ):
                logger.debug(
                    "filter_done phase=%s filter=%s elapsed_s=%.3f request_id=%s",
                    phase,
                    plugin.name,
                    elapsed,
                    ctx.request_id,
                )
        observe_pipeline_duration(phase, time.monotonic() - phase_start)
        return current

    def run_request(self, req: InternalRequest, ctx: RequestContext) -> InternalRequest:
        return self._run_phase(
            phase="request",
            current=req,
            filters=self.request_filters,
            ctx=ctx,
        )

    def run_response(
        self, resp: InternalResponse, ctx: RequestContext
    ) -> InternalResponse:
        is_stream = (
            resp.raw.get("stream", False) if isinstance(resp.raw, dict) else False
        )
        return self._run_phase(
            phase="response",
            current=resp,
            filters=self.response_filters,
            ctx=ctx,
            is_stream=is_stream,
        )
