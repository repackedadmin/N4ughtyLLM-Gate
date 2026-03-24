"""Observability package — metrics, tracing, and structured logging."""

from n4ughtyllm_gate.observability.logging import configure_logging, log_event
from n4ughtyllm_gate.observability.metrics import (
    emit_counter,
    get_metrics_app,
    inc_confirmation,
    inc_filter_hit,
    inc_request,
    inc_upstream_error,
    observe_pipeline_duration,
    observe_request_duration,
    set_pending_confirmations,
)
from n4ughtyllm_gate.observability.tracing import (
    get_tracer,
    init_tracing,
    trace,
    trace_span,
    traced,
)

__all__ = [
    "configure_logging",
    "emit_counter",
    "get_metrics_app",
    "get_tracer",
    "inc_confirmation",
    "inc_filter_hit",
    "inc_request",
    "inc_upstream_error",
    "init_tracing",
    "log_event",
    "observe_pipeline_duration",
    "observe_request_duration",
    "set_pending_confirmations",
    "trace",
    "trace_span",
    "traced",
]
