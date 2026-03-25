"""Prometheus metrics for N4ughtyLLM Gate.

All functions degrade to no-ops when ``prometheus-client`` is not installed,
so the gateway works without the ``observability`` extras.
"""

from __future__ import annotations

import threading
from typing import Any

from n4ughtyllm_gate.util.logger import logger

try:
    from prometheus_client import Counter, Histogram, Gauge, REGISTRY  # noqa: F401

    _HAS_PROMETHEUS = True
except ImportError:
    _HAS_PROMETHEUS = False

# Thread-safe cache of dynamically-registered Prometheus counters for
# emit_counter().  Keys are metric names; values are Counter instances.
_dynamic_counters: dict[str, Any] = {}
_dynamic_counters_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------
if _HAS_PROMETHEUS:
    REQUEST_TOTAL = Counter(
        "n4ughtyllm_gate_requests_total",
        "Total requests processed by the gateway",
        ["route", "status"],
    )
    FILTER_HIT_TOTAL = Counter(
        "n4ughtyllm_gate_filter_hits_total",
        "Number of times a security filter triggered",
        ["filter_name", "action"],
    )
    CONFIRMATION_TOTAL = Counter(
        "n4ughtyllm_gate_confirmations_total",
        "Human-in-the-loop confirmation decisions",
        ["decision"],
    )
    UPSTREAM_ERROR_TOTAL = Counter(
        "n4ughtyllm_gate_upstream_errors_total",
        "Upstream request failures",
        ["error_type"],
    )
else:
    REQUEST_TOTAL = None  # type: ignore[assignment]
    FILTER_HIT_TOTAL = None  # type: ignore[assignment]
    CONFIRMATION_TOTAL = None  # type: ignore[assignment]
    UPSTREAM_ERROR_TOTAL = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Histograms
# ---------------------------------------------------------------------------
if _HAS_PROMETHEUS:
    REQUEST_DURATION = Histogram(
        "n4ughtyllm_gate_request_duration_seconds",
        "End-to-end request latency",
        ["route"],
        buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
    )
    PIPELINE_DURATION = Histogram(
        "n4ughtyllm_gate_pipeline_duration_seconds",
        "Filter pipeline execution time",
        ["phase"],
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
    )
else:
    REQUEST_DURATION = None  # type: ignore[assignment]
    PIPELINE_DURATION = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Gauges
# ---------------------------------------------------------------------------
if _HAS_PROMETHEUS:
    PENDING_CONFIRMATIONS = Gauge(
        "n4ughtyllm_gate_pending_confirmations",
        "Current number of pending human confirmations",
    )
else:
    PENDING_CONFIRMATIONS = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Convenience helpers (always safe to call)
# ---------------------------------------------------------------------------

def inc_request(route: str, status: int) -> None:
    """Increment the request counter."""
    if REQUEST_TOTAL is not None:
        REQUEST_TOTAL.labels(route=route, status=str(status)).inc()
    else:
        logger.debug("metric request route=%s status=%s", route, status)


def observe_request_duration(route: str, seconds: float) -> None:
    """Observe request latency."""
    if REQUEST_DURATION is not None:
        REQUEST_DURATION.labels(route=route).observe(seconds)


def inc_filter_hit(filter_name: str, action: str) -> None:
    """Increment filter hit counter."""
    if FILTER_HIT_TOTAL is not None:
        FILTER_HIT_TOTAL.labels(filter_name=filter_name, action=action).inc()


def observe_pipeline_duration(phase: str, seconds: float) -> None:
    """Observe pipeline execution time."""
    if PIPELINE_DURATION is not None:
        PIPELINE_DURATION.labels(phase=phase).observe(seconds)


def inc_confirmation(decision: str) -> None:
    """Increment confirmation counter."""
    if CONFIRMATION_TOTAL is not None:
        CONFIRMATION_TOTAL.labels(decision=decision).inc()


def inc_upstream_error(error_type: str) -> None:
    """Increment upstream error counter."""
    if UPSTREAM_ERROR_TOTAL is not None:
        UPSTREAM_ERROR_TOTAL.labels(error_type=error_type).inc()


def set_pending_confirmations(count: int) -> None:
    """Set the pending confirmations gauge."""
    if PENDING_CONFIRMATIONS is not None:
        PENDING_CONFIRMATIONS.set(count)


# Legacy interface preserved for backward compatibility.
def emit_counter(name: str, value: int = 1, labels: dict | None = None) -> None:
    """Emit a named counter increment.

    When ``prometheus-client`` is installed, the counter is registered on first
    use under the name ``n4ughtyllm_gate_<name>_total`` and incremented by
    *value*.  Label names are derived from the keys of *labels*.  Callers must
    pass the same label set on every call for a given *name*; mixing different
    label sets for the same metric name raises a ``ValueError`` from
    ``prometheus-client``.

    When Prometheus is unavailable the call is a structured debug log only.
    """
    resolved_labels = labels or {}
    if _HAS_PROMETHEUS:
        safe_name = name.replace("-", "_").replace(".", "_")
        metric_name = f"n4ughtyllm_gate_{safe_name}_total"
        label_names = sorted(resolved_labels.keys())
        with _dynamic_counters_lock:
            counter = _dynamic_counters.get(metric_name)
            if counter is None:
                try:
                    counter = Counter(
                        metric_name,
                        f"Dynamic counter: {name}",
                        label_names,
                    )
                    _dynamic_counters[metric_name] = counter
                except Exception as exc:
                    # Counter may already be registered with a different label
                    # set (programming error); fall back to log so we don't
                    # crash the request path.
                    logger.warning(
                        "emit_counter registration failed name=%s error=%s",
                        metric_name,
                        exc,
                    )
                    logger.debug(
                        "metric counter name=%s value=%s labels=%s",
                        name,
                        value,
                        resolved_labels,
                    )
                    return
        try:
            if label_names:
                counter.labels(**{k: str(resolved_labels[k]) for k in label_names}).inc(value)
            else:
                counter.inc(value)
        except Exception as exc:
            logger.warning("emit_counter increment failed name=%s error=%s", metric_name, exc)
    else:
        logger.debug(
            "metric counter name=%s value=%s labels=%s", name, value, resolved_labels
        )


def get_metrics_app():
    """Return a Starlette-compatible ASGI app that serves ``/metrics``.

    Returns ``None`` when ``prometheus-client`` is unavailable.
    """
    if not _HAS_PROMETHEUS:
        return None
    from prometheus_client import make_asgi_app  # type: ignore[import-untyped]

    return make_asgi_app()
