"""Background task for pending confirmation cache cleanup."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from n4ughtyllm_gate.config.settings import settings
from n4ughtyllm_gate.core.security_boundary import now_ts
from n4ughtyllm_gate.observability.metrics import set_pending_confirmations
from n4ughtyllm_gate.storage.offload import run_store_io
from n4ughtyllm_gate.util.logger import logger


class ConfirmationCacheTask:
    """Owns periodic retention cleanup for pending confirmation cache."""

    def __init__(
        self,
        *,
        prune_func: Callable[[int], int],
        count_func: Callable[[], int] | None = None,
    ) -> None:
        self._prune_func = prune_func
        self._count_func = count_func
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        if self._task is not None:
            return
        self._task = asyncio.create_task(self._run_loop(), name="n4ughtyllm_gate-confirmation-cache-prune")
        logger.info("confirmation cache task started")

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        finally:
            self._task = None
        logger.info("confirmation cache task stopped")

    async def _run_loop(self) -> None:
        interval = max(5, int(settings.pending_prune_interval_seconds))
        while True:
            try:
                current_ts = int(now_ts())
                removed = int(await run_store_io(self._prune_func, current_ts))
                if removed > 0:
                    logger.info("confirmation cache pruned removed=%s now_ts=%s", removed, current_ts)
                if self._count_func is not None:
                    try:
                        pending_count = int(await run_store_io(self._count_func))
                        set_pending_confirmations(pending_count)
                    except Exception as count_exc:  # pragma: no cover - operational guard
                        logger.debug("confirmation cache count failed: %s", count_exc)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # pragma: no cover - operational guard
                logger.warning("confirmation cache prune task failed: %s", exc)
            await asyncio.sleep(interval)
