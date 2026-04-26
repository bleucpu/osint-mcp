from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..db import Database, now_iso
from ..events import Event, ingest, max_event_id, suppress_range

log = logging.getLogger("osint.watchers")


@dataclass
class WatcherResult:
    new_events: int = 0
    duplicate_events: int = 0
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class Watcher(ABC):
    """
    Base class. Subclasses implement run() which yields/returns Events.
    Identity is the watcher's `id` (e.g. 'rss:huggingface:blog'); used
    to track health and last_run in `watcher_state`.
    """

    kind: str = "unknown"

    def __init__(self, watcher_id: str, target_name: str | None):
        self.id = watcher_id
        self.target_name = target_name

    @abstractmethod
    async def run(self, db: Database) -> WatcherResult:
        ...

    async def execute(self, db: Database) -> WatcherResult:
        first_run = await _is_first_run(db, self.id)
        max_id_before = await max_event_id(db) if first_run else 0
        self._emit_sources: set[str] = set()

        await update_watcher_state(db, self, started=True)
        try:
            result = await self.run(db)
        except Exception as e:
            log.exception("watcher %s failed", self.id)
            await update_watcher_state(db, self, error=str(e))
            return WatcherResult(errors=[str(e)])

        if first_run and result.new_events > 0 and self._emit_sources:
            suppressed = 0
            for src in self._emit_sources:
                suppressed += await suppress_range(db, src, max_id_before)
            log.info(
                "watcher %s first run: suppressed %d backfill events from Discord",
                self.id, suppressed,
            )
            result.metadata["suppressed_backfill"] = suppressed

        await update_watcher_state(db, self, success=True, metadata=result.metadata)
        return result

    async def emit(self, db: Database, event: Event) -> bool:
        if not hasattr(self, "_emit_sources"):
            self._emit_sources = set()
        self._emit_sources.add(event.source)
        return await ingest(db, event)


async def _is_first_run(db: Database, watcher_id: str) -> bool:
    row = await db.fetchone(
        "SELECT last_success FROM watcher_state WHERE id = ?", (watcher_id,)
    )
    return row is None or row["last_success"] is None


async def update_watcher_state(
    db: Database,
    watcher: Watcher,
    *,
    started: bool = False,
    success: bool = False,
    error: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    now = now_iso()
    row = await db.fetchone(
        "SELECT consecutive_failures FROM watcher_state WHERE id = ?",
        (watcher.id,),
    )

    if row is None:
        await db.execute(
            """
            INSERT INTO watcher_state
                (id, target_name, kind, last_run, last_success, last_error,
                 consecutive_failures, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                watcher.id,
                watcher.target_name,
                watcher.kind,
                now if started or success or error else None,
                now if success else None,
                error,
                0 if success else (1 if error else 0),
                json.dumps(metadata) if metadata else None,
            ),
        )
        return

    sets = ["last_run = ?"]
    params: list[Any] = [now]
    if success:
        sets.append("last_success = ?")
        params.append(now)
        sets.append("consecutive_failures = 0")
        sets.append("last_error = NULL")
    elif error is not None:
        sets.append("last_error = ?")
        params.append(error)
        sets.append("consecutive_failures = ? ")
        params.append((row["consecutive_failures"] or 0) + 1)
    if metadata is not None:
        sets.append("metadata = ?")
        params.append(json.dumps(metadata))
    params.append(watcher.id)
    await db.execute(
        f"UPDATE watcher_state SET {', '.join(sets)} WHERE id = ?",
        tuple(params),
    )
