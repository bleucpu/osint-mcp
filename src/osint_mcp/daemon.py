from __future__ import annotations

import asyncio
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from .config import Config
from .db import Database
from .discord import DiscordRouter, deliver_pending
from .events import KIND_JS, KIND_NEWS, KIND_RECON, KIND_SCOPE
from .targets import list_targets
from .watchers.bbot import BbotWatcher
from .watchers.certstream import run_certstream
from .watchers.github_events import GitHubEventsWatcher
from .watchers.h1_hacktivity import HackerOneHacktivityWatcher
from .watchers.js import JsBundleWatcher
from .watchers.rss import RssWatcher
from .watchers.scope import BugcrowdScopeWatcher, HackerOneScopeWatcher

log = logging.getLogger("osint.daemon")


_DURATION_RE = re.compile(r"^\s*(\d+)\s*([smhdw])\s*$", re.IGNORECASE)
_UNIT_SECS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_duration(s: str) -> timedelta:
    m = _DURATION_RE.match(s)
    if not m:
        raise ValueError(f"bad duration string: {s!r}")
    n, unit = int(m.group(1)), m.group(2).lower()
    return timedelta(seconds=n * _UNIT_SECS[unit])


def cadence_for_kind(cfg: Config, target: dict[str, Any], kind: str) -> timedelta | None:
    overrides = target.get("cadence_overrides") or {}
    raw = overrides.get(kind) or cfg.cadences.get(kind)
    if not raw or raw == "live":
        return None
    try:
        return parse_duration(raw)
    except ValueError:
        return None


class Daemon:
    """
    Long-running supervisor. Owns:
      - the DB connection
      - the Discord router
      - per-watcher scheduling (last-run-aware, catches up missed cadences)
      - the Discord delivery loop
    """

    def __init__(self, cfg: Config, db: Database, router: DiscordRouter):
        self.cfg = cfg
        self.db = db
        self.router = router
        self._stop = asyncio.Event()
        self._tasks: list[asyncio.Task] = []
        self._inflight: set[str] = set()

    async def start(self) -> None:
        log.info("starting daemon")
        self._tasks.append(asyncio.create_task(self._scheduler_loop()))
        self._tasks.append(asyncio.create_task(self._delivery_loop()))
        if os.environ.get("CERTSTREAM_DISABLED", "").lower() not in ("1", "true", "yes"):
            self._tasks.append(asyncio.create_task(
                run_certstream(self.db, self._stop)
            ))

    async def stop(self) -> None:
        log.info("stopping daemon")
        self._stop.set()
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)

    async def trigger_target_now(
        self, name: str, kind: str | None = None,
        skip_kinds: set[str] | None = None,
    ) -> dict[str, Any]:
        targets = await list_targets(self.db)
        target = next((t for t in targets if t["name"] == name), None)
        if not target:
            raise ValueError(f"unknown target: {name}")
        watchers = self._build_watchers_for_target(target, kind_filter=kind)
        if skip_kinds:
            watchers = [w for w in watchers if w.kind not in skip_kinds]
        results = []
        for w in watchers:
            res = await w.execute(self.db)
            results.append({
                "watcher": w.id,
                "kind": w.kind,
                "new_events": res.new_events,
                "duplicate_events": res.duplicate_events,
                "errors": res.errors,
            })
        return {"target": name, "kind": kind, "watchers": results}

    async def prime_new_target(self, name: str) -> dict[str, Any]:
        """
        Fire light-weight watchers immediately for a freshly-added target —
        RSS / scope / news (H1 hacktivity, github events) / JS — so the
        target lights up with data right away instead of waiting for the
        next scheduler tick. BBOT (heavy, daily) is intentionally skipped;
        run target_force_scan(kind="recon") manually when ready.
        """
        return await self.trigger_target_now(
            name, kind=None, skip_kinds={KIND_RECON},
        )

    async def _scheduler_loop(self) -> None:
        try:
            while not self._stop.is_set():
                try:
                    await self._tick()
                except Exception:
                    log.exception("scheduler tick crashed")
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=30.0)
                    return
                except asyncio.TimeoutError:
                    continue
        except asyncio.CancelledError:
            pass

    async def _tick(self) -> None:
        targets = await list_targets(self.db)
        now = datetime.now(timezone.utc)

        for target in targets:
            if not target["enabled"]:
                continue
            for w in self._build_watchers_for_target(target):
                cadence = cadence_for_kind(self.cfg, target, w.kind)
                if cadence is None:
                    continue
                state = await self.db.fetchone(
                    "SELECT last_run, last_success FROM watcher_state WHERE id = ?",
                    (w.id,),
                )
                last = None
                if state and state["last_run"]:
                    try:
                        last = datetime.fromisoformat(state["last_run"])
                    except ValueError:
                        last = None
                due = last is None or (now - last) >= cadence
                if not due:
                    continue
                if w.id in self._inflight:
                    continue
                self._inflight.add(w.id)
                asyncio.create_task(self._run_and_release(w))

    async def _run_and_release(self, watcher) -> None:
        try:
            res = await watcher.execute(self.db)
            log.info(
                "watcher %s: +%d events (%d dupes, %d errors)",
                watcher.id, res.new_events, res.duplicate_events, len(res.errors),
            )
        finally:
            self._inflight.discard(watcher.id)

    async def _delivery_loop(self) -> None:
        try:
            while not self._stop.is_set():
                try:
                    n = await deliver_pending(self.db, self.router, batch=25)
                    if n == 0:
                        try:
                            await asyncio.wait_for(self._stop.wait(), timeout=5.0)
                            return
                        except asyncio.TimeoutError:
                            continue
                except Exception:
                    log.exception("delivery loop crashed")
                    await asyncio.sleep(10.0)
        except asyncio.CancelledError:
            pass

    def _build_watchers_for_target(
        self, target: dict[str, Any], *, kind_filter: str | None = None
    ) -> list:
        out: list = []
        if kind_filter is None or kind_filter == KIND_NEWS:
            for feed in target.get("rss_feeds") or []:
                if isinstance(feed, dict):
                    url = feed.get("url")
                    title = feed.get("title", "")
                else:
                    url, title = feed, ""
                if not url:
                    continue
                out.append(RssWatcher(target["name"], url, title))
        if kind_filter is None or kind_filter == KIND_RECON:
            for root in target.get("root_domains") or []:
                out.append(BbotWatcher(
                    target["name"],
                    root,
                    preset=target.get("bbot_preset") or self.cfg.bbot.preset,
                    output_dir=self.cfg.bbot.output_dir,
                ))
        if kind_filter is None or kind_filter == KIND_SCOPE:
            bb = target.get("bug_bounty") or {}
            platform = (bb.get("platform") or "").lower()
            slug = bb.get("slug")
            if slug and platform == "hackerone":
                out.append(HackerOneScopeWatcher(target["name"], slug))
            elif slug and platform == "bugcrowd":
                out.append(BugcrowdScopeWatcher(target["name"], slug))
        if kind_filter is None or kind_filter == KIND_NEWS:
            # H1 hacktivity for the target's program (disabled cleanly without
            # API token — see watcher impl).
            bb = target.get("bug_bounty") or {}
            if (bb.get("platform") or "").lower() == "hackerone" and bb.get("slug"):
                out.append(HackerOneHacktivityWatcher(target["name"], bb["slug"]))
            # GitHub public events for each org
            for org in target.get("github_orgs") or []:
                out.append(GitHubEventsWatcher(target["name"], org))
        if kind_filter is None or kind_filter == KIND_JS:
            seeds = target.get("js_pages") or [
                f"https://{d}/" for d in (target.get("root_domains") or [])
            ]
            if seeds and target.get("root_domains"):
                out.append(JsBundleWatcher(
                    target["name"],
                    seed_pages=seeds,
                    own_domains=target["root_domains"],
                ))
        return out
