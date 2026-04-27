from __future__ import annotations

import asyncio
import hashlib
import logging
from typing import Any

import feedparser
import httpx

from ..db import Database
from ..events import KIND_NEWS, Event
from .base import Watcher, WatcherResult

log = logging.getLogger("osint.rss")


class RssWatcher(Watcher):
    kind = KIND_NEWS

    def __init__(self, target_name: str, feed_url: str, feed_title: str = ""):
        wid = f"rss:{target_name}:{_short_hash(feed_url)}"
        super().__init__(wid, target_name)
        self.feed_url = feed_url
        self.feed_title = feed_title

    async def run(self, db: Database) -> WatcherResult:
        result = WatcherResult()
        try:
            text = await _fetch(self.feed_url)
        except Exception as e:
            result.errors.append(str(e) or repr(e))
            return result

        parsed = feedparser.parse(text)
        if parsed.bozo and not parsed.entries:
            result.errors.append(f"feed parse error: {parsed.bozo_exception}")
            return result

        feed_title = self.feed_title or (parsed.feed.get("title") if parsed.feed else "") or self.feed_url

        for entry in parsed.entries[:50]:
            event = _entry_to_event(self.target_name, self.feed_url, feed_title, entry)
            if event is None:
                continue
            if await self.emit(db, event):
                result.new_events += 1
            else:
                result.duplicate_events += 1

        result.metadata = {
            "feed_url": self.feed_url,
            "entries_seen": len(parsed.entries),
        }
        return result


_UA = "osint-mcp/0.1 (+https://github.com/bleucpu/osint-mcp; bug bounty research)"


async def _fetch(url: str) -> str:
    async with httpx.AsyncClient(
        timeout=12.0,
        follow_redirects=True,
        headers={"User-Agent": _UA, "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*"},
    ) as c:
        r = await c.get(url)
        r.raise_for_status()
        return r.text


def _entry_to_event(
    target: str | None, feed_url: str, feed_title: str, entry: Any
) -> Event | None:
    eid = entry.get("id") or entry.get("link") or entry.get("title")
    if not eid:
        return None
    title = (entry.get("title") or "").strip()
    link = entry.get("link")
    summary = entry.get("summary", "")[:1000] if entry.get("summary") else ""
    published = entry.get("published") or entry.get("updated") or ""
    payload = {
        "feed": feed_title,
        "feed_url": feed_url,
        "summary": _strip_html(summary),
        "published": published,
        "author": entry.get("author"),
    }
    return Event(
        kind=KIND_NEWS,
        source=f"rss:{feed_url}",
        target_name=target,
        title=title,
        url=link,
        payload=payload,
        dedup_key=str(eid),
    )


def _strip_html(text: str) -> str:
    if not text:
        return ""
    try:
        from bs4 import BeautifulSoup
        return BeautifulSoup(text, "lxml").get_text(" ", strip=True)[:1000]
    except Exception:
        return text[:1000]


def _short_hash(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()[:10]
