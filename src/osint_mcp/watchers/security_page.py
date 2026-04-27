"""
Security/scope page watcher — the company's *own* security/scope page.

Most companies with bug bounty programs publish their scope, payout
ranges, and disclosure policy on their own website (`/security`,
`/.well-known/security.txt`, `/security/disclosure`, `/bug-bounty`,
etc.). Watching those pages gives us scope-change signal *from the
source* — without ever touching HackerOne or Bugcrowd, no platform
credentials, no ToS risk.

Per-target config: `security_pages` is a list of URLs. Autodiscover
seeds it from common paths; the AI / user can edit via target_update.

We hash the visible-text of each page (HTML stripped of script/style)
so layout-only or CSS-only changes don't trigger false diffs. On a real
content change we emit a 'scope' event with a line-set diff.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from typing import Any

import httpx

from ..db import Database
from ..events import KIND_SCOPE, Event
from .base import Watcher, WatcherResult

log = logging.getLogger("osint.security_page")

_UA = "osint-mcp/0.1 (+https://github.com/bleucpu/osint-mcp; bug bounty research)"


class SecurityPageWatcher(Watcher):
    kind = KIND_SCOPE

    def __init__(self, target_name: str, page_url: str):
        wid = f"secpage:{target_name}:{_short_hash(page_url)}"
        super().__init__(wid, target_name)
        self.page_url = page_url

    async def run(self, db: Database) -> WatcherResult:
        result = WatcherResult()
        try:
            async with httpx.AsyncClient(
                timeout=15.0,
                follow_redirects=True,
                headers={"User-Agent": _UA, "Accept": "text/html,text/plain,*/*"},
            ) as c:
                r = await c.get(self.page_url)
        except httpx.HTTPError as e:
            result.errors.append(f"fetch failed: {str(e) or repr(e)}")
            return result

        if r.status_code >= 400:
            result.errors.append(f"HTTP {r.status_code}")
            return result

        body = r.text
        if "html" in r.headers.get("content-type", "").lower() or "<html" in body[:500].lower():
            body = _strip_html_for_diff(body)
        canonical = _normalize_text(body)
        cur_hash = _sha(canonical)

        prev = await db.fetchone(
            "SELECT metadata FROM watcher_state WHERE id = ?", (self.id,)
        )
        prev_hash = None
        prev_canonical = None
        if prev and prev["metadata"]:
            try:
                meta = json.loads(prev["metadata"])
                prev_hash = meta.get("hash")
                prev_canonical = meta.get("canonical")
            except (json.JSONDecodeError, TypeError):
                pass

        result.metadata = {
            "page_url": self.page_url,
            "hash": cur_hash,
            "canonical": canonical[:8000],
            "content_type": r.headers.get("content-type"),
            "length": len(body),
        }

        if prev_hash is None:
            log.info("security-page baseline captured for %s", self.page_url)
            return result
        if prev_hash == cur_hash:
            return result

        diff = _line_diff(prev_canonical or "", canonical)
        ev = Event(
            kind=KIND_SCOPE,
            source=f"secpage:{self.page_url}",
            target_name=self.target_name,
            title=f"Security page changed: {self.page_url}",
            url=self.page_url,
            payload={
                "page_url": self.page_url,
                "prev_hash": prev_hash,
                "new_hash": cur_hash,
                "diff": diff,
            },
            dedup_key=f"secpage:{self.page_url}:{cur_hash}",
            score=10.0,
            tags=["security_page", "scope_source"],
        )
        if await self.emit(db, ev):
            result.new_events += 1
        return result


def _strip_html_for_diff(html: str) -> str:
    html = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r"<style[^>]*>.*?</style>", "", html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r"<!--.*?-->", "", html, flags=re.DOTALL)
    text = re.sub(r"<[^>]+>", "\n", html)
    return text


def _normalize_text(text: str) -> str:
    """Collapse whitespace, drop empty lines, so reformatting doesn't trigger diffs."""
    lines = []
    for line in text.splitlines():
        s = re.sub(r"\s+", " ", line).strip()
        if s:
            lines.append(s)
    return "\n".join(lines)[:80000]


def _line_diff(prev: str, cur: str) -> dict[str, Any]:
    p = set(l for l in prev.splitlines() if l)
    c = set(l for l in cur.splitlines() if l)
    added = sorted(c - p)
    removed = sorted(p - c)
    return {
        "added_count": len(added),
        "removed_count": len(removed),
        "added_sample": added[:10],
        "removed_sample": removed[:10],
    }


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()


def _short_hash(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()[:10]
