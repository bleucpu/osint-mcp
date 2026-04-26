"""
Bug-bounty program scope watchers — OFFICIAL APIs ONLY.

Hard rule: we do not scrape program pages, we do not impersonate browsers,
we do not bypass Cloudflare. Getting banned from HackerOne or Bugcrowd
would cost real income. If no API token is configured for a platform,
the watcher is disabled — not silently fallen back to scraping.

References:
- HackerOne API:  https://api.hackerone.com/v1/  (auth: Basic <user>:<token>)
- Bugcrowd API:   https://api.bugcrowd.com/      (auth: Token <token>)

Both platforms require a researcher account and an API token. When the
required env vars are not set, the watchers no-op cleanly and report
their status as 'disabled' so it surfaces in target_health_check.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from typing import Any

import httpx

from ..db import Database
from ..events import KIND_SCOPE, Event
from .base import Watcher, WatcherResult

log = logging.getLogger("osint.scope")

# Honest, identifiable User-Agent. We're not pretending to be anything we're not.
_UA = "osint-mcp/0.1 (https://github.com/bleucpu/osint-mcp; bug bounty research)"

H1_API_BASE = "https://api.hackerone.com/v1"
BUGCROWD_API_BASE = "https://api.bugcrowd.com"


class HackerOneScopeWatcher(Watcher):
    """
    Polls the official HackerOne API for a program's structured scopes and
    bounty table. Emits a 'scope' event when any of it changes (asset added,
    removed, severity threshold changed, bounty range changed, etc.).

    Requires HACKERONE_API_USERNAME and HACKERONE_API_TOKEN env vars. Without
    both, the watcher reports 'disabled' and does nothing.
    """

    kind = KIND_SCOPE

    def __init__(self, target_name: str, slug: str):
        super().__init__(f"h1scope:{target_name}:{slug}", target_name)
        self.slug = slug
        self.program_url = f"https://hackerone.com/{slug}"

    async def run(self, db: Database) -> WatcherResult:
        result = WatcherResult()
        username = os.environ.get("HACKERONE_API_USERNAME")
        token = os.environ.get("HACKERONE_API_TOKEN")

        if not (username and token):
            result.metadata = {
                "disabled": True,
                "reason": "set HACKERONE_API_USERNAME + HACKERONE_API_TOKEN to enable",
                "slug": self.slug,
            }
            return result

        try:
            program = await _h1_get(
                f"{H1_API_BASE}/hackers/programs/{self.slug}", username, token
            )
            scopes = await _h1_get(
                f"{H1_API_BASE}/hackers/programs/{self.slug}/structured_scopes",
                username, token,
            )
        except _ApiError as e:
            result.errors.append(str(e))
            return result

        canonical = _canonicalize({"program": program, "scopes": scopes})
        cur_hash = _sha(canonical)

        prev = await db.fetchone(
            "SELECT metadata FROM watcher_state WHERE id = ?", (self.id,)
        )
        prev_hash = None
        prev_canonical = None
        if prev and prev["metadata"]:
            try:
                prev_meta = json.loads(prev["metadata"])
                prev_hash = prev_meta.get("hash")
                prev_canonical = prev_meta.get("canonical")
            except (json.JSONDecodeError, TypeError):
                pass

        result.metadata = {
            "hash": cur_hash,
            "canonical": canonical[:8000],
            "slug": self.slug,
            "program_url": self.program_url,
        }

        if prev_hash is None:
            log.info("h1 scope baseline captured for %s", self.slug)
            return result
        if prev_hash == cur_hash:
            return result

        diff = _diff_scopes(prev_canonical or "", canonical)
        ev = Event(
            kind=KIND_SCOPE,
            source=f"h1:{self.slug}",
            target_name=self.target_name,
            title=f"HackerOne scope changed: {self.slug}",
            url=self.program_url,
            payload={
                "platform": "hackerone",
                "slug": self.slug,
                "prev_hash": prev_hash,
                "new_hash": cur_hash,
                "diff": diff,
            },
            dedup_key=f"h1:{self.slug}:{cur_hash}",
            score=10.0,
        )
        if await self.emit(db, ev):
            result.new_events += 1
        return result


class BugcrowdScopeWatcher(Watcher):
    """
    Polls the official Bugcrowd API for a program's brief and scope. Emits
    a 'scope' event on change.

    Requires BUGCROWD_API_TOKEN env var. Without it the watcher is disabled.
    """

    kind = KIND_SCOPE

    def __init__(self, target_name: str, slug: str):
        super().__init__(f"bcscope:{target_name}:{slug}", target_name)
        self.slug = slug
        self.program_url = f"https://bugcrowd.com/{slug}"

    async def run(self, db: Database) -> WatcherResult:
        result = WatcherResult()
        token = os.environ.get("BUGCROWD_API_TOKEN")
        if not token:
            result.metadata = {
                "disabled": True,
                "reason": "set BUGCROWD_API_TOKEN to enable",
                "slug": self.slug,
            }
            return result

        try:
            engagement = await _bugcrowd_get(
                f"{BUGCROWD_API_BASE}/engagements/{self.slug}", token
            )
            brief = await _bugcrowd_get(
                f"{BUGCROWD_API_BASE}/engagements/{self.slug}/brief", token
            )
        except _ApiError as e:
            result.errors.append(str(e))
            return result

        canonical = _canonicalize({"engagement": engagement, "brief": brief})
        cur_hash = _sha(canonical)

        prev = await db.fetchone(
            "SELECT metadata FROM watcher_state WHERE id = ?", (self.id,)
        )
        prev_hash = None
        prev_canonical = None
        if prev and prev["metadata"]:
            try:
                prev_meta = json.loads(prev["metadata"])
                prev_hash = prev_meta.get("hash")
                prev_canonical = prev_meta.get("canonical")
            except (json.JSONDecodeError, TypeError):
                pass

        result.metadata = {
            "hash": cur_hash,
            "canonical": canonical[:8000],
            "slug": self.slug,
            "program_url": self.program_url,
        }

        if prev_hash is None:
            return result
        if prev_hash == cur_hash:
            return result

        diff = _diff_scopes(prev_canonical or "", canonical)
        ev = Event(
            kind=KIND_SCOPE,
            source=f"bugcrowd:{self.slug}",
            target_name=self.target_name,
            title=f"Bugcrowd scope changed: {self.slug}",
            url=self.program_url,
            payload={
                "platform": "bugcrowd",
                "slug": self.slug,
                "prev_hash": prev_hash,
                "new_hash": cur_hash,
                "diff": diff,
            },
            dedup_key=f"bugcrowd:{self.slug}:{cur_hash}",
            score=10.0,
        )
        if await self.emit(db, ev):
            result.new_events += 1
        return result


# ─── HTTP helpers ─────────────────────────────────────────────────────────────

class _ApiError(Exception):
    pass


async def _h1_get(url: str, username: str, token: str) -> Any:
    async with httpx.AsyncClient(
        timeout=20.0,
        headers={"User-Agent": _UA, "Accept": "application/json"},
        auth=(username, token),
    ) as c:
        try:
            r = await c.get(url)
        except httpx.HTTPError as e:
            raise _ApiError(f"h1 api request failed: {e}")
    if r.status_code == 401:
        raise _ApiError("h1 api 401 — check HACKERONE_API_USERNAME / HACKERONE_API_TOKEN")
    if r.status_code == 404:
        raise _ApiError(f"h1 api 404 — program {url.rsplit('/', 1)[-1]} not found or not visible to your account")
    if r.status_code == 429:
        retry = r.headers.get("retry-after", "?")
        raise _ApiError(f"h1 api 429 rate-limited (retry-after={retry})")
    if r.status_code >= 400:
        raise _ApiError(f"h1 api {r.status_code}: {r.text[:200]}")
    try:
        return r.json()
    except json.JSONDecodeError:
        raise _ApiError("h1 api returned non-JSON")


async def _bugcrowd_get(url: str, token: str) -> Any:
    async with httpx.AsyncClient(
        timeout=20.0,
        headers={
            "User-Agent": _UA,
            "Accept": "application/vnd.bugcrowd.v4+json",
            "Authorization": f"Token {token}",
        },
    ) as c:
        try:
            r = await c.get(url)
        except httpx.HTTPError as e:
            raise _ApiError(f"bugcrowd api request failed: {e}")
    if r.status_code == 401:
        raise _ApiError("bugcrowd api 401 — check BUGCROWD_API_TOKEN")
    if r.status_code == 404:
        raise _ApiError(f"bugcrowd api 404 — program not found or not enrolled")
    if r.status_code == 429:
        retry = r.headers.get("retry-after", "?")
        raise _ApiError(f"bugcrowd api 429 rate-limited (retry-after={retry})")
    if r.status_code >= 400:
        raise _ApiError(f"bugcrowd api {r.status_code}: {r.text[:200]}")
    try:
        return r.json()
    except json.JSONDecodeError:
        raise _ApiError("bugcrowd api returned non-JSON")


def _canonicalize(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, default=str)


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()


def _diff_scopes(prev: str, cur: str) -> dict[str, Any]:
    """Cheap line-set diff over the canonical JSON. Discord-friendly."""
    p_lines = set(l.strip() for l in prev.splitlines() if l.strip())
    c_lines = set(l.strip() for l in cur.splitlines() if l.strip())
    added = sorted(c_lines - p_lines)
    removed = sorted(p_lines - c_lines)
    return {
        "added_count": len(added),
        "removed_count": len(removed),
        "added_sample": added[:10],
        "removed_sample": removed[:10],
    }
