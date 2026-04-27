"""
JS bundle diff watcher.

For each target, fetch a small set of seed pages (default: each
root_domain's homepage; override via target.js_pages), parse their
<script src=...> tags, restrict to scripts hosted on the target's own
domains, and hash the content of each. On hash change, fetch the new
content, diff against the prior version, and extract:
  - new API endpoints (/v1/..., /api/...)
  - new feature-flag keys (Statsig, GrowthBook, LD, Optimizely)
  - new JWT 'kid' values
  - new OAuth client IDs

Emits one 'js' event per changed bundle, with the diff summary in payload
and the raw added/removed snippets capped to keep Discord embeds sane.

This is fully legitimate — it just retrieves public JS files via HTTPS the
same way a browser would. Honest UA, conservative cadence (default 6h).
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from ..db import Database
from ..events import KIND_JS, Event
from .base import Watcher, WatcherResult

log = logging.getLogger("osint.js")

_UA = "osint-mcp/0.1 (+https://github.com/bleucpu/osint-mcp; bug bounty research)"

_UUID_RE = re.compile(
    r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b"
)
_HEX_HASH_RE = re.compile(r"\b[0-9a-f]{16,64}\b")
_NEXT_HASH_RE = re.compile(r"[-.][a-f0-9]{8,}(?=\.(?:js|mjs|css)\b)")


def normalize_bundle_url(url: str) -> str:
    """
    Many SPAs serve bundles at URLs that include a deployment UUID or
    content-hash that rotates on every release (e.g. claude.ai's
    `https://a-cdn.claude.ai/v2/<UUID>/api.js`, or Next.js's
    `/_next/static/chunks/main-abcd1234.js`). If we key the watcher state
    by raw URL, we'd never see a "diff" because the URL itself changes.

    Normalize by replacing UUIDs / hex hashes / Next-style suffix hashes
    with `<HASH>`, so the bundle's logical identity is stable across
    deploys.
    """
    u = _UUID_RE.sub("<UUID>", url)
    u = _NEXT_HASH_RE.sub("-<HASH>", u)
    u = _HEX_HASH_RE.sub("<HASH>", u)
    return u


ENDPOINT_RE = re.compile(r'["\'`](/(?:v\d+|api|graphql|internal|admin)/[A-Za-z0-9_/{}.-]{2,80})["\'`]')
STATSIG_RE  = re.compile(r"client-[A-Za-z0-9]{20,}")
LD_RE       = re.compile(r"\bclient-side-id[\"'\s:=]+[\"']([A-Za-z0-9-]{20,})")
GROWTHBOOK_RE = re.compile(r"sdk-[A-Za-z0-9]{16,}")
JWT_KID_RE  = re.compile(r'"kid"\s*:\s*"([A-Za-z0-9_-]{6,80})"')
OAUTH_CLIENT_RE = re.compile(r'(?:client_id|clientId)[\"\':\s=]+[\"\']?([A-Za-z0-9_.\-]{16,80})[\"\']?')


class JsBundleWatcher(Watcher):
    kind = KIND_JS

    def __init__(
        self,
        target_name: str,
        seed_pages: list[str],
        own_domains: list[str],
    ):
        wid = f"js:{target_name}:{_short_hash(','.join(sorted(seed_pages)))}"
        super().__init__(wid, target_name)
        self.seed_pages = seed_pages
        self.own_domains = [d.lower().lstrip(".") for d in own_domains]

    async def run(self, db: Database) -> WatcherResult:
        result = WatcherResult()
        if not self.seed_pages:
            result.errors.append("no seed_pages configured")
            return result

        prev_state = await _load_prev_bundles(db, self.id)
        prev_extracts = prev_state.get("extracts", {})
        cur_state: dict[str, Any] = {"bundles": {}, "extracts": {}}

        async with httpx.AsyncClient(
            timeout=15.0, follow_redirects=True,
            headers={"User-Agent": _UA},
        ) as client:
            bundle_urls = await self._collect_bundle_urls(client)

            for burl in sorted(bundle_urls)[:30]:
                # Use the normalized URL as the watcher-state key so a
                # rotating UUID in the path doesn't break diffing.
                bkey = normalize_bundle_url(burl)
                try:
                    r = await client.get(burl)
                except httpx.HTTPError as e:
                    msg = str(e) or repr(e)
                    result.errors.append(f"{burl}: {msg}")
                    continue
                if r.status_code != 200:
                    result.errors.append(f"{burl}: HTTP {r.status_code}")
                    continue
                body = r.text

                bhash = hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()
                cur_state["bundles"][bkey] = bhash
                extracts = _extract_signals(body)
                cur_state["extracts"][bkey] = extracts

                prev_hash = prev_state.get("bundles", {}).get(bkey)
                # Tolerate older state that keyed by raw URL
                if prev_hash is None and burl != bkey:
                    prev_hash = prev_state.get("bundles", {}).get(burl)
                if prev_hash is None or prev_hash == bhash:
                    continue

                prev_ext = prev_extracts.get(bkey, prev_extracts.get(burl, {}))
                diff = _signal_diff(prev_ext, extracts)

                ev = Event(
                    kind=KIND_JS,
                    source=f"jsdiff:{bkey}",
                    target_name=self.target_name,
                    title=f"JS bundle changed: {bkey.rsplit('/', 1)[-1] or bkey}",
                    url=burl,
                    payload={
                        "bundle_url": burl,
                        "bundle_key": bkey,
                        "prev_hash": prev_hash,
                        "new_hash": bhash,
                        "diff": diff,
                    },
                    dedup_key=f"jsdiff:{bkey}:{bhash}",
                )
                if await self.emit(db, ev):
                    result.new_events += 1

        result.metadata = cur_state
        result.metadata["seed_pages"] = self.seed_pages
        return result

    async def _collect_bundle_urls(self, client: httpx.AsyncClient) -> set[str]:
        urls: set[str] = set()
        for page in self.seed_pages:
            try:
                r = await client.get(page)
            except httpx.HTTPError:
                continue
            if r.status_code != 200:
                continue
            base = str(r.url)
            try:
                soup = BeautifulSoup(r.text, "lxml")
            except Exception:
                soup = BeautifulSoup(r.text, "html.parser")
            for s in soup.find_all("script", src=True):
                src = urljoin(base, s["src"])
                host = (urlparse(src).hostname or "").lower()
                if not host:
                    continue
                if any(host == d or host.endswith("." + d) for d in self.own_domains):
                    urls.add(src)
        return urls


async def _load_prev_bundles(db: Database, watcher_id: str) -> dict:
    row = await db.fetchone(
        "SELECT metadata FROM watcher_state WHERE id = ?", (watcher_id,)
    )
    if not row or not row["metadata"]:
        return {}
    try:
        return json.loads(row["metadata"])
    except (json.JSONDecodeError, TypeError):
        return {}


def _extract_signals(js: str) -> dict[str, list[str]]:
    endpoints = sorted(set(ENDPOINT_RE.findall(js)))
    flags = sorted(set(
        STATSIG_RE.findall(js) + LD_RE.findall(js) + GROWTHBOOK_RE.findall(js)
    ))
    kids = sorted(set(JWT_KID_RE.findall(js)))
    oauth = sorted(set(OAUTH_CLIENT_RE.findall(js)))
    return {
        "endpoints": endpoints[:200],
        "feature_flags": flags[:50],
        "jwt_kids": kids[:50],
        "oauth_clients": oauth[:50],
    }


def _signal_diff(prev: dict, cur: dict) -> dict[str, Any]:
    def _diff(field: str) -> dict[str, list[str]]:
        p = set(prev.get(field) or [])
        c = set(cur.get(field) or [])
        return {"added": sorted(c - p), "removed": sorted(p - c)}

    fields = ("endpoints", "feature_flags", "jwt_kids", "oauth_clients")
    out: dict[str, dict[str, list[str]]] = {"added": {}, "removed": {}}
    for f in fields:
        d = _diff(f)
        out["added"][f] = d["added"]
        out["removed"][f] = d["removed"]
    return out


def _short_hash(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()[:10]
