"""
HackerOne hacktivity watcher — disclosed reports for a program.

Hard rule (codified in feedback_platform_tos memory):
    OFFICIAL API ONLY. No scraping. We do not hit hackerone.com/<slug>/
    hacktivity directly even though it's "publicly visible". We use
    api.hackerone.com/v1/hackers/hacktivity which serves the same data and
    is the documented programmatic interface.

Disclosed reports are arguably the highest-ROI signal for a hunter on the
same program — variants of disclosed bugs are often unfound, and the
weakness type / asset shows precisely where to dig next.

Disabled when HACKERONE_API_USERNAME / HACKERONE_API_TOKEN are not set.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

import httpx

from ..db import Database
from ..events import KIND_NEWS, Event
from .base import Watcher, WatcherResult

log = logging.getLogger("osint.h1_hacktivity")

_UA = "osint-mcp/0.1 (+https://github.com/bleucpu/osint-mcp; bug bounty research)"
H1_API_BASE = "https://api.hackerone.com/v1"


class HackerOneHacktivityWatcher(Watcher):
    kind = KIND_NEWS  # 'news' but tagged 'hacktivity' for filterable routing

    def __init__(self, target_name: str, slug: str):
        super().__init__(f"h1hacktivity:{target_name}:{slug}", target_name)
        self.slug = slug
        self.program_url = f"https://hackerone.com/{slug}"

    async def run(self, db: Database) -> WatcherResult:
        result = WatcherResult()

        # Same safety gate as scope.py — zero requests to hackerone.com when
        # OSINT_HACKERONE_API_ENABLED is not set to 1.
        from .scope import _platform_api_enabled
        enabled, reason = _platform_api_enabled("HACKERONE")
        if not enabled:
            result.metadata = {
                "disabled": True, "reason": reason, "slug": self.slug,
                "safety_gate": "OSINT_HACKERONE_API_ENABLED",
            }
            return result

        username = os.environ.get("HACKERONE_API_USERNAME")
        token = os.environ.get("HACKERONE_API_TOKEN")
        if not (username and token):
            result.metadata = {
                "disabled": True,
                "reason": "set HACKERONE_API_USERNAME + HACKERONE_API_TOKEN to enable",
                "slug": self.slug,
            }
            return result

        url = (
            f"{H1_API_BASE}/hackers/hacktivity"
            f"?filter[program][]={self.slug}"
            f"&page[size]=25&sort=-disclosed_at"
        )
        try:
            async with httpx.AsyncClient(
                timeout=20.0,
                headers={"User-Agent": _UA, "Accept": "application/json"},
                auth=(username, token),
            ) as c:
                r = await c.get(url)
        except httpx.HTTPError as e:
            result.errors.append(f"h1 hacktivity request failed: {e}")
            return result

        if r.status_code == 401:
            result.errors.append("h1 hacktivity 401 — check H1 API credentials")
            return result
        if r.status_code == 429:
            retry = r.headers.get("retry-after", "?")
            result.errors.append(f"h1 hacktivity 429 (retry-after={retry})")
            return result
        if r.status_code >= 400:
            result.errors.append(f"h1 hacktivity HTTP {r.status_code}: {r.text[:200]}")
            return result

        try:
            data = r.json()
        except json.JSONDecodeError:
            result.errors.append("h1 hacktivity returned non-JSON")
            return result

        items = data.get("data") or []
        for item in items:
            ev = _hacktivity_to_event(item, self.slug, self.target_name)
            if ev is None:
                continue
            if await self.emit(db, ev):
                result.new_events += 1
            else:
                result.duplicate_events += 1

        result.metadata = {
            "slug": self.slug,
            "items_seen": len(items),
            "program_url": self.program_url,
        }
        return result


def _hacktivity_to_event(item: dict, slug: str, target: str) -> Event | None:
    item_id = item.get("id")
    attrs = item.get("attributes") or {}
    rels = item.get("relationships") or {}
    if not item_id:
        return None

    report = (rels.get("report") or {}).get("data") or {}
    report_attrs = report.get("attributes") or {}
    weakness = (((rels.get("weakness") or {}).get("data") or {})
                .get("attributes") or {})
    severity = ((rels.get("severity") or {}).get("data") or {}).get("attributes") or {}

    title = report_attrs.get("title") or attrs.get("title") or "(disclosed report)"
    disclosed_at = attrs.get("disclosed_at") or report_attrs.get("disclosed_at") or ""
    bounty = attrs.get("total_awarded_amount") or attrs.get("bounty_amount")
    severity_rating = severity.get("rating") or attrs.get("severity_rating") or ""
    weakness_name = weakness.get("name") or ""

    url = f"https://hackerone.com/reports/{report.get('id') or item_id}"

    summary_bits = []
    if severity_rating:
        summary_bits.append(f"severity={severity_rating}")
    if weakness_name:
        summary_bits.append(f"weakness={weakness_name}")
    if bounty:
        summary_bits.append(f"bounty=${bounty}")
    summary = " · ".join(summary_bits) if summary_bits else ""

    payload = {
        "platform": "hackerone",
        "program": slug,
        "report_id": report.get("id") or item_id,
        "severity": severity_rating,
        "weakness": weakness_name,
        "bounty": bounty,
        "disclosed_at": disclosed_at,
        "summary": summary,
    }
    tags = ["hacktivity"]
    if weakness_name:
        tags.append(weakness_name.lower().replace(" ", "_"))
    if severity_rating:
        tags.append(f"severity:{severity_rating.lower()}")

    return Event(
        kind=KIND_NEWS,
        source=f"h1_hacktivity:{slug}",
        target_name=target,
        title=f"H1 disclosed: {title[:140]}",
        url=url,
        payload=payload,
        dedup_key=f"h1_hacktivity:{slug}:{report.get('id') or item_id}",
        tags=tags,
    )
