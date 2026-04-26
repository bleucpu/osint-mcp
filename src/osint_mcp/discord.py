from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict, deque
from typing import Any

import httpx

from .config import DiscordConfig
from .db import Database
from .events import claim_undelivered, mark_delivered

log = logging.getLogger("osint.discord")

KIND_COLORS = {
    "recon":   0x3498DB,
    "news":    0x2ECC71,
    "scope":   0xE67E22,
    "secrets": 0xE74C3C,
    "js":      0x9B59B6,
    "social":  0x1DA1F2,
}

KIND_EMOJI = {
    "recon":   "🛰️",
    "news":    "📰",
    "scope":   "🎯",
    "secrets": "🔑",
    "js":      "📦",
    "social":  "🐦",
}


class DiscordRouter:
    """
    Routes events to Discord webhooks based on kind, falling back to firehose.
    Per-channel sliding-window rate limit (Discord caps webhooks at 30/min).
    """

    def __init__(self, cfg: DiscordConfig, client: httpx.AsyncClient | None = None):
        self.cfg = cfg
        self.client = client or httpx.AsyncClient(timeout=10.0)
        self._owns_client = client is None
        self._timestamps: dict[str, deque[float]] = defaultdict(deque)
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def close(self) -> None:
        if self._owns_client:
            await self.client.aclose()

    def webhook_for(self, kind: str) -> str | None:
        return self.cfg.kind_webhooks.get(kind) or self.cfg.firehose

    async def post_event(self, event: dict[str, Any]) -> bool:
        if not self.cfg.enabled:
            return True
        url = self.webhook_for(event["kind"])
        if not url:
            log.debug("no webhook configured for kind=%s, dropping", event["kind"])
            return True

        body = self._format(event) if self.cfg.embed_events else self._format_plain(event)

        async with self._locks[url]:
            await self._respect_rate_limit(url)
            try:
                resp = await self.client.post(url, json=body)
                if resp.status_code == 429:
                    retry = float(resp.headers.get("retry-after", "1"))
                    log.warning("discord rate-limited, sleeping %.1fs", retry)
                    await asyncio.sleep(retry + 0.5)
                    return False
                if resp.status_code >= 400:
                    log.error("discord webhook %s returned %s: %s",
                              url[:60], resp.status_code, resp.text[:200])
                    return False
                self._timestamps[url].append(time.monotonic())
                return True
            except httpx.HTTPError as e:
                log.error("discord webhook error: %s", e)
                return False

    async def _respect_rate_limit(self, url: str) -> None:
        window = 60.0
        cap = max(1, self.cfg.rate_limit_per_minute)
        ts = self._timestamps[url]
        now = time.monotonic()
        while ts and now - ts[0] > window:
            ts.popleft()
        if len(ts) >= cap:
            wait = window - (now - ts[0]) + 0.1
            if wait > 0:
                log.debug("local rate limit hit, sleeping %.1fs", wait)
                await asyncio.sleep(wait)

    def _format(self, event: dict[str, Any]) -> dict[str, Any]:
        kind = event["kind"]
        emoji = KIND_EMOJI.get(kind, "•")
        target = event.get("target_name") or "(global)"

        embed: dict[str, Any] = {
            "title": f"{emoji} {event.get('title') or '(no title)'}"[:256],
            "color": KIND_COLORS.get(kind, 0x95A5A6),
            "timestamp": event["observed_at"],
            "footer": {"text": f"{kind} · {event['source']} · {target}"},
        }
        if event.get("url"):
            embed["url"] = event["url"]

        payload = event.get("payload") or {}
        desc = payload.get("description") or payload.get("summary")
        if desc:
            embed["description"] = str(desc)[:2000]

        fields = []
        for k, v in payload.items():
            if k in ("description", "summary"):
                continue
            if isinstance(v, (str, int, float, bool)):
                fields.append({"name": k[:256], "value": str(v)[:1024], "inline": True})
            if len(fields) >= 6:
                break
        if fields:
            embed["fields"] = fields

        return {"embeds": [embed]}

    def _format_plain(self, event: dict[str, Any]) -> dict[str, Any]:
        kind = event["kind"]
        emoji = KIND_EMOJI.get(kind, "•")
        target = event.get("target_name") or "(global)"
        line = f"{emoji} **[{kind}]** [{target}] {event.get('title') or '(no title)'}"
        if event.get("url"):
            line += f"\n<{event['url']}>"
        return {"content": line[:2000]}


async def deliver_pending(db: Database, router: DiscordRouter, batch: int = 25) -> int:
    """Deliver up to `batch` undelivered events. Returns count delivered."""
    events = await claim_undelivered(db, limit=batch)
    if not events:
        return 0
    delivered_ids: list[int] = []
    for ev in events:
        ok = await router.post_event(ev)
        if ok:
            delivered_ids.append(ev["id"])
    if delivered_ids:
        await mark_delivered(db, delivered_ids)
    return len(delivered_ids)
