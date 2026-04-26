"""
Certstream global watcher.

Connects to a public certstream websocket (which firehose every CT-log
entry on the public internet) and emits a `recon` event whenever a newly
issued certificate's SANs include any of our targeted root domains.

This catches subdomains *the moment they get a cert* — usually before
DNS resolves and before BBOT's daily scan would find them.

Default endpoint: wss://certstream.calidog.io  (public, free, can be flaky).
Override with CERTSTREAM_URL env var (e.g. self-hosted instance).

This is a long-running stream rather than a cadence-driven watcher, so the
daemon starts it once at boot via `start_certstream_stream(...)`.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Iterable

import websockets

from ..db import Database
from ..events import KIND_RECON, Event, ingest
from ..targets import list_targets

log = logging.getLogger("osint.certstream")

DEFAULT_URL = "wss://certstream.calidog.io/"


async def run_certstream(
    db: Database,
    stop_event: asyncio.Event,
    url: str | None = None,
    refresh_targets_every: float = 300.0,
) -> None:
    """
    Long-running coroutine. Reconnects on disconnect with backoff. Emits one
    event per matching cert (deduped by serial+hostname).
    """
    url = url or os.environ.get("CERTSTREAM_URL") or DEFAULT_URL
    log.info("certstream connecting to %s", url)
    backoff = 5.0

    suffix_index = await _load_target_suffix_index(db)
    last_refresh = asyncio.get_event_loop().time()

    while not stop_event.is_set():
        try:
            async with websockets.connect(
                url,
                ping_interval=30,
                ping_timeout=20,
                max_size=4 * 1024 * 1024,
            ) as ws:
                log.info("certstream connected")
                backoff = 5.0
                async for raw in ws:
                    if stop_event.is_set():
                        break
                    now = asyncio.get_event_loop().time()
                    if now - last_refresh > refresh_targets_every:
                        suffix_index = await _load_target_suffix_index(db)
                        last_refresh = now
                    if not suffix_index:
                        continue
                    try:
                        msg = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    if msg.get("message_type") != "certificate_update":
                        continue
                    await _handle_cert(db, msg.get("data") or {}, suffix_index)
        except asyncio.CancelledError:
            return
        except Exception as e:
            log.warning("certstream disconnect: %s; reconnecting in %.0fs", e, backoff)
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=backoff)
                return
            except asyncio.TimeoutError:
                pass
            backoff = min(backoff * 1.6, 120.0)


async def _load_target_suffix_index(db: Database) -> list[tuple[str, str]]:
    """Build a list of (suffix, target_name) tuples from current targets."""
    targets = await list_targets(db)
    out: list[tuple[str, str]] = []
    for t in targets:
        if not t.get("enabled"):
            continue
        for d in t.get("root_domains") or []:
            out.append((d.lower().lstrip("."), t["name"]))
    return out


async def _handle_cert(
    db: Database, data: dict, suffix_index: list[tuple[str, str]]
) -> None:
    leaf = data.get("leaf_cert") or {}
    serial = leaf.get("serial_number") or ""
    all_domains: list[str] = leaf.get("all_domains") or []
    if not all_domains:
        return

    for hostname in all_domains:
        h = hostname.lower().lstrip("*.").strip()
        if not h:
            continue
        target_name = _match_target(h, suffix_index)
        if not target_name:
            continue
        ev = Event(
            kind=KIND_RECON,
            source=f"certstream:{target_name}",
            target_name=target_name,
            title=f"new cert: {h}",
            url=f"https://{h}",
            payload={
                "hostname": h,
                "serial": serial,
                "issuer": (leaf.get("issuer") or {}).get("O"),
                "all_domains": all_domains[:20],
                "not_before": leaf.get("not_before"),
                "not_after": leaf.get("not_after"),
            },
            dedup_key=f"cert:{h}:{serial}",
            score=5.0,
        )
        await ingest(db, ev)


def _match_target(host: str, suffix_index: Iterable[tuple[str, str]]) -> str | None:
    for suffix, name in suffix_index:
        if host == suffix or host.endswith("." + suffix):
            return name
    return None
