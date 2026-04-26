from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from mcp.server.fastmcp import FastMCP

from .autodiscover import autodiscover
from .config import Config
from .daemon import Daemon
from .db import Database
from .events import ALL_KINDS, fetch_recent, fetch_search
from .summarize import heuristic_summary, llm_summary
from .targets import (
    TargetExists,
    TargetNotFound,
    add_target,
    get_target,
    list_targets,
    remove_target,
    target_health,
    update_target,
)

log = logging.getLogger("osint.mcp")


def build_server(cfg: Config, db: Database, daemon: Daemon) -> FastMCP:
    mcp = FastMCP("osint-mcp")

    @mcp.tool()
    async def target_autodiscover(name_or_domain: str) -> dict:
        """
        Read-only enrichment for a target candidate. Probes common TLDs (if a
        bare name is given), parses the homepage for RSS feeds, GitHub orgs,
        Twitter handles, and a status page, and checks whether HackerOne or
        Bugcrowd has a program with a matching slug. Does NOT add the target
        to the watchlist — call target_add to commit.
        """
        d = await autodiscover(name_or_domain)
        return d.to_dict()

    @mcp.tool()
    async def target_add(
        name: str,
        root_domains: list[str] | None = None,
        github_orgs: list[str] | None = None,
        rss_feeds: list[str] | None = None,
        status_page: str | None = None,
        twitter_handles: list[str] | None = None,
        bug_bounty: dict | None = None,
        bbot_preset: str | None = None,
        cadence_overrides: dict | None = None,
        notes: str | None = None,
        auto: bool = True,
    ) -> dict:
        """
        Add a target to the watchlist. If `auto=True` (default) and any major
        fields (root_domains, rss_feeds) are missing, autodiscover runs to
        fill them. Pass an empty list (`[]`) to mean "explicitly none, don't
        autodiscover this field". Returns the stored target plus the
        discovery report (when autodiscover ran).
        """
        try:
            return await add_target(
                db, name,
                root_domains=root_domains,
                github_orgs=github_orgs,
                rss_feeds=rss_feeds,
                status_page=status_page,
                twitter_handles=twitter_handles,
                bug_bounty=bug_bounty,
                bbot_preset=bbot_preset,
                cadence_overrides=cadence_overrides,
                notes=notes,
                auto=auto,
            )
        except TargetExists:
            return {"error": "target_exists", "name": name,
                    "hint": "use target_update to modify"}
        except ValueError as e:
            return {"error": "invalid_args", "message": str(e)}

    @mcp.tool()
    async def target_update(name: str, patch: dict) -> dict:
        """Patch fields on an existing target. Pass any subset of: root_domains,
        github_orgs, rss_feeds, status_page, twitter_handles, bug_bounty,
        bbot_preset, cadence_overrides, notes, enabled."""
        try:
            return await update_target(db, name, patch)
        except TargetNotFound:
            return {"error": "target_not_found", "name": name}

    @mcp.tool()
    async def target_remove(name: str) -> dict:
        """Stop watching a target and delete its watcher state. Events stay."""
        try:
            await remove_target(db, name)
            return {"removed": name}
        except TargetNotFound:
            return {"error": "target_not_found", "name": name}

    @mcp.tool()
    async def target_show(name: str) -> dict:
        """Return the full target spec plus watcher health."""
        try:
            target = await get_target(db, name)
        except TargetNotFound:
            return {"error": "target_not_found", "name": name}
        health = await target_health(db, name)
        return {"target": target, "watchers": health}

    @mcp.tool()
    async def target_list() -> dict:
        """List all targets with light summary info."""
        targets = await list_targets(db)
        return {"count": len(targets), "targets": targets}

    @mcp.tool()
    async def target_health_check(name: str | None = None) -> dict:
        """Health/status of every watcher for one target or all targets."""
        return {"watchers": await target_health(db, name)}

    @mcp.tool()
    async def target_force_scan(name: str, kind: str | None = None) -> dict:
        """
        Trigger an out-of-cadence scan now. `kind` filters to one watcher class
        (e.g. 'recon' for BBOT only, 'news' for RSS only). Blocks until scans
        finish; BBOT can take many minutes.
        """
        if kind is not None and kind not in ALL_KINDS:
            return {"error": "bad_kind", "valid_kinds": sorted(ALL_KINDS)}
        try:
            return await daemon.trigger_target_now(name, kind)
        except ValueError as e:
            return {"error": "target_not_found", "message": str(e)}

    @mcp.tool()
    async def feed_recent(
        target: str | None = None,
        kind: str | None = None,
        since: str | None = None,
        hours_ago: int | None = None,
        limit: int = 100,
    ) -> dict:
        """
        Recent events. Filter by target, by kind (recon|news|scope|secrets|js|social),
        and by `since` (ISO 8601) or `hours_ago` (convenience). Default returns
        the 100 most recent events across all targets.
        """
        if since is None and hours_ago is not None:
            since = (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).isoformat()
        events = await fetch_recent(db, target=target, kind=kind, since=since, limit=limit)
        return {"count": len(events), "events": events}

    @mcp.tool()
    async def feed_search(
        query: str,
        target: str | None = None,
        since: str | None = None,
        hours_ago: int | None = None,
        limit: int = 50,
    ) -> dict:
        """
        Full-text search over event titles + payloads. Uses SQLite FTS5 syntax
        (e.g. "oauth OR saml", "anthropic NEAR/5 release").
        """
        if since is None and hours_ago is not None:
            since = (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).isoformat()
        events = await fetch_search(db, query, target=target, since=since, limit=limit)
        return {"count": len(events), "events": events}

    @mcp.tool()
    async def feed_summary(
        target: str | None = None,
        kind: str | None = None,
        hours_ago: int = 24,
        limit: int = 200,
        use_llm: bool = True,
    ) -> dict:
        """
        Compact digest of recent events. If ANTHROPIC_API_KEY is set and
        use_llm=True, an LLM picks the highest-leverage threads to investigate
        first; otherwise a deterministic group-by-target/kind summary is
        returned. The summary is meant to be cheap context for an AI hacker
        deciding where to dig.
        """
        since = (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).isoformat()
        events = await fetch_recent(db, target=target, kind=kind, since=since, limit=limit)
        used_llm = False
        if use_llm and cfg.anthropic_api_key:
            text = await llm_summary(events, cfg.anthropic_api_key)
            used_llm = True
        else:
            text = heuristic_summary(events)
        return {
            "summary": text,
            "event_count": len(events),
            "window_hours": hours_ago,
            "target_filter": target,
            "kind_filter": kind,
            "used_llm": used_llm,
        }

    @mcp.tool()
    async def system_status() -> dict:
        """Daemon + Discord routing status. Useful for debugging."""
        return {
            "data_dir": str(cfg.data_dir),
            "db_path": str(cfg.db_path),
            "discord": {
                "enabled": cfg.discord.enabled,
                "firehose_set": bool(cfg.discord.firehose),
                "kind_overrides": sorted(cfg.discord.kind_webhooks.keys()),
            },
            "cadences": cfg.cadences,
            "bbot_preset": cfg.bbot.preset,
            "optional_keys": {
                "hackerone": bool(cfg.hackerone_token),
                "github": bool(cfg.github_token),
                "twitterapi_io": bool(cfg.twitterapi_io_key),
                "anthropic": bool(cfg.anthropic_api_key),
            },
        }

    return mcp
