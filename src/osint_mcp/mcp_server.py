from __future__ import annotations

import logging
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from mcp.server.fastmcp import FastMCP

from .autodiscover import autodiscover
from .config import Config
from .daemon import Daemon
from .db import Database
from .events import (
    ALL_KINDS, extract_tags, fetch_recent, fetch_search,
    score_event_with_breakdown, url_already_seen,
)
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
            result = await add_target(
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

        # Fire light-weight watchers immediately so the target lights up
        # with data right away. BBOT (heavy) is skipped — run
        # target_force_scan(kind="recon") manually when ready.
        try:
            prime = await daemon.prime_new_target(name)
            result["primed"] = prime
        except Exception as e:
            result["prime_error"] = str(e) or repr(e)
        return result

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
        """
        Return the full target spec plus watcher status. Watchers are
        derived from the target spec (so they're listed even before they've
        ever run), and merged with runtime state from the watcher_state
        table — including disabled-because reason when an env var is
        missing.
        """
        try:
            target = await get_target(db, name)
        except TargetNotFound:
            return {"error": "target_not_found", "name": name}
        watchers = await _watchers_view(target)
        return {"target": target, "watchers": watchers}

    @mcp.tool()
    async def target_list() -> dict:
        """List all targets with light summary info."""
        targets = await list_targets(db)
        return {"count": len(targets), "targets": targets}

    @mcp.tool()
    async def target_health_check(name: str | None = None) -> dict:
        """
        Health/status of every watcher for one target or all targets.
        Watchers are derived from each target's spec (not just from runtime
        state), so newly-added targets show their pending watchers too.
        """
        if name is not None:
            try:
                target = await get_target(db, name)
            except TargetNotFound:
                return {"error": "target_not_found", "name": name}
            return {"watchers": await _watchers_view(target)}

        out: list[dict] = []
        for t in await list_targets(db):
            out.extend(await _watchers_view(t))
        return {"watchers": out}

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
    async def target_rescore(
        name: str | None = None,
        delete_filtered: bool = False,
    ) -> dict:
        """
        Re-apply current per-target scoring_keywords + ignore_patterns to
        every existing event for this target (or all targets if name is
        None). Useful after changing the keyword config, or to backfill
        events ingested before scoring/tagging existed. With
        delete_filtered=True, events that now match an ignore_patterns
        regex are removed; default is to keep them.
        """
        import json as _json, re as _re
        from .events import matches_ignore_patterns

        if name:
            try:
                target = await get_target(db, name)
            except TargetNotFound:
                return {"error": "target_not_found", "name": name}
            targets = [target]
        else:
            targets = await list_targets(db)

        total_rescored = 0
        total_deleted = 0
        per_target: list[dict] = []

        for t in targets:
            tn = t["name"]
            kw = t.get("scoring_keywords") or None
            ignore = t.get("ignore_patterns") or []
            rows = await db.fetchall(
                "SELECT id, title, url, payload FROM events WHERE target_name = ?",
                (tn,),
            )
            rescored = 0
            deleted = 0
            for r in rows:
                try:
                    payload = _json.loads(r["payload"]) if r["payload"] else {}
                except (ValueError, TypeError):
                    payload = {}
                title = r["title"] or ""
                if delete_filtered and ignore:
                    haystack = title + "\n" + str(payload)
                    if matches_ignore_patterns(haystack, ignore):
                        await db.execute("DELETE FROM events WHERE id = ?", (r["id"],))
                        deleted += 1
                        continue
                # Recount novelty: was this URL the first one for the target?
                # For backfill we don't worry about historical novelty — treat
                # all as novel. This is a backfill tool, not a precise
                # reproduction of original ingestion.
                tags = extract_tags(title, payload, kw)
                score, breakdown = score_event_with_breakdown(title, payload, kw, True)
                payload["_score_breakdown"] = breakdown
                await db.execute(
                    "UPDATE events SET tags = ?, score = ?, payload = ? WHERE id = ?",
                    (
                        _json.dumps(tags) if tags else None,
                        score,
                        _json.dumps(payload, default=str),
                        r["id"],
                    ),
                )
                rescored += 1
            per_target.append({"target": tn, "rescored": rescored, "deleted": deleted})
            total_rescored += rescored
            total_deleted += deleted

        return {
            "total_rescored": total_rescored,
            "total_deleted": total_deleted,
            "delete_filtered": delete_filtered,
            "per_target": per_target,
        }

    @mcp.tool()
    async def feed_recent(
        target: str | None = None,
        kind: str | None = None,
        since: str | None = None,
        hours_ago: int | None = None,
        tags: list[str] | None = None,
        min_score: float | None = None,
        limit: int = 100,
        compact: bool = False,
    ) -> dict:
        """
        Recent events. Filter by target, by kind (recon|news|scope|secrets|js|social),
        by `since` (ISO 8601) or `hours_ago`, by tags (any match), and by
        min_score (events with score >= n). `compact=true` returns just
        title/url/kind/tags/score/observed_at/target — much cheaper for an
        AI consumer to scan.
        """
        if since is None and hours_ago is not None:
            since = (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).isoformat()
        events = await fetch_recent(
            db, target=target, kind=kind, since=since,
            tags=tags, min_score=min_score, limit=limit, compact=compact,
        )
        return {"count": len(events), "events": events}

    @mcp.tool()
    async def feed_search(
        query: str,
        target: str | None = None,
        since: str | None = None,
        hours_ago: int | None = None,
        limit: int = 50,
        compact: bool = False,
    ) -> dict:
        """
        Full-text search over event titles + payloads using SQLite FTS5.
        Special characters (hyphens, parens, etc) are auto-escaped, so
        `"managed-agents"` and `oauth OR saml` both work as expected.
        Operators AND/OR/NOT/NEAR are preserved.
        """
        if since is None and hours_ago is not None:
            since = (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).isoformat()
        events = await fetch_search(
            db, query, target=target, since=since, limit=limit, compact=compact
        )
        return {"count": len(events), "events": events}

    @mcp.tool()
    async def target_diff(
        name: str,
        since: str | None = None,
        hours_ago: int = 24,
        min_score: float = 1.0,
    ) -> dict:
        """
        "What changed for this target since I last looked." Returns events
        grouped by kind, scope changes flagged separately, plus a one-line
        per-event compact view. Default window: last 24h, score >= 1.0
        (mid-noise filtering).
        """
        try:
            target = await get_target(db, name)
        except TargetNotFound:
            return {"error": "target_not_found", "name": name}
        if since is None:
            since = (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).isoformat()
        events = await fetch_recent(
            db, target=name, since=since, min_score=min_score, limit=500, compact=True,
        )
        by_kind: dict[str, list[dict]] = {}
        scope_changes: list[dict] = []
        for e in events:
            by_kind.setdefault(e["kind"], []).append(e)
            if e["kind"] == "scope":
                scope_changes.append(e)
        summary_lines = [
            f"{len(events)} events for {name} since {since[:19]} (score >= {min_score})"
        ]
        for k in sorted(by_kind):
            summary_lines.append(f"  {k}: {len(by_kind[k])}")
        return {
            "target": name,
            "since": since,
            "min_score": min_score,
            "by_kind": by_kind,
            "scope_changes": scope_changes,
            "summary": "\n".join(summary_lines),
            "total": len(events),
        }

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
        returned. When the LLM path is requested but unavailable, the
        response includes `llm_skip_reason` explaining why (no key set,
        API call failed, etc.) so the caller knows.
        """
        since = (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).isoformat()
        events = await fetch_recent(db, target=target, kind=kind, since=since, limit=limit)
        used_llm = False
        llm_skip_reason: str | None = None
        if use_llm and cfg.anthropic_api_key:
            text = await llm_summary(events, cfg.anthropic_api_key)
            used_llm = True
            if "(LLM summary failed:" in text:
                llm_skip_reason = "anthropic api call failed; see summary text for details"
        elif use_llm and not cfg.anthropic_api_key:
            text = heuristic_summary(events)
            llm_skip_reason = "ANTHROPIC_API_KEY not set; using deterministic summary"
        else:
            text = heuristic_summary(events)
        out: dict[str, Any] = {
            "summary": text,
            "event_count": len(events),
            "window_hours": hours_ago,
            "target_filter": target,
            "kind_filter": kind,
            "used_llm": used_llm,
        }
        if llm_skip_reason:
            out["llm_skip_reason"] = llm_skip_reason
        return out

    @mcp.tool()
    async def system_status() -> dict:
        """Daemon + Discord routing + delivery stats + stale watchers."""
        from .watchers.github_events import resolve_github_token
        from .daemon import parse_duration

        # undelivered queue size
        row = await db.fetchone("SELECT COUNT(*) AS c FROM events WHERE delivered = 0")
        queue_size = row["c"] if row else 0
        delivery_stats = dict(daemon.router.stats)
        delivery_stats["queue_size"] = queue_size

        # Stale watchers: any expected watcher that should have run by now
        # (last_run is older than 2× its cadence) is flagged so silent
        # failures surface here instead of being invisible.
        now = datetime.now(timezone.utc)
        stale: list[dict] = []
        for t in await list_targets(db):
            if not t.get("enabled"):
                continue
            for w in daemon._build_watchers_for_target(t):
                cadence_str = (t.get("cadence_overrides") or {}).get(w.kind) \
                              or cfg.cadences.get(w.kind)
                if not cadence_str or cadence_str == "live":
                    continue
                try:
                    cadence = parse_duration(cadence_str)
                except Exception:
                    continue
                state = await db.fetchone(
                    "SELECT last_run, last_success, last_error, metadata FROM watcher_state WHERE id = ?",
                    (w.id,),
                )
                if state is None:
                    stale.append({
                        "id": w.id, "kind": w.kind, "target": t["name"],
                        "issue": "never_run", "expected_cadence": cadence_str,
                    })
                    continue
                meta = {}
                try:
                    meta = json.loads(state["metadata"]) if state["metadata"] else {}
                except Exception:
                    pass
                if isinstance(meta, dict) and meta.get("disabled"):
                    continue
                last = state["last_run"]
                if last:
                    try:
                        last_dt = datetime.fromisoformat(last)
                        age = now - last_dt
                        if age > cadence * 2:
                            stale.append({
                                "id": w.id, "kind": w.kind, "target": t["name"],
                                "issue": "overdue",
                                "last_run": last,
                                "age_seconds": int(age.total_seconds()),
                                "expected_cadence": cadence_str,
                                "last_error": state["last_error"],
                            })
                    except ValueError:
                        pass

        gh_tok, gh_src = await resolve_github_token()

        import os as _os
        h1_safety = _os.environ.get("OSINT_HACKERONE_API_ENABLED", "").lower() in ("1","true","yes","on")
        bc_safety = _os.environ.get("OSINT_BUGCROWD_API_ENABLED", "").lower() in ("1","true","yes","on")

        return {
            "data_dir": str(cfg.data_dir),
            "db_path": str(cfg.db_path),
            "discord": {
                "enabled": cfg.discord.enabled,
                "firehose_set": bool(cfg.discord.firehose),
                "kind_overrides": sorted(cfg.discord.kind_webhooks.keys()),
                "delivery_stats": delivery_stats,
            },
            "cadences": cfg.cadences,
            "bbot_preset": cfg.bbot.preset,
            "platform_api_safety": {
                "hackerone_enabled": h1_safety,
                "bugcrowd_enabled":  bc_safety,
                "note": (
                    "Off by default. With these flags off, no requests hit "
                    "api.hackerone.com or api.bugcrowd.com regardless of "
                    "tokens. Set OSINT_HACKERONE_API_ENABLED=1 (or _BUGCROWD_) "
                    "to opt in."
                ),
            },
            "optional_keys": {
                "hackerone": {
                    "credentials_set": bool(cfg.hackerone_token and cfg.hackerone_username),
                    "watcher_enabled": h1_safety,
                },
                "bugcrowd": {
                    "credentials_set": bool(cfg.bugcrowd_token),
                    "watcher_enabled": bc_safety,
                },
                "github": {"available": bool(gh_tok), "source": gh_src},
                "anthropic": bool(cfg.anthropic_api_key),
            },
            "stale_watchers": stale,
        }

    async def _watchers_view(target: dict) -> list[dict]:
        """
        Return one row per watcher derived from the target spec, merged with
        any runtime state. Watchers that didn't run yet show up as 'pending';
        watchers that won't run because of missing tokens show up as 'disabled'
        with a clear reason.
        """
        spec_watchers = daemon._build_watchers_for_target(target)
        # Pull runtime state for this target
        state_rows = await target_health(db, target["name"])
        state_by_id = {r["id"]: r for r in state_rows}
        out: list[dict] = []
        for w in spec_watchers:
            row = state_by_id.pop(w.id, None)
            entry = {
                "id": w.id,
                "kind": w.kind,
                "target_name": target["name"],
            }
            if row is None:
                entry.update({
                    "last_run": None,
                    "last_success": None,
                    "last_error": None,
                    "consecutive_failures": 0,
                    "metadata": {},
                    "status": "pending",
                })
            else:
                entry.update({
                    "last_run": row["last_run"],
                    "last_success": row["last_success"],
                    "last_error": row["last_error"],
                    "consecutive_failures": row["consecutive_failures"],
                    "metadata": row["metadata"],
                    "status": row["status"],
                })
                meta = row.get("metadata") or {}
                if isinstance(meta, dict) and meta.get("disabled"):
                    entry["status"] = "disabled"
                    entry["disabled_reason"] = meta.get("reason")
            out.append(entry)
        # Surface any orphan watcher_state rows whose watcher class no longer
        # applies (e.g. user removed an RSS feed but old state lingers)
        for row in state_by_id.values():
            out.append({**row, "status": row.get("status", "stale"), "orphan": True})
        return out

    return mcp
