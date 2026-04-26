from __future__ import annotations

import json
import logging
from typing import Any

from .autodiscover import autodiscover
from .db import Database, now_iso, row_to_target

log = logging.getLogger("osint.targets")


class TargetNotFound(Exception):
    pass


class TargetExists(Exception):
    pass


async def add_target(
    db: Database,
    name: str,
    *,
    root_domains: list[str] | None = None,
    github_orgs: list[str] | None = None,
    rss_feeds: list[str] | dict | None = None,
    status_page: str | None = None,
    twitter_handles: list[str] | None = None,
    bug_bounty: dict | None = None,
    bbot_preset: str | None = None,
    cadence_overrides: dict | None = None,
    notes: str | None = None,
    auto: bool = True,
) -> dict[str, Any]:
    """
    Add a target. If `auto=True` and any major fields are missing, run
    autodiscover to fill them. Always idempotent on `name`.
    """
    existing = await get_target(db, name, raise_on_missing=False)
    if existing is not None:
        raise TargetExists(name)

    discovery = None
    if auto and not (root_domains and (rss_feeds is not None)):
        log.info("autodiscovering target %s", name)
        d = await autodiscover(name)
        discovery = d.to_dict()
        if not root_domains:
            root_domains = d.candidate_root_domains
        if not github_orgs:
            github_orgs = d.github_orgs
        if rss_feeds is None and d.rss_feeds:
            rss_feeds = [f["url"] for f in d.rss_feeds]
        if not status_page and d.status_page:
            status_page = d.status_page
        if not twitter_handles and d.twitter_handles:
            twitter_handles = d.twitter_handles
        if not bug_bounty and d.bug_bounty_programs:
            bug_bounty = d.bug_bounty_programs[0]

    if not root_domains:
        raise ValueError(
            f"target_add({name!r}) failed: could not determine any root domain. "
            "Pass root_domains explicitly."
        )

    rss_list = _normalize_rss(rss_feeds)
    now = now_iso()

    await db.execute(
        """
        INSERT INTO targets
            (name, root_domains, github_orgs, rss_feeds, status_page,
             twitter_handles, bug_bounty, bbot_preset, cadence_overrides,
             notes, enabled, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
        """,
        (
            name,
            json.dumps(root_domains),
            json.dumps(github_orgs or []),
            json.dumps(rss_list),
            status_page,
            json.dumps(twitter_handles or []),
            json.dumps(bug_bounty) if bug_bounty else None,
            bbot_preset or "subdomain-enum",
            json.dumps(cadence_overrides) if cadence_overrides else None,
            notes,
            now,
            now,
        ),
    )

    target = await get_target(db, name)
    return {"target": target, "discovery": discovery}


async def get_target(
    db: Database, name: str, raise_on_missing: bool = True
) -> dict[str, Any] | None:
    row = await db.fetchone("SELECT * FROM targets WHERE name = ?", (name,))
    if row is None:
        if raise_on_missing:
            raise TargetNotFound(name)
        return None
    return row_to_target(row)


async def list_targets(db: Database) -> list[dict[str, Any]]:
    rows = await db.fetchall("SELECT * FROM targets ORDER BY name")
    return [row_to_target(r) for r in rows]


async def update_target(
    db: Database, name: str, patch: dict[str, Any]
) -> dict[str, Any]:
    target = await get_target(db, name)
    json_fields = {
        "root_domains", "github_orgs", "rss_feeds",
        "twitter_handles", "bug_bounty", "cadence_overrides",
    }
    scalar_fields = {"status_page", "bbot_preset", "notes", "enabled"}

    sets, params = [], []
    for k, v in patch.items():
        if k in json_fields:
            if k == "rss_feeds":
                v = _normalize_rss(v)
            sets.append(f"{k} = ?")
            params.append(json.dumps(v) if v is not None else None)
        elif k in scalar_fields:
            sets.append(f"{k} = ?")
            params.append(int(v) if k == "enabled" else v)
        else:
            log.warning("ignoring unknown field in target patch: %s", k)
    if not sets:
        return target
    sets.append("updated_at = ?")
    params.append(now_iso())
    params.append(name)
    await db.execute(
        f"UPDATE targets SET {', '.join(sets)} WHERE name = ?", tuple(params)
    )
    return await get_target(db, name)


async def remove_target(db: Database, name: str) -> bool:
    await get_target(db, name)
    await db.execute("DELETE FROM targets WHERE name = ?", (name,))
    await db.execute(
        "DELETE FROM watcher_state WHERE target_name = ?", (name,)
    )
    return True


async def target_health(db: Database, name: str | None = None) -> list[dict[str, Any]]:
    if name is not None:
        rows = await db.fetchall(
            "SELECT * FROM watcher_state WHERE target_name = ? ORDER BY id",
            (name,),
        )
    else:
        rows = await db.fetchall(
            "SELECT * FROM watcher_state ORDER BY target_name, id"
        )
    out = []
    for r in rows:
        meta = json.loads(r["metadata"]) if r["metadata"] else {}
        out.append({
            "id": r["id"],
            "target_name": r["target_name"],
            "kind": r["kind"],
            "last_run": r["last_run"],
            "last_success": r["last_success"],
            "last_error": r["last_error"],
            "consecutive_failures": r["consecutive_failures"],
            "metadata": meta,
            "status": _status_from_state(r),
        })
    return out


def _status_from_state(row) -> str:
    if row["consecutive_failures"] >= 5:
        return "broken"
    if row["consecutive_failures"] > 0:
        return "degraded"
    if row["last_success"] is None:
        return "pending"
    return "healthy"


def _normalize_rss(value) -> list[dict[str, str]]:
    """Accept list[str] | list[dict] | dict and normalize to list[dict[url,title]]."""
    if value is None:
        return []
    if isinstance(value, dict):
        value = [value]
    out = []
    for item in value:
        if isinstance(item, str):
            out.append({"url": item, "title": ""})
        elif isinstance(item, dict) and "url" in item:
            out.append({"url": item["url"], "title": item.get("title", "")})
    return out
