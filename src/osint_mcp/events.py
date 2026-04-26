from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from .db import Database, now_iso


KIND_RECON = "recon"
KIND_NEWS = "news"
KIND_SCOPE = "scope"
KIND_SECRETS = "secrets"
KIND_JS = "js"
KIND_SOCIAL = "social"

ALL_KINDS = {KIND_RECON, KIND_NEWS, KIND_SCOPE, KIND_SECRETS, KIND_JS, KIND_SOCIAL}


@dataclass
class Event:
    kind: str
    source: str
    target_name: str | None
    title: str
    url: str | None
    payload: dict[str, Any]
    dedup_key: str
    observed_at: str = field(default_factory=now_iso)
    score: float = 0.0

    def hash(self) -> str:
        h = hashlib.sha256()
        h.update(self.kind.encode())
        h.update(b"\x00")
        h.update(self.source.encode())
        h.update(b"\x00")
        h.update(self.dedup_key.encode())
        return h.hexdigest()


async def ingest(db: Database, event: Event) -> bool:
    """Insert event if new. Returns True if inserted, False if duplicate."""
    if event.kind not in ALL_KINDS:
        raise ValueError(f"unknown event kind: {event.kind}")

    h = event.hash()
    cur = await db.execute(
        """
        INSERT OR IGNORE INTO events
            (target_name, kind, source, observed_at, title, url, payload, hash, score, delivered)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
        """,
        (
            event.target_name,
            event.kind,
            event.source,
            event.observed_at,
            event.title,
            event.url,
            json.dumps(event.payload, default=str),
            h,
            event.score,
        ),
    )
    return cur.rowcount > 0


async def fetch_recent(
    db: Database,
    target: str | None = None,
    kind: str | None = None,
    since: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    where = []
    params: list[Any] = []
    if target:
        where.append("target_name = ?")
        params.append(target)
    if kind:
        where.append("kind = ?")
        params.append(kind)
    if since:
        where.append("observed_at >= ?")
        params.append(since)
    sql = "SELECT * FROM events"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY observed_at DESC LIMIT ?"
    params.append(limit)
    rows = await db.fetchall(sql, tuple(params))
    return [_row_to_dict(r) for r in rows]


async def fetch_search(
    db: Database,
    query: str,
    target: str | None = None,
    since: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    sql = """
        SELECT events.* FROM events
        JOIN events_fts ON events.id = events_fts.rowid
        WHERE events_fts MATCH ?
    """
    params: list[Any] = [query]
    if target:
        sql += " AND target_name = ?"
        params.append(target)
    if since:
        sql += " AND observed_at >= ?"
        params.append(since)
    sql += " ORDER BY observed_at DESC LIMIT ?"
    params.append(limit)
    rows = await db.fetchall(sql, tuple(params))
    return [_row_to_dict(r) for r in rows]


async def claim_undelivered(db: Database, limit: int = 25) -> list[dict[str, Any]]:
    rows = await db.fetchall(
        "SELECT * FROM events WHERE delivered = 0 ORDER BY id ASC LIMIT ?",
        (limit,),
    )
    return [_row_to_dict(r) for r in rows]


async def mark_delivered(db: Database, event_ids: list[int]) -> None:
    if not event_ids:
        return
    placeholders = ",".join("?" * len(event_ids))
    await db.execute(
        f"UPDATE events SET delivered = 1 WHERE id IN ({placeholders})",
        tuple(event_ids),
    )


def _row_to_dict(row) -> dict[str, Any]:
    payload = {}
    try:
        payload = json.loads(row["payload"]) if row["payload"] else {}
    except (json.JSONDecodeError, TypeError):
        payload = {"_raw": row["payload"]}
    return {
        "id": row["id"],
        "target_name": row["target_name"],
        "kind": row["kind"],
        "source": row["source"],
        "observed_at": row["observed_at"],
        "title": row["title"],
        "url": row["url"],
        "payload": payload,
        "score": row["score"],
        "delivered": bool(row["delivered"]),
    }
