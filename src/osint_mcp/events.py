from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from .db import Database, now_iso


KIND_RECON = "recon"
KIND_NEWS = "news"
KIND_SCOPE = "scope"
KIND_SECRETS = "secrets"
KIND_JS = "js"
KIND_SOCIAL = "social"

ALL_KINDS = {KIND_RECON, KIND_NEWS, KIND_SCOPE, KIND_SECRETS, KIND_JS, KIND_SOCIAL}

# Sensible default scoring keywords used when a target has no per-target
# scoring_keywords config. Skewed toward bug-bounty-relevant signal.
DEFAULT_SCORING_KEYWORDS: dict[str, float] = {
    "rce": 5, "ssrf": 5, "idor": 5, "xss": 4, "csrf": 4, "sqli": 5,
    "auth": 4, "authn": 4, "authz": 4, "oauth": 4, "saml": 4, "jwt": 3,
    "credential": 5, "secret": 4, "token": 3, "password": 3, "key": 2,
    "vault": 4, "admin": 4, "internal": 3, "private": 3,
    "leak": 5, "breach": 5, "disclosure": 4, "vulnerability": 5, "cve": 4,
    "scope": 3, "scope_change": 5, "in-scope": 4, "policy": 2,
    "release": 2, "launch": 2, "new": 1, "deprecate": 2, "deprecated": 2,
    "incident": 2, "outage": 1, "degraded": 1,
    "api": 1, "endpoint": 2, "graphql": 2, "webhook": 1,
}


def extract_tags(
    title: str | None,
    payload: dict[str, Any] | None,
    keywords: dict[str, float] | None = None,
) -> list[str]:
    """
    Cheap NER-lite. Pulls subsystem-style tokens from title/payload using:
      - target's per-target scoring_keywords (whichever ones appear)
      - heuristic CamelCase / Quoted "Subsystem Name" extraction
    Returns a deduped, lowercased list (max 12 entries).
    """
    text = (title or "")
    if payload:
        for k in ("summary", "description"):
            v = payload.get(k)
            if isinstance(v, str):
                text += "\n" + v
    text_l = text.lower()

    kw_pool = keywords if keywords is not None else DEFAULT_SCORING_KEYWORDS
    tags = set()
    for kw in kw_pool:
        # leading word-boundary only, so "vault" matches "Vaults", "credential"
        # matches "Credentials", etc. — common English plurals/inflections.
        if re.search(rf"\b{re.escape(kw.lower())}", text_l):
            tags.add(kw.lower())

    # Heuristic: quoted subsystem names like "Vaults", "MCP apps"
    for m in re.finditer(r'"([A-Z][A-Za-z0-9 ]{2,40})"', text):
        tags.add(m.group(1).strip().lower())

    # Heuristic: standalone capitalized tokens that look like product names
    for m in re.finditer(r"\b([A-Z][a-z]{2,})\b", text):
        tok = m.group(1).lower()
        if tok in {"the", "this", "that", "with", "from", "into", "when", "what",
                   "where", "after", "before", "also", "have"}:
            continue
        # Only include if it appears in a recognisable context (preceded by
        # "the" / inside quotes / etc) — too aggressive otherwise.
        # Skip: too noisy without a richer model.
        pass

    return sorted(tags)[:12]


def score_event(
    title: str | None,
    payload: dict[str, Any] | None,
    target_keywords: dict[str, float] | None,
    is_novel_url: bool,
) -> float:
    """
    score = novelty_factor * (1 + sum(matching_keyword_weights))
    novelty: 1.0 for unique URL within target, 0.3 for repeat
    Recency is applied at query time, not insert time.
    """
    novelty = 1.0 if is_novel_url else 0.3
    text = ((title or "") + " " + json.dumps(payload or {}, default=str)).lower()
    kw = target_keywords if target_keywords else DEFAULT_SCORING_KEYWORDS
    matched_sum = 0.0
    for keyword, weight in kw.items():
        if re.search(rf"\b{re.escape(keyword.lower())}", text):
            matched_sum += float(weight)
    return round(novelty * (1.0 + matched_sum), 2)


def matches_ignore_patterns(text: str, patterns: list[str]) -> bool:
    for pat in patterns or []:
        try:
            if re.search(pat, text):
                return True
        except re.error:
            continue
    return False


_NEAR_OP = re.compile(r"^NEAR(?:/\d+)?$", re.IGNORECASE)


def escape_fts5_query(user_query: str) -> str:
    """
    Make a user query safe for FTS5 MATCH while preserving the operators
    AND/OR/NOT/NEAR (and the NEAR/N variant). Tokens containing FTS5-special
    characters get wrapped in double quotes so e.g. "managed-agents" stays
    a single token rather than being parsed as `managed - agents`.
    """
    operators = {"AND", "OR", "NOT"}
    special_chars = set('-:()*<>=^"\\&!')
    out = []
    for tok in user_query.split():
        if tok.upper() in operators or _NEAR_OP.match(tok):
            out.append(tok)
            continue
        if any(c in special_chars for c in tok):
            tok = tok.replace('"', '""')
            out.append(f'"{tok}"')
        else:
            out.append(tok)
    return " ".join(out) if out else user_query


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
    tags: list[str] = field(default_factory=list)

    def hash(self) -> str:
        h = hashlib.sha256()
        h.update(self.kind.encode())
        h.update(b"\x00")
        h.update(self.source.encode())
        h.update(b"\x00")
        h.update(self.dedup_key.encode())
        return h.hexdigest()


async def url_already_seen(db: Database, target_name: str | None, url: str | None) -> bool:
    if not url or not target_name:
        return False
    row = await db.fetchone(
        "SELECT 1 FROM events WHERE target_name = ? AND url = ? LIMIT 1",
        (target_name, url),
    )
    return row is not None


async def ingest(db: Database, event: Event) -> bool:
    """
    Insert event if new. Returns True if inserted, False if duplicate.
    Two-layer dedup:
      1. (kind, source, dedup_key) — same source can't re-emit identical event
      2. (target_name, url) — different sources mirroring the same incident
         won't produce two events; second one is silently dropped
    """
    if event.kind not in ALL_KINDS:
        raise ValueError(f"unknown event kind: {event.kind}")

    if event.url and event.target_name:
        if await url_already_seen(db, event.target_name, event.url):
            return False

    h = event.hash()
    cur = await db.execute(
        """
        INSERT OR IGNORE INTO events
            (target_name, kind, source, observed_at, title, url, payload, hash,
             tags, score, delivered)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
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
            json.dumps(event.tags) if event.tags else None,
            event.score,
        ),
    )
    return cur.rowcount > 0


async def fetch_recent(
    db: Database,
    target: str | None = None,
    kind: str | None = None,
    since: str | None = None,
    tags: list[str] | None = None,
    min_score: float | None = None,
    limit: int = 100,
    compact: bool = False,
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
    if min_score is not None:
        where.append("score >= ?")
        params.append(min_score)
    sql = "SELECT * FROM events"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY observed_at DESC LIMIT ?"
    params.append(limit * 3 if tags else limit)
    rows = await db.fetchall(sql, tuple(params))
    out = [_row_to_dict(r, compact=compact) for r in rows]

    if tags:
        wanted = {t.lower() for t in tags}
        out = [e for e in out if wanted & set(t.lower() for t in (e.get("tags") or []))]
        out = out[:limit]

    return out


async def fetch_search(
    db: Database,
    query: str,
    target: str | None = None,
    since: str | None = None,
    limit: int = 50,
    compact: bool = False,
) -> list[dict[str, Any]]:
    safe_q = escape_fts5_query(query)
    sql = """
        SELECT events.* FROM events
        JOIN events_fts ON events.id = events_fts.rowid
        WHERE events_fts MATCH ?
    """
    params: list[Any] = [safe_q]
    if target:
        sql += " AND target_name = ?"
        params.append(target)
    if since:
        sql += " AND observed_at >= ?"
        params.append(since)
    sql += " ORDER BY observed_at DESC LIMIT ?"
    params.append(limit)
    rows = await db.fetchall(sql, tuple(params))
    return [_row_to_dict(r, compact=compact) for r in rows]


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


async def max_event_id(db: Database) -> int:
    row = await db.fetchone("SELECT COALESCE(MAX(id), 0) AS m FROM events")
    return row["m"] if row else 0


async def suppress_range(db: Database, source: str, after_id: int) -> int:
    """Mark all events with the given source and id > after_id as already
    delivered. Used for first-ingestion suppression so a new target doesn't
    flood Discord with backfill."""
    cur = await db.execute(
        "UPDATE events SET delivered = 1 WHERE source = ? AND id > ? AND delivered = 0",
        (source, after_id),
    )
    return cur.rowcount


def _row_to_dict(row, compact: bool = False) -> dict[str, Any]:
    tags: list[str] = []
    try:
        tags = json.loads(row["tags"]) if row["tags"] else []
    except (json.JSONDecodeError, TypeError, IndexError, KeyError):
        tags = []

    if compact:
        return {
            "id": row["id"],
            "target_name": row["target_name"],
            "kind": row["kind"],
            "observed_at": row["observed_at"],
            "title": row["title"],
            "url": row["url"],
            "tags": tags,
            "score": row["score"],
        }

    payload: dict = {}
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
        "tags": tags,
        "score": row["score"],
        "delivered": bool(row["delivered"]),
    }
