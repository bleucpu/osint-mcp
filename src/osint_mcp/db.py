from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    name              TEXT PRIMARY KEY,
    root_domains      TEXT NOT NULL,    -- JSON array
    github_orgs       TEXT,             -- JSON array
    rss_feeds         TEXT,             -- JSON array
    status_page       TEXT,
    twitter_handles   TEXT,             -- JSON array
    bug_bounty        TEXT,             -- JSON object
    bbot_preset       TEXT DEFAULT 'subdomain-enum',
    cadence_overrides TEXT,             -- JSON object {kind: duration}
    notes             TEXT,
    enabled           INTEGER DEFAULT 1,
    scoring_keywords  TEXT,             -- JSON object {keyword: weight}
    ignore_patterns   TEXT,             -- JSON array of regex strings
    js_pages          TEXT,             -- JSON array of URLs to scan for <script src>
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT,
    kind        TEXT NOT NULL,
    source      TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    title       TEXT,
    url         TEXT,
    payload     TEXT NOT NULL,
    hash        TEXT NOT NULL UNIQUE,
    tags        TEXT,                    -- JSON array
    score       REAL DEFAULT 0,
    delivered   INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_events_target_kind_obs
    ON events(target_name, kind, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_events_undelivered
    ON events(delivered) WHERE delivered = 0;

CREATE INDEX IF NOT EXISTS idx_events_target_url
    ON events(target_name, url) WHERE url IS NOT NULL;

CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
    title, payload,
    content='events',
    content_rowid='id',
    tokenize='porter unicode61'
);

CREATE TRIGGER IF NOT EXISTS events_ai AFTER INSERT ON events BEGIN
    INSERT INTO events_fts(rowid, title, payload)
    VALUES (new.id, new.title, new.payload);
END;

CREATE TRIGGER IF NOT EXISTS events_ad AFTER DELETE ON events BEGIN
    INSERT INTO events_fts(events_fts, rowid, title, payload)
    VALUES ('delete', old.id, old.title, old.payload);
END;

CREATE TABLE IF NOT EXISTS watcher_state (
    id                    TEXT PRIMARY KEY,    -- e.g. 'rss:huggingface:blog'
    target_name           TEXT,
    kind                  TEXT NOT NULL,
    last_run              TEXT,
    last_success          TEXT,
    last_error            TEXT,
    consecutive_failures  INTEGER DEFAULT 0,
    metadata              TEXT                 -- JSON, watcher-specific
);

CREATE INDEX IF NOT EXISTS idx_watcher_state_target
    ON watcher_state(target_name);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    def __init__(self, path: Path):
        self.path = path
        self._conn: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        self._conn = await aiosqlite.connect(self.path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.executescript(SCHEMA)
        await self._migrate()
        await self._conn.commit()

    async def _migrate(self) -> None:
        """Add columns introduced after a DB was first created. Idempotent."""
        async def _cols(table: str) -> set[str]:
            async with self._conn.execute(f"PRAGMA table_info({table})") as cur:
                return {r["name"] for r in await cur.fetchall()}

        adds = [
            ("targets", "scoring_keywords", "TEXT"),
            ("targets", "ignore_patterns",  "TEXT"),
            ("targets", "js_pages",         "TEXT"),
            ("events",  "tags",             "TEXT"),
        ]
        for table, col, typ in adds:
            if col not in await _cols(table):
                await self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")
        await self._conn.commit()

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    @property
    def conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("Database not connected; call connect() first")
        return self._conn

    async def execute(self, sql: str, params: tuple = ()) -> aiosqlite.Cursor:
        cur = await self.conn.execute(sql, params)
        await self.conn.commit()
        return cur

    async def fetchone(self, sql: str, params: tuple = ()) -> aiosqlite.Row | None:
        async with self.conn.execute(sql, params) as cur:
            return await cur.fetchone()

    async def fetchall(self, sql: str, params: tuple = ()) -> list[aiosqlite.Row]:
        async with self.conn.execute(sql, params) as cur:
            return list(await cur.fetchall())


def row_to_target(row: aiosqlite.Row) -> dict[str, Any]:
    def _json(field: str | None, default: Any) -> Any:
        return json.loads(field) if field else default

    def _opt(field: str, default: Any = None) -> Any:
        try:
            return row[field]
        except (IndexError, KeyError):
            return default

    return {
        "name": row["name"],
        "root_domains": _json(row["root_domains"], []),
        "github_orgs": _json(row["github_orgs"], []),
        "rss_feeds": _json(row["rss_feeds"], []),
        "status_page": row["status_page"],
        "twitter_handles": _json(row["twitter_handles"], []),
        "bug_bounty": _json(row["bug_bounty"], None),
        "bbot_preset": row["bbot_preset"],
        "cadence_overrides": _json(row["cadence_overrides"], {}),
        "notes": row["notes"],
        "enabled": bool(row["enabled"]),
        "scoring_keywords": _json(_opt("scoring_keywords"), {}),
        "ignore_patterns": _json(_opt("ignore_patterns"), []),
        "js_pages": _json(_opt("js_pages"), []),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
