from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from .config import load_config
from .daemon import Daemon
from .db import Database
from .discord import DiscordRouter
from .mcp_server import build_server


def _setup_logging() -> None:
    level = os.environ.get("OSINT_MCP_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def _load_env_file() -> Path | None:
    """Search CWD then this package's parent for a .env file. First wins."""
    candidates = [
        Path.cwd() / ".env",
        Path(__file__).resolve().parent.parent.parent / ".env",
    ]
    for p in candidates:
        if p.is_file():
            load_dotenv(p, override=False)
            return p
    return None


async def _async_main() -> None:
    _setup_logging()
    log = logging.getLogger("osint.main")

    env_path = _load_env_file()
    if env_path:
        log.info("loaded env from %s", env_path)
    else:
        log.info("no .env found, using process environment only")

    cfg = load_config()
    db = Database(cfg.db_path)
    await db.connect()

    router = DiscordRouter(cfg.discord)
    daemon = Daemon(cfg, db, router)
    await daemon.start()

    if not cfg.discord.firehose and not cfg.discord.kind_webhooks:
        log.warning(
            "DISCORD_WEBHOOK_FIREHOSE not set and no per-kind overrides. "
            "Events will accumulate but never be delivered."
        )

    server = build_server(cfg, db, daemon)
    log.info("osint-mcp ready, serving over stdio")
    try:
        await server.run_stdio_async()
    finally:
        await daemon.stop()
        await router.close()
        await db.close()


def main() -> None:
    try:
        asyncio.run(_async_main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
