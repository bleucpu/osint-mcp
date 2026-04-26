from __future__ import annotations

import asyncio
import logging
import os
import sys

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


async def _async_main() -> None:
    _setup_logging()
    log = logging.getLogger("osint.main")

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
