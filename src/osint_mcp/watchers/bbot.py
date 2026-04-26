from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from ..db import Database
from ..events import KIND_RECON, Event
from .base import Watcher, WatcherResult

log = logging.getLogger("osint.bbot")


class BbotWatcher(Watcher):
    """
    Subprocess wrapper around BBOT.
    Runs `bbot -t <root> -p <preset> -o <scan_dir> -y --json` and parses
    the resulting `output.json` (NDJSON) for DNS_NAME and URL events.
    """

    kind = KIND_RECON

    def __init__(
        self,
        target_name: str,
        root_domain: str,
        preset: str = "subdomain-enum",
        output_dir: Path = Path("./scans"),
    ):
        wid = f"bbot:{target_name}:{root_domain}"
        super().__init__(wid, target_name)
        self.root_domain = root_domain
        self.preset = preset
        self.output_dir = output_dir

    async def run(self, db: Database) -> WatcherResult:
        result = WatcherResult()
        bbot_bin = _find_bbot()
        if not bbot_bin:
            msg = "bbot binary not found; install with `pip install bbot`"
            log.warning(msg)
            result.errors.append(msg)
            return result

        scan_id = f"{self.target_name}_{int(asyncio.get_event_loop().time()*1000)}"
        scan_dir = self.output_dir / scan_id
        scan_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            bbot_bin,
            "-t", self.root_domain,
            "-p", self.preset,
            "-o", str(scan_dir),
            "--name", scan_id,
            "-y",
            "--silent",
        ]
        log.info("running bbot: %s", " ".join(cmd))
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=3600)
        except asyncio.TimeoutError:
            result.errors.append("bbot scan timed out (>1h)")
            return result
        except Exception as e:
            result.errors.append(f"bbot exec failed: {e}")
            return result

        if proc.returncode != 0:
            err_tail = (stderr or b"").decode("utf-8", "replace")[-400:]
            result.errors.append(f"bbot exited {proc.returncode}: {err_tail}")
            return result

        out_files = list((scan_dir / scan_id).rglob("output.ndjson")) + \
                    list((scan_dir / scan_id).rglob("output.json")) + \
                    list(scan_dir.rglob("output.ndjson")) + \
                    list(scan_dir.rglob("output.json"))

        if not out_files:
            result.errors.append("bbot produced no output file")
            return result

        for path in out_files[:1]:
            for ev in _read_ndjson(path):
                event = _bbot_event_to_event(self.target_name, self.root_domain, ev)
                if event is None:
                    continue
                if await self.emit(db, event):
                    result.new_events += 1
                else:
                    result.duplicate_events += 1

        result.metadata = {
            "root_domain": self.root_domain,
            "preset": self.preset,
            "scan_dir": str(scan_dir),
        }
        return result


def _find_bbot() -> str | None:
    """Locate bbot binary. Checks PATH first, then alongside the current
    Python interpreter (so unactivated venvs work too)."""
    p = shutil.which("bbot")
    if p:
        return p
    bin_dir = Path(sys.executable).parent
    for candidate in ("bbot.exe", "bbot"):
        cand = bin_dir / candidate
        if cand.is_file():
            return str(cand)
    return None


def _read_ndjson(path: Path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        return


def _bbot_event_to_event(target: str, root: str, ev: dict[str, Any]) -> Event | None:
    et = ev.get("type") or ev.get("event_type")
    data = ev.get("data")
    if et == "DNS_NAME" and isinstance(data, str):
        return Event(
            kind=KIND_RECON,
            source=f"bbot:{root}",
            target_name=target,
            title=f"new subdomain: {data}",
            url=f"https://{data}",
            payload={
                "subdomain": data,
                "root": root,
                "tags": ev.get("tags", []),
                "module": ev.get("module"),
            },
            dedup_key=f"subdomain:{data}",
        )
    if et == "URL" and isinstance(data, str):
        return Event(
            kind=KIND_RECON,
            source=f"bbot:{root}",
            target_name=target,
            title=f"new URL: {data}",
            url=data,
            payload={
                "url": data,
                "root": root,
                "tags": ev.get("tags", []),
                "module": ev.get("module"),
                "status_code": ev.get("resolved_hosts"),
            },
            dedup_key=f"url:{data}",
        )
    if et == "FINDING" and isinstance(data, dict):
        desc = data.get("description") or "(no description)"
        return Event(
            kind=KIND_RECON,
            source=f"bbot:{root}",
            target_name=target,
            title=f"finding: {desc[:120]}",
            url=data.get("url"),
            payload={"finding": data, "module": ev.get("module")},
            dedup_key=f"finding:{desc}:{data.get('host', '')}",
        )
    return None
