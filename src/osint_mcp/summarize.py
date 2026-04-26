"""
LLM digest of recent events. Uses the Anthropic API directly via httpx so
we don't take an extra SDK dep. Falls back to a deterministic
group-by-kind text summary if no API key is configured — that way the
endpoint always returns something useful.
"""
from __future__ import annotations

import json
import logging
import os
from collections import Counter, defaultdict
from typing import Any

import httpx

log = logging.getLogger("osint.summary")

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = "claude-haiku-4-5-20251001"
SYSTEM_PROMPT = (
    "You are an OSINT analyst summarizing recent attack-surface events for a bug "
    "bounty hunter. Be terse. Group by target. Highlight what's new and what an "
    "AI hacker would want to investigate first. Skip noise. Output plain text, "
    "no preamble, no caveats. Always cite event source/url inline when relevant."
)


def heuristic_summary(events: list[dict[str, Any]]) -> str:
    if not events:
        return "(no events in window)"
    by_target: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        by_target[e.get("target_name") or "(global)"].append(e)
    by_kind = Counter(e["kind"] for e in events)
    lines = [
        f"{len(events)} events across {len(by_target)} targets — "
        + ", ".join(f"{k}:{v}" for k, v in by_kind.most_common()),
        "",
    ]
    for tgt, evs in sorted(by_target.items(), key=lambda kv: -len(kv[1])):
        kinds = Counter(e["kind"] for e in evs)
        lines.append(f"## {tgt} — {len(evs)} ({', '.join(f'{k}:{v}' for k, v in kinds.most_common())})")
        for e in evs[:5]:
            t = (e.get("title") or "(no title)")[:120]
            lines.append(f"  - [{e['kind']}] {t}")
            if e.get("url"):
                lines.append(f"      {e['url']}")
        if len(evs) > 5:
            lines.append(f"  …and {len(evs) - 5} more")
        lines.append("")
    return "\n".join(lines)


async def llm_summary(
    events: list[dict[str, Any]],
    api_key: str,
    model: str = DEFAULT_MODEL,
) -> str:
    if not events:
        return "(no events in window)"

    compact = []
    for e in events[:200]:
        compact.append({
            "t": (e.get("title") or "")[:200],
            "kind": e["kind"],
            "tgt": e.get("target_name"),
            "url": e.get("url"),
            "src": e["source"],
            "at": e["observed_at"][:19],
        })

    prompt = (
        "Summarize the following attack-surface events for a bug bounty hunter. "
        "Pick the 3-5 highest-leverage threads to investigate first. Be terse.\n\n"
        f"{json.dumps(compact, indent=1)}"
    )
    body = {
        "model": model,
        "max_tokens": 1024,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": prompt}],
    }
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    async with httpx.AsyncClient(timeout=60.0) as c:
        r = await c.post(ANTHROPIC_URL, headers=headers, json=body)
    if r.status_code != 200:
        log.warning("anthropic summary failed: %s %s", r.status_code, r.text[:300])
        return heuristic_summary(events) + f"\n\n(LLM summary failed: HTTP {r.status_code})"
    data = r.json()
    blocks = data.get("content") or []
    text = "\n".join(b.get("text", "") for b in blocks if b.get("type") == "text")
    return text.strip() or heuristic_summary(events)
