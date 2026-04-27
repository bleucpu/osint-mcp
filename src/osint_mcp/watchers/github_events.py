"""
GitHub events watcher — public activity on each of a target's GitHub orgs.

Uses the official GitHub API:
  - GET /orgs/{org}/events           (primary; returns repo activity)
  - GET /users/{user}/events/public  (fallback for personal accounts / when
                                      the org endpoint 404s)

60 req/hour without a token; 5000 req/hour with one.

Token resolution (first that wins):
  1. GITHUB_TOKEN / GH_TOKEN env var
  2. `gh auth token` — the GitHub CLI's stored token (zero-config if you've
     run `gh auth login` on this machine)

Both are official and authorized methods for accessing the GitHub API with
a researcher's own credentials. We don't try to scrape, and we don't read
on-disk gh config files directly.

We focus on PushEvent (commits to public repos), ReleaseEvent (versioned
releases — high signal for new feature shipping), and CreateEvent (new
branches / tags / repos). Each ingested as a 'news' event tagged 'github'
+ event-type.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
from typing import Any

import httpx

from ..db import Database
from ..events import KIND_NEWS, Event
from .base import Watcher, WatcherResult

log = logging.getLogger("osint.github_events")

_UA = "osint-mcp/0.1 (+https://github.com/bleucpu/osint-mcp; bug bounty research)"
GH_API = "https://api.github.com"

# Per-process cache so we don't shell out to `gh` on every poll.
_TOKEN_CACHE: dict[str, str | None] = {"token": None, "source": None, "tried": False}


async def resolve_github_token() -> tuple[str | None, str]:
    """
    Returns (token, source). Source is one of: 'env', 'gh-cli', 'none'.
    Cached per-process; restart the daemon to re-resolve after `gh auth login`.
    """
    if _TOKEN_CACHE["tried"]:
        return _TOKEN_CACHE["token"], _TOKEN_CACHE["source"] or "none"

    env_tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if env_tok:
        _TOKEN_CACHE.update(token=env_tok, source="env", tried=True)
        return env_tok, "env"

    if shutil.which("gh"):
        try:
            proc = await asyncio.create_subprocess_exec(
                "gh", "auth", "token",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                env={**os.environ, "GH_PROMPT_DISABLED": "1"},
            )
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=5.0)
            if proc.returncode == 0:
                tok = out.decode("utf-8", "replace").strip()
                if tok and not tok.startswith("error"):
                    _TOKEN_CACHE.update(token=tok, source="gh-cli", tried=True)
                    log.info("using github token from `gh auth token`")
                    return tok, "gh-cli"
        except (asyncio.TimeoutError, FileNotFoundError, OSError):
            pass

    _TOKEN_CACHE.update(token=None, source="none", tried=True)
    return None, "none"


INTERESTING_TYPES = {
    "PushEvent",
    "ReleaseEvent",
    "CreateEvent",            # new branches/tags/repos
    "PublicEvent",             # repo turned public
    "MemberEvent",             # collaborator added
    "RepositoryEvent",         # repo created/transferred/etc.
    "IssuesEvent",             # new issue (action=opened only — see filter)
    "PullRequestEvent",        # new PR (action=opened only — see filter)
    "PullRequestReviewEvent",  # PR review submitted (action=submitted)
}

# Per-event-type action filters: when set, only events whose
# payload.action matches one of these values are kept. Drops most of the
# noise (closing/labeling/edits) while keeping "something new appeared".
INTERESTING_ACTIONS = {
    "IssuesEvent": {"opened", "reopened"},
    "PullRequestEvent": {"opened", "reopened"},
    "PullRequestReviewEvent": {"submitted"},
    "MemberEvent": {"added"},
    "RepositoryEvent": {"created", "publicized", "transferred"},
}


class GitHubEventsWatcher(Watcher):
    kind = KIND_NEWS

    def __init__(self, target_name: str, org: str):
        super().__init__(f"github_events:{target_name}:{org}", target_name)
        self.org = org

    async def run(self, db: Database) -> WatcherResult:
        result = WatcherResult()
        token, token_source = await resolve_github_token()
        headers = {
            "User-Agent": _UA,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

        # Try the org endpoint first (returns repo activity); fall back to
        # /users/{handle}/events/public if it 404s (personal account case).
        primary = f"{GH_API}/orgs/{self.org}/events?per_page=100"
        fallback = f"{GH_API}/users/{self.org}/events/public?per_page=100"
        used_endpoint = primary
        try:
            async with httpx.AsyncClient(timeout=20.0, headers=headers) as c:
                r = await c.get(primary)
                if r.status_code == 404:
                    used_endpoint = fallback
                    r = await c.get(fallback)
        except httpx.HTTPError as e:
            result.errors.append(f"github events request failed: {e}")
            return result

        if r.status_code == 401:
            result.errors.append("github 401 — invalid token")
            return result
        if r.status_code == 403:
            remaining = r.headers.get("x-ratelimit-remaining", "?")
            reset = r.headers.get("x-ratelimit-reset", "?")
            hint = "" if token else " (no token resolved — `gh auth login` raises the limit from 60/hr to 5000/hr)"
            result.errors.append(
                f"github 403 — rate limited (remaining={remaining}, reset={reset}){hint}"
            )
            return result
        if r.status_code == 404:
            result.errors.append(f"github account {self.org} not found")
            return result
        if r.status_code >= 400:
            result.errors.append(f"github HTTP {r.status_code}: {r.text[:200]}")
            return result

        try:
            items = r.json()
        except Exception:
            result.errors.append("github events returned non-JSON")
            return result

        for item in items:
            etype = item.get("type")
            if etype not in INTERESTING_TYPES:
                continue
            allowed_actions = INTERESTING_ACTIONS.get(etype)
            if allowed_actions is not None:
                action = (item.get("payload") or {}).get("action") or ""
                if action not in allowed_actions:
                    continue
            ev = _gh_event_to_event(item, self.org, self.target_name)
            if ev is None:
                continue
            if await self.emit(db, ev):
                result.new_events += 1
            else:
                result.duplicate_events += 1

        result.metadata = {
            "org": self.org,
            "endpoint": used_endpoint,
            "items_seen": len(items),
            "interesting_seen": sum(1 for x in items if x.get("type") in INTERESTING_TYPES),
            "rate_limit_remaining": r.headers.get("x-ratelimit-remaining"),
            "token_source": token_source,
        }
        return result


def _gh_event_to_event(item: dict, org: str, target: str) -> Event | None:
    eid = item.get("id")
    etype = item.get("type")
    repo = (item.get("repo") or {}).get("name") or "(unknown)"
    actor = (item.get("actor") or {}).get("login") or ""
    payload = item.get("payload") or {}
    created_at = item.get("created_at") or ""

    title = ""
    url: str | None = None
    detail: dict[str, Any] = {"event_type": etype, "repo": repo, "actor": actor}

    if etype == "PushEvent":
        commits = payload.get("commits") or []
        ref = payload.get("ref") or ""
        title = f"GitHub: {actor} pushed {len(commits)} commit(s) to {repo}"
        if commits:
            first_msg = (commits[0].get("message") or "").split("\n", 1)[0][:120]
            title += f" — {first_msg}"
        url = f"https://github.com/{repo}/commits/{ref.split('/')[-1] if ref else ''}"
        detail["commit_messages"] = [
            (c.get("message") or "").split("\n", 1)[0][:200] for c in commits[:10]
        ]
        detail["ref"] = ref
    elif etype == "ReleaseEvent":
        rel = payload.get("release") or {}
        tag = rel.get("tag_name") or ""
        name = rel.get("name") or tag or "(release)"
        title = f"GitHub release: {repo} {tag} — {name}"[:200]
        url = rel.get("html_url")
        detail["tag"] = tag
        detail["body"] = (rel.get("body") or "")[:1500]
        detail["prerelease"] = rel.get("prerelease")
    elif etype == "CreateEvent":
        ref_type = payload.get("ref_type")
        ref = payload.get("ref") or ""
        title = f"GitHub: new {ref_type} {ref} in {repo}"[:200]
        url = f"https://github.com/{repo}"
        detail["ref_type"] = ref_type
        detail["ref"] = ref
    elif etype == "PublicEvent":
        title = f"GitHub: repo {repo} made public"
        url = f"https://github.com/{repo}"
    elif etype == "MemberEvent":
        member = (payload.get("member") or {}).get("login") or ""
        action = payload.get("action") or ""
        title = f"GitHub: collaborator {member} {action} on {repo}"
        url = f"https://github.com/{repo}"
    elif etype == "RepositoryEvent":
        action = payload.get("action") or ""
        title = f"GitHub: repo {repo} {action}"
        url = f"https://github.com/{repo}"
    elif etype == "IssuesEvent":
        issue = payload.get("issue") or {}
        action = payload.get("action") or "opened"
        num = issue.get("number")
        issue_title = issue.get("title") or "(no title)"
        title = f"GitHub issue {action}: {repo}#{num} — {issue_title}"[:200]
        url = issue.get("html_url") or f"https://github.com/{repo}/issues/{num}"
        detail["issue_number"] = num
        detail["action"] = action
        detail["body"] = (issue.get("body") or "")[:1500]
        detail["labels"] = [l.get("name") for l in (issue.get("labels") or []) if isinstance(l, dict)]
        detail["author"] = (issue.get("user") or {}).get("login")
    elif etype == "PullRequestEvent":
        pr = payload.get("pull_request") or {}
        action = payload.get("action") or "opened"
        num = pr.get("number") or payload.get("number")
        pr_title = pr.get("title") or "(no title)"
        title = f"GitHub PR {action}: {repo}#{num} — {pr_title}"[:200]
        url = pr.get("html_url") or f"https://github.com/{repo}/pull/{num}"
        detail["pr_number"] = num
        detail["action"] = action
        detail["body"] = (pr.get("body") or "")[:1500]
        detail["author"] = (pr.get("user") or {}).get("login")
        detail["base"] = (pr.get("base") or {}).get("ref")
        detail["head"] = (pr.get("head") or {}).get("ref")
    elif etype == "PullRequestReviewEvent":
        pr = payload.get("pull_request") or {}
        review = payload.get("review") or {}
        num = pr.get("number")
        pr_title = pr.get("title") or "(no title)"
        state = review.get("state") or ""
        title = f"GitHub review ({state}): {repo}#{num} — {pr_title}"[:200]
        url = review.get("html_url") or pr.get("html_url")
        detail["state"] = state
        detail["body"] = (review.get("body") or "")[:1000]

    if not title:
        return None

    tags = ["github", etype.lower().replace("event", "")]

    return Event(
        kind=KIND_NEWS,
        source=f"github:{org}",
        target_name=target,
        title=title,
        url=url,
        payload=detail,
        dedup_key=f"github:{eid}",
        tags=tags,
    )
