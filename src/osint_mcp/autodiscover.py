from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

log = logging.getLogger("osint.autodiscover")

USER_AGENT = (
    "osint-mcp/0.1 (+https://github.com/bleucpu/osint-mcp; bug bounty research)"
)

COMMON_TLDS = ["com", "io", "ai", "co", "org", "net", "dev", "app"]
COMMON_SUBPATHS = ["", "/blog", "/changelog", "/news", "/security"]
RSS_TYPES = {
    "application/rss+xml",
    "application/atom+xml",
    "application/feed+json",
    "application/json",
}
SOCIAL_PATTERNS = {
    "twitter": re.compile(r"^https?://(?:www\.)?(?:twitter|x)\.com/([A-Za-z0-9_]{1,15})/?$"),
    "github":  re.compile(r"^https?://(?:www\.)?github\.com/([A-Za-z0-9-]+)/?$"),
}
STATUS_PATTERNS = (
    "status.",
    "statuspage.io",
    ".statuspage.io",
)


@dataclass
class Discovery:
    candidate_root_domains: list[str] = field(default_factory=list)
    github_orgs: list[str] = field(default_factory=list)
    rss_feeds: list[dict[str, str]] = field(default_factory=list)
    status_page: str | None = None
    twitter_handles: list[str] = field(default_factory=list)
    bug_bounty_programs: list[dict[str, Any]] = field(default_factory=list)
    ct_subdomain_count: int | None = None
    notes: list[str] = field(default_factory=list)
    confidence: str = "low"

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_root_domains": self.candidate_root_domains,
            "github_orgs": self.github_orgs,
            "rss_feeds": self.rss_feeds,
            "status_page": self.status_page,
            "twitter_handles": self.twitter_handles,
            "bug_bounty_programs": self.bug_bounty_programs,
            "ct_subdomain_count": self.ct_subdomain_count,
            "notes": self.notes,
            "confidence": self.confidence,
        }


def _slugify(name: str) -> str:
    s = name.lower().strip()
    s = re.sub(r"[^a-z0-9]+", "", s)
    return s


def _slug_variants(name: str) -> list[str]:
    base = name.lower().strip()
    variants = {
        re.sub(r"[^a-z0-9]+", "", base),
        re.sub(r"[^a-z0-9]+", "-", base).strip("-"),
        re.sub(r"[^a-z0-9]+", "_", base).strip("_"),
    }
    return [v for v in variants if v]


async def autodiscover(name_or_domain: str) -> Discovery:
    """
    Read-only enrichment for a target. Probes:
      - candidate root domains (TLD probing if a name was given)
      - homepage HTML for RSS, GitHub, Twitter, status page
      - HackerOne / Bugcrowd program existence (slug variants)
      - crt.sh subdomain count for sanity
    """
    d = Discovery()
    looks_like_domain = "." in name_or_domain and " " not in name_or_domain

    async with httpx.AsyncClient(
        timeout=8.0,
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        if looks_like_domain:
            d.candidate_root_domains = [name_or_domain.lower()]
        else:
            d.candidate_root_domains = await _probe_tlds(client, name_or_domain)

        for domain in list(d.candidate_root_domains):
            await _enrich_from_homepage(client, domain, d)

        # NOTE: We deliberately DO NOT probe hackerone.com / bugcrowd.com to
        # detect program existence. Anything against those platforms must go
        # through their official APIs — see watchers/scope.py and the
        # platform-tos memory. The AI can web-search for the program slug
        # and pass it explicitly to target_add(bug_bounty=...).
        d.notes.append(
            "platform program detection skipped — pass bug_bounty={'platform':..,'slug':..} "
            "to target_add manually; uses official API only when watcher runs"
        )

        if d.candidate_root_domains:
            try:
                d.ct_subdomain_count = await _crtsh_count(client, d.candidate_root_domains[0])
            except Exception as e:
                d.notes.append(f"crt.sh check failed: {e}")

    d.confidence = _score_confidence(d)
    return d


async def _probe_tlds(client: httpx.AsyncClient, name: str) -> list[str]:
    slug = _slugify(name)
    if not slug:
        return []
    candidates = [f"{slug}.{tld}" for tld in COMMON_TLDS]

    async def probe(domain: str) -> str | None:
        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}"
            try:
                r = await client.head(url)
                if r.status_code < 500:
                    return domain
            except httpx.HTTPError:
                pass
            try:
                r = await client.get(url)
                if r.status_code < 500:
                    return domain
            except httpx.HTTPError:
                pass
        return None

    results = await asyncio.gather(*[probe(c) for c in candidates], return_exceptions=True)
    found = [r for r in results if isinstance(r, str)]
    return found[:3]


async def _enrich_from_homepage(
    client: httpx.AsyncClient, domain: str, d: Discovery
) -> None:
    for path in COMMON_SUBPATHS:
        url = f"https://{domain}{path}"
        try:
            r = await client.get(url)
        except httpx.HTTPError as e:
            if path == "":
                d.notes.append(f"could not fetch {url}: {e}")
            continue
        if r.status_code >= 400 or "html" not in r.headers.get("content-type", ""):
            continue
        _parse_html(r.text, str(r.url), d)


def _parse_html(html: str, base_url: str, d: Discovery) -> None:
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")

    for link in soup.find_all("link", rel=True):
        rels = link.get("rel") or []
        if "alternate" not in rels:
            continue
        ftype = (link.get("type") or "").lower()
        href = link.get("href")
        if not href or ftype not in RSS_TYPES:
            continue
        feed_url = urljoin(base_url, href)
        title = link.get("title") or ""
        if not any(f["url"] == feed_url for f in d.rss_feeds):
            d.rss_feeds.append({"url": feed_url, "title": title, "type": ftype})

    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href.startswith("http"):
            continue

        for platform, pat in SOCIAL_PATTERNS.items():
            m = pat.match(href)
            if not m:
                continue
            handle = m.group(1)
            if platform == "twitter" and handle not in d.twitter_handles:
                if handle.lower() not in {"share", "intent", "home", "login"}:
                    d.twitter_handles.append(handle)
            elif platform == "github":
                if handle.lower() not in {"login", "signup", "features", "pricing", "about"}:
                    if handle not in d.github_orgs:
                        d.github_orgs.append(handle)

        host = urlparse(href).hostname or ""
        if d.status_page is None and any(p in host for p in STATUS_PATTERNS):
            d.status_page = href.split("?")[0].rstrip("/")


async def _crtsh_count(client: httpx.AsyncClient, domain: str) -> int:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = await client.get(url, timeout=15.0)
    except httpx.HTTPError as e:
        raise RuntimeError(str(e))
    if r.status_code != 200:
        raise RuntimeError(f"status {r.status_code}")
    try:
        data = r.json()
    except Exception as e:
        raise RuntimeError(f"json parse: {e}")
    names = set()
    for entry in data:
        nm = entry.get("name_value", "")
        for line in nm.split("\n"):
            line = line.strip().lower().lstrip("*.")
            if line.endswith(domain):
                names.add(line)
    return len(names)


def _score_confidence(d: Discovery) -> str:
    score = 0
    if d.candidate_root_domains:
        score += 1
    if d.rss_feeds:
        score += 1
    if d.github_orgs:
        score += 1
    if d.bug_bounty_programs:
        score += 2
    if d.status_page:
        score += 1
    if score >= 4:
        return "high"
    if score >= 2:
        return "medium"
    return "low"
