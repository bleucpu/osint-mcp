# osint-mcp

Continuous OSINT / attack-surface monitoring stack for bug bounty hunting.

One Python daemon, one SQLite database, many watchers (subdomains, RSS, changelogs, certs, GitHub, scope changes, social), exposed as an **MCP server** so AI agents can pull fresh attack surface on any target — and pushed in real time to **Discord** so you see it too.

## Why

Every bounty hunter runs the same recon cron job: subfinder + httpx + nuclei, daily, on the same targets. By the time a new subdomain lands in CT logs, fifty hunters already saw it.

The edge in 2026 is **breadth of signal**. New subdomains are one of five things worth watching:

1. New asset (subdomains, ports, certs, cloud)
2. Changed asset (JS bundle hash, headers, tech)
3. New code (commits, leaked secrets, "oops" force pushes)
4. New product/feature (blog, changelog, GitHub release, status page, tweet)
5. New scope (HackerOne / Bugcrowd program changes, payout bumps)

This system watches all five, normalizes them into a single event stream, and lets an AI hacker decide what's interesting — instead of pre-filtering with static heuristics that go stale.

## Architecture

```
┌──────────── watcher daemon ────────────┐
│  assets   code     news     social     │
│  ──────   ────     ────     ──────     │
│  BBOT     Truffle  RSS      twitter    │
│  CT logs  NoseyP   H1 API   GH events  │
│  httpx    git-oops status              │
│       │     │       │       │          │
│       └─────┴───┬───┴───────┘          │
│                 ▼                      │
│      normalize → dedupe → score        │
│                 │                      │
│         SQLite (FTS5)                  │
│                 │                      │
│     ┌───────────┴───────────┐          │
│     ▼                       ▼          │
│ Discord webhook       MCP server       │
└────────────────────────────────────────┘
```

One process. Stdio MCP server + asyncio daemon tasks. Daemon lives as long as the MCP server is connected; on restart it catches up any cadences it missed.

## Quickstart

```bash
pip install -e .
# optionally install BBOT for the subdomain watcher
pip install -e ".[bbot]"

cp osint.example.yaml osint.yaml
# at minimum set DISCORD_WEBHOOK_FIREHOSE in your env
export DISCORD_WEBHOOK_FIREHOSE="https://discord.com/api/webhooks/..."

osint-mcp
```

Then in your MCP client (Claude Code, Cursor, etc.) point at `osint-mcp` over stdio.

Add a target:
```
target_autodiscover("HuggingFace")    → see what we can find automatically
target_add("HuggingFace")              → commit to watchlist
feed_recent(target="HuggingFace")      → query events
```

## Discord routing

One required env var:
```
DISCORD_WEBHOOK_FIREHOSE   # everything goes here unless overridden
```

Optional per-kind overrides. Set any subset; missing kinds fall back to firehose:
```
DISCORD_WEBHOOK_RECON       # new subdomains, ports, certs
DISCORD_WEBHOOK_NEWS        # blog posts, changelogs, GH releases
DISCORD_WEBHOOK_SCOPE       # H1/Bugcrowd program changes
DISCORD_WEBHOOK_SECRETS     # leaked keys
DISCORD_WEBHOOK_JS          # JS bundle changes / new endpoints
DISCORD_WEBHOOK_SOCIAL      # twitter
```

## Optional API keys

All optional — the system runs without them, just with reduced signal.
```
HACKERONE_API_TOKEN        # scope-diff watcher (Phase 2)
GITHUB_TOKEN               # higher rate limits + private secret scan (Phase 2)
TWITTERAPI_IO_KEY          # twitter watcher (Phase 3)
ANTHROPIC_API_KEY          # feed_summary endpoint (Phase 3)
```

## MCP tools

**Targets**
- `target_autodiscover(name_or_domain)` — read-only, returns everything we can find about a target
- `target_add(name, ...)` — commit to watchlist (auto-discovers if no fields given)
- `target_update(name, patch)` — fix/extend
- `target_remove(name)`
- `target_show(name)` — current config + watcher health
- `target_list()`
- `target_health(name?)` — which sources are healthy/broken/stale
- `target_force_scan(name, kind?)` — trigger out-of-cadence scan

**Feed**
- `feed_recent(target?, kind?, since?, limit?)` — raw events, time-windowed
- `feed_search(query, target?, since?)` — FTS5 keyword search
- `feed_summary(target?, kind?, hours_ago?)` — compact digest; uses Anthropic API if `ANTHROPIC_API_KEY` is set, otherwise a deterministic group-by summary

## Compliance and Terms of Service

This is a tool for legitimate bug bounty researchers. Our hard rule across
the entire project is: **only use official APIs and services that are
designed to be consumed programmatically. Never scrape platform UIs, never
impersonate browsers, never bypass anti-bot protections.** Getting your
researcher account banned is not worth any amount of recon signal.

| Service           | How we use it                                                              |
|-------------------|----------------------------------------------------------------------------|
| HackerOne         | `api.hackerone.com/v1` only. Disabled without API token.                   |
| Bugcrowd          | `api.bugcrowd.com` only. Disabled without API token.                       |
| Discord           | Official webhook API with respectful rate limits.                          |
| Anthropic         | Official `api.anthropic.com` for `feed_summary` (when key set).            |
| GitHub (planned)  | Official GitHub API only.                                                  |
| Twitter / X       | **Not implemented.** Third-party scrapers like twitterapi.io violate X ToS upstream — we won't depend on them. If ever added, only via paid X API v2. |
| crt.sh            | Documented public JSON API; one query per `target_add`.                    |
| certstream        | Public WebSocket service operated by Cali Dog Security for this use case.  |
| RSS feeds         | Designed for syndication; honest UA; polled at conservative cadences.      |
| Target homepages  | Single visit per `target_add` to parse public RSS/social links; honest UA. |

If you don't have an API token for a platform, the corresponding watcher
is simply disabled — it will appear in `target_health_check` with
`disabled: true` and a hint to set the env var. We don't fall back to
scraping, ever.

## Bug bounty platform required env vars

| Platform   | Required env vars                                   |
|------------|-----------------------------------------------------|
| HackerOne  | `HACKERONE_API_USERNAME` + `HACKERONE_API_TOKEN`    |
| Bugcrowd   | `BUGCROWD_API_TOKEN`                                |

## Status

- [x] Phase 1: schema, Discord router, target tools, RSS watcher, BBOT watcher, MCP server
- [x] Phase 2: H1/Bugcrowd scope-diff (official API only), certstream live watcher, feed_summary, first-ingestion Discord suppression
- [ ] Phase 3: JS bundle hash watcher, GitHub secrets watcher (TruffleHog/NoseyParker via official GitHub API), semantic search, auto-trigger downstream tasks
  - Twitter is intentionally *not* on the roadmap — third-party scrapers violate X ToS and the official API is paid; signal is already covered by company RSS, status pages, and GitHub release feeds.
