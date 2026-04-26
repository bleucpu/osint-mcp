from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

DEFAULT_CADENCES = {
    "rss": "15m",
    "bbot": "24h",
    "certstream": "live",
    "scope_diff": "1h",
    "github_events": "1h",
    "twitter": "30m",
    "jsdiff": "6h",
}

DISCORD_KIND_ENV_MAP = {
    "recon": "DISCORD_WEBHOOK_RECON",
    "news": "DISCORD_WEBHOOK_NEWS",
    "scope": "DISCORD_WEBHOOK_SCOPE",
    "secrets": "DISCORD_WEBHOOK_SECRETS",
    "js": "DISCORD_WEBHOOK_JS",
    "social": "DISCORD_WEBHOOK_SOCIAL",
}


@dataclass
class DiscordConfig:
    firehose: str | None = None
    kind_webhooks: dict[str, str] = field(default_factory=dict)
    enabled: bool = True
    rate_limit_per_minute: int = 30
    embed_events: bool = True


@dataclass
class BbotConfig:
    preset: str = "subdomain-enum"
    output_dir: Path = field(default_factory=lambda: Path("./scans"))


@dataclass
class Config:
    data_dir: Path = field(default_factory=lambda: Path("./data"))
    cadences: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_CADENCES))
    bbot: BbotConfig = field(default_factory=BbotConfig)
    discord: DiscordConfig = field(default_factory=DiscordConfig)
    verify_on_add: bool = True

    hackerone_username: str | None = None
    hackerone_token: str | None = None
    bugcrowd_token: str | None = None
    github_token: str | None = None
    twitterapi_io_key: str | None = None
    anthropic_api_key: str | None = None

    @property
    def db_path(self) -> Path:
        return self.data_dir / "osint.db"


def load_config(path: str | os.PathLike | None = None) -> Config:
    cfg = Config()

    if path is None:
        cwd_yaml = Path.cwd() / "osint.yaml"
        path = cwd_yaml if cwd_yaml.exists() else None

    raw: dict = {}
    if path is not None:
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}

    if "data_dir" in raw:
        cfg.data_dir = Path(raw["data_dir"])
    if "cadences" in raw and isinstance(raw["cadences"], dict):
        cfg.cadences.update(raw["cadences"])
    if "bbot" in raw and isinstance(raw["bbot"], dict):
        b = raw["bbot"]
        cfg.bbot.preset = b.get("preset", cfg.bbot.preset)
        if "output_dir" in b:
            cfg.bbot.output_dir = Path(b["output_dir"])
    if "discord" in raw and isinstance(raw["discord"], dict):
        d = raw["discord"]
        cfg.discord.enabled = d.get("enabled", cfg.discord.enabled)
        cfg.discord.rate_limit_per_minute = d.get(
            "rate_limit_per_minute", cfg.discord.rate_limit_per_minute
        )
        cfg.discord.embed_events = d.get("embed_events", cfg.discord.embed_events)
    if "verify_on_add" in raw:
        cfg.verify_on_add = bool(raw["verify_on_add"])

    cfg.discord.firehose = os.environ.get("DISCORD_WEBHOOK_FIREHOSE")
    for kind, env_name in DISCORD_KIND_ENV_MAP.items():
        val = os.environ.get(env_name)
        if val:
            cfg.discord.kind_webhooks[kind] = val

    cfg.hackerone_username = os.environ.get("HACKERONE_API_USERNAME")
    cfg.hackerone_token = os.environ.get("HACKERONE_API_TOKEN")
    cfg.bugcrowd_token = os.environ.get("BUGCROWD_API_TOKEN")
    cfg.github_token = os.environ.get("GITHUB_TOKEN")
    cfg.twitterapi_io_key = os.environ.get("TWITTERAPI_IO_KEY")
    cfg.anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY")

    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    cfg.bbot.output_dir.mkdir(parents=True, exist_ok=True)

    return cfg
