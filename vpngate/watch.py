from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time
from pathlib import Path
from typing import Optional

from vpngate.node import node_conf_path


@dataclass(frozen=True)
class WatchSettings:
    rotate_hour: int = 4
    health_interval: int = 120
    health_fails: int = 3


def should_scheduled_rotate(
    now: datetime,
    started_at: datetime,
    last_fired_on: Optional[date],
    hour: int = 4,
) -> bool:
    """True once we have passed today's local `hour`:00 and this session
    started before that instant. A process that starts after 04:00 waits
    until tomorrow — we do not rotate on every restart."""
    if hour < 0 or hour > 23:
        return False
    if now.hour < hour:
        return False
    today = now.date()
    if last_fired_on == today:
        return False
    scheduled = datetime.combine(today, time(hour=hour), tzinfo=now.tzinfo)
    return started_at < scheduled


def health_ok(exit_ip: Optional[str], host_ip: Optional[str]) -> bool:
    if not exit_ip:
        return False
    if host_ip and exit_ip == host_ip:
        return False
    return True


class HealthTracker:
    def __init__(self, fails_needed: int = 3):
        self.fails_needed = max(1, fails_needed)
        self.fails = 0

    def record(self, ok: bool) -> bool:
        """Feed one probe result. Return True when it is time to rotate."""
        if ok:
            self.fails = 0
            return False
        self.fails += 1
        return self.fails >= self.fails_needed


def _parse_int(raw: str, default: int, lo: int, hi: int) -> int:
    try:
        value = int(raw.strip())
    except ValueError:
        return default
    if value < lo or value > hi:
        return default
    return value


def load_watch_settings(path: Optional[Path] = None) -> WatchSettings:
    defaults = WatchSettings()
    conf = path or node_conf_path()
    if not conf.is_file():
        return defaults
    data: dict[str, str] = {}
    try:
        text = conf.read_text(encoding="utf-8")
    except OSError:
        return defaults
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip().strip('"').strip("'")
    return WatchSettings(
        rotate_hour=_parse_int(data.get("ROTATE_HOUR", ""), defaults.rotate_hour, 0, 23),
        health_interval=_parse_int(data.get("HEALTH_INTERVAL", ""), defaults.health_interval, 30, 3600),
        health_fails=_parse_int(data.get("HEALTH_FAILS", ""), defaults.health_fails, 1, 20),
    )
