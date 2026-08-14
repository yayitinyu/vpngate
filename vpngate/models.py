from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional


# Preference order for --class filtering and ranking.
CLASS_ORDER = (
    "residential",
    "isp",
    "academic",
    "unknown",
    "official",
    "datacenter",
)


@dataclass
class AsInfo:
    asn: int
    prefix: str
    name: str
    cc: str = ""


@dataclass
class Server:
    hostname: str
    ip: str
    score: int
    ping: Optional[int]
    speed: int
    country_long: str
    country_short: str
    sessions: int
    uptime_ms: int
    total_users: int
    total_traffic: int
    log_type: str
    operator: str
    message: str
    ovpn_b64: str
    proto: str = "tcp"
    port: int = 443
    klass: str = "unknown"
    klass_reason: str = ""
    asn: Optional[int] = None
    as_name: str = ""
    as_prefix: str = ""

    def to_public_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("ovpn_b64", None)
        return data


@dataclass
class GatewayState:
    ns: str
    socks: str
    exit_ip: str
    host_ip: str
    server: dict[str, Any] = field(default_factory=dict)
    pids: dict[str, int] = field(default_factory=dict)
    started_at: str = ""
