from __future__ import annotations

from typing import Iterable, Optional

from vpngate.models import CLASS_ORDER, Server


def class_rank(klass: str) -> int:
    try:
        return CLASS_ORDER.index(klass)
    except ValueError:
        return len(CLASS_ORDER)


def rank_key(server: Server) -> tuple:
    """Lower is better. Class first, then speed, ping, load, score."""
    ping = server.ping if server.ping is not None else 10_000
    return (
        class_rank(server.klass),
        -server.speed,
        ping,
        server.sessions,
        -server.score,
    )


def select(
    servers: Iterable[Server],
    *,
    classes: Iterable[str],
    min_speed: int = 0,
    max_sessions: Optional[int] = None,
    max_ping: Optional[int] = None,
    skip_ips: Optional[set[str]] = None,
) -> list[Server]:
    allowed = {c.strip().lower() for c in classes}
    skip = skip_ips or set()
    out: list[Server] = []
    for s in servers:
        if s.ip in skip or s.hostname in skip:
            continue
        if s.klass not in allowed:
            continue
        if s.speed < min_speed:
            continue
        if max_sessions is not None and s.sessions > max_sessions:
            continue
        if max_ping is not None and s.ping is not None and s.ping > max_ping:
            continue
        if not s.ovpn_b64:
            continue
        out.append(s)
    out.sort(key=rank_key)
    return out
