from __future__ import annotations

import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable

from vpngate.models import Server

LOG = logging.getLogger(__name__)


def _tcp_open(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def probe_servers(
    servers: Iterable[Server],
    *,
    timeout: float = 2.0,
    workers: int = 32,
) -> list[Server]:
    """Keep TCP listeners; leave UDP candidates in (cannot probe cheaply)."""
    servers = list(servers)
    tcp = [s for s in servers if s.proto == "tcp"]
    udp = [s for s in servers if s.proto != "tcp"]
    alive: list[Server] = []

    if tcp:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            futs = {pool.submit(_tcp_open, s.ip, s.port, timeout): s for s in tcp}
            for fut in as_completed(futs):
                server = futs[fut]
                try:
                    ok = fut.result()
                except Exception as exc:  # noqa: BLE001
                    LOG.debug("probe error %s: %s", server.ip, exc)
                    continue
                if ok:
                    alive.append(server)
                else:
                    LOG.debug("probe miss %s:%s", server.ip, server.port)

    LOG.info("probe: %d/%d TCP reachable, %d UDP kept", len(alive), len(tcp), len(udp))
    # Preserve original rank order among survivors.
    order = {id(s): i for i, s in enumerate(servers)}
    survivors = alive + udp
    survivors.sort(key=lambda s: order.get(id(s), 10_000))
    return survivors
