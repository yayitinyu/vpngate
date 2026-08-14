from __future__ import annotations

import logging
import socket
from typing import Iterable

from vpngate.models import AsInfo

LOG = logging.getLogger(__name__)

WHOIS_HOST = "whois.cymru.com"
WHOIS_PORT = 43


def lookup(ips: Iterable[str], timeout: float = 12.0) -> dict[str, AsInfo]:
    unique: list[str] = []
    seen: set[str] = set()
    for ip in ips:
        if ip and ip not in seen:
            seen.add(ip)
            unique.append(ip)
    if not unique:
        return {}

    payload = "begin\nverbose\n" + "\n".join(unique) + "\nend\n"
    try:
        raw = _whois(payload, timeout=timeout)
    except OSError as exc:
        LOG.warning("Team Cymru whois failed: %s", exc)
        return {}

    return _parse(raw)


def _whois(payload: str, timeout: float) -> str:
    with socket.create_connection((WHOIS_HOST, WHOIS_PORT), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(payload.encode("ascii"))
        chunks: list[bytes] = []
        while True:
            data = sock.recv(8192)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="replace")


def _parse(text: str) -> dict[str, AsInfo]:
    result: dict[str, AsInfo] = {}
    for line in text.splitlines():
        if not line or line.lower().startswith("bulk mode") or line.lower().startswith("as "):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 7:
            continue
        asn_s, ip, prefix, cc, _reg, _alloc, name = parts[:7]
        if not asn_s.isdigit() or asn_s == "0":
            continue
        result[ip] = AsInfo(asn=int(asn_s), prefix=prefix, name=name, cc=cc)
    return result
