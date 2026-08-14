from __future__ import annotations

import base64
import csv
import io
import logging
import urllib.request
from typing import Iterable, Optional

from vpngate.models import Server
from vpngate.ovpn import extract_endpoint

LOG = logging.getLogger(__name__)

DEFAULT_URL = "https://www.vpngate.net/api/iphone/"
USER_AGENT = "vpngate-socks/0.1 (personal gateway; +https://www.vpngate.net/)"


def fetch_csv(url: str = DEFAULT_URL, timeout: float = 30.0) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def load_servers(source: str, *, from_file: bool = False, timeout: float = 30.0) -> list[Server]:
    if from_file:
        with open(source, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    else:
        text = fetch_csv(source, timeout=timeout)
    return parse_csv(text)


def parse_csv(text: str) -> list[Server]:
    lines = [ln for ln in text.splitlines() if ln and not ln.startswith("*")]
    if not lines:
        return []
    if lines[0].startswith("#"):
        lines[0] = lines[0][1:]
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    servers: list[Server] = []
    for row in reader:
        try:
            servers.append(_row_to_server(row))
        except (KeyError, ValueError) as exc:
            LOG.debug("skipping malformed row: %s", exc)
    return servers


def _to_int(value: Optional[str], default: int = 0) -> int:
    if value is None:
        return default
    text = value.strip()
    if not text or text == "-":
        return default
    return int(text)


def _to_opt_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    text = value.strip()
    if not text or text == "-":
        return None
    try:
        return int(text)
    except ValueError:
        return None


def _row_to_server(row: dict[str, str]) -> Server:
    # DictReader keys follow the CSV header after stripping the leading '#'.
    hostname = (row.get("HostName") or row.get("#HostName") or "").strip()
    ip = (row.get("IP") or "").strip()
    if not hostname or not ip:
        raise ValueError("missing hostname or ip")

    ovpn_b64 = (row.get("OpenVPN_ConfigData_Base64") or "").strip()
    proto, port = "tcp", 443
    if ovpn_b64:
        try:
            ovpn = base64.b64decode(ovpn_b64).decode("utf-8", errors="replace")
            proto, port, remote_ip = extract_endpoint(ovpn)
            if remote_ip:
                ip = remote_ip
        except Exception as exc:  # noqa: BLE001 — keep the row even if ovpn is junk
            LOG.debug("ovpn parse failed for %s: %s", hostname, exc)

    return Server(
        hostname=hostname,
        ip=ip,
        score=_to_int(row.get("Score")),
        ping=_to_opt_int(row.get("Ping")),
        speed=_to_int(row.get("Speed")),
        country_long=(row.get("CountryLong") or "").strip(),
        country_short=(row.get("CountryShort") or "").strip().upper(),
        sessions=_to_int(row.get("NumVpnSessions")),
        uptime_ms=_to_int(row.get("Uptime")),
        total_users=_to_int(row.get("TotalUsers")),
        total_traffic=_to_int(row.get("TotalTraffic")),
        log_type=(row.get("LogType") or "").strip(),
        operator=(row.get("Operator") or "").strip(),
        message=(row.get("Message") or "").strip(),
        ovpn_b64=ovpn_b64,
        proto=proto,
        port=port,
    )


def filter_country(servers: Iterable[Server], countries: Iterable[str]) -> list[Server]:
    wanted = {c.strip().upper() for c in countries if c.strip()}
    if not wanted:
        return list(servers)
    return [s for s in servers if s.country_short in wanted]
