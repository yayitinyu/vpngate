from __future__ import annotations

import ipaddress
import logging
import urllib.request
from typing import Optional

from vpngate.netns import ns_exec

LOG = logging.getLogger(__name__)

IP_URLS = (
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
)


def _parse_ip(text: str) -> Optional[str]:
    candidate = text.strip().split()[0] if text.strip() else ""
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def public_ip(timeout: float = 10.0) -> Optional[str]:
    for url in IP_URLS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "vpngate-socks/0.1"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                found = _parse_ip(resp.read().decode("utf-8", errors="replace"))
            if found:
                return found
        except OSError as exc:
            LOG.debug("public ip via %s failed: %s", url, exc)
    return None


def public_ip_in_ns(ns: str, python: str, timeout: float = 20.0) -> Optional[str]:
    code = (
        "import urllib.request\n"
        f"urls={list(IP_URLS)!r}\n"
        "for u in urls:\n"
        "    try:\n"
        "        r=urllib.request.urlopen(u, timeout=12)\n"
        "        print(r.read().decode().strip())\n"
        "        break\n"
        "    except Exception:\n"
        "        pass\n"
    )
    proc = ns_exec(ns, [python, "-c", code], check=False, timeout=timeout)
    return _parse_ip(proc.stdout or "")
