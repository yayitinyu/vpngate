from __future__ import annotations

import base64
import re
from typing import Optional

REMOTE_RE = re.compile(r"^\s*remote\s+(\S+)(?:\s+(\d+))?", re.MULTILINE | re.IGNORECASE)
PROTO_RE = re.compile(r"^\s*proto\s+(\S+)", re.MULTILINE | re.IGNORECASE)

# Lines we rewrite ourselves so host DNS / scripts are never touched.
DROP_PREFIXES = (
    "up ",
    "down ",
    "route-up ",
    "route-pre-down ",
    "ipchange ",
    "script-security",
    "verb ",
    "http-proxy",
    "socks-proxy",
    "redirect-gateway",
    "dhcp-option",
    "auth-user-pass",
    "providers ",
    "tls-cipher",
    "data-ciphers",
    "data-ciphers-fallback",
    "mssfix",
    "tun-mtu",
    "ping ",
    "ping-restart",
    "resolv-retry",
)


def extract_endpoint(ovpn: str) -> tuple[str, int, Optional[str]]:
    proto = "tcp"
    m = PROTO_RE.search(ovpn)
    if m:
        proto = m.group(1).lower().replace("tcp-client", "tcp").replace("udp-client", "udp")
        if proto.startswith("tcp"):
            proto = "tcp"
        elif proto.startswith("udp"):
            proto = "udp"

    port = 443
    remote_ip = None
    m = REMOTE_RE.search(ovpn)
    if m:
        remote_ip = m.group(1)
        if m.group(2):
            port = int(m.group(2))
    return proto, port, remote_ip


def decode_config(b64: str) -> str:
    text = base64.b64decode(b64).decode("utf-8", errors="replace")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _option_name(line: str) -> Optional[str]:
    stripped = line.strip()
    if not stripped or stripped[0] in "#;<":
        return None
    return stripped.split()[0].lower()


def sanitize(
    ovpn: str,
    *,
    auth_file: Optional[str] = None,
    openvpn_version: tuple[int, int] = (2, 6),
    verbose: bool = False,
) -> str:
    """Drop host-touching options and pin fail-closed, legacy-crypto-safe flags."""
    ovpn = ovpn.replace("\r\n", "\n").replace("\r", "\n")
    kept: list[str] = []
    for raw in ovpn.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#") or line.startswith(";"):
            kept.append(line)
            continue
        lower = line.lower()
        if any(lower.startswith(p) for p in DROP_PREFIXES):
            continue
        kept.append(line)

    extras = [
        "client",
        "nobind",
        "persist-key",
        "resolv-retry 8",
        "ping 10",
        "ping-restart 45",
        "mssfix 1280",
        "sndbuf 0",
        "rcvbuf 0",
        # Force all traffic in the netns through tun; host default route stays put.
        "redirect-gateway def1 bypass-dhcp",
        f"verb {4 if verbose else 1}",
        "mute-replay-warnings",
        "auth-nocache",
        "pull-filter ignore dhcp-option",
        "pull-filter ignore redirect-gateway",
        "redirect-gateway def1 bypass-dhcp",
    ]
    if auth_file:
        extras.append(f'auth-user-pass "{auth_file}"')

    major, minor = openvpn_version
    if (major, minor) >= (2, 6):
        extras.extend(
            [
                "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-128-CBC",
                "data-ciphers-fallback AES-128-CBC",
                "providers legacy default",
                "tls-cipher DEFAULT:@SECLEVEL=0",
            ]
        )
    elif (major, minor) >= (2, 5):
        extras.extend(
            [
                "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-128-CBC",
                "data-ciphers-fallback AES-128-CBC",
                "tls-cipher DEFAULT:@SECLEVEL=0",
            ]
        )
    else:
        extras.append("cipher AES-128-CBC")

    # Only skip extras whose *option name* is already present.
    # Never dedup full lines: CA and client cert both start with
    # -----BEGIN CERTIFICATE----- and must both survive.
    present = {name for name in (_option_name(line) for line in kept) if name}
    out = list(kept)
    for extra in extras:
        name = _option_name(extra)
        if name and name in present and name != "pull-filter":
            continue
        out.append(extra)
        if name:
            present.add(name)
    return "\n".join(out) + "\n"


def detect_openvpn_version(version_text: str) -> tuple[int, int]:
    m = re.search(r"OpenVPN\s+(\d+)\.(\d+)", version_text)
    if not m:
        return (2, 6)
    return int(m.group(1)), int(m.group(2))
