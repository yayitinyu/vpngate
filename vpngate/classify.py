from __future__ import annotations

import ipaddress
import re
from typing import Optional

from vpngate.models import AsInfo, Server

# Tsukuba / SoftEther academic cluster. These are the stable "official"
# exits — datacenter-like, often already blocklisted, not home FTTH.
OFFICIAL_NETWORKS = (
    ipaddress.ip_network("219.100.37.0/24"),
)
OFFICIAL_ASNS = {36599}
OFFICIAL_HOST_RE = re.compile(r"^public-vpn-\d+", re.IGNORECASE)
OFFICIAL_TEXT_RE = re.compile(
    r"daiyuu\s*nobori|academic use only|softether telecommunication",
    re.IGNORECASE,
)

# Match against Team Cymru AS names. Longer / more specific strings first
# is not required — we walk official → dc → residential → isp → academic.
_DC_AS = (
    "sakura internet",
    "gmo internet",
    "gmo pepabo",
    "amazon.",
    "amazon.com",
    "amazon-aes",
    "google llc",
    "google cloud",
    "microsoft corporation",
    "microsoft azure",
    "digitalocean",
    "choopa",
    "vultr",
    "linode",
    "akamai connected cloud",
    "hetzner",
    "ovh sas",
    "ovh hosting",
    "cloudflare",
    "xserver",
    "conoha",
    "idc frontier",
    "equinix",
    "oracle cloud",
    "alibaba",
    "tencent",
    "hostinger",
    "contabo",
    "scaleway",
    "leaseweb",
    "hurricane electric",
    "kagoya",
    "mfeed",
    "bit-isle",
    "broadband tower",
    "colocation",
    "data center",
    "datacenter",
    "data centre",
)
# Standalone tokens that are too short to substring-match blindly.
_DC_TOKENS = ("vps", "aws", "gcp", "azure")

_RESIDENTIAL_AS = (
    "kddi",
    "softbank",
    "gigainfra",
    "ocn",
    "ntt docomo",
    "sony network",
    "so-net",
    "biglobe",
    "nifty",
    "optage",
    "jcom",
    "jcn",
    "jupiter telecommunications",
    "chubu telecommunications",
    "ctcx",
    "nuro",
    "freebit",
    "asahi net",
    "usen",
    "energia",
    "stnet",
    "k-opti",
    "tokai",
    "nct co",
    "ogaki cable",
    "cable television",
    "cable tv",
    "rakuten mobile",
    "ymobile",
    "ntt east",
    "ntt west",
    "ntt-east",
    "ntt-west",
    "flets",
    "commufa",
    "kopt",
)

_ISP_AS = (
    "internet initiative japan",
    " iij",
    "iij ",
    "arteria",
    "vectant",
    "ucom",
    "infosphere",
    "ntt pc",
    "ntt communications",
    "ntt docomo business",
)

_ACADEMIC_AS = (
    "university",
    "univ.",
    "daigaku",
    "sinet",
    "wide project",
    "national institute of informatics",
    "research institute",
    "college",
    "institute of technology",
)

_VOLUNTEER_HOST_RE = re.compile(r"^vpn\d+$", re.IGNORECASE)
_HOME_OPERATOR_RE = re.compile(
    r"(desktop-|laptop-|['’]s owner|windows's owner)",
    re.IGNORECASE,
)


def _ip_in_official(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in OFFICIAL_NETWORKS)


def _contains_any(text: str, needles: tuple[str, ...]) -> Optional[str]:
    for n in needles:
        if n in text:
            return n
    return None


def classify_server(server: Server, as_info: Optional[AsInfo] = None) -> Server:
    """Mutate and return server with klass / ASN fields filled in."""
    if as_info is not None:
        server.asn = as_info.asn
        server.as_name = as_info.name
        server.as_prefix = as_info.prefix

    klass, reason = _classify(
        hostname=server.hostname,
        ip=server.ip,
        operator=server.operator,
        message=server.message,
        as_info=as_info,
    )
    server.klass = klass
    server.klass_reason = reason
    return server


def _classify(
    *,
    hostname: str,
    ip: str,
    operator: str,
    message: str,
    as_info: Optional[AsInfo],
) -> tuple[str, str]:
    blob = f"{operator} {message}".lower()
    as_name = (as_info.name if as_info else "").lower()
    asn = as_info.asn if as_info else None

    if OFFICIAL_HOST_RE.match(hostname):
        return "official", f"hostname {hostname}"
    if _ip_in_official(ip):
        return "official", f"prefix {ip} in 219.100.37.0/24"
    if asn in OFFICIAL_ASNS:
        return "official", f"AS{asn} SoftEther research cluster"
    if OFFICIAL_TEXT_RE.search(blob) or OFFICIAL_TEXT_RE.search(as_name):
        return "official", "operator/AS marks academic cluster"

    hit = _contains_any(as_name, _DC_AS)
    if hit:
        return "datacenter", f"AS name contains {hit!r}"
    tokens = set(re.findall(r"[a-z0-9]+", as_name))
    for tok in _DC_TOKENS:
        if tok in tokens:
            return "datacenter", f"AS name token {tok!r}"

    hit = _contains_any(as_name, _RESIDENTIAL_AS)
    if hit:
        return "residential", f"AS name contains {hit!r}"

    hit = _contains_any(as_name, _ISP_AS)
    if hit:
        return "isp", f"AS name contains {hit!r}"

    hit = _contains_any(as_name, _ACADEMIC_AS)
    if hit:
        return "academic", f"AS name contains {hit!r}"

    # Offline / Cymru-miss fallback: volunteer SoftEther clients on JP
    # home PCs almost always look like vpnNNNNNN + "DESKTOP-…'s owner".
    if _VOLUNTEER_HOST_RE.match(hostname) or _HOME_OPERATOR_RE.search(operator):
        return "residential", "volunteer hostname/operator heuristic"

    if as_info is None:
        return "unknown", "no ASN data"
    return "unknown", f"unclassified AS{asn} {as_info.name}"


def apply_classification(servers: list[Server], as_map: dict[str, AsInfo]) -> list[Server]:
    for server in servers:
        classify_server(server, as_map.get(server.ip))
    return servers
