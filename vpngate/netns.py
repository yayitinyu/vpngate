from __future__ import annotations

import logging
import os
import re
import shutil
from pathlib import Path
from typing import Optional, Sequence

from vpngate.util import CommandError, run

LOG = logging.getLogger(__name__)

DEFAULT_NS = "vpngate"
VETH_HOST = "vg-host"
VETH_NS = "vg-ns"
HOST_IP = "10.87.0.1"
NS_IP = "10.87.0.2"
PREFIX = 24
NETWORK = "10.87.0.0/24"
COMMENT = "vpngate"


def ns_exists(ns: str) -> bool:
    proc = run(["ip", "netns", "list"], check=False)
    for line in (proc.stdout or "").splitlines():
        if line.split()[0] == ns:
            return True
    return False


def ns_exec(ns: str, argv: Sequence[str], **kwargs):
    return run(["ip", "netns", "exec", ns, *argv], **kwargs)


def setup(
    ns: str = DEFAULT_NS,
    *,
    host_ip: str = HOST_IP,
    ns_ip: str = NS_IP,
    dns: Sequence[str] = ("1.1.1.1", "8.8.8.8"),
) -> None:
    if ns_exists(ns):
        teardown(ns)

    run(["ip", "netns", "add", ns])
    run(["ip", "link", "add", VETH_HOST, "type", "veth", "peer", "name", VETH_NS])
    run(["ip", "link", "set", VETH_NS, "netns", ns])
    run(["ip", "addr", "add", f"{host_ip}/{PREFIX}", "dev", VETH_HOST])
    run(["ip", "link", "set", VETH_HOST, "up"])
    ns_exec(ns, ["ip", "addr", "add", f"{ns_ip}/{PREFIX}", "dev", VETH_NS])
    ns_exec(ns, ["ip", "link", "set", VETH_NS, "up"])
    ns_exec(ns, ["ip", "link", "set", "lo", "up"])
    ns_exec(ns, ["ip", "route", "add", "default", "via", host_ip])

    resolv_dir = Path(f"/etc/netns/{ns}")
    resolv_dir.mkdir(parents=True, exist_ok=True)
    resolv = "".join(f"nameserver {d}\n" for d in dns)
    (resolv_dir / "resolv.conf").write_text(resolv, encoding="utf-8")

    _iptables_ensure(
        ["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", NETWORK, "!", "-d", NETWORK,
         "-m", "comment", "--comment", COMMENT, "-j", "MASQUERADE"]
    )
    _iptables_ensure(
        ["iptables", "-A", "FORWARD", "-i", VETH_HOST, "-m", "comment", "--comment", COMMENT, "-j", "ACCEPT"]
    )
    _iptables_ensure(
        ["iptables", "-A", "FORWARD", "-o", VETH_HOST, "-m", "state", "--state",
         "ESTABLISHED,RELATED", "-m", "comment", "--comment", COMMENT, "-j", "ACCEPT"]
    )
    Path("/proc/sys/net/ipv4/ip_forward").write_text("1\n", encoding="ascii")
    LOG.info("netns %s ready (%s <-> %s)", ns, host_ip, ns_ip)


def teardown(ns: str = DEFAULT_NS) -> None:
    if ns_exists(ns):
        run(["ip", "netns", "del", ns], check=False)
    run(["ip", "link", "del", VETH_HOST], check=False)
    _iptables_purge(COMMENT)
    resolv_dir = Path(f"/etc/netns/{ns}")
    if resolv_dir.exists():
        for child in resolv_dir.iterdir():
            child.unlink(missing_ok=True)
        try:
            resolv_dir.rmdir()
        except OSError:
            pass
    LOG.info("netns %s removed", ns)


def find_tun(ns: str) -> Optional[str]:
    proc = ns_exec(ns, ["ip", "-o", "link", "show"], check=False)
    if proc.returncode != 0:
        return None
    for line in (proc.stdout or "").splitlines():
        m = re.search(r"\d+:\s+(tun\d+)", line)
        if m:
            return m.group(1)
    return None


def lock_routes(ns: str, vpn_ip: str, tun: str, gw: str = HOST_IP) -> None:
    ns_exec(ns, ["ip", "route", "replace", f"{vpn_ip}/32", "via", gw, "dev", VETH_NS])
    ns_exec(ns, ["ip", "route", "replace", "default", "dev", tun])


def relax_for_reconnect(ns: str, gw: str = HOST_IP) -> None:
    """Undo kill-switch and point default back at the veth.

    Otherwise the next OpenVPN handshake is blackholed (Network is unreachable)
    because OUTPUT is still DROP and default still points at a dead tun.
    """
    for tool in ("iptables", "ip6tables"):
        if not _has(tool):
            continue
        ns_exec(ns, [tool, "-F"], check=False)
        ns_exec(ns, [tool, "-X"], check=False)
        ns_exec(ns, [tool, "-P", "INPUT", "ACCEPT"], check=False)
        ns_exec(ns, [tool, "-P", "OUTPUT", "ACCEPT"], check=False)
        ns_exec(ns, [tool, "-P", "FORWARD", "ACCEPT"], check=False)
    ns_exec(ns, ["ip", "route", "replace", "default", "via", gw, "dev", VETH_NS], check=False)
    LOG.info("kill-switch off, default via %s", gw)


def apply_killswitch(ns: str, vpn_ip: str) -> None:
    """Fail-closed: after tun is up, only tun + the VPN endpoint may leave the ns."""
    for family, tool in (("ipv4", "iptables"), ("ipv6", "ip6tables")):
        if not _has(tool):
            continue
        ns_exec(ns, [tool, "-F"], check=False)
        ns_exec(ns, [tool, "-X"], check=False)
        ns_exec(ns, [tool, "-P", "INPUT", "DROP"], check=False)
        ns_exec(ns, [tool, "-P", "OUTPUT", "DROP"], check=False)
        ns_exec(ns, [tool, "-P", "FORWARD", "DROP"], check=False)
        if family == "ipv6":
            continue
        ns_exec(ns, [tool, "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])
        ns_exec(ns, [tool, "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])
        ns_exec(ns, [tool, "-A", "INPUT", "-i", "tun+", "-j", "ACCEPT"])
        ns_exec(ns, [tool, "-A", "OUTPUT", "-o", "tun+", "-j", "ACCEPT"])
        ns_exec(ns, [tool, "-A", "INPUT", "-s", NETWORK, "-j", "ACCEPT"])
        ns_exec(ns, [tool, "-A", "OUTPUT", "-d", NETWORK, "-j", "ACCEPT"])
        ns_exec(ns, [tool, "-A", "OUTPUT", "-d", vpn_ip, "-j", "ACCEPT"])
        ns_exec(ns, [tool, "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    LOG.info("kill-switch on (ns=%s vpn=%s)", ns, vpn_ip)


def _has(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _iptables_ensure(argv: list[str]) -> None:
    check = list(argv)
    try:
        idx = check.index("-A")
        check[idx] = "-C"
    except ValueError:
        pass
    exists = run(check, check=False)
    if exists.returncode != 0:
        run(argv)


def _iptables_purge(comment: str) -> None:
    for table, chain in (("nat", "POSTROUTING"), ("filter", "FORWARD")):
        while True:
            proc = run(["iptables", "-t", table, "-S", chain], check=False)
            target = None
            for line in (proc.stdout or "").splitlines():
                if f"--comment {comment}" in line or f'--comment "{comment}"' in line:
                    target = line
                    break
            if not target:
                break
            delete = ["iptables", "-t", table] + target.split()
            if delete[3] == "-A":
                delete[3] = "-D"
            elif delete[4] == "-A":
                delete[4] = "-D"
            run(delete, check=False)


def write_auth_file(path: Path, username: str = "vpn", password: str = "vpn") -> None:
    path.write_text(f"{username}\n{password}\n", encoding="ascii")
    os.chmod(path, 0o600)
