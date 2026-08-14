from __future__ import annotations

import os
import random
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from vpngate.health import public_ip
from vpngate.util import have, is_linux, is_root, run

DEFAULT_NODE_CONF = Path("/etc/vpngate/node.conf")
PORT_MIN = 30000
PORT_MAX = 59999
# URL-safe, no 0/O/1/l so the string is easy to copy by hand.
_ALPHABET = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def node_conf_path() -> Path:
    override = os.environ.get("VPNGATE_NODE_CONF")
    if override:
        return Path(override)
    return DEFAULT_NODE_CONF


@dataclass
class Node:
    user: str
    password: str
    port: int
    bind: str = "0.0.0.0"

    @property
    def listen(self) -> str:
        return f"{self.bind}:{self.port}"

    def url(self, host: Optional[str] = None) -> str:
        return format_url(self.user, self.password, host or advertise_host(), self.port)


def format_url(user: str, password: str, host: str, port: int) -> str:
    return f"socks5h://{user}:{password}@{host}:{port}"


def advertise_host() -> str:
    found = public_ip(timeout=6.0)
    if found:
        return found
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("1.1.1.1", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def _rand(n: int) -> str:
    rng = random.SystemRandom()
    return "".join(rng.choice(_ALPHABET) for _ in range(n))


def _port_taken(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", port))
        except OSError:
            return True
    return False


def pick_port() -> int:
    rng = random.SystemRandom()
    for _ in range(40):
        port = rng.randint(PORT_MIN, PORT_MAX)
        if not _port_taken(port):
            return port
    raise RuntimeError(f"could not find a free port in {PORT_MIN}-{PORT_MAX}")


def generate_node() -> Node:
    return Node(
        user="vg_" + _rand(8),
        password=_rand(18),
        port=pick_port(),
        bind="0.0.0.0",
    )


def load_node(path: Optional[Path] = None) -> Optional[Node]:
    conf = path or node_conf_path()
    if not conf.is_file():
        return None
    data: dict[str, str] = {}
    for raw in conf.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip().strip('"').strip("'")
    try:
        return Node(
            user=data["SOCKS_USER"],
            password=data["SOCKS_PASS"],
            port=int(data["SOCKS_PORT"]),
            bind=data.get("SOCKS_BIND") or "0.0.0.0",
        )
    except (KeyError, ValueError):
        return None


def save_node(node: Node, path: Optional[Path] = None) -> Path:
    conf = path or node_conf_path()
    conf.parent.mkdir(parents=True, exist_ok=True)
    body = (
        "# vpngate-socks node. chmod 600. restart keeps the same URL.\n"
        f"SOCKS_USER={node.user}\n"
        f"SOCKS_PASS={node.password}\n"
        f"SOCKS_PORT={node.port}\n"
        f"SOCKS_BIND={node.bind}\n"
        "# ROTATE_HOUR=4\n"
        "# HEALTH_INTERVAL=120\n"
        "# HEALTH_FAILS=3\n"
    )
    conf.write_text(body, encoding="utf-8")
    try:
        os.chmod(conf, 0o600)
    except OSError:
        pass
    return conf


def ensure_node(*, rotate: bool = False, path: Optional[Path] = None) -> tuple[Node, bool]:
    """Return (node, created). created is True when creds were freshly minted."""
    conf = path or node_conf_path()
    if not rotate:
        existing = load_node(conf)
        if existing is not None:
            return existing, False
    old = load_node(conf)
    if old is not None:
        firewall_close(old.port)
    node = generate_node()
    save_node(node, conf)
    return node, True


def apply_node(opt, node: Node) -> None:
    opt.socks = node.listen
    opt.socks_user = node.user
    opt.socks_pass = node.password


def _ufw_active() -> bool:
    proc = run(["ufw", "status"], check=False)
    text = (proc.stdout or "") + (proc.stderr or "")
    return "Status: active" in text


def _firewalld_running() -> bool:
    return run(["firewall-cmd", "--state"], check=False).returncode == 0


def firewall_open(port: int) -> list[str]:
    """Open TCP/port on the host. Idempotent. Returns backends that were touched."""
    if not is_linux() or not is_root():
        return []
    done: list[str] = []
    if have("ufw") and _ufw_active():
        run(
            ["ufw", "allow", f"{port}/tcp", "comment", "vpngate"],
            check=False,
        )
        done.append("ufw")
    if have("firewall-cmd") and _firewalld_running():
        run(["firewall-cmd", "--quiet", "--permanent", f"--add-port={port}/tcp"], check=False)
        run(["firewall-cmd", "--quiet", "--reload"], check=False)
        done.append("firewalld")
    if have("iptables"):
        check = [
            "iptables", "-C", "INPUT", "-p", "tcp", "--dport", str(port),
            "-m", "comment", "--comment", "vpngate", "-j", "ACCEPT",
        ]
        if run(check, check=False).returncode != 0:
            run(
                [
                    "iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", str(port),
                    "-m", "comment", "--comment", "vpngate", "-j", "ACCEPT",
                ],
                check=False,
            )
        done.append("iptables")
    return done


def firewall_close(port: int) -> None:
    if not is_linux() or not is_root():
        return
    if have("ufw") and _ufw_active():
        run(["ufw", "delete", "allow", f"{port}/tcp"], check=False)
    if have("firewall-cmd") and _firewalld_running():
        run(["firewall-cmd", "--quiet", "--permanent", f"--remove-port={port}/tcp"], check=False)
        run(["firewall-cmd", "--quiet", "--reload"], check=False)
    if have("iptables"):
        delete = [
            "iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port),
            "-m", "comment", "--comment", "vpngate", "-j", "ACCEPT",
        ]
        while run(delete, check=False).returncode == 0:
            pass
