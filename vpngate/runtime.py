from __future__ import annotations

import json
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from vpngate import __version__
from vpngate.api import filter_country, load_servers
from vpngate.classify import apply_classification
from vpngate.cymru import lookup
from vpngate.health import public_ip, public_ip_in_ns
from vpngate.models import GatewayState, Server
from vpngate.netns import (
    DEFAULT_NS,
    NS_IP,
    apply_killswitch,
    find_tun,
    lock_routes,
    ns_exists,
    setup as setup_ns,
    teardown as teardown_ns,
    write_auth_file,
)
from vpngate.ovpn import decode_config, detect_openvpn_version, sanitize
from vpngate.probe import probe_servers
from vpngate.rank import select
from vpngate.relay import serve_relay
from vpngate.util import CommandError, have, is_linux, is_root, run

LOG = logging.getLogger(__name__)

DEFAULT_CLASSES = ("residential", "isp", "academic")
CONNECT_WAIT = 28
LIST_API = "https://www.vpngate.net/api/iphone/"


def _ovpn_option_error(log_path: Path) -> bool:
    if not log_path.exists():
        return False
    text = log_path.read_text(encoding="utf-8", errors="replace").lower()
    return any(s in text for s in ("unrecognized option", "unknown option", "bad option"))


def default_state_dir() -> Path:
    if is_linux() and os.path.isdir("/run") and is_root():
        return Path("/run/vpngate")
    return Path.cwd() / ".vpngate"


def package_root() -> Path:
    return Path(__file__).resolve().parent.parent


class Options:
    def __init__(
        self,
        *,
        country: list[str] | None = None,
        classes: list[str] | None = None,
        min_speed: int = 0,
        max_sessions: Optional[int] = None,
        max_ping: Optional[int] = None,
        tries: int = 6,
        probe: bool = True,
        no_asn: bool = False,
        csv_file: Optional[str] = None,
        url: str = LIST_API,
        ns: str = DEFAULT_NS,
        socks: str = "127.0.0.1:1080",
        socks_user: Optional[str] = None,
        socks_pass: Optional[str] = None,
        watch: bool = False,
        state_dir: Optional[Path] = None,
        skip_ips: Optional[set[str]] = None,
        verbose: bool = False,
    ):
        self.country = country or ["JP"]
        self.classes = classes or list(DEFAULT_CLASSES)
        self.min_speed = min_speed
        self.max_sessions = max_sessions
        self.max_ping = max_ping
        self.tries = tries
        self.probe = probe
        self.no_asn = no_asn
        self.csv_file = csv_file
        self.url = url
        self.ns = ns
        self.socks = socks
        self.socks_user = socks_user
        self.socks_pass = socks_pass
        self.watch = watch
        self.state_dir = Path(state_dir) if state_dir else default_state_dir()
        self.skip_ips = skip_ips or set()
        self.verbose = verbose


def build_catalog(opt: Options) -> list[Server]:
    if opt.csv_file:
        LOG.info("loading list from %s", opt.csv_file)
        servers = load_servers(opt.csv_file, from_file=True)
    else:
        LOG.info("fetching %s", opt.url)
        servers = load_servers(opt.url)
    LOG.info("list: %d servers", len(servers))
    servers = filter_country(servers, opt.country)
    LOG.info("after country %s: %d", ",".join(opt.country), len(servers))

    as_map = {} if opt.no_asn else lookup(s.ip for s in servers)
    if as_map:
        LOG.info("ASN map: %d addresses", len(as_map))
    apply_classification(servers, as_map)

    ranked = select(
        servers,
        classes=opt.classes,
        min_speed=opt.min_speed,
        max_sessions=opt.max_sessions,
        max_ping=opt.max_ping,
        skip_ips=opt.skip_ips,
    )
    LOG.info("candidates in %s: %d", ",".join(opt.classes), len(ranked))
    if opt.probe:
        ranked = probe_servers(ranked)
    return ranked


def format_table(servers: list[Server], limit: int = 40) -> str:
    lines = [
        f"{'#':>3}  {'class':<12} {'cc':<3} {'ping':>5} {'speed':>7} {'sess':>4}  "
        f"{'ip':<16} {'host':<16} as"
    ]
    for i, s in enumerate(servers[:limit], 1):
        as_col = ""
        if s.asn:
            as_col = f"AS{s.asn} {s.as_name[:42]}"
        elif s.klass_reason:
            as_col = s.klass_reason[:48]
        from vpngate.util import format_ping, format_speed

        lines.append(
            f"{i:3d}  {s.klass:<12} {s.country_short:<3} {format_ping(s.ping):>5} "
            f"{format_speed(s.speed):>7} {s.sessions:4d}  {s.ip:<16} {s.hostname[:16]:<16} {as_col}"
        )
    if len(servers) > limit:
        lines.append(f"... {len(servers) - limit} more")
    return "\n".join(lines)


class Gateway:
    def __init__(self, opt: Options):
        self.opt = opt
        self.state_dir = opt.state_dir
        self.stop = threading.Event()
        self.openvpn: Optional[subprocess.Popen] = None
        self.socks_proc: Optional[subprocess.Popen] = None
        self.relay_thread: Optional[threading.Thread] = None
        self._ovpn_log = None
        self._socks_log = None

    @property
    def state_path(self) -> Path:
        return self.state_dir / "state.json"

    def up(self) -> int:
        self._require_linux_root()
        self._require_tools()
        self.state_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        host_ip = public_ip()
        if host_ip:
            LOG.info("host public IP %s (must not leak)", host_ip)

        signal.signal(signal.SIGINT, self._on_signal)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, self._on_signal)

        setup_ns(self.opt.ns)
        skip = set(self.opt.skip_ips)
        try:
            while not self.stop.is_set():
                opt = self.opt
                opt.skip_ips = skip
                candidates = build_catalog(opt)
                if not candidates:
                    LOG.error(
                        "no candidates. try --include-official or a wider --class"
                    )
                    if not opt.watch:
                        return 1
                    self._wait(60)
                    continue

                attempts = 0
                connected = False
                for server in candidates:
                    if self.stop.is_set():
                        break
                    if attempts >= opt.tries:
                        break
                    attempts += 1
                    skip.add(server.ip)
                    LOG.info(
                        "try %d/%d %s %s (%s, %s)",
                        attempts,
                        opt.tries,
                        server.hostname,
                        server.ip,
                        server.klass,
                        server.klass_reason,
                    )
                    if self._connect_one(server, host_ip):
                        connected = True
                        if opt.watch:
                            self._supervise()
                            self._stop_vpn_processes()
                            if self.stop.is_set():
                                break
                            LOG.warning("tunnel died, rotating")
                            connected = False
                            continue
                        self._supervise()
                        return 0 if self.stop.is_set() else 1
                if connected:
                    continue
                if not opt.watch:
                    LOG.error("all attempts failed")
                    return 1
                LOG.warning("exhausted list, refetch in 45s")
                self._wait(45)
        finally:
            self.down()
        return 0

    def down(self) -> int:
        self._stop_vpn_processes()
        if is_linux() and have("ip"):
            self._kill_ns_pids()
            teardown_ns(self.opt.ns)
        if self.state_path.exists():
            self.state_path.unlink()
        return 0

    def status(self) -> int:
        if not self.state_path.exists():
            print("down")
            return 1
        data = json.loads(self.state_path.read_text(encoding="utf-8"))
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return 0

    def rotate(self) -> int:
        current_ip = None
        if self.state_path.exists():
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
            current_ip = (data.get("server") or {}).get("ip")
        self.down()
        if current_ip:
            self.opt.skip_ips.add(current_ip)
        return self.up()

    def _connect_one(self, server: Server, host_ip: Optional[str]) -> bool:
        self._stop_vpn_processes()
        ovpn_raw = decode_config(server.ovpn_b64)
        version = (2, 6)
        if have("openvpn"):
            ver = run(["openvpn", "--version"], check=False)
            version = detect_openvpn_version((ver.stdout or "") + (ver.stderr or ""))
        auth = self.state_dir / "auth.txt"
        write_auth_file(auth)
        ovpn_path = self.state_dir / "current.ovpn"
        log_path = self.state_dir / "openvpn.log"
        pid_path = self.state_dir / "openvpn.pid"

        def start_with(ver: tuple[int, int]) -> Optional[str]:
            ovpn_path.write_text(
                sanitize(
                    ovpn_raw,
                    auth_file=str(auth),
                    openvpn_version=ver,
                    verbose=self.opt.verbose,
                ),
                encoding="utf-8",
            )
            os.chmod(ovpn_path, 0o600)
            argv = [
                "ip",
                "netns",
                "exec",
                self.opt.ns,
                "openvpn",
                "--config",
                str(ovpn_path),
                "--writepid",
                str(pid_path),
            ]
            self._ovpn_log = log_path.open("ab")
            self.openvpn = subprocess.Popen(argv, stdout=self._ovpn_log, stderr=subprocess.STDOUT)
            tun_name = self._wait_tun()
            if tun_name:
                return tun_name
            LOG.warning("openvpn did not bring tun up")
            self._dump_ovpn_tail(log_path)
            self._stop_vpn_processes()
            return None

        tun = start_with(version)
        if not tun and version >= (2, 6) and _ovpn_option_error(log_path):
            LOG.info("retrying without OpenSSL-3 providers (older option set)")
            tun = start_with((2, 5))
        if not tun:
            return False

        try:
            lock_routes(self.opt.ns, server.ip, tun)
            apply_killswitch(self.opt.ns, server.ip)
        except CommandError as exc:
            LOG.warning("route/kill-switch failed: %s", exc)
            self._stop_vpn_processes()
            return False

        exit_ip = public_ip_in_ns(self.opt.ns, sys.executable)
        if not exit_ip:
            LOG.warning("no exit IP through tun")
            self._stop_vpn_processes()
            return False
        if host_ip and exit_ip == host_ip:
            LOG.warning("exit IP equals host IP (%s) — leak, skipping", exit_ip)
            self._stop_vpn_processes()
            return False
        LOG.info("exit IP %s via %s", exit_ip, tun)

        if not self._start_socks():
            self._stop_vpn_processes()
            return False

        self._write_state(server, exit_ip, host_ip or "")
        from vpngate.node import advertise_host, format_url

        listen_host, port_s = self.opt.socks.rsplit(":", 1)
        shown_host = advertise_host() if listen_host in {"0.0.0.0", "::", ""} else listen_host
        if self.opt.socks_user:
            endpoint = format_url(self.opt.socks_user, self.opt.socks_pass or "", shown_host, int(port_s))
        else:
            endpoint = f"socks5h://{shown_host}:{port_s}"
        print(
            f"{endpoint}\n"
            f"出口  {exit_ip}  ({server.hostname} {server.ip} {server.klass})",
            flush=True,
        )
        return True

    def _start_socks(self) -> bool:
        env = os.environ.copy()
        root = str(package_root())
        env["PYTHONPATH"] = root + os.pathsep + env.get("PYTHONPATH", "")
        socks_bind = f"{NS_IP}:1080"
        argv = [
            "ip",
            "netns",
            "exec",
            self.opt.ns,
            sys.executable,
            "-m",
            "vpngate",
            "socks",
            "--bind",
            socks_bind,
        ]
        if self.opt.socks_user is not None:
            argv.extend(["--socks-user", self.opt.socks_user])
            argv.extend(["--socks-pass", self.opt.socks_pass or ""])
        self._socks_log = (self.state_dir / "socks.log").open("ab")
        self.socks_proc = subprocess.Popen(
            argv, env=env, stdout=self._socks_log, stderr=subprocess.STDOUT
        )
        time.sleep(0.4)
        if self.socks_proc.poll() is not None:
            LOG.error("socks process exited immediately")
            return False

        time.sleep(0.15)
        ready = threading.Event()
        self._relay_stop = threading.Event()
        self.relay_thread = threading.Thread(
            target=serve_relay,
            kwargs={
                "listen": self.opt.socks,
                "dest": socks_bind,
                "stop": self._relay_stop,
                "ready": ready,
            },
            daemon=True,
        )
        try:
            self.relay_thread.start()
        except OSError as exc:
            LOG.error("cannot publish %s: %s", self.opt.socks, exc)
            return False
        if not ready.wait(2):
            LOG.error("relay did not start")
            return False
        return True

    def _supervise(self) -> None:
        assert self.openvpn is not None
        while not self.stop.is_set():
            rc = self.openvpn.poll()
            if rc is not None:
                LOG.warning("openvpn exited %s", rc)
                return
            if self.socks_proc is not None and self.socks_proc.poll() is not None:
                LOG.warning("socks exited %s", self.socks_proc.returncode)
                return
            time.sleep(0.5)

    def _wait_tun(self) -> Optional[str]:
        deadline = time.time() + CONNECT_WAIT
        while time.time() < deadline and not self.stop.is_set():
            if self.openvpn is not None and self.openvpn.poll() is not None:
                return None
            tun = find_tun(self.opt.ns)
            if tun:
                time.sleep(0.8)
                return tun
            time.sleep(0.4)
        return None

    def _stop_vpn_processes(self) -> None:
        relay_stop = getattr(self, "_relay_stop", None)
        if relay_stop is not None:
            relay_stop.set()
        for proc in (self.socks_proc, self.openvpn):
            if proc is None or proc.poll() is not None:
                continue
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
        self.socks_proc = None
        self.openvpn = None
        for fh in (self._ovpn_log, self._socks_log):
            if fh is not None:
                try:
                    fh.close()
                except OSError:
                    pass
        self._ovpn_log = None
        self._socks_log = None

    def _kill_ns_pids(self) -> None:
        if not ns_exists(self.opt.ns):
            return
        proc = run(["ip", "netns", "pids", self.opt.ns], check=False)
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if not line.isdigit():
                continue
            pid = int(line)
            if pid == os.getpid():
                continue
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
        time.sleep(0.3)
        proc = run(["ip", "netns", "pids", self.opt.ns], check=False)
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if line.isdigit():
                try:
                    os.kill(int(line), signal.SIGKILL)
                except OSError:
                    pass

    def _write_state(self, server: Server, exit_ip: str, host_ip: str) -> None:
        ovpn_pid = None
        pid_path = self.state_dir / "openvpn.pid"
        if pid_path.exists():
            text = pid_path.read_text(encoding="ascii").strip()
            if text.isdigit():
                ovpn_pid = int(text)
        state = GatewayState(
            ns=self.opt.ns,
            socks=self.opt.socks,
            exit_ip=exit_ip,
            host_ip=host_ip,
            server=server.to_public_dict(),
            pids={
                "openvpn": ovpn_pid or (self.openvpn.pid if self.openvpn else 0),
                "socks": self.socks_proc.pid if self.socks_proc else 0,
            },
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state.__dict__, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.state_path)

    def _dump_ovpn_tail(self, log_path: Path, lines: int = 20) -> None:
        if not log_path.exists():
            return
        tail = log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:]
        for line in tail:
            LOG.info("openvpn: %s", line)

    def _wait(self, seconds: float) -> None:
        self.stop.wait(seconds)

    def _on_signal(self, _sig, _frame) -> None:
        LOG.info("signal received, shutting down")
        self.stop.set()

    def _require_linux_root(self) -> None:
        if not is_linux():
            raise SystemExit("up/down/rotate require Linux (ip netns)")
        if not is_root():
            raise SystemExit("up/down/rotate must run as root")

    def _require_tools(self) -> None:
        missing = [c for c in ("ip", "iptables", "openvpn") if not have(c)]
        if missing:
            raise SystemExit("missing commands: " + ", ".join(missing))
        if not Path("/dev/net/tun").exists():
            raise SystemExit("/dev/net/tun is missing (enable TUN on this VPS)")


def doctor() -> int:
    print(f"vpngate-socks {__version__}")
    print(f"python        {sys.executable} {sys.version.split()[0]}")
    print(f"platform      {sys.platform}")
    print(f"linux         {is_linux()}")
    print(f"root          {is_root()}")
    for cmd in ("ip", "iptables", "ip6tables", "openvpn"):
        print(f"have {cmd:<10} {have(cmd)}")
    tun = Path("/dev/net/tun")
    print(f"/dev/net/tun  {tun.exists()}")
    if have("openvpn"):
        ver = run(["openvpn", "--version"], check=False)
        first = ((ver.stdout or ver.stderr or "").splitlines() or [""])[0]
        print(f"openvpn       {first}")
    if is_linux() and have("ip"):
        print(f"netns exists  {ns_exists(DEFAULT_NS)}")
    ok = is_linux() and have("ip") and have("iptables") and have("openvpn")
    if is_linux() and not tun.exists():
        ok = False
    return 0 if ok else 1
