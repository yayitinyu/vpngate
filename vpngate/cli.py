from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Optional, Sequence

from vpngate import __version__
from vpngate.node import apply_node, ensure_node, firewall_open, load_node
from vpngate.runtime import DEFAULT_CLASSES, Gateway, Options, build_catalog, doctor, format_table
from vpngate.socks import run_cli as socks_run
from vpngate.util import have, is_root, parse_speed, setup_logging


def _csv_list(text: str) -> list[str]:
    return [p.strip() for p in text.split(",") if p.strip()]


def _add_select_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--country", default="JP", help="comma-separated ISO codes (default: JP)")
    p.add_argument(
        "--class",
        dest="classes",
        default=None,
        help="comma-separated classes (default: residential,isp,academic)",
    )
    p.add_argument("--include-official", action="store_true", help="also use Tsukuba public-vpn-* cluster")
    p.add_argument("--allow-dc", action="store_true", help="also use datacenter / VPS exits")
    p.add_argument("--allow-unknown", action="store_true", help="keep unclassified IPs")
    p.add_argument("--min-speed", default="0", help="minimum advertised bps (also 8m, 20m)")
    p.add_argument("--max-sessions", type=int, default=None)
    p.add_argument("--max-ping", type=int, default=None, help="CSV ping cap in ms (measured by VPN Gate, not you)")
    p.add_argument("--url", dest="list_url", default=None, help="CSV list URL")
    p.add_argument("--csv-file", default=None, help="use a cached CSV instead of fetching")
    p.add_argument("--no-asn", action="store_true", help="skip Team Cymru (heuristics only)")


def _classes_from_args(args: argparse.Namespace) -> list[str]:
    if args.classes:
        classes = _csv_list(args.classes.lower())
    else:
        classes = list(DEFAULT_CLASSES)
    if getattr(args, "include_official", False) and "official" not in classes:
        classes.append("official")
    if getattr(args, "allow_dc", False) and "datacenter" not in classes:
        classes.append("datacenter")
    if getattr(args, "allow_unknown", False) and "unknown" not in classes:
        classes.append("unknown")
    return classes


def _options_from_args(args: argparse.Namespace, *, probe: bool) -> Options:
    socks = getattr(args, "socks", None)
    socks_user = getattr(args, "socks_user", None)
    socks_pass = getattr(args, "socks_pass", None)
    node = load_node()
    if socks is None and node is not None:
        socks = node.listen
        if socks_user is None:
            socks_user = node.user
            socks_pass = node.password
    if socks is None:
        socks = "127.0.0.1:1080"

    return Options(
        country=_csv_list(args.country) if hasattr(args, "country") else ["JP"],
        classes=_classes_from_args(args) if hasattr(args, "classes") else list(DEFAULT_CLASSES),
        min_speed=parse_speed(args.min_speed) if hasattr(args, "min_speed") else 0,
        max_sessions=getattr(args, "max_sessions", None),
        max_ping=getattr(args, "max_ping", None),
        tries=getattr(args, "tries", 6),
        probe=probe,
        no_asn=getattr(args, "no_asn", False),
        csv_file=getattr(args, "csv_file", None),
        url=getattr(args, "list_url", None) or "https://www.vpngate.net/api/iphone/",
        ns=getattr(args, "ns", "vpngate"),
        socks=socks,
        socks_user=socks_user,
        socks_pass=socks_pass,
        watch=getattr(args, "watch", False),
        verbose=args.verbose,
    )


def _print_url(*, quiet: bool = False) -> int:
    node = load_node()
    if node is None:
        print("还没有节点。先运行: sudo vpngate init  或重新执行 install.sh", file=sys.stderr)
        return 1
    url = node.url()
    if quiet:
        print(url)
        return 0
    running = Path("/run/vpngate/state.json").is_file()
    state_line = "运行中" if running else "已创建（隧道可能还在连）"
    print(url)
    print(f"状态  {state_line}")
    if running:
        try:
            data = json.loads(Path("/run/vpngate/state.json").read_text(encoding="utf-8"))
            server = data.get("server") or {}
            print(
                f"出口  {data.get('exit_ip', '?')}  "
                f"({server.get('hostname', '?')} {server.get('klass', '')})"
            )
        except (OSError, json.JSONDecodeError):
            pass
    return 0


def _cmd_init(rotate: bool) -> int:
    node, created = ensure_node(rotate=rotate)
    backends = firewall_open(node.port)
    url = node.url()
    if created:
        print("已生成新节点（重启后账号端口不变）")
    else:
        print("已有节点，沿用原来的账号和端口（换新的请加 --rotate）")
    if backends:
        print("已放行 TCP/" + str(node.port) + "  (" + ", ".join(backends) + ")")
    print()
    print(url)
    return 0


def _has_unit() -> bool:
    if not have("systemctl"):
        return False
    proc = subprocess.run(
        ["systemctl", "list-unit-files", "vpngate.service"],
        check=False,
        capture_output=True,
        text=True,
    )
    return proc.returncode == 0 and "vpngate.service" in (proc.stdout or "")


def _cmd_start() -> int:
    node, _ = ensure_node(rotate=False)
    firewall_open(node.port)
    if _has_unit():
        proc = subprocess.run(["systemctl", "start", "vpngate"], check=False)
        if proc.returncode != 0:
            return proc.returncode
        print("已交给 systemd 启动: systemctl status vpngate")
        print(node.url())
        return 0
    opt = Options(
        socks=node.listen,
        socks_user=node.user,
        socks_pass=node.password,
        watch=True,
    )
    apply_node(opt, node)
    return Gateway(opt).up()


def _cmd_stop() -> int:
    if _has_unit():
        proc = subprocess.run(["systemctl", "stop", "vpngate"], check=False)
        return proc.returncode
    return Gateway(Options()).down()


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vpngate",
        description="一键把 VPN Gate 日本家宽做成 socks5h://用户:密码@IP:端口",
    )
    parser.add_argument("--version", action="version", version=f"vpngate-socks {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("url", help="打印 socks5h://用户:密码@IP:端口")
    p_init = sub.add_parser("init", help="生成随机账号/高位端口并放行防火墙")
    p_init.add_argument("--rotate", action="store_true", help="作废旧账号，换一套新的")
    sub.add_parser("start", help="启动节点（有 systemd 就走服务）")
    sub.add_parser("stop", help="停止节点")

    p_list = sub.add_parser("list", help="拉列表、分类、排序")
    _add_select_flags(p_list)
    p_list.add_argument("--probe", action="store_true", help="TCP-probe endpoints")
    p_list.add_argument("--json", action="store_true")
    p_list.add_argument("--limit", type=int, default=40)

    p_up = sub.add_parser("up", help="前台连隧道（systemd 会自己调用）")
    _add_select_flags(p_up)
    p_up.add_argument("--tries", type=int, default=6)
    p_up.add_argument("--no-probe", action="store_true")
    p_up.add_argument("--socks", default=None, help="覆盖 node.conf 的监听地址")
    p_up.add_argument("--socks-user", default=None)
    p_up.add_argument("--socks-pass", default=None)
    p_up.add_argument("--watch", action="store_true", help="隧道死后自动换下一个")
    p_up.add_argument("--ns", default="vpngate")

    p_down = sub.add_parser("down", help="拆掉 netns / 隧道 / SOCKS")
    p_down.add_argument("--ns", default="vpngate")

    sub.add_parser("status", help="当前出口 JSON")

    p_rot = sub.add_parser("rotate", help="丢掉当前出口再选")
    _add_select_flags(p_rot)
    p_rot.add_argument("--tries", type=int, default=6)
    p_rot.add_argument("--no-probe", action="store_true")
    p_rot.add_argument("--socks", default=None)
    p_rot.add_argument("--socks-user", default=None)
    p_rot.add_argument("--socks-pass", default=None)
    p_rot.add_argument("--watch", action="store_true")
    p_rot.add_argument("--ns", default="vpngate")

    sub.add_parser("doctor", help="检查本机依赖")

    p_socks = sub.add_parser("socks", help="netns 内 SOCKS 进程（内部用）")
    p_socks.add_argument("--bind", required=True)
    p_socks.add_argument("--socks-user", default=None)
    p_socks.add_argument("--socks-pass", default=None)

    args = parser.parse_args(argv)
    setup_logging(args.verbose)

    if args.cmd is None or args.cmd == "url":
        return _print_url()

    if args.cmd == "init":
        return _cmd_init(rotate=args.rotate)

    if args.cmd == "start":
        if not is_root():
            print("start 需要 root", file=sys.stderr)
            return 1
        return _cmd_start()

    if args.cmd == "stop":
        if not is_root():
            print("stop 需要 root", file=sys.stderr)
            return 1
        return _cmd_stop()

    if args.cmd == "doctor":
        return doctor()

    if args.cmd == "socks":
        return socks_run(args.bind, args.socks_user, args.socks_pass)

    if args.cmd == "list":
        opt = _options_from_args(args, probe=args.probe)
        servers = build_catalog(opt)
        if args.json:
            print(json.dumps([s.to_public_dict() for s in servers[: args.limit]], ensure_ascii=False, indent=2))
        else:
            print(format_table(servers, limit=args.limit), flush=True)
            print(f"\n{len(servers)} candidates", flush=True)
        return 0 if servers else 1

    if args.cmd == "status":
        return Gateway(Options()).status()

    if args.cmd == "down":
        return Gateway(Options(ns=args.ns)).down()

    if args.cmd in {"up", "rotate"}:
        node = load_node()
        if args.socks_user and args.socks_pass is None:
            print("error: --socks-user requires --socks-pass", file=sys.stderr)
            return 2
        opt = _options_from_args(args, probe=not args.no_probe)
        listen_host = opt.socks.rsplit(":", 1)[0]
        if listen_host in {"0.0.0.0", "::"} and not opt.socks_user:
            print("error: 对外监听必须有账号密码（先 sudo vpngate init）", file=sys.stderr)
            return 2
        if node is not None and listen_host != "127.0.0.1":
            firewall_open(node.port if args.socks is None else int(opt.socks.rsplit(":", 1)[1]))
        gw = Gateway(opt)
        if args.cmd == "up":
            return gw.up()
        return gw.rotate()

    parser.error(f"unknown command {args.cmd}")
    return 2
