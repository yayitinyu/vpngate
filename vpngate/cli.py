from __future__ import annotations

import argparse
import json
import sys
from typing import Optional, Sequence

from vpngate import __version__
from vpngate.runtime import DEFAULT_CLASSES, Gateway, Options, build_catalog, doctor, format_table
from vpngate.socks import run_cli as socks_run
from vpngate.util import parse_speed, setup_logging


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
    p.add_argument("--url", default=None, help="CSV list URL")
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
    return Options(
        country=_csv_list(args.country),
        classes=_classes_from_args(args),
        min_speed=parse_speed(args.min_speed),
        max_sessions=args.max_sessions,
        max_ping=args.max_ping,
        tries=getattr(args, "tries", 6),
        probe=probe,
        no_asn=args.no_asn,
        csv_file=args.csv_file,
        url=args.url or "https://www.vpngate.net/api/iphone/",
        ns=getattr(args, "ns", "vpngate"),
        socks=getattr(args, "socks", "127.0.0.1:1080"),
        socks_user=getattr(args, "socks_user", None),
        socks_pass=getattr(args, "socks_pass", None),
        watch=getattr(args, "watch", False),
        verbose=args.verbose,
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vpngate",
        description="VPN Gate OpenVPN + netns SOCKS5H gateway (occasional JP home/ISP exits)",
    )
    parser.add_argument("--version", action="version", version=f"vpngate-socks {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list", help="fetch, classify, and rank servers")
    _add_select_flags(p_list)
    p_list.add_argument("--probe", action="store_true", help="TCP-probe endpoints")
    p_list.add_argument("--json", action="store_true")
    p_list.add_argument("--limit", type=int, default=40)

    p_up = sub.add_parser("up", help="select a server, connect in a netns, publish SOCKS5H")
    _add_select_flags(p_up)
    p_up.add_argument("--tries", type=int, default=6)
    p_up.add_argument("--no-probe", action="store_true")
    p_up.add_argument("--socks", default="127.0.0.1:1080", help="host publish address")
    p_up.add_argument("--socks-user", default=None)
    p_up.add_argument("--socks-pass", default=None)
    p_up.add_argument("--watch", action="store_true", help="rotate when the tunnel dies")
    p_up.add_argument("--ns", default="vpngate")

    p_down = sub.add_parser("down", help="tear down netns, tunnel, and SOCKS")
    p_down.add_argument("--ns", default="vpngate")

    sub.add_parser("status", help="print current gateway state")

    p_rot = sub.add_parser("rotate", help="drop the current exit and pick the next one")
    _add_select_flags(p_rot)
    p_rot.add_argument("--tries", type=int, default=6)
    p_rot.add_argument("--no-probe", action="store_true")
    p_rot.add_argument("--socks", default="127.0.0.1:1080")
    p_rot.add_argument("--socks-user", default=None)
    p_rot.add_argument("--socks-pass", default=None)
    p_rot.add_argument("--watch", action="store_true")
    p_rot.add_argument("--ns", default="vpngate")

    sub.add_parser("doctor", help="check local prerequisites")

    p_socks = sub.add_parser("socks", help="run the in-netns SOCKS5H server (internal)")
    p_socks.add_argument("--bind", required=True)
    p_socks.add_argument("--socks-user", default=None)
    p_socks.add_argument("--socks-pass", default=None)

    args = parser.parse_args(argv)
    setup_logging(args.verbose)

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
        if args.socks_user and args.socks_pass is None:
            print("error: --socks-user requires --socks-pass", file=sys.stderr)
            return 2
        if args.socks.startswith("0.0.0.0") and not args.socks_user:
            print("error: publishing on 0.0.0.0 requires --socks-user/--socks-pass", file=sys.stderr)
            return 2
        opt = _options_from_args(args, probe=not args.no_probe)
        gw = Gateway(opt)
        if args.cmd == "up":
            return gw.up()
        return gw.rotate()

    parser.error(f"unknown command {args.cmd}")
    return 2
