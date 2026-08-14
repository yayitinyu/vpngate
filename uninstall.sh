#!/bin/sh
# Remove a vpngate-socks install created by install.sh.
#   sudo ./uninstall.sh
#   sudo /opt/vpngate/uninstall.sh
#   sudo sh uninstall.sh --prefix /opt/vpngate

set -eu

CONF_DIR="/etc/vpngate"
PREFIX="${PREFIX:-}"
BINDIR="${BINDIR:-/usr/local/bin}"
FORCE=0

log() { printf '%s\n' "$*"; }
die() { printf 'uninstall: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        --prefix) PREFIX="${2:-}"; shift 2 ;;
        --bindir) BINDIR="${2:-}"; shift 2 ;;
        --force) FORCE=1; shift ;;
        *) die "unknown option: $1" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "run as root"

if [ -z "$PREFIX" ] && [ -f "$CONF_DIR/install.conf" ]; then
    # shellcheck disable=SC1091
    . "$CONF_DIR/install.conf"
fi

if [ -z "$PREFIX" ]; then
    PREFIX=/opt/vpngate
fi

case "$PREFIX" in
    /|/usr|/usr/local|/usr/local/bin|/bin|/sbin|/etc|/var|/home|/root|"")
        die "refusing to remove $PREFIX"
        ;;
esac

if [ ! -f "$PREFIX/.vpngate-installed" ] && [ "$FORCE" -ne 1 ]; then
    die "$PREFIX is not a vpngate-socks prefix (no .vpngate-installed). pass --force to override"
fi

if [ -x "$BINDIR/vpngate" ]; then
    log "关闭防火墙端口并拆掉隧道"
    PYTHONPATH="$PREFIX" python3 - <<'PY' || true
from vpngate.node import firewall_close, load_node
node = load_node()
if node is not None:
    firewall_close(node.port)
PY
elif [ -f "$CONF_DIR/node.conf" ]; then
    # shellcheck disable=SC1091
    . "$CONF_DIR/node.conf"
    if [ -n "${SOCKS_PORT:-}" ] && command -v iptables >/dev/null 2>&1; then
        iptables -D INPUT -p tcp --dport "$SOCKS_PORT" -m comment --comment vpngate -j ACCEPT >/dev/null 2>&1 || true
    fi
fi

if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files vpngate.service >/dev/null 2>&1; then
        systemctl stop vpngate.service >/dev/null 2>&1 || true
        systemctl disable vpngate.service >/dev/null 2>&1 || true
    fi
    rm -f /etc/systemd/system/vpngate.service
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

if [ -x "$BINDIR/vpngate" ]; then
    "$BINDIR/vpngate" down >/dev/null 2>&1 || true
fi

if command -v ip >/dev/null 2>&1; then
    ip netns del vpngate >/dev/null 2>&1 || true
    ip link del vg-host >/dev/null 2>&1 || true
fi

rm -f "$BINDIR/vpngate"
rm -rf "$PREFIX"
rm -rf /run/vpngate
rm -rf "$CONF_DIR"

log "uninstalled."
