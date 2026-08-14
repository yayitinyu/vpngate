#!/bin/sh
# Install vpngate-socks onto a Linux host.
#
# From a clone:
#   sudo ./install.sh
# One-liner (public repo):
#   curl -fsSL https://raw.githubusercontent.com/yayitinyu/vpngate/main/install.sh | sudo sh
#
# Options (env or flags):
#   --prefix DIR       install tree (default /opt/vpngate)
#   --bindir DIR       wrapper path dir (default /usr/local/bin)
#   --with-service     install and enable systemd unit (optional)
#   --repo URL         git URL when the script is not run from a checkout

set -eu

REPO_DEFAULT="https://github.com/yayitinyu/vpngate.git"
PREFIX="${PREFIX:-/opt/vpngate}"
BINDIR="${BINDIR:-/usr/local/bin}"
REPO_URL="${VPNGATE_REPO:-$REPO_DEFAULT}"
WITH_SERVICE=0
CONF_DIR="/etc/vpngate"
MARKER_NAME=".vpngate-installed"

usage() {
    sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

log() { printf '%s\n' "$*"; }
die() { printf 'install: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) usage 0 ;;
        --prefix) PREFIX="${2:-}"; shift 2 ;;
        --bindir) BINDIR="${2:-}"; shift 2 ;;
        --repo) REPO_URL="${2:-}"; shift 2 ;;
        --with-service) WITH_SERVICE=1; shift ;;
        --) shift; break ;;
        *) die "unknown option: $1" ;;
    esac
done

[ -n "$PREFIX" ] || die "--prefix is empty"
[ -n "$BINDIR" ] || die "--bindir is empty"

case "$PREFIX" in
    /|/usr|/usr/local|/usr/local/bin|/bin|/sbin|/etc|/var|/home|/root)
        die "refusing to install into $PREFIX"
        ;;
esac

[ "$(id -u)" -eq 0 ] || die "run as root"
[ "$(uname -s)" = "Linux" ] || die "Linux only"

script_dir() {
    # When piped from curl, $0 is "sh" and this returns empty.
    case "$0" in
        /*) dirname "$0" ;;
        ./*|../*) (CDPATH= cd -- "$(dirname "$0")" && pwd) ;;
        *)
            if [ -f "$0" ]; then
                (CDPATH= cd -- "$(dirname "$0")" && pwd)
            else
                printf ''
            fi
            ;;
    esac
}

install_packages() {
    if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq python3 openvpn iproute2 iptables ca-certificates git
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y python3 openvpn iproute iptables ca-certificates git
    elif command -v yum >/dev/null 2>&1; then
        yum install -y python3 openvpn iproute iptables ca-certificates git
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache python3 openvpn iproute2 iptables ca-certificates git
    else
        die "no supported package manager; install python3 openvpn iproute2 iptables git yourself"
    fi
}

copy_tree() {
    src=$1
    dest=$2
    mkdir -p "$dest"
    # Explicit list: do not dump tests/cache/.git into the prefix.
    for item in vpngate contrib pyproject.toml README.md LICENSE install.sh uninstall.sh; do
        if [ -e "$src/$item" ]; then
            rm -rf "$dest/$item"
            cp -a "$src/$item" "$dest/$item"
        fi
    done
}

write_wrapper() {
    mkdir -p "$BINDIR"
    cat > "$BINDIR/vpngate" <<EOF
#!/bin/sh
export PYTHONPATH="$PREFIX\${PYTHONPATH:+:\$PYTHONPATH}"
exec python3 -m vpngate "\$@"
EOF
    chmod 755 "$BINDIR/vpngate"
}

write_unit() {
    unit=/etc/systemd/system/vpngate.service
    cat > "$unit" <<EOF
[Unit]
Description=VPN Gate OpenVPN netns SOCKS5H gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$PREFIX
Environment=PYTHONPATH=$PREFIX
ExecStart=$BINDIR/vpngate up --watch
ExecStop=$BINDIR/vpngate down
Restart=on-failure
RestartSec=20
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable vpngate.service
}

write_conf() {
    mkdir -p "$CONF_DIR"
    cat > "$CONF_DIR/install.conf" <<EOF
PREFIX=$PREFIX
BINDIR=$BINDIR
EOF
    chmod 644 "$CONF_DIR/install.conf"
    printf 'installed %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$PREFIX/$MARKER_NAME"
}

SRC_DIR=$(script_dir)
TMP=
cleanup() {
    if [ -n "${TMP:-}" ] && [ -d "$TMP" ]; then
        rm -rf "$TMP"
    fi
}
trap cleanup EXIT

if [ -n "$SRC_DIR" ] && [ -f "$SRC_DIR/vpngate/cli.py" ]; then
    SOURCE=$SRC_DIR
    log "installing from checkout $SOURCE"
else
    command -v git >/dev/null 2>&1 || install_packages
    TMP=$(mktemp -d)
    log "cloning $REPO_URL"
    git clone --depth 1 "$REPO_URL" "$TMP/src"
    SOURCE=$TMP/src
    [ -f "$SOURCE/vpngate/cli.py" ] || die "clone does not look like vpngate-socks"
fi

install_packages
copy_tree "$SOURCE" "$PREFIX"
write_wrapper
write_conf

if [ "$WITH_SERVICE" -eq 1 ]; then
    if command -v systemctl >/dev/null 2>&1; then
        write_unit
        log "systemd unit enabled (not started; run: systemctl start vpngate)"
    else
        die "systemd not found; omit --with-service"
    fi
fi

if [ ! -e /dev/net/tun ]; then
    log "warning: /dev/net/tun is missing; enable TUN before 'vpngate up'"
fi

log "running doctor"
"$BINDIR/vpngate" doctor || die "doctor failed"

log
log "installed."
log "  prefix  $PREFIX"
log "  binary  $BINDIR/vpngate"
log
log "  vpngate list"
log "  vpngate up"
log "  vpngate down"
log "  uninstall.sh   (or: $PREFIX/uninstall.sh)"
