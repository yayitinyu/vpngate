#!/bin/sh
# 一键装好并打出 socks5h://用户:密码@IP:端口
#
#   curl -fsSL https://raw.githubusercontent.com/yayitinyu/vpngate/main/install.sh | sudo sh
#   sudo ./install.sh
#   sudo ./install.sh --no-service     # 不装 systemd，只生成节点
#   sudo ./install.sh --rotate         # 换一套新账号端口

set -eu

REPO_DEFAULT="https://github.com/yayitinyu/vpngate.git"
PREFIX="${PREFIX:-/opt/vpngate}"
BINDIR="${BINDIR:-/usr/local/bin}"
REPO_URL="${VPNGATE_REPO:-$REPO_DEFAULT}"
WITH_SERVICE=1
ROTATE=0
CONF_DIR="/etc/vpngate"
MARKER_NAME=".vpngate-installed"

usage() {
    sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
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
        --no-service) WITH_SERVICE=0; shift ;;
        --rotate) ROTATE=1; shift ;;
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

[ "$(id -u)" -eq 0 ] || die "需要 root"
[ "$(uname -s)" = "Linux" ] || die "只支持 Linux"

script_dir() {
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
        die "没有可用的包管理器，请先自行安装 python3 openvpn iproute2 iptables git"
    fi
}

copy_tree() {
    src=$1
    dest=$2
    mkdir -p "$dest"
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
Description=VPN Gate SOCKS5H node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$PREFIX
Environment=PYTHONPATH=$PREFIX
ExecStart=$BINDIR/vpngate up --watch
ExecStop=$BINDIR/vpngate down
Restart=on-failure
RestartSec=15
TimeoutStartSec=0
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

wait_ready() {
    i=0
    while [ "$i" -lt 45 ]; do
        if [ -f /run/vpngate/state.json ]; then
            return 0
        fi
        # systemd 启动失败就别傻等
        if command -v systemctl >/dev/null 2>&1; then
            if systemctl is-failed vpngate.service >/dev/null 2>&1; then
                return 1
            fi
        fi
        i=$((i + 1))
        sleep 2
    done
    return 1
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
    log "从本地目录安装 $SOURCE"
else
    command -v git >/dev/null 2>&1 || install_packages
    TMP=$(mktemp -d)
    log "克隆 $REPO_URL"
    git clone --depth 1 "$REPO_URL" "$TMP/src"
    SOURCE=$TMP/src
    [ -f "$SOURCE/vpngate/cli.py" ] || die "克隆结果不像 vpngate 仓库"
fi

install_packages
copy_tree "$SOURCE" "$PREFIX"
write_wrapper
write_conf

if [ ! -e /dev/net/tun ]; then
    log "警告: 没有 /dev/net/tun，先在面板里打开 TUN"
fi

"$BINDIR/vpngate" doctor >/dev/null || die "doctor 失败，依赖不齐"

if [ "$ROTATE" -eq 1 ]; then
    "$BINDIR/vpngate" init --rotate
else
    "$BINDIR/vpngate" init
fi

if [ "$WITH_SERVICE" -eq 1 ]; then
    if command -v systemctl >/dev/null 2>&1; then
        write_unit
        log "启动 systemd 服务…"
        systemctl restart vpngate.service
        if wait_ready; then
            log "出口已接通"
        else
            log "服务已拉起，还在选日本出口。稍后再执行: vpngate url"
            systemctl --no-pager --full status vpngate.service || true
        fi
    else
        die "没有 systemd。加 --no-service，然后手动: vpngate start"
    fi
else
    log "未安装 systemd。需要时执行: vpngate start"
fi

log
log "========================================"
"$BINDIR/vpngate" url || true
log "========================================"
log
log "客户端填上面这一整行（必须是 socks5h，不要写成 socks5）。"
log "再看一次:  vpngate url"
log "停:        vpngate stop"
log "卸:        $PREFIX/uninstall.sh"
