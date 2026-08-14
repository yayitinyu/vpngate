from __future__ import annotations

import logging
import select
import socket
import struct
import threading
from typing import Optional

LOG = logging.getLogger(__name__)

SOCKS_VERSION = 5
AUTH_NONE = 0x00
AUTH_USERPASS = 0x02
AUTH_NO_ACCEPTABLE = 0xFF
CMD_CONNECT = 0x01
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04


class SocksError(Exception):
    def __init__(self, reply_code: int, message: str):
        super().__init__(message)
        self.reply_code = reply_code


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise SocksError(0x01, "peer closed during handshake")
        buf.extend(chunk)
    return bytes(buf)


def _reply(sock: socket.socket, code: int, bind: tuple[str, int] = ("0.0.0.0", 0)) -> None:
    try:
        addr = socket.inet_aton(bind[0])
    except OSError:
        addr = b"\x00\x00\x00\x00"
    sock.sendall(b"\x05" + bytes([code]) + b"\x00\x01" + addr + struct.pack("!H", bind[1]))


def _pipe(a: socket.socket, b: socket.socket) -> None:
    try:
        while True:
            r, _, _ = select.select([a, b], [], [], 120)
            if not r:
                break
            for src in r:
                dst = b if src is a else a
                data = src.recv(65536)
                if not data:
                    return
                dst.sendall(data)
    except OSError:
        return
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass


def _resolve_ipv4(host: str, port: int) -> tuple[str, int]:
    infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    if not infos:
        raise SocksError(0x04, f"cannot resolve {host}")
    return infos[0][4][0], infos[0][4][1]


def handle_client(
    client: socket.socket,
    *,
    username: Optional[str],
    password: Optional[str],
    connect_timeout: float = 20.0,
) -> None:
    client.settimeout(30)
    try:
        header = _recv_exact(client, 2)
        if header[0] != SOCKS_VERSION:
            return
        methods = set(_recv_exact(client, header[1]))
        want_auth = username is not None
        if want_auth:
            if AUTH_USERPASS not in methods:
                client.sendall(b"\x05\xff")
                return
            client.sendall(bytes([SOCKS_VERSION, AUTH_USERPASS]))
            auth = _recv_exact(client, 2)
            if auth[0] != 0x01:
                return
            ulen = auth[1]
            user = _recv_exact(client, ulen).decode("utf-8", errors="replace")
            plen = _recv_exact(client, 1)[0]
            pw = _recv_exact(client, plen).decode("utf-8", errors="replace")
            if user != username or pw != (password or ""):
                client.sendall(b"\x01\x01")
                return
            client.sendall(b"\x01\x00")
        else:
            if AUTH_NONE not in methods:
                client.sendall(b"\x05\xff")
                return
            client.sendall(bytes([SOCKS_VERSION, AUTH_NONE]))

        req = _recv_exact(client, 4)
        if req[0] != SOCKS_VERSION:
            return
        cmd, _, atyp = req[1], req[2], req[3]
        if cmd != CMD_CONNECT:
            _reply(client, 0x07)
            return

        if atyp == ATYP_IPV4:
            host = socket.inet_ntoa(_recv_exact(client, 4))
        elif atyp == ATYP_DOMAIN:
            ln = _recv_exact(client, 1)[0]
            raw_host = _recv_exact(client, ln)
            try:
                host = raw_host.decode("idna")
            except UnicodeError:
                host = raw_host.decode("utf-8", errors="replace")
        elif atyp == ATYP_IPV6:
            _recv_exact(client, 16)
            _recv_exact(client, 2)
            _reply(client, 0x08)  # IPv6 not supported — tun is v4-only
            return
        else:
            _reply(client, 0x08)
            return
        port = struct.unpack("!H", _recv_exact(client, 2))[0]

        dest_ip, dest_port = _resolve_ipv4(host, port)
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.settimeout(connect_timeout)
        try:
            remote.connect((dest_ip, dest_port))
        except OSError:
            remote.close()
            _reply(client, 0x05)
            return

        remote.settimeout(None)
        client.settimeout(None)
        bind_ip, bind_port = remote.getsockname()[:2]
        _reply(client, 0x00, (bind_ip, bind_port))
        _pipe(client, remote)
    except SocksError as exc:
        try:
            _reply(client, exc.reply_code)
        except OSError:
            pass
        try:
            client.close()
        except OSError:
            pass
    except OSError:
        try:
            client.close()
        except OSError:
            pass


def serve(
    bind_host: str,
    bind_port: int,
    *,
    username: Optional[str] = None,
    password: Optional[str] = None,
    ready: Optional[threading.Event] = None,
    stop: Optional[threading.Event] = None,
    port_holder: Optional[list] = None,
) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_host, bind_port))
    sock.listen(128)
    sock.settimeout(0.5)
    if port_holder is not None:
        port_holder.append(sock.getsockname()[1])
    if ready is not None:
        ready.set()
    LOG.info("SOCKS5H listening on %s:%s", bind_host, sock.getsockname()[1])
    try:
        while stop is None or not stop.is_set():
            try:
                client, _addr = sock.accept()
            except socket.timeout:
                continue
            t = threading.Thread(
                target=handle_client,
                args=(client,),
                kwargs={"username": username, "password": password},
                daemon=True,
            )
            t.start()
    finally:
        sock.close()
    return sock


def run_cli(bind: str, username: Optional[str], password: Optional[str]) -> int:
    host, port_s = _split_bind(bind)
    serve(host, int(port_s), username=username, password=password)
    return 0


def _split_bind(bind: str) -> tuple[str, str]:
    if bind.startswith("["):
        raise ValueError("IPv6 bind is not supported")
    if ":" not in bind:
        raise ValueError(f"bind must be host:port, got {bind!r}")
    host, port = bind.rsplit(":", 1)
    return host, port
