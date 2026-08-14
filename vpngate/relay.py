from __future__ import annotations

import logging
import select
import socket
import threading
from typing import Optional

from vpngate.socks import _split_bind

LOG = logging.getLogger(__name__)


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
                s.close()
            except OSError:
                pass


def serve_relay(
    listen: str,
    dest: str,
    *,
    stop: Optional[threading.Event] = None,
    ready: Optional[threading.Event] = None,
) -> None:
    lhost, lport_s = _split_bind(listen)
    dhost, dport_s = _split_bind(dest)
    dport = int(dport_s)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((lhost, int(lport_s)))
    sock.listen(128)
    sock.settimeout(0.5)
    LOG.info("publish %s -> %s", listen, dest)
    if ready is not None:
        ready.set()
    try:
        while stop is None or not stop.is_set():
            try:
                client, _ = sock.accept()
            except socket.timeout:
                continue
            try:
                remote = socket.create_connection((dhost, dport), timeout=5)
            except OSError:
                client.close()
                continue
            threading.Thread(target=_pipe, args=(client, remote), daemon=True).start()
    finally:
        sock.close()
