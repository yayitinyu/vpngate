from __future__ import annotations

import socket
import struct
import threading
import unittest

from vpngate.socks import serve


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RuntimeError("closed")
        buf.extend(chunk)
    return bytes(buf)


class SocksTests(unittest.TestCase):
    def _backend(self) -> tuple[socket.socket, int]:
        backend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        backend.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        backend.bind(("127.0.0.1", 0))
        backend.listen(1)
        return backend, backend.getsockname()[1]

    def _start_proxy(self, **kwargs) -> tuple[threading.Event, int]:
        stop = threading.Event()
        ready = threading.Event()
        ports: list[int] = []
        t = threading.Thread(
            target=serve,
            args=("127.0.0.1", 0),
            kwargs={"stop": stop, "ready": ready, "port_holder": ports, **kwargs},
            daemon=True,
        )
        t.start()
        self.assertTrue(ready.wait(2))
        self.addCleanup(stop.set)
        return stop, ports[0]

    def test_domain_connect_noauth(self):
        backend, bport = self._backend()
        self.addCleanup(backend.close)

        def accept() -> None:
            conn, _ = backend.accept()
            data = conn.recv(64)
            conn.sendall(b"echo:" + data)
            conn.close()

        threading.Thread(target=accept, daemon=True).start()
        _stop, pport = self._start_proxy()

        c = socket.create_connection(("127.0.0.1", pport), timeout=3)
        self.addCleanup(c.close)
        c.sendall(b"\x05\x01\x00")
        self.assertEqual(c.recv(2), b"\x05\x00")

        host = b"localhost"
        req = b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack("!H", bport)
        c.sendall(req)
        reply = _recv_exact(c, 10)
        self.assertEqual(reply[0:2], b"\x05\x00")

        c.sendall(b"ping")
        self.assertEqual(c.recv(32), b"echo:ping")

    def test_userpass(self):
        backend, bport = self._backend()
        self.addCleanup(backend.close)

        def accept() -> None:
            conn, _ = backend.accept()
            conn.sendall(b"ok")
            conn.close()

        threading.Thread(target=accept, daemon=True).start()
        _stop, pport = self._start_proxy(username="u", password="p")

        c = socket.create_connection(("127.0.0.1", pport), timeout=3)
        self.addCleanup(c.close)
        c.sendall(b"\x05\x01\x02")
        self.assertEqual(c.recv(2), b"\x05\x02")
        c.sendall(b"\x01\x01u\x01p")
        self.assertEqual(c.recv(2), b"\x01\x00")

        req = b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", bport)
        c.sendall(req)
        reply = _recv_exact(c, 10)
        self.assertEqual(reply[1], 0x00)
        self.assertEqual(c.recv(8), b"ok")

    def test_bad_password(self):
        _stop, pport = self._start_proxy(username="u", password="p")
        c = socket.create_connection(("127.0.0.1", pport), timeout=3)
        self.addCleanup(c.close)
        c.sendall(b"\x05\x01\x02")
        self.assertEqual(c.recv(2), b"\x05\x02")
        c.sendall(b"\x01\x01u\x01x")
        self.assertEqual(c.recv(2), b"\x01\x01")


if __name__ == "__main__":
    unittest.main()
