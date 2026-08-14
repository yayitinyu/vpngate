from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from vpngate.node import (
    Node,
    format_url,
    generate_node,
    load_node,
    save_node,
    ensure_node,
    PORT_MIN,
    PORT_MAX,
)


class NodeTests(unittest.TestCase):
    def test_url_is_socks5h_and_url_safe(self):
        url = format_url("vg_abc", "Passw3rdXYZ", "203.0.113.10", 41287)
        self.assertEqual(url, "socks5h://vg_abc:Passw3rdXYZ@203.0.113.10:41287")

    def test_generate_ranges(self):
        node = generate_node()
        self.assertTrue(node.user.startswith("vg_"))
        self.assertGreaterEqual(len(node.password), 16)
        self.assertTrue(node.user.replace("vg_", "").isalnum())
        self.assertTrue(node.password.isalnum())
        self.assertGreaterEqual(node.port, PORT_MIN)
        self.assertLessEqual(node.port, PORT_MAX)
        self.assertEqual(node.bind, "0.0.0.0")
        self.assertNotIn(":", node.password)
        self.assertNotIn("@", node.password)

    def test_roundtrip_conf(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "node.conf"
            original = Node(user="vg_testhost", password="Abcdefgh23456789XY", port=41287)
            save_node(original, path)
            loaded = load_node(path)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded.user, original.user)
            self.assertEqual(loaded.password, original.password)
            self.assertEqual(loaded.port, original.port)
            if os.name != "nt":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_ensure_keeps_existing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "node.conf"
            first, created = ensure_node(path=path)
            self.assertTrue(created)
            second, created_again = ensure_node(path=path)
            self.assertFalse(created_again)
            self.assertEqual(first.user, second.user)
            self.assertEqual(first.port, second.port)

    def test_cli_url_reads_env_path(self):
        from io import StringIO
        from contextlib import redirect_stdout
        from vpngate.cli import main

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "node.conf"
            save_node(Node("vg_cli", "SecretPass12345678", 35001, "0.0.0.0"), path)
            old = os.environ.get("VPNGATE_NODE_CONF")
            os.environ["VPNGATE_NODE_CONF"] = str(path)
            try:
                buf = StringIO()
                with redirect_stdout(buf):
                    rc = main(["url"])
                self.assertEqual(rc, 0)
                self.assertIn("socks5h://vg_cli:SecretPass12345678@", buf.getvalue())
                self.assertIn(":35001", buf.getvalue())
            finally:
                if old is None:
                    os.environ.pop("VPNGATE_NODE_CONF", None)
                else:
                    os.environ["VPNGATE_NODE_CONF"] = old
