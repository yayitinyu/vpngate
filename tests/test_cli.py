from __future__ import annotations

import json
import unittest
from pathlib import Path

from vpngate.cli import main

FIXTURE = Path(__file__).parent / "fixtures" / "servers.csv"


class CliListTests(unittest.TestCase):
    def test_list_fixture_json(self):
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(
                [
                    "list",
                    "--csv-file",
                    str(FIXTURE),
                    "--no-asn",
                    "--json",
                    "--class",
                    "residential,official",
                ]
            )
        self.assertEqual(rc, 0)
        rows = json.loads(buf.getvalue())
        hosts = [r["hostname"] for r in rows]
        self.assertIn("vpn111", hosts)
        self.assertIn("public-vpn-1", hosts)
        self.assertTrue(all(r["country_short"] == "JP" for r in rows))
        self.assertTrue(all("ovpn_b64" not in r for r in rows))

    def test_list_default_drops_official(self):
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["list", "--csv-file", str(FIXTURE), "--no-asn", "--json"])
        self.assertEqual(rc, 0)
        rows = json.loads(buf.getvalue())
        self.assertEqual([r["hostname"] for r in rows], ["vpn111"])
        self.assertEqual(rows[0]["klass"], "residential")
