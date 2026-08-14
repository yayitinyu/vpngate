from __future__ import annotations

import base64
import unittest
from pathlib import Path

from vpngate.api import parse_csv

FIXTURE = Path(__file__).parent / "fixtures" / "servers.csv"


def _ovpn(ip: str, port: int = 443, proto: str = "tcp") -> str:
    body = f"dev tun\nproto {proto}\nremote {ip} {port}\n"
    return base64.b64encode(body.encode()).decode()


class ParseCsvTests(unittest.TestCase):
    def test_fixture(self):
        servers = parse_csv(FIXTURE.read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(servers), 4)
        by_host = {s.hostname: s for s in servers}
        official = by_host["public-vpn-1"]
        self.assertEqual(official.ip, "219.100.37.10")
        self.assertEqual(official.country_short, "JP")
        self.assertEqual(official.proto, "tcp")
        self.assertEqual(official.port, 443)
        home = by_host["vpn111"]
        self.assertEqual(home.ip, "126.1.2.3")
        self.assertEqual(home.ping, 8)
        self.assertIsNone(by_host["sakura-node"].ping)

    def test_skips_star_lines_and_blank_ping(self):
        ovpn = _ovpn("203.0.113.9")
        text = (
            "*vpn_servers\n"
            "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,"
            "Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n"
            f"vpn1,203.0.113.9,10,-,1000,Japan,JP,1,1,1,1,2weeks,owner,,{ovpn}\n"
            "*\n"
        )
        servers = parse_csv(text)
        self.assertEqual(len(servers), 1)
        self.assertIsNone(servers[0].ping)
        self.assertEqual(servers[0].speed, 1000)


if __name__ == "__main__":
    unittest.main()
