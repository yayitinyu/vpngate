from __future__ import annotations

import unittest

from vpngate.models import Server
from vpngate.rank import select


def _srv(hostname, klass, speed=10_000_000, ping=10, sessions=5, score=100, ip=None) -> Server:
    return Server(
        hostname=hostname,
        ip=ip or f"203.0.113.{len(hostname)}",
        score=score,
        ping=ping,
        speed=speed,
        country_long="Japan",
        country_short="JP",
        sessions=sessions,
        uptime_ms=1,
        total_users=1,
        total_traffic=1,
        log_type="",
        operator="",
        message="",
        ovpn_b64="ZGV2IHR1bg==",
        klass=klass,
    )


class RankTests(unittest.TestCase):
    def test_class_order_and_speed(self):
        servers = [
            _srv("dc", "datacenter", speed=1_000_000_000),
            _srv("off", "official", speed=500_000_000),
            _srv("slow-home", "residential", speed=8_000_000, ping=3),
            _srv("fast-home", "residential", speed=200_000_000, ping=20),
            _srv("isp", "isp", speed=300_000_000),
        ]
        picked = select(servers, classes=["residential", "isp"])
        self.assertEqual([s.hostname for s in picked], ["fast-home", "slow-home", "isp"])

    def test_skip_and_filters(self):
        servers = [
            _srv("a", "residential", speed=50_000_000, sessions=3, ip="1.1.1.1"),
            _srv("b", "residential", speed=9_000_000, sessions=1, ip="2.2.2.2"),
            _srv("c", "residential", speed=80_000_000, sessions=40, ip="3.3.3.3"),
        ]
        picked = select(
            servers,
            classes=["residential"],
            min_speed=10_000_000,
            max_sessions=10,
            skip_ips={"1.1.1.1"},
        )
        self.assertEqual([s.hostname for s in picked], [])

        picked = select(
            servers,
            classes=["residential"],
            min_speed=10_000_000,
            max_sessions=50,
            skip_ips={"1.1.1.1"},
        )
        self.assertEqual([s.hostname for s in picked], ["c"])


if __name__ == "__main__":
    unittest.main()
