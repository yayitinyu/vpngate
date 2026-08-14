from __future__ import annotations

import unittest

from vpngate.classify import classify_server
from vpngate.models import AsInfo, Server


def _srv(**kwargs) -> Server:
    base = dict(
        hostname="vpn1",
        ip="203.0.113.1",
        score=1,
        ping=10,
        speed=1,
        country_long="Japan",
        country_short="JP",
        sessions=1,
        uptime_ms=1,
        total_users=1,
        total_traffic=1,
        log_type="",
        operator="",
        message="",
        ovpn_b64="Zg==",
    )
    base.update(kwargs)
    return Server(**base)


class ClassifyTests(unittest.TestCase):
    def test_official_hostname(self):
        s = classify_server(_srv(hostname="public-vpn-64", ip="8.8.8.8"))
        self.assertEqual(s.klass, "official")

    def test_official_prefix(self):
        s = classify_server(_srv(hostname="weird", ip="219.100.37.23"))
        self.assertEqual(s.klass, "official")

    def test_official_asn(self):
        s = classify_server(
            _srv(),
            AsInfo(36599, "219.100.37.0/24", "SOFTETHER-AMERICA - SoftEther ..."),
        )
        self.assertEqual(s.klass, "official")

    def test_official_operator(self):
        s = classify_server(_srv(operator="Daiyuu Nobori_ Japan. Academic Use Only."))
        self.assertEqual(s.klass, "official")

    def test_softbank_residential(self):
        s = classify_server(
            _srv(ip="126.129.181.24"),
            AsInfo(17676, "126.129.0.0/16", "GIGAINFRA - SoftBank Corp., JP"),
        )
        self.assertEqual(s.klass, "residential")

    def test_kddi_residential(self):
        s = classify_server(
            _srv(),
            AsInfo(2516, "106.168.0.0/16", "KDDI - KDDI CORPORATION, JP"),
        )
        self.assertEqual(s.klass, "residential")

    def test_ocn_residential(self):
        s = classify_server(
            _srv(),
            AsInfo(4713, "153.192.0.0/11", "OCN - NTT DOCOMO BUSINESS,Inc., JP"),
        )
        self.assertEqual(s.klass, "residential")

    def test_iij_isp(self):
        s = classify_server(
            _srv(),
            AsInfo(2497, "220.100.0.0/17", "IIJ - Internet Initiative Japan Inc., JP"),
        )
        self.assertEqual(s.klass, "isp")

    def test_sakura_datacenter(self):
        s = classify_server(
            _srv(),
            AsInfo(9370, "163.43.0.0/16", "SAKURA-A SAKURA Internet Inc., JP"),
        )
        self.assertEqual(s.klass, "datacenter")

    def test_heuristic_volunteer_without_asn(self):
        s = classify_server(_srv(hostname="vpn711674780", operator="DESKTOP-ABC's owner"))
        self.assertEqual(s.klass, "residential")
        self.assertIn("heuristic", s.klass_reason)

    def test_unknown_without_hints(self):
        s = classify_server(_srv(hostname="mystery", operator="someone"))
        self.assertEqual(s.klass, "unknown")


if __name__ == "__main__":
    unittest.main()
