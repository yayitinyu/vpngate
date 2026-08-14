from __future__ import annotations

import unittest

from vpngate.ovpn import detect_openvpn_version, extract_endpoint, sanitize


SAMPLE = """\
dev tun
proto tcp
remote 203.0.113.50 443
up /etc/openvpn/update-resolv-conf
down /etc/openvpn/update-resolv-conf
http-proxy 10.0.0.1 8080
verb 3
#auth-user-pass
<ca>
dummy
</ca>
"""


class OvpnTests(unittest.TestCase):
    def test_extract(self):
        proto, port, ip = extract_endpoint(SAMPLE)
        self.assertEqual((proto, port, ip), ("tcp", 443, "203.0.113.50"))

    def test_sanitize_drops_host_hooks(self):
        out = sanitize(SAMPLE, auth_file="/run/vpngate/auth.txt", openvpn_version=(2, 6))
        self.assertNotIn("update-resolv-conf", out)
        self.assertNotIn("http-proxy", out)
        self.assertIn("redirect-gateway def1", out)
        self.assertIn("auth-user-pass", out)
        self.assertIn("providers legacy default", out)
        self.assertIn("<ca>", out)

    def test_old_openvpn_has_no_providers(self):
        out = sanitize(SAMPLE, openvpn_version=(2, 4))
        self.assertNotIn("providers", out)
        self.assertIn("cipher AES-128-CBC", out)

    def test_version_parse(self):
        self.assertEqual(
            detect_openvpn_version("OpenVPN 2.6.12 x86_64-pc-linux-gnu [SSL (OpenSSL)]"),
            (2, 6),
        )

    def test_keeps_both_pem_certificates(self):
        raw = (
            "dev tun\r\n"
            "<ca>\r\n"
            "-----BEGIN CERTIFICATE-----\r\n"
            "CABODY\r\n"
            "-----END CERTIFICATE-----\r\n"
            "</ca>\r\n"
            "<cert>\r\n"
            "-----BEGIN CERTIFICATE-----\r\n"
            "CLIENTBODY\r\n"
            "-----END CERTIFICATE-----\r\n"
            "</cert>\r\n"
        )
        out = sanitize(raw, openvpn_version=(2, 6))
        self.assertNotIn("\r", out)
        self.assertEqual(out.count("-----BEGIN CERTIFICATE-----"), 2)
        self.assertIn("CABODY", out)
        self.assertIn("CLIENTBODY", out)
        self.assertIn("<cert>", out)


if __name__ == "__main__":
    unittest.main()
