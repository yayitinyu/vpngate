from __future__ import annotations

import unittest

from vpngate.cymru import _parse


SAMPLE = """\
Bulk mode; whois.cymru.com [2026-08-14 15:02:02 +0000]
AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name
17676   | 126.129.181.24   | 126.129.0.0/16      | JP | apnic    | 2005-02-08 | GIGAINFRA - SoftBank Corp., JP
36599   | 219.100.37.96    | 219.100.37.0/24     | JP | apnic    | 2002-03-07 | SOFTETHER-AMERICA - SoftEther Telecommunication Research Institute, LLC, US
NA      | 0.0.0.0          |                     |    |          |            | 
"""


class CymruParseTests(unittest.TestCase):
    def test_parse(self):
        mapped = _parse(SAMPLE)
        self.assertEqual(set(mapped), {"126.129.181.24", "219.100.37.96"})
        self.assertEqual(mapped["126.129.181.24"].asn, 17676)
        self.assertIn("SoftBank", mapped["126.129.181.24"].name)
        self.assertEqual(mapped["219.100.37.96"].asn, 36599)
