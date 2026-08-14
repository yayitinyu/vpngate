from __future__ import annotations

import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from vpngate.watch import (
    HealthTracker,
    WatchSettings,
    health_ok,
    load_watch_settings,
    should_scheduled_rotate,
)


def _dt(text: str) -> datetime:
    return datetime.fromisoformat(text)


class ScheduledRotateTests(unittest.TestCase):
    def test_crosses_four_am(self):
        started = _dt("2026-08-14T22:10:00")
        now = _dt("2026-08-15T04:00:01")
        self.assertTrue(should_scheduled_rotate(now, started, None, 4))

    def test_before_four_am_stays(self):
        started = _dt("2026-08-14T22:10:00")
        now = _dt("2026-08-15T03:59:59")
        self.assertFalse(should_scheduled_rotate(now, started, None, 4))

    def test_started_after_four_waits_until_tomorrow(self):
        started = _dt("2026-08-15T10:00:00")
        now = _dt("2026-08-15T10:05:00")
        self.assertFalse(should_scheduled_rotate(now, started, None, 4))

    def test_next_morning_after_afternoon_start(self):
        started = _dt("2026-08-15T10:00:00")
        now = _dt("2026-08-16T04:00:00")
        self.assertTrue(should_scheduled_rotate(now, started, None, 4))

    def test_does_not_fire_twice_same_day(self):
        started = _dt("2026-08-14T22:10:00")
        now = _dt("2026-08-15T04:10:00")
        self.assertFalse(should_scheduled_rotate(now, started, now.date(), 4))

    def test_same_morning_reconnect_after_four_does_not_rotate_again(self):
        started = _dt("2026-08-15T04:05:00")
        now = _dt("2026-08-15T04:20:00")
        self.assertFalse(should_scheduled_rotate(now, started, None, 4))


class HealthTests(unittest.TestCase):
    def test_probe_rules(self):
        self.assertFalse(health_ok(None, "1.1.1.1"))
        self.assertFalse(health_ok("1.1.1.1", "1.1.1.1"))
        self.assertTrue(health_ok("8.8.8.8", "1.1.1.1"))
        self.assertTrue(health_ok("8.8.8.8", None))

    def test_three_strikes(self):
        tracker = HealthTracker(3)
        self.assertFalse(tracker.record(False))
        self.assertFalse(tracker.record(False))
        self.assertTrue(tracker.record(False))

    def test_success_resets(self):
        tracker = HealthTracker(3)
        self.assertFalse(tracker.record(False))
        self.assertFalse(tracker.record(False))
        self.assertFalse(tracker.record(True))
        self.assertFalse(tracker.record(False))
        self.assertFalse(tracker.record(False))
        self.assertTrue(tracker.record(False))


class WatchSettingsTests(unittest.TestCase):
    def test_defaults_when_missing(self):
        self.assertEqual(load_watch_settings(Path("/no/such/node.conf")), WatchSettings())

    def test_reads_optional_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "node.conf"
            path.write_text(
                "SOCKS_USER=vg_x\nROTATE_HOUR=5\nHEALTH_INTERVAL=90\nHEALTH_FAILS=2\n",
                encoding="utf-8",
            )
            settings = load_watch_settings(path)
            self.assertEqual(settings.rotate_hour, 5)
            self.assertEqual(settings.health_interval, 90)
            self.assertEqual(settings.health_fails, 2)

    def test_rejects_out_of_range(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "node.conf"
            path.write_text("ROTATE_HOUR=99\nHEALTH_INTERVAL=1\n", encoding="utf-8")
            settings = load_watch_settings(path)
            self.assertEqual(settings.rotate_hour, 4)
            self.assertEqual(settings.health_interval, 120)
