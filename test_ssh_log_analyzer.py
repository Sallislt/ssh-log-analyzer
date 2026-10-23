"""Tests: python -m unittest -v"""

import io
import json
import unittest
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path

import ssh_log_analyzer as sla

SAMPLE = Path(__file__).parent / "samples" / "auth.log"


class ParseLineTests(unittest.TestCase):
    def test_failed_password_for_invalid_user(self):
        e = sla.parse_line(
            "Oct 23 08:12:03 srv01 sshd[2101]: Failed password for invalid user admin from 203.0.113.45 port 51022 ssh2",
            2026,
        )
        self.assertEqual((e.kind, e.user, e.ip), ("failed", "admin", "203.0.113.45"))
        self.assertEqual(e.time, datetime(2026, 10, 23, 8, 12, 3))

    def test_accepted_publickey(self):
        e = sla.parse_line(
            "Oct 23 11:45:00 srv01 sshd[2501]: Accepted publickey for deploy from 192.168.10.30 port 42210 ssh2", 2026
        )
        self.assertEqual((e.kind, e.user, e.method), ("accepted", "deploy", "publickey"))

    def test_iso_timestamp_and_ipv6(self):
        e = sla.parse_line(
            "2026-10-23T08:12:03.123456+02:00 srv01 sshd[2101]: Failed password for root from 2001:db8::7 port 22 ssh2",
            1999,
        )
        self.assertEqual((e.ip, e.time.year), ("2001:db8::7", 2026))

    def test_single_digit_day_is_padded_with_two_spaces(self):
        e = sla.parse_line("Oct  3 08:00:00 srv01 sshd[1]: Failed password for root from 203.0.113.1 port 1 ssh2", 2026)
        self.assertEqual(e.time.day, 3)

    def test_invalid_user_line_is_not_counted_twice(self):
        self.assertIsNone(sla.parse_line("Oct 23 08:12:01 srv01 sshd[2101]: Invalid user admin from 203.0.113.45 port 1", 2026))

    def test_other_services_are_ignored(self):
        self.assertIsNone(sla.parse_line("Oct 23 11:45:00 srv01 CRON[2502]: session opened for user root", 2026))


class AnalyzeTests(unittest.TestCase):
    def setUp(self):
        with open(SAMPLE, encoding="utf-8") as fh:
            self.events = sla.parse(fh, 2026)
        self.findings = sla.analyze(self.events, threshold=5, window_minutes=10, spray_users=3)
        self.rules = {(f.rule, f.ip) for f in self.findings}

    def test_brute_force_detected(self):
        self.assertIn(("brute_force", "203.0.113.45"), self.rules)

    def test_password_spraying_detected(self):
        self.assertIn(("password_spraying", "203.0.113.45"), self.rules)

    def test_success_after_failures_detected(self):
        self.assertIn(("success_after_failures", "198.51.100.7"), self.rules)

    def test_single_typo_is_not_an_alert(self):
        self.assertFalse(any(ip == "192.168.10.25" for _, ip in self.rules))

    def test_window_is_respected(self):
        events = [
            sla.Event(datetime(2026, 1, 1, 10, m), "failed", "root", "203.0.113.9") for m in (0, 20, 40, 59)
        ]
        found = sla.analyze(events, threshold=3, window_minutes=10, spray_users=99)
        self.assertEqual(found, [])

    def test_json_output_and_exit_code(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = sla.main([str(SAMPLE), "--json", "--year", "2026"])
        data = json.loads(buf.getvalue())
        self.assertEqual(code, 2)
        self.assertEqual(data["summary"]["failed"], 11)
        self.assertEqual(data["summary"]["accepted"], 3)


if __name__ == "__main__":
    unittest.main()
