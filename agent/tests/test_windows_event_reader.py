import sys
import unittest
from pathlib import Path
from unittest.mock import patch


AGENT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(AGENT_DIR))

import windows_event_reader  # noqa: E402


class WindowsEventReaderTests(unittest.TestCase):
    def test_security_event_mapping(self):
        event_type, severity = windows_event_reader.map_event_type("Security", 4625)

        self.assertEqual(event_type, "failed_login")
        self.assertEqual(severity, "medium")

    def test_sysmon_event_mapping(self):
        event_type, severity = windows_event_reader.map_event_type("Microsoft-Windows-Sysmon/Operational", 10)

        self.assertEqual(event_type, "process_access")
        self.assertEqual(severity, "medium")

    def test_sysmon_process_create_mapping(self):
        event_type, severity = windows_event_reader.map_event_type("Microsoft-Windows-Sysmon/Operational", 1)

        self.assertEqual(event_type, "process_create")
        self.assertEqual(severity, "info")

    def test_unknown_event_fallback(self):
        event_type, severity = windows_event_reader.map_event_type("Security", 999999)

        self.assertEqual(event_type, "windows_event")
        self.assertEqual(severity, "info")

    def test_normalization_shape(self):
        normalized = windows_event_reader.normalize_event(
            "Security",
            {
                "timestamp": "2026-05-09T00:00:00Z",
                "event_id": 4625,
                "record_id": 123,
                "provider": "Microsoft-Windows-Security-Auditing",
                "computer": "WIN-01",
                "fields": {
                    "TargetUserName": "alice",
                    "IpAddress": "10.0.0.5",
                },
                "message": "An account failed to log on",
            },
        )

        self.assertEqual(normalized["event_type"], "failed_login")
        self.assertEqual(normalized["source"], "windows_event_log")
        self.assertEqual(normalized["source_ip"], "10.0.0.5")
        self.assertEqual(normalized["username"], "alice")
        self.assertEqual(normalized["raw_payload"]["record_id"], 123)

    def test_missing_pywin32_graceful_failure(self):
        with patch.object(windows_event_reader, "is_windows", return_value=True), patch.object(
            windows_event_reader, "win32evtlog", None
        ):
            result = windows_event_reader.read_windows_events(
                ["Security"],
                cursors={},
                batch_size=10,
                max_per_cycle=10,
                start_position="latest",
            )

        self.assertFalse(result["available"])
        self.assertEqual(result["events"], [])
        self.assertIn("pywin32 is not installed", result["warnings"][0])

    def test_non_windows_graceful_failure(self):
        with patch.object(windows_event_reader, "is_windows", return_value=False):
            result = windows_event_reader.read_windows_events(
                ["Security"],
                cursors={},
                batch_size=10,
                max_per_cycle=10,
                start_position="latest",
            )

        self.assertFalse(result["available"])
        self.assertEqual(result["events"], [])
        self.assertIn("only supported on Windows", result["warnings"][0])

    def test_evt_query_uses_pywin32_argument_order(self):
        class FakeEvt:
            EvtQueryChannelPath = 1
            EvtQueryForwardDirection = 2
            EvtQueryReverseDirection = 4

            def __init__(self):
                self.calls = []

            def EvtQuery(self, path, flags, query):
                self.calls.append((path, flags, query))
                return "handle"

        fake = FakeEvt()

        with patch.object(windows_event_reader, "win32evtlog", fake):
            handle = windows_event_reader.evt_query("Security", "*[System[EventRecordID > 0]]", direction="forward")

        self.assertEqual(handle, "handle")
        self.assertEqual(fake.calls, [("Security", 3, "*[System[EventRecordID > 0]]")])

    def test_validate_channel_graceful_without_pywin32(self):
        with patch.object(windows_event_reader, "is_windows", return_value=True), patch.object(
            windows_event_reader, "win32evtlog", None
        ):
            result = windows_event_reader.validate_channel("Security")

        self.assertFalse(result["success"])
        self.assertEqual(result["channel"], "Security")
        self.assertIn("pywin32 is not installed", result["error"])

    def test_validate_sysmon_missing_pywin32(self):
        with patch.object(windows_event_reader, "is_windows", return_value=True), patch.object(
            windows_event_reader, "win32evtlog", None
        ), patch.object(windows_event_reader, "is_sysmon_installed", return_value=False):
            result = windows_event_reader.validate_sysmon()

        self.assertFalse(result["sysmon_installed"])
        self.assertFalse(result["channel_available"])
        self.assertEqual(result["status"], "WARNING")


if __name__ == "__main__":
    unittest.main()
