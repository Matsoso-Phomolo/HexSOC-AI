import json
import tempfile
import unittest
from pathlib import Path

import sys


AGENT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(AGENT_DIR))

import agent_state  # noqa: E402


class AgentStateTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_path = Path(self.temp_dir.name) / "agent_state.json"

    def tearDown(self):
        self.temp_dir.cleanup()

    def sample_event(self, raw_message="Failed login", username="alice"):
        return {
            "timestamp": "2026-05-09T00:00:00Z",
            "event_type": "failed_login",
            "source": "sysmon",
            "source_ip": "10.0.0.5",
            "destination_ip": "10.0.0.10",
            "username": username,
            "hostname": "WIN-ENDPOINT-01",
            "raw_message": raw_message,
        }

    def test_state_file_creation(self):
        state = agent_state.load_state(self.state_path)

        self.assertTrue(self.state_path.exists())
        self.assertEqual(state["total_events_sent"], 0)
        self.assertEqual(state["sent_event_fingerprints"], [])

    def test_fingerprint_stable_for_same_event(self):
        event = self.sample_event()

        self.assertEqual(agent_state.event_fingerprint(event), agent_state.event_fingerprint(dict(event)))

    def test_different_event_changes_fingerprint(self):
        first = agent_state.event_fingerprint(self.sample_event())
        second = agent_state.event_fingerprint(self.sample_event(username="bob"))

        self.assertNotEqual(first, second)

    def test_duplicate_filtering(self):
        state = agent_state.default_state()
        event = self.sample_event()
        fingerprint = agent_state.event_fingerprint(event)
        agent_state.add_sent_fingerprints(state, [fingerprint])

        new_events, fingerprints, duplicates = agent_state.filter_new_events([event, self.sample_event(username="bob")], state)

        self.assertEqual(duplicates, 1)
        self.assertEqual(len(new_events), 1)
        self.assertEqual(len(fingerprints), 1)
        self.assertEqual(new_events[0]["username"], "bob")

    def test_counters_update(self):
        state = agent_state.default_state()

        agent_state.increment_counters(state, events_sent=3, batches_sent=1, duplicates_skipped=2)

        self.assertEqual(state["total_events_sent"], 3)
        self.assertEqual(state["total_batches_sent"], 1)
        self.assertEqual(state["total_duplicates_skipped"], 2)

    def test_fingerprint_pruning(self):
        state = agent_state.default_state()

        agent_state.add_sent_fingerprints(state, [str(index) for index in range(10)], limit=5)

        self.assertEqual(state["sent_event_fingerprints"], ["5", "6", "7", "8", "9"])

    def test_no_api_key_stored_in_state(self):
        state = agent_state.default_state()
        event = self.sample_event()
        event["collector_api_key"] = "hexsoc_live_secret"
        fingerprint = agent_state.event_fingerprint(event)
        agent_state.add_sent_fingerprints(state, [fingerprint])
        agent_state.save_state(self.state_path, state)

        serialized = self.state_path.read_text(encoding="utf-8")

        self.assertNotIn("hexsoc_live_secret", serialized)
        self.assertNotIn("collector_api_key", serialized)
        self.assertEqual(json.loads(serialized)["sent_event_fingerprints"], [fingerprint])

    def test_windows_cursor_update_logic(self):
        state = agent_state.default_state()

        agent_state.update_windows_event_cursors(state, {"Security": 10})
        agent_state.update_windows_event_cursors(state, {"Security": 8, "System": 5})

        self.assertEqual(agent_state.get_windows_event_cursors(state), {"Security": 10, "System": 5})

    def test_reset_windows_cursors(self):
        state = agent_state.default_state()
        agent_state.update_windows_event_cursors(state, {"Security": 10})

        agent_state.reset_windows_event_cursors(state)

        self.assertEqual(agent_state.get_windows_event_cursors(state), {})


if __name__ == "__main__":
    unittest.main()
