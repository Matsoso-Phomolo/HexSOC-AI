import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


AGENT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(AGENT_DIR))

import hexsoc_agent  # noqa: E402
import offline_queue  # noqa: E402


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


class AgentNetworkResilienceTests(unittest.TestCase):
    def test_post_json_timeout_becomes_controlled_error(self):
        with patch("hexsoc_agent.request.urlopen", side_effect=TimeoutError("read timed out")):
            with patch("hexsoc_agent.time.sleep", return_value=None):
                with self.assertRaises(hexsoc_agent.AgentNetworkError):
                    hexsoc_agent.post_json(
                        "https://hexsoc-ai.onrender.com/api/test",
                        "hexsoc_live_test",
                        {},
                        timeout_seconds=1,
                        max_retries=1,
                        backoff_seconds=1,
                    )

    def test_retry_count_is_bounded(self):
        with patch("hexsoc_agent.request.urlopen", side_effect=TimeoutError("read timed out")) as urlopen:
            with patch("hexsoc_agent.time.sleep", return_value=None):
                with self.assertRaises(hexsoc_agent.AgentNetworkError):
                    hexsoc_agent.post_json(
                        "https://hexsoc-ai.onrender.com/api/test",
                        "hexsoc_live_test",
                        {},
                        timeout_seconds=1,
                        max_retries=2,
                        backoff_seconds=1,
                    )
        self.assertEqual(urlopen.call_count, 3)

    def test_successful_retry_returns_response(self):
        with patch("hexsoc_agent.request.urlopen", side_effect=[TimeoutError("read timed out"), FakeResponse({"ok": True})]):
            with patch("hexsoc_agent.time.sleep", return_value=None):
                result = hexsoc_agent.post_json(
                    "https://hexsoc-ai.onrender.com/api/test",
                    "hexsoc_live_test",
                    {},
                    timeout_seconds=1,
                    max_retries=2,
                    backoff_seconds=1,
                )
        self.assertEqual(result, {"ok": True})

    def test_service_loop_handles_heartbeat_timeout_without_exiting_as_error(self):
        with patch("hexsoc_agent.send_heartbeat", side_effect=hexsoc_agent.AgentNetworkError("read timed out")):
            with patch("hexsoc_agent.time.sleep", side_effect=KeyboardInterrupt):
                hexsoc_agent.run_service_loop(
                    backend_url="https://hexsoc-ai.onrender.com",
                    api_key="hexsoc_live_test",
                    config={},
                    events_payload={},
                    batch_size=10,
                    auto_detect=True,
                    interval=5,
                    retry_delay=1,
                    queue_enabled=False,
                    queue_path="data/offline_queue.jsonl",
                    dead_letter_path="data/dead_letter_queue.jsonl",
                    max_retry_attempts=10,
                    state_path="data/agent_state.json",
                    deduplicate_events=True,
                    fingerprint_history_limit=5000,
                    debug=False,
                    agent_mode="windows_sysmon_sample",
                    windows_event_channels=[],
                    windows_event_batch_size=50,
                    windows_event_max_per_cycle=200,
                    windows_event_start_position="latest",
                    heartbeat_enabled=True,
                    telemetry_enabled=False,
                )

    def test_ingestion_timeout_queues_batch_when_queue_enabled(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            queue_path = Path(temp_dir) / "offline_queue.jsonl"
            with patch("hexsoc_agent.send_windows_events", side_effect=hexsoc_agent.AgentNetworkError("read timed out")):
                sent = hexsoc_agent.send_sample_batches(
                    "https://hexsoc-ai.onrender.com",
                    "hexsoc_live_test",
                    {"events": [{"event_type": "failed_login", "raw_message": "x"}]},
                    10,
                    True,
                    queue_enabled=True,
                    queue_path=str(queue_path),
                    state_path=str(Path(temp_dir) / "state.json"),
                    deduplicate_events=False,
                )
            self.assertEqual(sent, 0)
            self.assertEqual(offline_queue.queue_size(queue_path), 1)


if __name__ == "__main__":
    unittest.main()
