import json
import tempfile
import unittest
from pathlib import Path

import sys


AGENT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(AGENT_DIR))

import offline_queue  # noqa: E402


class OfflineQueueTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.queue_path = Path(self.temp_dir.name) / "offline_queue.jsonl"
        self.dead_letter_path = Path(self.temp_dir.name) / "dead_letter_queue.jsonl"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_enqueue_writes_item_without_api_key(self):
        offline_queue.enqueue(
            "/api/test",
            {"events": [{"message": "hello"}], "collector_api_key": "hexsoc_live_secret"},
            reason="network down",
            queue_path=self.queue_path,
        )

        records = offline_queue.load_queue(self.queue_path)

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["endpoint"], "/api/test")
        self.assertEqual(records[0]["attempts"], 0)
        serialized = self.queue_path.read_text(encoding="utf-8")
        self.assertNotIn("hexsoc_live_secret", serialized)
        self.assertNotIn("collector_api_key", serialized)

    def test_queue_size_counts_records(self):
        offline_queue.enqueue("/api/one", {"a": 1}, queue_path=self.queue_path)
        offline_queue.enqueue("/api/two", {"b": 2}, queue_path=self.queue_path)

        self.assertEqual(offline_queue.queue_size(self.queue_path), 2)

    def test_successful_flush_removes_item(self):
        offline_queue.enqueue("/api/test", {"ok": True}, queue_path=self.queue_path)

        def success(url, api_key, payload):
            self.assertEqual(url, "http://backend/api/test")
            self.assertEqual(api_key, "hexsoc_live_secret")
            return {"ingested": 1}

        result = offline_queue.flush_queue(
            "http://backend",
            "hexsoc_live_secret",
            queue_path=self.queue_path,
            dead_letter_path=self.dead_letter_path,
            post_func=success,
        )

        self.assertEqual(result["flushed"], 1)
        self.assertEqual(offline_queue.queue_size(self.queue_path), 0)

    def test_failed_flush_increments_attempts(self):
        offline_queue.enqueue("/api/test", {"ok": False}, queue_path=self.queue_path)

        def fail(url, api_key, payload):
            raise RuntimeError("backend down")

        result = offline_queue.flush_queue(
            "http://backend",
            "hexsoc_live_secret",
            queue_path=self.queue_path,
            dead_letter_path=self.dead_letter_path,
            max_retry_attempts=10,
            post_func=fail,
        )

        records = offline_queue.load_queue(self.queue_path)

        self.assertEqual(result["failed"], 1)
        self.assertEqual(records[0]["attempts"], 1)
        self.assertEqual(records[0]["last_error"], "backend down")

    def test_max_attempts_moves_item_to_dead_letter(self):
        record = offline_queue.enqueue("/api/test", {"ok": False}, queue_path=self.queue_path)
        record["attempts"] = 9
        offline_queue.write_queue([record], self.queue_path)

        def fail(url, api_key, payload):
            raise RuntimeError("still down")

        result = offline_queue.flush_queue(
            "http://backend",
            "hexsoc_live_secret",
            queue_path=self.queue_path,
            dead_letter_path=self.dead_letter_path,
            max_retry_attempts=10,
            post_func=fail,
        )

        self.assertEqual(result["dead_lettered"], 1)
        self.assertEqual(offline_queue.queue_size(self.queue_path), 0)
        self.assertEqual(offline_queue.dead_letter_size(self.dead_letter_path), 1)
        dead_letter = json.loads(self.dead_letter_path.read_text(encoding="utf-8").strip())
        self.assertEqual(dead_letter["attempts"], 10)


if __name__ == "__main__":
    unittest.main()
