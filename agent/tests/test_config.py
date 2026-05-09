import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


AGENT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(AGENT_DIR))

import hexsoc_agent  # noqa: E402


class AgentConfigTests(unittest.TestCase):
    def test_env_overrides_json_config(self):
        base_config = {
            "backend_url": "http://127.0.0.1:9000",
            "collector_api_key": "hexsoc_live_file_secret",
            "agent_name": "file-agent",
        }

        with patch.dict(
            os.environ,
            {
                "HEXSOC_BACKEND_URL": "https://hexsoc-ai.onrender.com",
                "HEXSOC_API_KEY": "hexsoc_live_env_secret",
                "HEXSOC_AGENT_NAME": "env-agent",
            },
            clear=True,
        ):
            active, overridden = hexsoc_agent.apply_env_overrides(base_config)

        self.assertEqual(active["backend_url"], "https://hexsoc-ai.onrender.com")
        self.assertEqual(active["collector_api_key"], "hexsoc_live_env_secret")
        self.assertEqual(active["agent_name"], "env-agent")
        self.assertEqual(active["host_name"], "env-agent")
        self.assertEqual(hexsoc_agent.config_source(overridden, base_config), "MIXED")

    def test_env_only_config_source(self):
        with patch.dict(
            os.environ,
            {
                "HEXSOC_BACKEND_URL": "http://127.0.0.1:9000",
                "HEXSOC_API_KEY": "hexsoc_live_env_only_secret",
            },
            clear=True,
        ):
            active, overridden = hexsoc_agent.apply_env_overrides({})

        self.assertEqual(active["backend_url"], "http://127.0.0.1:9000")
        self.assertEqual(active["collector_api_key"], "hexsoc_live_env_only_secret")
        self.assertEqual(hexsoc_agent.config_source(overridden, {}), "ENVIRONMENT_VARIABLES")

    def test_environment_resolves_from_hexsoc_env(self):
        with patch.dict(os.environ, {"HEXSOC_ENV": "staging"}, clear=True):
            environment = hexsoc_agent.resolve_environment(SimpleNamespace(env=None))

        self.assertEqual(environment, "staging")

    def test_production_validation_blocks_localhost_and_requires_https(self):
        api_key = "hexsoc_live_test_secret"

        localhost_errors = hexsoc_agent.validate_runtime_config("production", "http://127.0.0.1:9000", api_key)
        http_errors = hexsoc_agent.validate_runtime_config("production", "http://example.com", api_key)
        valid_errors = hexsoc_agent.validate_runtime_config("production", "https://hexsoc-ai.onrender.com", api_key)

        self.assertIn("production cannot use localhost backend_url.", localhost_errors)
        self.assertIn("production backend_url must use https.", localhost_errors)
        self.assertIn("production backend_url must use https.", http_errors)
        self.assertEqual(valid_errors, [])

    def test_secret_masking_never_returns_full_key(self):
        secret = "hexsoc_live_abcd1234567890SECRET"
        masked = hexsoc_agent.mask_secret(secret)

        self.assertTrue(masked.startswith("hexsoc_live_abcd"))
        self.assertTrue(masked.endswith("****************"))
        self.assertNotEqual(masked, secret)
        self.assertNotIn("567890SECRET", masked)

    def test_queue_clear_confirmation_is_case_insensitive(self):
        for value in ("YES", "yes", "Yes", "Y", "y", " yes ", " y "):
            with self.subTest(value=value):
                self.assertTrue(hexsoc_agent.is_clear_queue_confirmation(value))

        for value in ("n", "no", "random text", "", "  "):
            with self.subTest(value=value):
                self.assertFalse(hexsoc_agent.is_clear_queue_confirmation(value))


if __name__ == "__main__":
    unittest.main()
