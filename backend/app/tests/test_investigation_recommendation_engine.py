"""Contract tests for deterministic investigation recommendations."""

from __future__ import annotations

import sys
import unittest
from importlib import util
from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parents[2]


def _load_recommendation_module():
    path = BACKEND_ROOT / "app" / "services" / "investigation_recommendation_engine.py"
    spec = util.spec_from_file_location("investigation_recommendation_engine_test_module", path)
    if not spec or not spec.loader:
        raise RuntimeError(f"Unable to load {path}")
    module = util.module_from_spec(spec)
    sys.modules["investigation_recommendation_engine_test_module"] = module
    spec.loader.exec_module(module)
    return module


recommendation_module = _load_recommendation_module()
recommend_for_attack_chain = recommendation_module.recommend_for_attack_chain
recommend_for_context = recommendation_module.recommend_for_context


class InvestigationRecommendationEngineTests(unittest.TestCase):
    def test_critical_attack_chain_recommends_escalation_and_evidence(self) -> None:
        result = recommend_for_attack_chain(
            {
                "chain_id": "1",
                "risk_score": 97,
                "classification": "critical",
                "stages": ["Initial Access", "Credential Access", "Command and Control"],
                "mitre_tactics": ["Credential Access", "Command and Control"],
                "mitre_techniques": ["T1110", "T1105"],
                "affected_assets": [{"hostname": "prod-web-01"}],
                "usernames": ["svc_backup"],
            }
        )

        self.assertEqual(result["priority"], "critical")
        self.assertTrue(result["escalation_required"])
        self.assertGreaterEqual(len(result["recommended_actions"]), 3)
        self.assertGreaterEqual(len(result["evidence_to_collect"]), 3)
        self.assertEqual(result["mitre_context"][0]["technique"], "T1110")

    def test_context_recommendation_is_bounded_and_deterministic(self) -> None:
        result = recommend_for_context(
            "alert",
            "42",
            {
                "risk_score": 45,
                "severity": "medium",
                "mitre_techniques": ["T1059.001"],
                "stages": ["Execution"],
                "affected_assets": [{"hostname": f"host-{index}"} for index in range(30)],
            },
        )

        self.assertEqual(result["entity_type"], "alert")
        self.assertEqual(result["entity_id"], "42")
        self.assertEqual(result["priority"], "medium")
        self.assertLessEqual(len(result["recommended_actions"]), 12)


if __name__ == "__main__":
    unittest.main()
