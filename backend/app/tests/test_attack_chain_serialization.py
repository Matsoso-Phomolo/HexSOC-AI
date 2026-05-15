"""Serialization contract tests for attack-chain and graph API payloads."""

from __future__ import annotations

import sys
import types
import unittest
from datetime import datetime
from importlib import util
from pathlib import Path
from types import SimpleNamespace


BACKEND_ROOT = Path(__file__).resolve().parents[2]
SERVICES_ROOT = BACKEND_ROOT / "app" / "services"


def _load_module(module_name: str, path: Path):
    spec = util.spec_from_file_location(module_name, path)
    if not spec or not spec.loader:
        raise RuntimeError(f"Unable to load {path}")
    module = util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


sys.modules.setdefault("app", types.ModuleType("app"))
sys.modules.setdefault("app.db", types.ModuleType("app.db"))
sys.modules.setdefault("app.db.models", types.ModuleType("app.db.models"))
sys.modules["app.db"].models = sys.modules["app.db.models"]
sys.modules.setdefault("app.services", types.ModuleType("app.services"))
sqlalchemy_module = types.ModuleType("sqlalchemy")
sqlalchemy_orm_module = types.ModuleType("sqlalchemy.orm")
sqlalchemy_orm_module.Session = object
sys.modules.setdefault("sqlalchemy", sqlalchemy_module)
sys.modules.setdefault("sqlalchemy.orm", sqlalchemy_orm_module)
campaign_module = types.ModuleType("app.services.campaign_cluster_engine")
campaign_module.build_campaign_clusters = lambda *_args, **_kwargs: []
sys.modules.setdefault("app.services.campaign_cluster_engine", campaign_module)

attack_serializers = _load_module(
    "app.services.attack_chain_persistence_service",
    SERVICES_ROOT / "attack_chain_persistence_service.py",
)
graph_relationships = _load_module(
    "app.services.graph_relationship_builder",
    SERVICES_ROOT / "graph_relationship_builder.py",
)

serialize_attack_chain = attack_serializers.serialize_attack_chain
serialize_attack_chain_step = attack_serializers.serialize_attack_chain_step
serialize_campaign = attack_serializers.serialize_campaign
build_relationship = graph_relationships.build_relationship


class AttackChainSerializationTests(unittest.TestCase):
    def test_empty_chain_lists_are_serialized_as_lists(self) -> None:
        chain = SimpleNamespace(
            id=1,
            stable_fingerprint="fingerprint",
            title="Suspicious chain",
            classification=None,
            risk_score=None,
            confidence=None,
            status=None,
            source_type="source_ip",
            source_value="203.0.113.45",
            chain_key="source_ip:203.0.113.45",
            stage_count=None,
            related_users=None,
            related_assets=None,
            event_count=None,
            alert_count=None,
            related_iocs=None,
            mitre_tactics=None,
            mitre_techniques=None,
            first_seen=None,
            last_seen=None,
            summary=None,
            version=None,
        )

        payload = serialize_attack_chain(chain)

        self.assertEqual(payload["classification"], "suspicious")
        self.assertEqual(payload["risk_score"], 0)
        self.assertEqual(payload["status"], "open")
        self.assertEqual(payload["usernames"], [])
        self.assertEqual(payload["affected_assets"], [])
        self.assertEqual(payload["mitre_tactics"], [])
        self.assertEqual(payload["mitre_techniques"], [])
        self.assertEqual(payload["related_iocs"], {"count": 0})

    def test_attack_chain_step_datetime_serializes_to_iso(self) -> None:
        step = SimpleNamespace(
            id=7,
            event_id=42,
            alert_id=None,
            timestamp=datetime(2026, 5, 15, 12, 30, 0),
            event_type="failed_login",
            description="Failed login observed",
            severity=None,
            stage=None,
            mitre_tactic=None,
            mitre_technique=None,
            hostname=None,
            username=None,
            source_ip=None,
            destination_ip=None,
        )

        payload = serialize_attack_chain_step(step)

        self.assertEqual(payload["timestamp"], "2026-05-15T12:30:00")
        self.assertEqual(payload["severity"], "info")
        self.assertEqual(payload["attack_stage"], "unknown")

    def test_campaign_cluster_nulls_are_bounded(self) -> None:
        campaign = SimpleNamespace(
            id=3,
            stable_fingerprint="campaign",
            campaign_key="campaign:source",
            title="Campaign",
            classification=None,
            risk_score=None,
            chain_count=None,
            shared_source_ips=None,
            shared_iocs=None,
            shared_assets=None,
            shared_users=None,
            shared_techniques=None,
            first_seen=None,
            last_seen=None,
            summary=None,
        )

        payload = serialize_campaign(campaign)

        self.assertEqual(payload["classification"], "suspicious")
        self.assertEqual(payload["risk_score"], 0)
        self.assertEqual(payload["chain_count"], 0)
        self.assertEqual(payload["source_ips"], [])

    def test_graph_edge_datetime_is_json_ready(self) -> None:
        edge = build_relationship(
            "source_ip:203.0.113.45",
            "asset:1",
            "affects_asset",
            first_seen=datetime(2026, 5, 15, 10, 0, 0),
            last_seen=datetime(2026, 5, 15, 11, 0, 0),
        )

        self.assertEqual(edge["first_seen"], "2026-05-15T10:00:00")
        self.assertEqual(edge["last_seen"], "2026-05-15T11:00:00")


if __name__ == "__main__":
    unittest.main()
