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
materialize_attack_chains = attack_serializers.materialize_attack_chains
build_relationship = graph_relationships.build_relationship


class FakeAttackChain:
    stable_fingerprint = ""

    def __init__(self, **kwargs):
        self.id = None
        self.created_at = None
        self.updated_at = None
        self.title = None
        self.classification = None
        self.risk_score = None
        self.confidence = None
        self.source_type = None
        self.source_value = None
        self.stage_count = None
        self.event_count = None
        self.alert_count = None
        self.first_seen = None
        self.last_seen = None
        self.mitre_techniques = None
        self.mitre_tactics = None
        self.related_assets = None
        self.related_users = None
        self.related_iocs = None
        self.summary = None
        for key, value in kwargs.items():
            setattr(self, key, value)


class FakeAttackChainStep:
    attack_chain_id = None

    def __init__(self, **kwargs):
        self.id = None
        for key, value in kwargs.items():
            setattr(self, key, value)


class FakeCampaignCluster:
    stable_fingerprint = ""

    def __init__(self, **kwargs):
        self.id = None
        self.title = None
        self.classification = None
        self.risk_score = None
        self.chain_count = None
        self.shared_iocs = None
        self.shared_source_ips = None
        self.shared_assets = None
        self.shared_users = None
        self.shared_techniques = None
        self.first_seen = None
        self.last_seen = None
        self.summary = None
        for key, value in kwargs.items():
            setattr(self, key, value)


class FakeQuery:
    def __init__(self, session, model):
        self.session = session
        self.model = model

    def filter(self, *_args, **_kwargs):
        return self

    def first(self):
        if self.model is FakeAttackChain:
            return self.session.chains[0] if self.session.chains else None
        if self.model is FakeCampaignCluster:
            return self.session.campaigns[0] if self.session.campaigns else None
        return None

    def delete(self):
        if self.model is FakeAttackChainStep:
            self.session.steps.clear()
        return 0


class FakeNestedTransaction:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


class FakeSession:
    def __init__(self):
        self.chains = []
        self.steps = []
        self.campaigns = []

    def query(self, model):
        return FakeQuery(self, model)

    def add(self, item):
        if isinstance(item, FakeAttackChain) and item not in self.chains:
            self.chains.append(item)
        elif isinstance(item, FakeAttackChainStep):
            self.steps.append(item)
        elif isinstance(item, FakeCampaignCluster) and item not in self.campaigns:
            self.campaigns.append(item)

    def flush(self):
        for collection in [self.chains, self.steps, self.campaigns]:
            for item in collection:
                if item.id is None:
                    item.id = len([entry for entry in collection if entry.id is not None]) + 1

    def begin_nested(self):
        return FakeNestedTransaction()


class AttackChainSerializationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_models = attack_serializers.models
        self.original_campaign_builder = attack_serializers.build_campaign_clusters
        attack_serializers.models = SimpleNamespace(
            AttackChain=FakeAttackChain,
            AttackChainStep=FakeAttackChainStep,
            CampaignCluster=FakeCampaignCluster,
        )
        attack_serializers.build_campaign_clusters = lambda *_args, **_kwargs: [
            {
                "cluster_key": "campaign:203.0.113.45",
                "title": "Campaign",
                "classification": "high",
                "max_risk_score": 80,
                "chain_count": 1,
                "source_ips": ["203.0.113.45"],
            }
        ]

    def tearDown(self) -> None:
        attack_serializers.models = self.original_models
        attack_serializers.build_campaign_clusters = self.original_campaign_builder

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

    def test_attack_chain_materialization_persists_chain_steps_and_campaign(self) -> None:
        session = FakeSession()
        candidate = _candidate()

        result = materialize_attack_chains(session, [candidate])

        self.assertEqual(result["chains_generated"], 1)
        self.assertEqual(result["chains_persisted"], 1)
        self.assertEqual(result["steps_persisted"], 2)
        self.assertEqual(result["campaigns_persisted"], 1)
        self.assertEqual(result["persistence_errors"], [])
        self.assertEqual(len(session.chains), 1)
        self.assertEqual(len(session.steps), 2)
        self.assertTrue(all(step.attack_chain_id == session.chains[0].id for step in session.steps))

    def test_duplicate_rebuild_updates_existing_chain(self) -> None:
        session = FakeSession()
        candidate = _candidate()

        first = materialize_attack_chains(session, [candidate])
        second = materialize_attack_chains(session, [candidate])

        self.assertEqual(first["chains_persisted"], 1)
        self.assertEqual(second["chains_persisted"], 1)
        self.assertEqual(len(session.chains), 1)
        self.assertEqual(len(session.steps), 2)


def _candidate() -> dict:
    return {
        "chain_id": "chain:test",
        "title": "Source IP 203.0.113.45 attack chain",
        "primary_group": "source_ip:203.0.113.45",
        "related_events": {"count": 2, "ids": [1, 2]},
        "related_alerts": {"count": 1, "ids": [3]},
        "related_iocs": {"count": 1},
        "affected_assets": [{"id": 1, "hostname": "prod-web-01"}],
        "usernames": ["svc_backup"],
        "stages": ["Initial Access", "Command and Control"],
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1110"],
        "timeline": {
            "first_seen": "2026-05-15T10:00:00",
            "last_seen": "2026-05-15T10:02:00",
            "summary": "Observed Initial Access.",
        },
        "risk_score": 88,
        "confidence": 90,
        "classification": "critical",
        "timeline_steps": [
            {
                "entity_type": "event",
                "entity_id": 1,
                "timestamp": "2026-05-15T10:00:00",
                "event_type": "failed_login",
                "severity": "high",
                "attack_stage": "Initial Access",
                "summary": "Failed login spike",
            },
            {
                "entity_type": "alert",
                "entity_id": 3,
                "timestamp": "2026-05-15T10:02:00",
                "event_type": "malware_indicator",
                "severity": "critical",
                "attack_stage": "Command and Control",
                "summary": "Malware beacon",
            },
        ],
    }


if __name__ == "__main__":
    unittest.main()
