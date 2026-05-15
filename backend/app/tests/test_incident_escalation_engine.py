"""Tests for deterministic incident escalation behavior."""

from __future__ import annotations

import sys
import types
import unittest
from importlib import util
from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parents[2]
SERVICE_PATH = BACKEND_ROOT / "app" / "services" / "incident_escalation_engine.py"


def _load_module():
    sys.modules.setdefault("app", types.ModuleType("app"))
    sys.modules.setdefault("app.db", types.ModuleType("app.db"))
    models_module = types.ModuleType("app.db.models")
    models_module.Incident = FakeIncident
    sys.modules["app.db.models"] = models_module
    sys.modules["app.db"].models = models_module
    sqlalchemy_orm = types.ModuleType("sqlalchemy.orm")
    sqlalchemy_orm.Session = object
    sys.modules.setdefault("sqlalchemy", types.ModuleType("sqlalchemy"))
    sys.modules["sqlalchemy.orm"] = sqlalchemy_orm
    spec = util.spec_from_file_location("incident_escalation_engine_test_module", SERVICE_PATH)
    if not spec or not spec.loader:
        raise RuntimeError(f"Unable to load {SERVICE_PATH}")
    module = util.module_from_spec(spec)
    sys.modules["incident_escalation_engine_test_module"] = module
    spec.loader.exec_module(module)
    return module


class FakeIncident:
    description = None
    status = None
    id = None

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class FakeColumn:
    def ilike(self, _value):
        return self

    def in_(self, _value):
        return self

    def desc(self):
        return self


FakeIncident.description = FakeColumn()
FakeIncident.status = FakeColumn()
FakeIncident.id = FakeColumn()


class FakeQuery:
    def __init__(self, session):
        self.session = session

    def filter(self, *_args, **_kwargs):
        return self

    def order_by(self, *_args, **_kwargs):
        return self

    def first(self):
        return self.session.incidents[0] if self.session.incidents else None


class FakeSession:
    def __init__(self):
        self.incidents = []

    def query(self, _model):
        return FakeQuery(self)

    def add(self, incident):
        self.incidents.append(incident)

    def flush(self):
        for index, incident in enumerate(self.incidents, start=1):
            if incident.id is None or isinstance(incident.id, FakeColumn):
                incident.id = index


engine = _load_module()


class IncidentEscalationEngineTests(unittest.TestCase):
    def test_critical_attack_chain_escalates_to_new_incident(self) -> None:
        session = FakeSession()
        context = {
            "chain_id": "1",
            "risk_score": 92,
            "classification": "critical",
            "stages": ["Credential Access", "Command and Control"],
            "title": "Critical chain",
        }
        recommendation = {"priority": "critical", "escalation_required": True, "analyst_next_steps": ["Contain host"]}

        result = engine.escalate_attack_chain(session, context, recommendation)

        self.assertTrue(result["escalated"])
        self.assertTrue(result["created"])
        self.assertEqual(result["incident_id"], 1)
        self.assertIn("[hexsoc-escalation:attack_chain:1]", session.incidents[0].description)

    def test_duplicate_escalation_updates_existing_incident(self) -> None:
        session = FakeSession()
        context = {"chain_id": "1", "risk_score": 92, "classification": "critical"}
        recommendation = {"priority": "critical", "escalation_required": True}

        first = engine.escalate_attack_chain(session, context, recommendation)
        second = engine.escalate_attack_chain(session, context, recommendation)

        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertEqual(len(session.incidents), 1)

    def test_low_risk_context_does_not_escalate(self) -> None:
        required, reason = engine.should_escalate({"risk_score": 10, "classification": "low"}, {})

        self.assertFalse(required)
        self.assertIn("not met", reason)


if __name__ == "__main__":
    unittest.main()
