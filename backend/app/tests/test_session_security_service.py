"""Session security service tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import sys
import types
import unittest
from importlib import util
from pathlib import Path
from types import SimpleNamespace


BACKEND_ROOT = Path(__file__).resolve().parents[2]
SERVICE_PATH = BACKEND_ROOT / "app" / "services" / "session_security_service.py"


class FakeColumn:
    def __eq__(self, other):
        return ("eq", other)

    def __ne__(self, other):
        return ("ne", other)

    def __ge__(self, other):
        return ("ge", other)

    def in_(self, values):
        return ("in", values)

    def is_(self, value):
        return ("is", value)


class FakeSession:
    user_id = FakeColumn()
    token_jti = FakeColumn()
    is_active = FakeColumn()
    revoked_at = FakeColumn()
    expires_at = FakeColumn()

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class FakeAttempt:
    email_or_username = FakeColumn()
    ip_address = FakeColumn()
    created_at = FakeColumn()
    outcome = FakeColumn()

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class FakeQuery:
    def __init__(self, rows):
        self.rows = rows

    def filter(self, *args):
        return self

    def first(self):
        return self.rows[0] if self.rows else None

    def order_by(self, *args):
        return self

    def limit(self, value):
        self.rows = self.rows[:value]
        return self

    def all(self):
        return self.rows


class FakeDb:
    def __init__(self, rows=None):
        self.rows = rows or []
        self.added = []
        self.commits = 0

    def add(self, item):
        self.added.append(item)

    def commit(self):
        self.commits += 1

    def query(self, model):
        return FakeQuery(list(self.rows))


def _load_service():
    fastapi_module = types.ModuleType("fastapi")
    fastapi_module.Request = object
    sys.modules["fastapi"] = fastapi_module

    sqlalchemy_module = types.ModuleType("sqlalchemy")
    sqlalchemy_module.or_ = lambda *args: ("or", args)
    sqlalchemy_orm_module = types.ModuleType("sqlalchemy.orm")
    sqlalchemy_orm_module.Session = object
    sys.modules["sqlalchemy"] = sqlalchemy_module
    sys.modules["sqlalchemy.orm"] = sqlalchemy_orm_module

    sys.modules.setdefault("app", types.ModuleType("app"))
    sys.modules.setdefault("app.core", types.ModuleType("app.core"))
    config_module = types.ModuleType("app.core.config")
    config_module.settings = SimpleNamespace(
        access_token_expire_minutes=480,
        session_idle_timeout_minutes=120,
        max_failed_login_attempts=5,
        account_lockout_minutes=15,
    )
    sys.modules["app.core.config"] = config_module

    sys.modules.setdefault("app.db", types.ModuleType("app.db"))
    models_module = types.ModuleType("app.db.models")
    models_module.UserSession = FakeSession
    models_module.LoginAttempt = FakeAttempt
    models_module.User = object
    sys.modules["app.db.models"] = models_module
    sys.modules["app.db"].models = models_module

    spec = util.spec_from_file_location("session_security_service_test_module", SERVICE_PATH)
    if not spec or not spec.loader:
        raise RuntimeError(f"Unable to load {SERVICE_PATH}")
    module = util.module_from_spec(spec)
    sys.modules["session_security_service_test_module"] = module
    spec.loader.exec_module(module)
    return module


service = _load_service()


class SessionSecurityServiceTests(unittest.TestCase):
    def test_session_creation(self):
        db = FakeDb()
        user = SimpleNamespace(id=42)
        request = SimpleNamespace(headers={"user-agent": "unit-test"}, client=SimpleNamespace(host="127.0.0.1"))

        session = service.create_user_session(db, user, request=request, token_jti="jti-1")

        self.assertEqual(session.token_jti, "jti-1")
        self.assertEqual(session.user_id, 42)
        self.assertEqual(session.ip_address, "127.0.0.1")
        self.assertEqual(db.added[0], session)

    def test_revoked_session_rejected(self):
        session = FakeSession(token_jti="jti-1", revoked_at=datetime.now(timezone.utc), is_active=False)
        db = FakeDb(rows=[session])

        with self.assertRaises(service.SessionRejected):
            service.validate_session(db, "jti-1")

    def test_expired_session_rejected_and_marked_inactive(self):
        session = FakeSession(
            token_jti="jti-2",
            revoked_at=None,
            is_active=True,
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
            created_at=datetime.now(timezone.utc) - timedelta(minutes=10),
            last_seen_at=datetime.now(timezone.utc) - timedelta(minutes=10),
        )
        db = FakeDb(rows=[session])

        with self.assertRaises(service.SessionRejected):
            service.validate_session(db, "jti-2")

        self.assertFalse(session.is_active)
        self.assertEqual(session.revoked_reason, "expired")
        self.assertEqual(db.commits, 1)

    def test_logout_all_revokes_active_sessions(self):
        sessions = [
            FakeSession(token_jti="a", user_id=1, revoked_at=None, is_active=True),
            FakeSession(token_jti="b", user_id=1, revoked_at=None, is_active=True),
        ]
        db = FakeDb(rows=sessions)

        count = service.revoke_user_sessions(db, 1, reason="logout_all")

        self.assertEqual(count, 2)
        self.assertTrue(all(not session.is_active for session in sessions))
        self.assertTrue(all(session.revoked_reason == "logout_all" for session in sessions))

    def test_login_attempt_record_has_no_secret_fields(self):
        db = FakeDb()
        request = SimpleNamespace(headers={"user-agent": "unit-test"}, client=SimpleNamespace(host="10.0.0.5"))

        attempt = service.record_login_attempt(
            db,
            username="Analyst",
            request=request,
            outcome=service.FAILURE,
            reason="invalid_credentials",
        )

        self.assertEqual(attempt.email_or_username, "analyst")
        self.assertFalse(hasattr(attempt, "password"))
        self.assertEqual(db.added[0], attempt)


if __name__ == "__main__":
    unittest.main()
