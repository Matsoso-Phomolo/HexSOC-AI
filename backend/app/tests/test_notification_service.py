"""Notification integration tests without external provider dependencies."""

from __future__ import annotations

from datetime import datetime, timezone
import sys
import types
import unittest
from importlib import util
from pathlib import Path
from types import SimpleNamespace


BACKEND_ROOT = Path(__file__).resolve().parents[2]
SERVICE_PATH = BACKEND_ROOT / "app" / "services" / "notification_service.py"
PERMISSIONS_PATH = BACKEND_ROOT / "app" / "security" / "permissions.py"


class FakeColumn:
    def __eq__(self, other):
        return ("eq", other)

    def __ge__(self, other):
        return ("ge", other)

    def desc(self):
        return ("desc", self)


class FakeNotificationLog:
    id = FakeColumn()
    event_type = FakeColumn()
    channel = FakeColumn()
    outcome = FakeColumn()
    created_at = FakeColumn()

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.id = kwargs.get("id")
        self.created_at = kwargs.get("created_at", datetime.now(timezone.utc))


class FakeQuery:
    def __init__(self, rows=None):
        self.rows = rows or []

    def filter(self, *args):
        return self

    def first(self):
        return self.rows[0] if self.rows else None

    def scalar(self):
        return len(self.rows)

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

    def add(self, item):
        self.added.append(item)

    def query(self, model):
        return FakeQuery(list(self.rows))


def fake_sanitize_metadata(value, depth=0):
    if isinstance(value, dict):
        sanitized = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if any(secret in lowered for secret in ("password", "token", "secret", "api_key", "authorization", "webhook")):
                sanitized[key] = "[redacted]"
            else:
                sanitized[key] = fake_sanitize_metadata(item, depth + 1)
        return sanitized
    if isinstance(value, list):
        return [fake_sanitize_metadata(item, depth + 1) for item in value[:50]]
    return value


def _install_service_stubs():
    sqlalchemy_module = types.ModuleType("sqlalchemy")
    sqlalchemy_module.func = SimpleNamespace(count=lambda column: ("count", column))
    sqlalchemy_orm_module = types.ModuleType("sqlalchemy.orm")
    sqlalchemy_orm_module.Session = object
    sys.modules["sqlalchemy"] = sqlalchemy_module
    sys.modules["sqlalchemy.orm"] = sqlalchemy_orm_module

    sys.modules.setdefault("app", types.ModuleType("app"))
    sys.modules.setdefault("app.core", types.ModuleType("app.core"))
    config_module = types.ModuleType("app.core.config")
    config_module.settings = SimpleNamespace(
        notifications_enabled=False,
        notification_webhook_url=None,
        notification_email_enabled=False,
        notification_email_from=None,
        notification_email_to=None,
        notification_rate_limit_seconds=300,
    )
    sys.modules["app.core.config"] = config_module

    sys.modules.setdefault("app.db", types.ModuleType("app.db"))
    models_module = types.ModuleType("app.db.models")
    models_module.NotificationLog = FakeNotificationLog
    sys.modules["app.db.models"] = models_module
    sys.modules["app.db"].models = models_module

    sys.modules.setdefault("app.services", types.ModuleType("app.services"))
    audit_module = types.ModuleType("app.services.audit_log_service")
    audit_module.sanitize_metadata = fake_sanitize_metadata
    sys.modules["app.services.audit_log_service"] = audit_module


def _load_service():
    _install_service_stubs()
    spec = util.spec_from_file_location("notification_service_test_module", SERVICE_PATH)
    if not spec or not spec.loader:
        raise RuntimeError(f"Unable to load {SERVICE_PATH}")
    module = util.module_from_spec(spec)
    sys.modules["notification_service_test_module"] = module
    spec.loader.exec_module(module)
    return module


def _load_permissions_module():
    fastapi_module = types.ModuleType("fastapi")
    fastapi_module.Depends = lambda dependency=None: dependency
    fastapi_module.HTTPException = Exception
    fastapi_module.Request = object
    fastapi_module.status = SimpleNamespace(HTTP_403_FORBIDDEN=403)
    sys.modules["fastapi"] = fastapi_module

    sqlalchemy_orm_module = types.ModuleType("sqlalchemy.orm")
    sqlalchemy_orm_module.Session = object
    sys.modules["sqlalchemy.orm"] = sqlalchemy_orm_module

    sys.modules.setdefault("app.api", types.ModuleType("app.api"))
    deps_module = types.ModuleType("app.api.deps")
    deps_module.get_db = lambda: None
    sys.modules["app.api.deps"] = deps_module
    sys.modules.setdefault("app.db", types.ModuleType("app.db"))
    models_module = types.ModuleType("app.db.models")
    models_module.User = object
    sys.modules["app.db.models"] = models_module
    sys.modules["app.db"].models = models_module
    sys.modules.setdefault("app.services", types.ModuleType("app.services"))
    audit_module = types.ModuleType("app.services.audit_log_service")
    audit_module.log_denied = lambda *args, **kwargs: None
    sys.modules["app.services.audit_log_service"] = audit_module
    auth_module = types.ModuleType("app.services.auth_service")
    auth_module.SUPER_ADMIN_EMAIL = "phomolomatsoso@gmail.com"
    auth_module.get_current_user = lambda: None
    sys.modules["app.services.auth_service"] = auth_module

    spec = util.spec_from_file_location("notification_permissions_test_module", PERMISSIONS_PATH)
    if not spec or not spec.loader:
        raise RuntimeError(f"Unable to load {PERMISSIONS_PATH}")
    module = util.module_from_spec(spec)
    sys.modules["notification_permissions_test_module"] = module
    spec.loader.exec_module(module)
    return module


service = _load_service()


class NotificationServiceTests(unittest.TestCase):
    def setUp(self):
        service.settings.notifications_enabled = False
        service.settings.notification_webhook_url = None
        service.settings.notification_email_enabled = False
        service.settings.notification_email_from = None
        service.settings.notification_email_to = None
        service.settings.notification_rate_limit_seconds = 300

    def test_notification_disabled_is_safe_noop(self):
        db = FakeDb()

        logs = service.send_notification(
            db,
            event_type="incident_escalated",
            title="Incident",
            message="Escalated",
            metadata={"api_key": "hexsoc_live_secret"},
        )

        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0].outcome, "skipped")
        self.assertEqual(logs[0].channel, "system")
        self.assertEqual(logs[0].notification_metadata["metadata"]["api_key"], "[redacted]")

    def test_webhook_payload_is_sanitized(self):
        payload = service._notification_payload(
            "collector_offline",
            "Collector offline",
            "Collector stopped reporting",
            "warning",
            {"webhook_url": "https://example.invalid/secret", "nested": {"token": "secret"}},
        )

        self.assertEqual(payload["metadata"]["webhook_url"], "[redacted]")
        self.assertEqual(payload["metadata"]["nested"]["token"], "[redacted]")

    def test_repeated_successful_event_is_rate_limited(self):
        service.settings.notifications_enabled = True
        service.settings.notification_webhook_url = "https://example.invalid/webhook"
        existing = FakeNotificationLog(event_type="collector_offline", outcome="success")
        db = FakeDb(rows=[existing])

        logs = service.send_notification(
            db,
            event_type="collector_offline",
            title="Collector offline",
            message="Collector offline",
        )

        self.assertEqual(logs[0].outcome, "skipped")
        self.assertEqual(logs[0].notification_metadata["reason"], "rate_limited")

    def test_webhook_failure_does_not_raise(self):
        service.settings.notifications_enabled = True
        service.settings.notification_webhook_url = "https://example.invalid/webhook"
        service.settings.notification_rate_limit_seconds = 0
        db = FakeDb()

        original_urlopen = service.urllib.request.urlopen
        service.urllib.request.urlopen = lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError("timeout"))
        try:
            logs = service.send_notification(
                db,
                event_type="incident_escalated",
                title="Incident",
                message="Escalated",
            )
        finally:
            service.urllib.request.urlopen = original_urlopen

        self.assertEqual(logs[0].outcome, "failure")
        self.assertEqual(logs[0].error_message, "TimeoutError")

    def test_notification_access_permission_is_admin_only(self):
        permissions = _load_permissions_module()
        viewer = SimpleNamespace(role="viewer", email="viewer@example.com")
        analyst = SimpleNamespace(role="analyst", email="analyst@example.com")
        admin = SimpleNamespace(role="admin", email="admin@example.com")
        super_admin = SimpleNamespace(role="admin", email="phomolomatsoso@gmail.com")

        self.assertFalse(permissions.has_permission(viewer, permissions.Permission.AUDIT_READ))
        self.assertFalse(permissions.has_permission(analyst, permissions.Permission.AUDIT_READ))
        self.assertTrue(permissions.has_permission(admin, permissions.Permission.AUDIT_READ))
        self.assertTrue(permissions.has_permission(super_admin, permissions.Permission.AUDIT_READ))


if __name__ == "__main__":
    unittest.main()
