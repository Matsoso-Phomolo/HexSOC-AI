"""Audit and compliance logging tests without external service dependencies."""

from __future__ import annotations

import sys
import types
import unittest
from importlib import util
from pathlib import Path
from types import SimpleNamespace


BACKEND_ROOT = Path(__file__).resolve().parents[2]
AUDIT_SERVICE_PATH = BACKEND_ROOT / "app" / "services" / "audit_log_service.py"
PERMISSIONS_PATH = BACKEND_ROOT / "app" / "security" / "permissions.py"


class FakeHttpException(Exception):
    def __init__(self, status_code=None, detail=None, headers=None):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.headers = headers


class FakeAuditLog:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.id = kwargs.get("id")
        self.created_at = kwargs.get("created_at")


class FakeDb:
    def __init__(self) -> None:
        self.added = []
        self.commits = 0
        self.rollbacks = 0

    def add(self, item) -> None:
        self.added.append(item)

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1


def _install_common_stubs() -> None:
    fastapi_module = types.ModuleType("fastapi")
    fastapi_module.Depends = lambda dependency=None: dependency
    fastapi_module.HTTPException = FakeHttpException
    fastapi_module.Request = object
    fastapi_module.status = SimpleNamespace(HTTP_403_FORBIDDEN=403)
    sys.modules["fastapi"] = fastapi_module

    sqlalchemy_module = types.ModuleType("sqlalchemy")
    sqlalchemy_exc_module = types.ModuleType("sqlalchemy.exc")
    sqlalchemy_orm_module = types.ModuleType("sqlalchemy.orm")
    sqlalchemy_exc_module.SQLAlchemyError = Exception
    sqlalchemy_orm_module.Session = object
    sys.modules["sqlalchemy"] = sqlalchemy_module
    sys.modules["sqlalchemy.exc"] = sqlalchemy_exc_module
    sys.modules["sqlalchemy.orm"] = sqlalchemy_orm_module

    sys.modules.setdefault("app", types.ModuleType("app"))
    sys.modules.setdefault("app.db", types.ModuleType("app.db"))
    models_module = types.ModuleType("app.db.models")
    models_module.AuditLog = FakeAuditLog
    models_module.User = object
    sys.modules["app.db.models"] = models_module
    sys.modules["app.db"].models = models_module


def _load_audit_module():
    _install_common_stubs()
    spec = util.spec_from_file_location("audit_log_service_test_module", AUDIT_SERVICE_PATH)
    if not spec or not spec.loader:
        raise RuntimeError(f"Unable to load {AUDIT_SERVICE_PATH}")
    module = util.module_from_spec(spec)
    sys.modules["audit_log_service_test_module"] = module
    spec.loader.exec_module(module)
    return module


def _load_permissions_module(audit_module):
    _install_common_stubs()
    sys.modules.setdefault("app.api", types.ModuleType("app.api"))
    deps_module = types.ModuleType("app.api.deps")
    deps_module.get_db = lambda: None
    sys.modules["app.api.deps"] = deps_module
    sys.modules.setdefault("app.services", types.ModuleType("app.services"))
    sys.modules["app.services.audit_log_service"] = audit_module
    auth_module = types.ModuleType("app.services.auth_service")
    auth_module.SUPER_ADMIN_EMAIL = "phomolomatsoso@gmail.com"
    auth_module.get_current_user = lambda: None
    sys.modules["app.services.auth_service"] = auth_module

    spec = util.spec_from_file_location("permissions_audit_test_module", PERMISSIONS_PATH)
    if not spec or not spec.loader:
        raise RuntimeError(f"Unable to load {PERMISSIONS_PATH}")
    module = util.module_from_spec(spec)
    sys.modules["permissions_audit_test_module"] = module
    spec.loader.exec_module(module)
    return module


audit_service = _load_audit_module()
permissions = _load_permissions_module(audit_service)


class AuditLoggingTests(unittest.TestCase):
    def test_audit_log_write_success(self):
        db = FakeDb()
        actor = SimpleNamespace(id=7, username="admin_user", role="admin")
        request = SimpleNamespace(headers={"user-agent": "unit-test", "x-request-id": "req-1"}, client=SimpleNamespace(host="127.0.0.1"))

        audit = audit_service.write_audit_log(
            db,
            action="collector_revoked",
            category="collector",
            actor=actor,
            request=request,
            target_type="collector",
            target_id=3,
            metadata={"collector_api_key": "hexsoc_live_secret", "result": "revoked"},
        )

        self.assertIsNotNone(audit)
        self.assertEqual(len(db.added), 1)
        serialized = audit_service.serialize_audit_log(audit)
        self.assertEqual(serialized["actor_username"], "admin_user")
        self.assertEqual(serialized["metadata"]["collector_api_key"], "[redacted]")
        self.assertEqual(serialized["ip_address"], "127.0.0.1")

    def test_metadata_sanitization_redacts_secrets_and_bounds_payload(self):
        metadata = audit_service.sanitize_metadata(
            {
                "password": "super-secret",
                "nested": {"authorization": "Bearer token"},
                "values": list(range(75)),
            }
        )

        self.assertEqual(metadata["password"], "[redacted]")
        self.assertEqual(metadata["nested"]["authorization"], "[redacted]")
        self.assertEqual(len(metadata["values"]), 51)
        self.assertEqual(metadata["values"][-1], {"__truncated__": True})

    def test_permission_denied_writes_audit_event(self):
        db = FakeDb()
        request = SimpleNamespace(headers={"user-agent": "unit-test"}, client=SimpleNamespace(host="10.0.0.5"))
        user = SimpleNamespace(id=9, username="viewer_user", role="viewer", email="viewer@example.com")
        dependency = permissions.require_permission(permissions.Permission.COLLECTOR_MANAGE)

        with self.assertRaises(FakeHttpException) as raised:
            dependency(request=request, db=db, user=user)

        self.assertEqual(raised.exception.status_code, 403)
        self.assertEqual(db.commits, 1)
        self.assertEqual(len(db.added), 1)
        audit = db.added[0]
        self.assertEqual(audit.outcome, "denied")
        self.assertEqual(audit.action, "permission_denied")
        self.assertEqual(audit.audit_metadata["required_permission"], permissions.Permission.COLLECTOR_MANAGE.value)

    def test_audit_permission_matrix(self):
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
