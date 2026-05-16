"""RBAC permission matrix tests."""

from __future__ import annotations

import unittest
import sys
import types
from importlib import util
from pathlib import Path
from types import SimpleNamespace


BACKEND_ROOT = Path(__file__).resolve().parents[2]
PERMISSIONS_PATH = BACKEND_ROOT / "app" / "security" / "permissions.py"


def _load_permissions_module():
    fastapi_module = types.ModuleType("fastapi")

    class FakeHttpException(Exception):
        def __init__(self, status_code=None, detail=None, headers=None):
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail
            self.headers = headers

    fastapi_module.Depends = lambda dependency=None: dependency
    fastapi_module.HTTPException = FakeHttpException
    fastapi_module.Request = object
    fastapi_module.status = SimpleNamespace(HTTP_403_FORBIDDEN=403)
    sys.modules["fastapi"] = fastapi_module

    sys.modules.setdefault("app", types.ModuleType("app"))
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

    spec = util.spec_from_file_location("rbac_permissions_test_module", PERMISSIONS_PATH)
    if not spec or not spec.loader:
        raise RuntimeError(f"Unable to load {PERMISSIONS_PATH}")
    module = util.module_from_spec(spec)
    sys.modules["rbac_permissions_test_module"] = module
    spec.loader.exec_module(module)
    return module


permissions = _load_permissions_module()
Permission = permissions.Permission
effective_role = permissions.effective_role
has_permission = permissions.has_permission


class RbacPermissionTests(unittest.TestCase):
    def test_viewer_cannot_manage_collectors(self):
        user = SimpleNamespace(role="viewer", email="viewer@example.com")
        self.assertFalse(has_permission(user, Permission.COLLECTOR_MANAGE))

    def test_admin_can_manage_collectors(self):
        user = SimpleNamespace(role="admin", email="admin@example.com")
        self.assertTrue(has_permission(user, Permission.COLLECTOR_MANAGE))
        self.assertTrue(has_permission(user, Permission.AUDIT_READ))

    def test_analyst_cannot_delete_user(self):
        user = SimpleNamespace(role="analyst", email="analyst@example.com")
        self.assertFalse(has_permission(user, Permission.USER_DELETE))

    def test_admin_cannot_delete_user(self):
        user = SimpleNamespace(role="admin", email="admin@example.com")
        self.assertFalse(has_permission(user, Permission.USER_DELETE))

    def test_super_admin_can_delete_user(self):
        user = SimpleNamespace(role="admin", email="phomolomatsoso@gmail.com")
        self.assertEqual(effective_role(user), "super_admin")
        self.assertTrue(has_permission(user, Permission.USER_DELETE))

    def test_analyst_can_escalate_incident(self):
        user = SimpleNamespace(role="analyst", email="analyst@example.com")
        self.assertTrue(has_permission(user, Permission.INCIDENT_ESCALATE))

    def test_viewer_cannot_rebuild_attack_chains(self):
        user = SimpleNamespace(role="viewer", email="viewer@example.com")
        self.assertFalse(has_permission(user, Permission.ATTACK_CHAIN_REBUILD))


if __name__ == "__main__":
    unittest.main()
