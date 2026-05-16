"""Central RBAC permission matrix for HexSOC AI."""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum
from typing import Callable

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.services.audit_log_service import log_denied
from app.services.auth_service import SUPER_ADMIN_EMAIL, get_current_user


class Permission(StrEnum):
    """Stable permission identifiers used by backend and frontend."""

    DASHBOARD_READ = "dashboard.read"
    SOC_READ = "soc.read"
    SOC_WRITE = "soc.write"
    ALERT_UPDATE = "alert.update"
    INCIDENT_UPDATE = "incident.update"
    INCIDENT_ESCALATE = "incident.escalate"
    CASE_MANAGE = "case.manage"
    DETECTION_RUN = "detection.run"
    CORRELATION_RUN = "correlation.run"
    THREAT_INTEL_READ = "threat_intel.read"
    THREAT_INTEL_RUN = "threat_intel.run"
    GRAPH_READ = "graph.read"
    MITRE_READ = "mitre.read"
    MITRE_RUN = "mitre.run"
    ATTACK_CHAIN_READ = "attack_chain.read"
    ATTACK_CHAIN_REBUILD = "attack_chain.rebuild"
    ATTACK_CHAIN_UPDATE = "attack_chain.update"
    INVESTIGATION_READ = "investigation.read"
    INVESTIGATION_MANAGE = "investigation.manage"
    COLLECTOR_READ = "collector.read"
    COLLECTOR_CREATE = "collector.create"
    COLLECTOR_MANAGE = "collector.manage"
    USER_READ = "user.read"
    USER_MANAGE = "user.manage"
    USER_DELETE = "user.delete"
    USER_GRANT_PRIVILEGED_ROLE = "user.grant_privileged_role"
    USER_APPROVE_PRIVILEGED = "user.approve_privileged"
    AUDIT_READ = "audit.read"


VIEWER_PERMISSIONS = {
    Permission.DASHBOARD_READ,
    Permission.SOC_READ,
    Permission.THREAT_INTEL_READ,
    Permission.GRAPH_READ,
    Permission.MITRE_READ,
    Permission.ATTACK_CHAIN_READ,
    Permission.INVESTIGATION_READ,
    Permission.COLLECTOR_READ,
}

ANALYST_PERMISSIONS = {
    *VIEWER_PERMISSIONS,
    Permission.SOC_WRITE,
    Permission.ALERT_UPDATE,
    Permission.INCIDENT_UPDATE,
    Permission.INCIDENT_ESCALATE,
    Permission.CASE_MANAGE,
    Permission.DETECTION_RUN,
    Permission.CORRELATION_RUN,
    Permission.THREAT_INTEL_RUN,
    Permission.MITRE_RUN,
    Permission.ATTACK_CHAIN_REBUILD,
    Permission.ATTACK_CHAIN_UPDATE,
    Permission.INVESTIGATION_MANAGE,
}

ADMIN_PERMISSIONS = {
    *ANALYST_PERMISSIONS,
    Permission.COLLECTOR_CREATE,
    Permission.COLLECTOR_MANAGE,
    Permission.USER_READ,
    Permission.USER_MANAGE,
    Permission.AUDIT_READ,
}

SUPER_ADMIN_PERMISSIONS = {
    *ADMIN_PERMISSIONS,
    Permission.USER_DELETE,
    Permission.USER_GRANT_PRIVILEGED_ROLE,
    Permission.USER_APPROVE_PRIVILEGED,
}

ROLE_PERMISSIONS = {
    "viewer": VIEWER_PERMISSIONS,
    "analyst": ANALYST_PERMISSIONS,
    "admin": ADMIN_PERMISSIONS,
    "super_admin": SUPER_ADMIN_PERMISSIONS,
}


def effective_role(user: models.User | None) -> str:
    """Return the virtual RBAC role for a user."""
    if is_super_admin(user):
        return "super_admin"
    return (getattr(user, "role", None) or "viewer").lower()


def is_super_admin(user: models.User | None) -> bool:
    """Return whether the user is the designated HexSOC AI super admin."""
    return bool(
        user
        and (getattr(user, "role", "") or "").lower() == "admin"
        and (getattr(user, "email", "") or "").strip().lower() == SUPER_ADMIN_EMAIL
    )


def permissions_for(user: models.User | None) -> set[Permission]:
    """Return the permission set for the user's effective role."""
    return set(ROLE_PERMISSIONS.get(effective_role(user), VIEWER_PERMISSIONS))


def has_permission(user: models.User | None, permission: Permission | str) -> bool:
    """Return whether the user has one permission."""
    permission_value = Permission(permission)
    return permission_value in permissions_for(user)


def require_permission(permission: Permission | str) -> Callable:
    """FastAPI dependency enforcing one permission."""
    required = Permission(permission)

    def dependency(
        request: Request,
        db: Session = Depends(get_db),
        user: models.User = Depends(get_current_user),
    ) -> models.User:
        if has_permission(user, required):
            return user
        log_denied(
            db,
            action="permission_denied",
            category="rbac",
            actor=user,
            request=request,
            target_type="permission",
            target_id=required.value,
            target_label=required.value,
            metadata={"required_permission": required.value},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Insufficient permission: {required.value} required",
        )

    return dependency


def require_any_permission(required_permissions: Iterable[Permission | str]) -> Callable:
    """FastAPI dependency enforcing at least one permission."""
    required = [Permission(permission) for permission in required_permissions]

    def dependency(
        request: Request,
        db: Session = Depends(get_db),
        user: models.User = Depends(get_current_user),
    ) -> models.User:
        if any(has_permission(user, permission) for permission in required):
            return user
        joined = ", ".join(permission.value for permission in required)
        log_denied(
            db,
            action="permission_denied",
            category="rbac",
            actor=user,
            request=request,
            target_type="permission",
            target_id=joined,
            target_label=joined,
            metadata={"required_permissions": [permission.value for permission in required]},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Insufficient permission: one of [{joined}] required",
        )

    return dependency
