const SUPER_ADMIN_EMAIL = "phomolomatsoso@gmail.com";

export const PERMISSIONS = {
  DASHBOARD_READ: "dashboard.read",
  SOC_READ: "soc.read",
  SOC_WRITE: "soc.write",
  ALERT_UPDATE: "alert.update",
  INCIDENT_UPDATE: "incident.update",
  INCIDENT_ESCALATE: "incident.escalate",
  CASE_MANAGE: "case.manage",
  DETECTION_RUN: "detection.run",
  CORRELATION_RUN: "correlation.run",
  THREAT_INTEL_READ: "threat_intel.read",
  THREAT_INTEL_RUN: "threat_intel.run",
  GRAPH_READ: "graph.read",
  MITRE_READ: "mitre.read",
  MITRE_RUN: "mitre.run",
  ATTACK_CHAIN_READ: "attack_chain.read",
  ATTACK_CHAIN_REBUILD: "attack_chain.rebuild",
  ATTACK_CHAIN_UPDATE: "attack_chain.update",
  INVESTIGATION_READ: "investigation.read",
  INVESTIGATION_MANAGE: "investigation.manage",
  COLLECTOR_READ: "collector.read",
  COLLECTOR_CREATE: "collector.create",
  COLLECTOR_MANAGE: "collector.manage",
  USER_READ: "user.read",
  USER_MANAGE: "user.manage",
  USER_DELETE: "user.delete",
  USER_GRANT_PRIVILEGED_ROLE: "user.grant_privileged_role",
  USER_APPROVE_PRIVILEGED: "user.approve_privileged",
  AUDIT_READ: "audit.read",
};

const VIEWER = new Set([
  PERMISSIONS.DASHBOARD_READ,
  PERMISSIONS.SOC_READ,
  PERMISSIONS.THREAT_INTEL_READ,
  PERMISSIONS.GRAPH_READ,
  PERMISSIONS.MITRE_READ,
  PERMISSIONS.ATTACK_CHAIN_READ,
  PERMISSIONS.INVESTIGATION_READ,
  PERMISSIONS.COLLECTOR_READ,
]);

const ANALYST = new Set([
  ...VIEWER,
  PERMISSIONS.SOC_WRITE,
  PERMISSIONS.ALERT_UPDATE,
  PERMISSIONS.INCIDENT_UPDATE,
  PERMISSIONS.INCIDENT_ESCALATE,
  PERMISSIONS.CASE_MANAGE,
  PERMISSIONS.DETECTION_RUN,
  PERMISSIONS.CORRELATION_RUN,
  PERMISSIONS.THREAT_INTEL_RUN,
  PERMISSIONS.MITRE_RUN,
  PERMISSIONS.ATTACK_CHAIN_REBUILD,
  PERMISSIONS.ATTACK_CHAIN_UPDATE,
  PERMISSIONS.INVESTIGATION_MANAGE,
]);

const ADMIN = new Set([
  ...ANALYST,
  PERMISSIONS.COLLECTOR_CREATE,
  PERMISSIONS.COLLECTOR_MANAGE,
  PERMISSIONS.USER_READ,
  PERMISSIONS.USER_MANAGE,
  PERMISSIONS.AUDIT_READ,
]);

const SUPER_ADMIN = new Set([
  ...ADMIN,
  PERMISSIONS.USER_DELETE,
  PERMISSIONS.USER_GRANT_PRIVILEGED_ROLE,
  PERMISSIONS.USER_APPROVE_PRIVILEGED,
]);

const ROLE_PERMISSIONS = {
  viewer: VIEWER,
  analyst: ANALYST,
  admin: ADMIN,
  super_admin: SUPER_ADMIN,
};

export function effectiveRole(user) {
  if (user?.role === "admin" && String(user?.email || "").toLowerCase() === SUPER_ADMIN_EMAIL) {
    return "super_admin";
  }
  return user?.role || "viewer";
}

export function can(userOrRole, permission) {
  const role = typeof userOrRole === "string" ? userOrRole : effectiveRole(userOrRole);
  return Boolean(ROLE_PERMISSIONS[role]?.has(permission));
}

export function canAny(userOrRole, permissions) {
  return permissions.some((permission) => can(userOrRole, permission));
}
