# RBAC Permission Matrix

HexSOC AI uses a centralized permission matrix for backend enforcement and frontend action visibility.

## Roles

- `viewer`
- `analyst`
- `admin`
- `super_admin`

`super_admin` is a virtual role derived from the designated governance account:

- PHOMOLO MATSOSO
- `phomolomatsoso@gmail.com`

## Permission Groups

Viewer:

- Read dashboard summaries
- Read SOC records where permitted
- Read graph, MITRE, attack-chain, investigation, threat-intel, and collector summaries
- Cannot create, update, delete, rebuild, escalate, or manage credentials

Analyst:

- All viewer permissions
- Create/update SOC records
- Update alert and incident status
- Run detection, MITRE mapping, correlation, and safe threat-intel workflows
- Manage cases, evidence, investigation sessions, and escalations
- Cannot manage users or collector keys

Admin:

- All analyst permissions
- Create, update, rotate, and revoke collector credentials
- View and manage user profile/account status
- Cannot delete users
- Cannot grant analyst/admin roles
- Cannot approve/disapprove privileged registration requests

Super Admin:

- All permissions
- Delete users
- Grant analyst/admin roles
- Approve/disapprove analyst/admin registration requests
- Perform highest-risk governance actions

## Backend Enforcement

Central permission helpers live in:

```text
backend/app/security/permissions.py
```

Routes should prefer:

- `require_permission(permission)`
- `require_any_permission([...])`
- `has_permission(user, permission)`
- `is_super_admin(user)`

New route protections should not rely on scattered role checks.

## Frontend Enforcement

Frontend action visibility uses:

```text
frontend/src/utils/permissions.js
```

The frontend hides or disables actions by permission, but backend enforcement remains authoritative.

## Error Contract

Permission denial uses explicit 403 responses:

```json
{
  "detail": "Insufficient permission: collector.manage required"
}
```

## Governance Rules

- Viewer is read-only.
- Analyst can investigate and escalate.
- Admin can manage collectors and users but not privileged governance.
- Super admin controls deletion, privileged role grants, and privileged approvals.
