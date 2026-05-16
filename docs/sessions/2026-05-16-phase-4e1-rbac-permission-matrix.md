# Phase 4E.1 — RBAC Permission Matrix Hardening

## Date
2026-05-16

## Goal
Centralize and harden HexSOC AI role-based access control across backend routes and frontend actions.

## Context
HexSOC AI already supports admin, analyst, viewer, and super-admin governance workflows. Access checks were spread across route-level role checks. This phase introduces a centralized permission matrix.

## Files Changed
- `backend/app/security/permissions.py`
- `backend/app/security/__init__.py`
- `backend/app/services/auth_service.py`
- `backend/app/api/routes/users.py`
- `backend/app/api/routes/collectors.py`
- `backend/app/api/routes/incidents.py`
- `backend/app/api/routes/attack_chains.py`
- `backend/app/api/routes/threat_intel.py`
- `backend/app/api/routes/graph.py`
- `backend/app/tests/test_rbac_permissions.py`
- `frontend/src/utils/permissions.js`
- `frontend/src/pages/Dashboard.jsx`
- `docs/architecture/rbac-permission-matrix.md`

## What Changed
- Added backend permission constants and role-to-permission mapping.
- Added `require_permission`, `require_any_permission`, `has_permission`, and `is_super_admin` helpers.
- Migrated high-risk route protections to explicit permission checks.
- Added frontend permission helper to hide/disable role-inappropriate actions.
- Added tests for viewer, analyst, admin, and super-admin authorization behavior.

## Architecture Impact
RBAC is now policy-driven instead of scattered through individual route implementations. Frontend behavior reflects the same matrix while backend checks remain authoritative.

## Validation
- Python compile checks required.
- Backend tests required.
- Agent tests required.
- Frontend build required.

## Production Notes
The designated super-admin identity remains PHOMOLO MATSOSO at `phomolomatsoso@gmail.com`.

## Known Limitations
Some low-risk read endpoints may still use legacy role dependencies and can be migrated incrementally.

## Next Steps
Extend permission tests with API-client integration tests as the backend test harness matures.
