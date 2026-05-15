# Phase 4C.2 — Automated Incident Escalation

## Date
2026-05-15

## Goal
Create or update persistent incident records from critical attack-chain, campaign, or recommendation context.

## Context
HexSOC AI already produces persistent attack chains, campaign clusters, timeline steps, graph relationships, MITRE context, and deterministic investigation recommendations.

## Files Changed
- `backend/app/services/incident_escalation_engine.py`
- `backend/app/api/routes/incidents.py`
- `backend/app/tests/test_incident_escalation_engine.py`
- `docs/architecture/automated-incident-escalation.md`
- `docs/sessions/2026-05-15-phase-4c2-automated-incident-escalation.md`
- `README.md`

## What Changed
- Added deterministic escalation criteria.
- Added idempotent incident creation/update using stable escalation markers.
- Added escalation APIs under `/api/incidents/escalate`.
- Added activity timeline and WebSocket/dashboard refresh events through existing incident workflow plumbing.

## Architecture Impact
This extends the Autonomous SOC Investigation Layer from recommendation into controlled workflow materialization. It intentionally stops before automated containment or SOAR playbook execution.

## Validation
- Backend compile check.
- Agent tests.
- Backend tests for escalation criteria and idempotency.
- Frontend build because deployed frontend artifacts should remain valid.

## Production Notes
The feature is safe for production because it only creates or updates incident records. It does not perform endpoint isolation, firewall changes, account disables, or external API lookups.

## Known Limitations
- Incident linkage is stored as a stable marker in description rather than a dedicated relationship table.
- Frontend buttons are deferred to a later bounded UI phase.

## Next Steps
- Add dashboard escalation buttons for high/critical chains.
- Add dedicated incident relationship metadata if case workflows require richer linkage.
- Later connect escalation output to SOAR-style playbooks after approval gates exist.
