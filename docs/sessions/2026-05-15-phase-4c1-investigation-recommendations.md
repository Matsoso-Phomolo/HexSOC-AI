# Phase 4C.1 — Investigation Recommendations Engine

## Date
2026-05-15

## Goal
Add deterministic SOC analyst recommendations from persisted attack-chain and campaign intelligence.

## Context
HexSOC AI already reconstructs attack chains, stores timeline steps, builds campaign clusters, maps MITRE context, and exposes attack-chain visibility in the dashboard.

## Files Changed
- `backend/app/services/investigation_recommendation_engine.py`
- `backend/app/api/routes/investigation_recommendations.py`
- `backend/app/main.py`
- `backend/app/tests/test_investigation_recommendation_engine.py`
- `docs/architecture/investigation-recommendation-engine.md`
- `docs/sessions/2026-05-15-phase-4c1-investigation-recommendations.md`
- `README.md`

## What Changed
- Added recommendation generation for attack chains, campaign clusters, and bounded ad hoc context.
- Added APIs under `/api/investigation/recommendations`.
- Added deterministic outputs for containment, evidence collection, escalation, MITRE context, analyst notes, and next steps.

## Architecture Impact
This starts the Autonomous SOC Investigation Layer without adding LLM calls or automated response actions. The service consumes existing intelligence and remains explainable, bounded, and production-safe.

## Validation
- Backend compile check.
- Agent test suite.
- Backend recommendation tests.

## Production Notes
The feature is read-only and uses existing RBAC. Viewer, analyst, and admin roles can request recommendation summaries. No secrets or provider calls are introduced.

## Known Limitations
- Recommendations are deterministic and template-based.
- No case auto-creation or response execution.
- No AI narrative expansion yet.

## Next Steps
- Surface recommendation summaries in the dashboard.
- Link recommendations into investigation sessions and case reports.
- Later add AI-assisted narrative generation once deterministic behavior is stable.
