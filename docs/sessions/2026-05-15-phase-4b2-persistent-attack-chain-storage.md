# Phase 4B.2 — Persistent Attack Chain Storage + Investigation Sessions

## Date
2026-05-15

## Goal
Make attack chains stable persistent investigation objects so dashboard timeline lookup no longer fails for chains returned by the list endpoint.

## Context
Phase 4B created computed attack-chain reconstruction. Phase 4B.1 exposed that intelligence in the dashboard. Dynamic chain IDs could become invalid between list and timeline calls, producing intermittent `404 Attack chain not found` errors.

## Files Changed
- `backend/app/db/models.py`
- `backend/app/db/database.py`
- `backend/app/api/routes/attack_chains.py`
- `backend/app/services/attack_chain_persistence_service.py`
- `backend/app/services/investigation_session_service.py`
- `docs/architecture/persistent-attack-chain-storage.md`
- `docs/sessions/2026-05-15-phase-4b2-persistent-attack-chain-storage.md`
- `README.md`

## What Changed
- Added persistent `AttackChain`, `AttackChainStep`, `CampaignCluster`, and `InvestigationSession` models.
- Added additive startup schema creation for attack-chain persistence tables.
- Rebuild now computes candidates and persists stable chain/timeline records.
- `GET /api/attack-chains` now returns persisted chains.
- `GET /api/attack-chains/{chain_id}/timeline` now reads persisted timeline steps.
- Added chain status update endpoint.
- Added investigation session create/list/update endpoints.

## Architecture Impact
Attack chains are now first-class SOC investigation objects. This prepares HexSOC AI for timeline replay, AI chain summaries, case-management linkage, campaign history, and autonomous investigation workflows.

## Validation
Run:

```powershell
python -m compileall backend\app backend\scripts agent
python -m unittest discover agent\tests
```

## Production Notes
Rebuild remains explicit and does not call external providers. Startup schema changes are additive and table-creation only for the new persistence layer.

## Known Limitations
- Persisted chain steps are replaced on rebuild rather than versioned individually.
- Campaign clustering remains lightweight.
- Investigation sessions are backend-ready; no dedicated frontend panel was added in this phase.

## Next Steps
- Add dashboard controls for attack-chain status and investigation sessions.
- Connect AI Copilot to persisted attack chains.
- Add chain version diffing and timeline replay.
