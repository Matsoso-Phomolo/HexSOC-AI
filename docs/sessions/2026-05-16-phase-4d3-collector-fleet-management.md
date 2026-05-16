# Phase 4D.3 — Collector Fleet Management

## Date
2026-05-16

## Goal
Add fleet-level collector monitoring so HexSOC AI can manage many endpoint collectors, not just one Windows agent.

## Context
HexSOC AI already has resilient collectors, offline queueing, Task Scheduler runtime, silent background mode, and live collector health. The next step is bounded fleet visibility and operational grouping.

## Files Changed
- `backend/app/services/collector_fleet_service.py`
- `backend/app/api/routes/collectors.py`
- `backend/app/schemas/collector.py`
- `frontend/src/pages/Dashboard.jsx`
- `frontend/src/styles/globals.css`
- `docs/architecture/collector-fleet-management.md`
- `README.md`

## What Changed
- Added a collector fleet service for health summaries, grouping, version drift, and offline detection.
- Added `/api/collectors/fleet/*` endpoints.
- Added degraded health semantics for collectors that are online but reporting errors.
- Improved the Live Collectors panel with fleet summary, filters, version distribution, detail inspection, and local control guidance.
- Added copyable local Task Scheduler commands.

## Architecture Impact
Collector management remains cloud-observed and endpoint-controlled. HexSOC AI gains fleet visibility without adding remote code execution or command channels.

## Validation
- Compile checks required.
- Agent tests required.
- Backend tests required.
- Frontend build required.

## Production Notes
Use local shortcuts or Task Scheduler scripts for collector start/stop. Rotate and revoke collector keys from the dashboard when needed.

## Known Limitations
No remote policy management, signed command channel, or endpoint action orchestration yet.

## Next Steps
Add fleet policy/config distribution only after signing, authorization, and audit controls are designed.
