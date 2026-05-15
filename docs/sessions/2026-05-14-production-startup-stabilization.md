# Production Startup Stabilization

## Date
2026-05-14

## Goal
Restore predictable Render cold starts for the HexSOC AI backend after the Phase 4A threat intelligence schema additions.

## Context
The production backend URL resolved, but Render stayed on the application loading screen instead of returning `/api/health`. The backend startup path was still running the full legacy schema repair pass on every production cold start.

## Files Changed
- `backend/app/core/config.py`
- `backend/app/db/database.py`
- `.env.example`
- `README.md`

## What Changed
- Added `STARTUP_SCHEMA_SYNC` with `auto`, `full`, and `off` behavior.
- Added PostgreSQL connection timeout configuration.
- Kept full schema repair for local development by default.
- Switched production startup to a lightweight additive sync focused on current critical tables.
- Made schema statements fail-soft with structured warnings so one additive DDL issue does not block API startup.

## Architecture Impact
This keeps Render startup bounded while preserving the pre-Alembic schema bridge. It is a stabilization step before formal migrations.

## Validation
- Python compile check required after patch.
- Route import check recommended before deploy.

## Production Notes
Render should keep `APP_ENV=production` and may set `STARTUP_SCHEMA_SYNC=auto`. Use `STARTUP_SCHEMA_SYNC=full` only for maintenance windows.

## Known Limitations
This is still not a substitute for Alembic migrations. Formal migrations remain required before enterprise production hardening.

## Next Steps
- Deploy the patch to Render.
- Verify `https://hexsoc-ai.onrender.com/api/health` returns JSON.
- Plan Alembic migration adoption.
