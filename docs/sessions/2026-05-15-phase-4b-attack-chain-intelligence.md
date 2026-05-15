# Phase 4B — Attack Chain Intelligence

## Date
2026-05-15

## Goal
Move HexSOC AI from individual alert and IOC correlation into bounded multi-stage attack reconstruction.

## Context
Phase 4A completed IOC lifecycle, IOC-to-graph enrichment, dashboard IOC visibility, provider adapter foundations, and automated threat-intelligence correlation. Phase 4B builds on stored telemetry, alerts, MITRE metadata, IOC links, and assets without external provider calls or heavy graph rendering.

## Files Changed
- `backend/app/services/attack_chain_engine.py`
- `backend/app/services/attack_timeline_builder.py`
- `backend/app/services/campaign_cluster_engine.py`
- `backend/app/api/routes/attack_chains.py`
- `backend/app/main.py`
- `docs/architecture/attack-chain-intelligence.md`
- `docs/sessions/2026-05-15-phase-4b-attack-chain-intelligence.md`
- `README.md`

## What Changed
- Added computed attack-chain reconstruction from recent bounded SOC records.
- Added replay-ready timeline steps for events and alerts.
- Added lightweight campaign clustering over computed attack chains.
- Added APIs for chain listing, chain details, chain timelines, campaign summaries, and rebuild runs.
- Added activity and WebSocket broadcasts for explicit attack-chain rebuilds.

## Architecture Impact
Attack Chain Intelligence is a new backend service layer between graph/threat intelligence and future AI correlation. The first implementation is computed and bounded, avoiding premature persistence and keeping Render memory risk low.

## Validation
Run:

```powershell
python -m compileall backend\app backend\scripts agent
python -m unittest discover agent\tests
```

## Production Notes
The rebuild endpoint does not call external threat-intelligence providers. It uses already-stored events, alerts, MITRE metadata, IOC links, and assets.

## Known Limitations
- Attack chains are computed on demand and not yet stored as durable cases.
- Campaign clustering is lightweight and source/technique oriented.
- Timeline replay UI is prepared by API shape but not built in this phase.

## Next Steps
- Validate chain quality against live Windows/Sysmon telemetry.
- Add persistence in Phase 4B.1 if computed output proves useful.
- Connect AI Copilot to attack-chain summaries.
- Add attack-path visualization after graph scalability is stable.
