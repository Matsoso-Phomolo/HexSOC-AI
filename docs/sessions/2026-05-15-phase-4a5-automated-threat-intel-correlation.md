# Phase 4A.5 — Automated Threat Intelligence Correlation Pipeline

## Date
2026-05-15

## Goal
Add automated IOC extraction and local threat-intelligence correlation from events, alerts, assets, incidents, or raw payloads.

## Context
HexSOC AI already supports IOC ingestion, normalization, deduplication, correlation, graph relationship enrichment, dashboard IOC visibility, and provider adapter foundations. This phase turns that into an automated bounded correlation pipeline.

## Files Changed
- `backend/app/services/ioc_extractor.py`
- `backend/app/services/automated_correlation_engine.py`
- `backend/app/api/routes/threat_intel.py`
- `backend/app/api/routes/alerts.py`
- `backend/app/schemas/threat_ioc.py`
- `backend/app/services/threat_intel_provider_orchestrator.py`
- `backend/app/services/threat_intel_cache.py`
- `backend/app/services/threat_intel_adapters/*`
- `docs/architecture/automated-threat-intel-correlation.md`
- `README.md`

## What Changed
- Added bounded IOC extraction from safe text and payload fields.
- Added automated local IOC correlation.
- Added optional provider enrichment path gated by `use_providers`.
- Added graph relationship creation through existing IOC graph enrichment.
- Added deterministic risk amplification and classification.
- Added correlation summary and risk hotspot endpoints.
- Hooked local-only IOC correlation into alert creation without blocking alert creation.

## Architecture Impact
The threat intelligence layer now supports:

```text
telemetry/alert payload -> IOC extraction -> local IOC correlation -> weighted relationship -> risk amplification
```

This completes the transition from manual lookup to automated cyber-intelligence correlation.

## Validation
- `python -m compileall backend\app backend\scripts agent`
- `python -m unittest discover agent\tests`

## Production Notes
- Provider enrichment is disabled by default.
- No external provider calls are made by dashboard load or alert creation.
- All list endpoints are bounded.
- Alert creation catches correlation failures so analyst workflows remain stable.

## Known Limitations
- Correlation summaries are derived from `ThreatIOCLink`; dedicated correlation history persistence is future work.
- `/api/graph/attack-paths` remains a future Phase 4B capability.

## Next Steps
- Add persistent correlation run records.
- Add graph overlay for IOC relationships.
- Add AI interpretation of risk amplification and relationship hotspots.
