# Phase 4A.1 — IOC Normalization, Deduplication, and Correlation

## Date
2026-05-14

## Goal
Build the local IOC intelligence lifecycle foundation for HexSOC AI before integrating live external threat intelligence providers.

## Context
Phase 4A already introduced threat intelligence feed routes, schemas, adapter boundaries, provider placeholders, and architecture documentation. This phase turns that foundation into a real internal subsystem for IOC ingestion, normalization, deduplication, storage, and correlation.

## Files Changed
- `backend/app/services/ioc_normalizer.py`
- `backend/app/services/ioc_deduplicator.py`
- `backend/app/services/ioc_correlation_engine.py`
- `backend/app/services/threat_intel_feed_service.py`
- `backend/app/api/routes/threat_intel_feeds.py`
- `backend/app/schemas/threat_ioc.py`
- `backend/app/db/models.py`
- `backend/app/db/database.py`
- `docs/architecture/ioc-correlation-engine.md`
- `README.md`

## What Changed
- Added IOC normalization for IPs, domains, URLs, hashes, emails, and CVEs.
- Added source-independent IOC fingerprinting.
- Added deduplication that merges sources, source counts, severity, confidence, risk, timestamps, tags, and raw context.
- Added correlation engine for supplied raw indicators and stored IOC-to-SOC entity relationships.
- Added IOC search and sync status API endpoints.
- Extended existing threat-intel routes instead of creating duplicate route surfaces.

## Architecture Impact
Threat intelligence is now modeled as a lifecycle:

```text
IOC ingestion -> normalization -> deduplication -> storage -> correlation -> enrichment/graph-ready relationships
```

This keeps future VirusTotal, AbuseIPDB, OTX, Shodan, GreyNoise, and MISP integrations behind adapter and normalization boundaries.

## Validation
- Run `python -m compileall backend\app backend\scripts agent`.
- Run existing tests if available.

## Production Notes
- No live external provider calls were added.
- No provider API keys or secrets were introduced.
- Query limits remain bounded.
- Existing graph and dashboard behavior is preserved.

## Known Limitations
- Provider-specific rate limiting and quota handling are not implemented yet.
- Formal database migrations are still needed before enterprise release.
- Correlation is deterministic and rule-based; AI-assisted reasoning remains a future layer.

## Next Steps
- Add provider-specific adapter tests.
- Add IOC expiration analytics and provider sync history.
- Connect IOC relationships into graph intelligence with weighted relationships.
