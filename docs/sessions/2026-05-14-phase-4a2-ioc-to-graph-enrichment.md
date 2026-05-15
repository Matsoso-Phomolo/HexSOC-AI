# Phase 4A.2 — IOC-to-Graph Relationship Enrichment

## Date
2026-05-14

## Goal
Convert IOC matches into graph-native weighted relationships so threat intelligence becomes connected cyber intelligence.

## Context
Phase 4A.1 introduced IOC normalization, deduplication, search, sync status, and correlation. This phase connects that IOC lifecycle to the graph investigation architecture without loading the full graph or adding frontend churn.

## Files Changed
- `backend/app/services/graph_entity_mapper.py`
- `backend/app/services/graph_relationship_builder.py`
- `backend/app/services/ioc_graph_enrichment.py`
- `backend/app/api/routes/threat_intel_feeds.py`
- `backend/app/api/routes/graph.py`
- `backend/app/schemas/threat_ioc.py`
- `docs/architecture/ioc-to-graph-enrichment.md`
- `README.md`

## What Changed
- Added stable graph node identity mapping for SOC entities and IOCs.
- Added standardized weighted relationship construction.
- Added IOC graph enrichment service that converts matched IOCs into bounded nodes and edges.
- Added deduplication for graph relationships.
- Added persisted `ThreatIOCLink` creation during entity enrichment.
- Added bounded API endpoints for IOC graph enrichment and IOC relationship summaries.

## Architecture Impact
Threat intelligence now has a graph-native path:

```text
IOC correlation -> graph nodes -> weighted relationships -> graph-ready enrichment payloads -> future investigation UX and AI correlation
```

## Validation
- Run `python -m compileall backend\app backend\scripts agent`.
- Run `python -m unittest discover agent\tests`.

## Production Notes
- The enrichment endpoint accepts one entity and up to 100 indicators.
- Relationship graph endpoint defaults to 100 and caps at 500.
- No external feed providers were called.
- No heavy layout or full graph expansion was added.

## Known Limitations
- The frontend does not yet visualize the new IOC relationship endpoint directly.
- Relationship storage still uses the existing `ThreatIOCLink` model; deeper relationship metadata can be added later with migrations.

## Next Steps
- Add provider sync history.
- Add IOC graph overlay to the investigation workspace.
- Feed IOC graph relationships into AI correlation summaries.
