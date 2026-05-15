# IOC-to-Graph Enrichment

## Purpose
IOC-to-Graph Enrichment converts threat intelligence matches into graph-native cyber relationships. It allows HexSOC AI to connect indicators, alerts, events, assets, and incidents without loading the full investigation graph or running expensive layout work on the backend.

## Flow
```text
IOC correlation result
-> Graph entity mapper
-> Relationship builder
-> IOC graph enrichment
-> Weighted graph-ready nodes and edges
-> Future graph investigation UX and AI correlation
```

## Services

### Graph Entity Mapper
`backend/app/services/graph_entity_mapper.py`

Maps platform entities into stable graph node identities:
- `alert:{id}`
- `event:{id}`
- `asset:{id}`
- `incident:{id}`
- `ioc:{fingerprint}`
- `ip:{normalized_ip}`
- `domain:{normalized_domain}`

### Graph Relationship Builder
`backend/app/services/graph_relationship_builder.py`

Creates standardized weighted edges with:
- `source_id`
- `target_id`
- `relationship_type`
- `weight`
- `confidence`
- `severity`
- `first_seen`
- `last_seen`
- `metadata`

### IOC Graph Enrichment
`backend/app/services/ioc_graph_enrichment.py`

Accepts a single bounded entity context and a bounded indicator list. It returns graph-ready IOC nodes and weighted relationships, and optionally stores deduplicated `ThreatIOCLink` records for future investigation.

## Relationship Types
- `MATCHES_IOC`
- `CONTACTED_IOC`
- `ASSOCIATED_WITH_IOC`
- `RESOLVES_TO_IOC`
- `OBSERVED_IN_EVENT`
- `TRIGGERED_ALERT`
- `PART_OF_INCIDENT`

## API Surface
- `POST /api/threat-intel/graph-enrich`
- `GET /api/threat-intel/relationship-summary`
- `GET /api/graph/ioc-relationships`

## Production Safety
- Default limit is 100.
- Maximum limit is 500.
- No full graph layout is performed.
- No external provider API calls are made.
- Responses are graph-safe and bounded.
