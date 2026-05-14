# Threat Intelligence Feed Integrator

HexSOC AI Phase 4A introduces the Threat Intelligence Feed Integrator as a first-class subsystem. It is not a single lookup endpoint. Its role is to ingest, normalize, deduplicate, score, expire, and correlate IOCs before downstream enrichment, graph investigation, AI correlation, and response workflows use them.

## Scope

Supported IOC types:

- `ip`
- `domain`
- `url`
- `hash`

Initial source adapter targets:

- VirusTotal
- AbuseIPDB
- AlienVault OTX
- Shodan
- GreyNoise
- Generic/custom normalized feeds

## Architecture

```text
Provider Payload / Manual IOC
  -> Source Adapter
  -> Normalization Layer
  -> IOC Deduplication
  -> Confidence + Risk Scoring
  -> Expiration / TTL
  -> PostgreSQL IOC Store
  -> IOC Correlation Links
  -> Alerts / Events / Assets / Graph
```

## Backend Boundaries

- Models: `ThreatIOC`, `ThreatIOCLink`
- Schemas: `backend/app/schemas/threat_ioc.py`
- Routes: `backend/app/api/routes/threat_intel_feeds.py`
- Service: `backend/app/services/threat_intel_feed_service.py`
- Adapters: `backend/app/services/threat_intel_adapters/`

## Design Rules

- Provider adapters normalize already-received payloads and do not perform network calls.
- Future provider fetchers should run as workers and pass payloads into this subsystem.
- Raw feed payloads may be retained for audit/debugging, but API keys and secrets must never be stored.
- IOC deduplication is based on `source + ioc_type + normalized_value`.
- IOC expiration deactivates indicators instead of deleting them.
- Correlation links are additive and connect IOCs to alerts, events, and assets.

## API Surface

- `GET /api/threat-intel/iocs`
- `POST /api/threat-intel/iocs`
- `POST /api/threat-intel/iocs/bulk`
- `POST /api/threat-intel/feeds/normalize`
- `POST /api/threat-intel/correlate`

## Future Work

- Async feed polling workers
- MISP adapter
- Feed health metrics
- IOC source reliability scoring
- Campaign and malware-family entities
- Graph overlays for IOC relationships
- Tenant-scoped feeds and private intel collections
