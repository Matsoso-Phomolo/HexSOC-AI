# IOC Correlation Engine

## Purpose
The IOC Correlation Engine is the Phase 4A.1 foundation for HexSOC AI threat intelligence lifecycle management. It prepares the platform for provider feeds without coupling the core SOC platform to live external APIs.

## Lifecycle
```text
Raw IOC input
-> IOC Normalizer
-> IOC Deduplicator
-> ThreatIOC storage
-> Correlation Engine
-> IOC links to events, alerts, assets
-> Graph relationship payloads
-> Future enrichment and AI correlation
```

## Supported IOC Types
- IP addresses
- Domains
- URLs
- File hashes
- Email addresses
- CVEs

## Normalization
`backend/app/services/ioc_normalizer.py` trims raw values, detects IOC type when possible, validates basic shape, and emits:
- `ioc_type`
- `value`
- `normalized_value`
- `fingerprint`
- validation status

The fingerprint is generated from `ioc_type + normalized_value` so the same indicator can be deduplicated across sources.

## Deduplication
`backend/app/services/ioc_deduplicator.py` merges repeated indicators into one source-independent IOC record. It preserves:
- highest severity
- highest confidence
- highest risk score
- first seen and last seen timestamps
- source list and source count
- recent source context

## Correlation
`backend/app/services/ioc_correlation_engine.py` supports two modes:
- correlate supplied raw indicators against stored IOCs
- correlate stored active IOCs against existing SOC entities

Correlation produces graph-ready relationship payloads so future graph intelligence can connect IOC nodes to events, alerts, and assets.

## API Surface
- `POST /api/threat-intel/iocs`
- `GET /api/threat-intel/iocs`
- `GET /api/threat-intel/search`
- `POST /api/threat-intel/correlate`
- `GET /api/threat-intel/sync-status`

## Provider Boundary
This phase does not call live VirusTotal, AbuseIPDB, Shodan, OTX, GreyNoise, or MISP APIs. Provider adapters remain local/mock-ready until the feed integrator is hardened with rate limits, credentials, and provider-specific failure handling.

## Production Notes
- Database reads are bounded with explicit limits.
- IOC data is additive and non-destructive.
- API keys and provider secrets are not stored in this subsystem.
- Formal Alembic migrations should replace startup schema sync before enterprise release.
