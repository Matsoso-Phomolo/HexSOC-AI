# Real Threat Feed Providers

## Purpose
Phase 4A.4 introduces controlled provider adapter foundations for real threat intelligence enrichment while keeping HexSOC AI safe, bounded, and production-minded.

## Providers
- VirusTotal API v3
- AbuseIPDB API v2
- AlienVault OTX DirectConnect
- MISP REST API

## Safety Model
Provider calls are never automatic on dashboard load. They only run when explicitly requested through:

```text
POST /api/threat-intel/enrich
```

The request must include `indicators`. Existing stored event/alert enrichment behavior remains available when no indicators are supplied.

## Provider-Neutral Result Shape
Each provider adapter returns:

```json
{
  "provider": "virustotal",
  "ioc_type": "ip",
  "value": "8.8.8.8",
  "normalized_value": "8.8.8.8",
  "matched": false,
  "severity": "info",
  "confidence_score": 0,
  "risk_score": 0,
  "tags": [],
  "source_reputation": 0,
  "raw_context": {},
  "error": null
}
```

## Orchestration
`backend/app/services/threat_intel_provider_orchestrator.py`:
- normalizes indicators
- selects compatible providers
- enforces max lookups per request
- applies a short provider timeout
- uses a minimal cache boundary
- merges provider results into a fused result
- optionally persists fused IOCs through the existing IOC lifecycle

## Cache Boundary
`backend/app/services/threat_intel_cache.py` provides an in-memory cache keyed by:

```text
provider + ioc_type + normalized_value
```

This is intentionally simple for the first provider foundation. A persistent provider cache can be added later.

## Configuration
Environment variables:
- `VIRUSTOTAL_API_KEY`
- `ABUSEIPDB_API_KEY`
- `OTX_API_KEY`
- `MISP_URL`
- `MISP_API_KEY`
- `THREAT_INTEL_PROVIDER_TIMEOUT_SECONDS`
- `THREAT_INTEL_PROVIDER_CACHE_TTL_SECONDS`
- `THREAT_INTEL_PROVIDER_MAX_LOOKUPS_PER_REQUEST`

Secrets must remain in environment variables. They are never returned by API status endpoints.

## API Surface
- `POST /api/threat-intel/enrich`
- `GET /api/threat-intel/providers/status`

## Production Constraints
- No uncontrolled bulk lookups.
- No secrets in responses or logs.
- Provider-specific schemas do not leak into the core IOC model.
- Provider failures are returned as sanitized errors.
- Disabled providers fail gracefully.
