# Automated Threat Intelligence Correlation

## Purpose
Phase 4A.5 moves HexSOC AI from manual IOC lookup toward automated cyber-intelligence correlation. The pipeline extracts indicators from telemetry or alerts, correlates them against local IOC intelligence, optionally invokes provider enrichment, creates graph-ready relationships, and returns a bounded risk summary.

## Flow
```text
Entity payload
-> IOC extractor
-> IOC normalizer
-> Local IOC correlation
-> Optional provider enrichment
-> IOC graph enrichment
-> Risk amplification
-> Analyst/API summary
```

## Services

### IOC Extractor
`backend/app/services/ioc_extractor.py`

Extracts IPs, domains, URLs, hashes, emails, and CVEs from bounded safe fields:
- `message`
- `description`
- `source_ip`
- `destination_ip`
- `command_line`
- `process_name`
- `file_hash`
- `url`
- `domain`
- `raw_payload`

### Automated Correlation Engine
`backend/app/services/automated_correlation_engine.py`

Responsibilities:
- extract IOC candidates
- normalize candidates through the existing IOC normalizer
- correlate with local stored IOCs
- optionally call provider orchestrator when explicitly enabled
- create graph relationships through existing IOC graph enrichment
- compute deterministic risk amplification

## API Surface
- `POST /api/threat-intel/auto-correlate`
- `GET /api/threat-intel/correlation-summary`
- `GET /api/threat-intel/risk-hotspots`

## Risk Classification
- `0-24`: safe
- `25-49`: suspicious
- `50-74`: malicious
- `75-100`: critical

## Production Safety
- Local IOC correlation is the default.
- Provider enrichment is opt-in per request.
- Inputs are bounded.
- No dashboard auto-enrichment is introduced.
- No heavy graph layout is performed.
- Alert creation can trigger local IOC correlation, but provider calls are never automatic.

## Future Work
- Persist correlation summary records.
- Add attack-path endpoint in Phase 4B.
- Feed risk amplification into AI correlation and case priority.
