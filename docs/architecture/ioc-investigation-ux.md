# IOC Investigation UX

## Purpose
The IOC Investigation UX exposes threat intelligence lifecycle data to SOC analysts without introducing heavy graph rendering or external provider calls.

## User Flow
```text
IOC search
-> IOC correlation test
-> relationship summary
-> graph enrichment preview
-> future investigation graph overlay
```

## Dashboard Capabilities
- View active IOC count.
- View relationship totals and top relationship categories.
- Search stored IOCs by IP, domain, URL, hash, email, CVE, source, or classification.
- Correlate a bounded list of indicators against stored IOCs.
- Preview graph enrichment for one entity and a bounded indicator list.
- Display relationship counts, max edge weight, and risk amplification.

## Production Constraints
- No continuous polling.
- No full graph expansion.
- No external provider API calls.
- Search result lists are capped.
- Relationship summaries are bounded.
- Graph enrichment previews one entity at a time.

## Related APIs
- `GET /api/threat-intel/sync-status`
- `GET /api/threat-intel/search`
- `POST /api/threat-intel/correlate`
- `GET /api/threat-intel/relationship-summary`
- `POST /api/threat-intel/graph-enrich`

## Future Work
- Add IOC relationship overlay to Graph Investigation.
- Add provider sync status once live adapters are enabled.
- Add AI correlation summaries that consume IOC relationship weights.
