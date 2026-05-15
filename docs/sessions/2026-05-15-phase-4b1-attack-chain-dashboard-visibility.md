# Phase 4B.1 — Attack Chain Dashboard Visibility

## Date
2026-05-15

## Goal
Expose Phase 4B attack-chain intelligence in the SOC dashboard through a compact, bounded analyst workflow.

## Context
Phase 4B added computed attack-chain and campaign APIs. This phase adds frontend visibility without heavy graph rendering or unrelated UI redesign.

## Files Changed
- `frontend/src/api/client.js`
- `frontend/src/pages/Dashboard.jsx`
- `frontend/src/styles/globals.css`
- `docs/architecture/attack-chain-dashboard-visibility.md`
- `docs/sessions/2026-05-15-phase-4b1-attack-chain-dashboard-visibility.md`
- `README.md`

## What Changed
- Added frontend API helpers for attack chains, chain timelines, campaign clusters, and rebuilds.
- Added an `Attack Chain Intelligence` dashboard panel.
- Added chain summary cards, bounded chain list, selected chain timeline preview, and campaign summaries.
- Added rebuild button with loading, error, and last-result states.

## Architecture Impact
Attack-chain intelligence now has a SOC-facing visibility layer. The UI remains bounded and consumes computed API results rather than performing graph layout or provider enrichment in the browser.

## Validation
Run:

```powershell
python -m compileall backend\app backend\scripts agent
python -m unittest discover agent\tests
npm run build
```

## Production Notes
The panel uses authenticated backend APIs. Viewer users can read chain intelligence; analyst and admin users can rebuild chains.

## Known Limitations
- Timeline replay is a compact ordered preview, not an animated replay.
- Campaign clusters are lightweight summaries.
- Attack chains are computed on demand and not yet persisted.

## Next Steps
- Validate attack-chain quality against live Windows/Sysmon telemetry.
- Connect Copilot to Phase 4B chain output.
- Add persistence and historical comparisons if analyst workflow proves useful.
