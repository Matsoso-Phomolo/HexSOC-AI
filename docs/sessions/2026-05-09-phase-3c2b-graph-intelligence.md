# Phase 3C.2B — Graph Intelligence & Investigation Engine

## Date
2026-05-09

## Goal
Transform HexSOC AI graph investigation from a raw demo visualization into an enterprise SOC investigation workspace that can handle real Windows/Sysmon telemetry without overwhelming analysts.

## Context
Real endpoint telemetry now flows through the HexSOC Agent, collector API keys, ingestion pipeline, detection engine, MITRE mapping, and realtime dashboard. The previous graph rendered too many raw event and alert nodes, creating label clutter and unstable investigation focus.

## Files Changed
- `backend/app/api/routes/graph.py`
- `backend/app/services/graph_engine.py`
- `frontend/src/pages/Dashboard.jsx`
- `frontend/src/styles/globals.css`
- `docs/architecture/hexsoc-ai-platform-overview.md`

## What Changed
- Added server-side graph aggregation for investigation data.
- Grouped repeated telemetry into `event_cluster` and `alert_cluster` nodes.
- Added enterprise node types: `asset`, `user`, `source_ip`, `destination_ip`, `process`, `alert_cluster`, `event_cluster`, `incident`, and `mitre_technique`.
- Added graph filters for node type, severity, MITRE tactic, source IP, hostname, time window, and max nodes.
- Added graph intelligence stats for top source IPs, top techniques, most connected assets, and high-risk clusters.
- Added frontend focus mode so selecting a node highlights direct neighbors and dims unrelated graph entities.
- Added progressive label rendering so labels appear for selected, high-risk, or zoomed-in nodes instead of every node.
- Tuned layout rings by node type to reduce graph collapse and visual overlap.
- Fixed edge preservation during backend node pruning so graph stats and rendered edges do not collapse to `0 edges` when node limits are applied.
- Added aggressive server-side summarization when graph inputs exceed 100 records, grouping repeated detections by source IP and detection family.
- Added frontend graph controls for label visibility, physics spacing, cluster mode, and edge visibility.
- Added temporary cluster expansion for sampled event and alert members.

## Architecture Impact
Graph rendering now defaults to server-side aggregation before the React dashboard receives graph data. This keeps frontend rendering bounded and preserves analyst usability as telemetry volume grows.

The raw graph behavior remains available with `aggregate=false`, which preserves compatibility for debugging and future raw-forensics views.

Dense graph responses now prioritize connected source IP, asset, alert cluster, MITRE technique, event cluster, and incident nodes so rendered graphs preserve investigation paths instead of isolated high-risk nodes.

## Validation
- `python -m compileall backend\app backend\scripts agent` passed.
- `python -m unittest discover agent\tests` passed with 30 tests.
- `npm run build` passed after rerunning outside the Windows sandbox due a local Vite config access-denied sandbox issue.
- Follow-up graph rendering fix validated with the same compile, unit test, and build checks.

## Production Notes
The graph endpoint default limit is now 150 nodes, with backend validation capped at 500 for controlled investigation expansion.

## Known Limitations
- The current frontend graph layout is still custom SVG rather than a dedicated graph engine.
- Cluster drill-down is metadata-based; a future phase should add expandable cluster views and saved investigations.

## Next Steps
- Add cluster expansion and raw-event drill-down.
- Add saved investigation workspaces.
- Add fleet-wide graph filtering by collector and endpoint group.
- Add Sigma and ATT&CK-driven graph overlays.
