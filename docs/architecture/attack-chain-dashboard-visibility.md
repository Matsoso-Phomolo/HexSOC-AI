# Attack Chain Dashboard Visibility

Phase 4B.1 exposes computed attack-chain intelligence in the HexSOC AI dashboard without adding heavy graph rendering or changing the existing investigation graph.

## Purpose

Analysts need a compact SOC-facing surface for multi-stage intrusion candidates:

- rebuild attack-chain intelligence on demand
- view risk-ranked chains
- inspect ordered timeline previews
- review lightweight campaign clusters

This phase keeps the UI bounded and operational. It does not introduce replay animation, full attack-path graphing, or external provider lookups.

## Dashboard Surface

The `Attack Chain Intelligence` panel shows:

- total computed chains
- critical and high chain count
- campaign cluster count
- highest risk score
- last rebuild status
- top 20 chain candidates
- selected chain timeline preview
- top campaign cluster summaries

## API Usage

The frontend uses these bounded endpoints:

- `GET /api/attack-chains?limit=20`
- `GET /api/attack-chains/{chain_id}/timeline`
- `GET /api/campaigns?limit=20`
- `POST /api/attack-chains/rebuild?limit=50`

The panel does not poll. It loads during authenticated dashboard initialization and refreshes after explicit rebuild or relevant realtime hints.

## UX Guardrails

- No heavy graph canvas.
- No infinite expansion.
- No automatic provider enrichment.
- No dashboard redesign.
- Lists are capped for browser performance.
- Empty states guide analysts to ingest telemetry, run detection/MITRE mapping, or rebuild chains.

## Future Work

Future phases can add durable attack-chain persistence, timeline replay, AI chain summaries, and graph attack-path overlays once chain quality is validated against production telemetry.
