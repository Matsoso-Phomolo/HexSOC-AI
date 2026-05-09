# ADR-0001 - Agent Offline Queue

## Status

Accepted

## Context

The HexSOC Agent must continue operating when the backend or network is temporarily unavailable. Without local buffering, endpoint telemetry would be lost during outages or Render/backend downtime.

## Decision

Use a local JSONL offline queue at `agent/data/offline_queue.jsonl` for early reliable telemetry buffering.

Each failed telemetry payload is stored as one JSON line with:

- queue item ID
- creation timestamp
- target endpoint
- payload
- retry attempts
- last error

Collector API keys are never stored in the queue.

## Consequences

The agent can preserve telemetry during temporary outages and flush it later. JSONL is easy to inspect, append, test, and recover manually.

This is not the final enterprise queue technology, but it is appropriate for the current agent maturity level.

## Alternatives Considered

- SQLite local queue
- Windows Event Forwarding
- Direct retry only without persistence
- External message broker

SQLite may be appropriate later, but JSONL keeps the early agent simple and transparent.

## Related Files / Phases

- Phase 3B.5 Offline Queue + Retry System
- `agent/offline_queue.py`
- `agent/hexsoc_agent.py`
- `agent/data/README.md`
