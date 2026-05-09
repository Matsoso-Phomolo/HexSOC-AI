# ADR-0003 - Agent Event Fingerprinting

## Status

Accepted

## Context

The HexSOC Agent initially replayed sample telemetry every loop cycle. This created repeated events and alerts. The agent needed persistent duplicate prevention across restarts.

## Decision

Use deterministic SHA-256 fingerprints generated from stable event fields:

- `timestamp`
- `event_type`
- `source`
- `source_ip`
- `destination_ip`
- `username`
- `hostname`
- `raw_message`

Fingerprints are stored in `agent/data/agent_state.json` with a bounded history, defaulting to the last 5000 fingerprints.

## Consequences

The agent can skip events it has already sent and prevent alert spam from repeated telemetry samples or repeated local reads.

The fingerprint approach is simple and portable. It does not require backend-side global deduplication, but backend deduplication may still be added later for defense in depth.

## Alternatives Considered

- Backend-only duplicate detection
- Cursor-only deduplication
- UUIDs generated at read time
- Local database tracking

Stable local fingerprints were chosen because they work across sample telemetry, parsed Windows events, and restarts.

## Related Files / Phases

- Phase 3B.8 Real Event Cursor / Duplicate Prevention
- `agent/agent_state.py`
- `agent/hexsoc_agent.py`
- `agent/tests/test_agent_state.py`
