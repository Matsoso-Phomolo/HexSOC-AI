# Phase 4D.1 — Collector Resilience and Fault Tolerance

## Date
2026-05-16

## Goal
Prevent transient Render/backend HTTPS read timeouts from crashing the HexSOC Windows production collector.

## Context
The agent was successfully sending heartbeat and telemetry, but `urllib.request.urlopen(... timeout=30)` could raise raw timeout exceptions during live telemetry mode.

## Files Changed
- `agent/hexsoc_agent.py`
- `agent/offline_queue.py`
- `agent/tests/test_network_resilience.py`
- `agent/config.local.example.json`
- `agent/config.staging.example.json`
- `agent/config.production.example.json`
- `docs/architecture/collector-resilience.md`

## What Changed
- Added controlled `AgentNetworkError` handling for transient network failures.
- Added configurable request timeout, bounded retries, backoff, and jitter.
- Hardened heartbeat, ingestion, queue flush, and service loop handling.
- Added degraded/recovered runtime logging.
- Added offline queue behavior for failed telemetry batches.

## Architecture Impact
Collector network I/O is now treated as a resilience boundary. The agent can keep running while HexSOC backend availability fluctuates.

## Validation
- Compile checks required.
- Agent test suite includes timeout, retry, service-loop, and queueing coverage.

## Production Notes
Production can tune:
- `AGENT_REQUEST_TIMEOUT_SECONDS`
- `AGENT_MAX_RETRIES`
- `AGENT_BACKOFF_SECONDS`

## Known Limitations
This phase does not add a message broker, async runtime, or backend-side collector command channel.

## Next Steps
Observe production agent logs for degraded/recovered transitions and confirm queued telemetry flushes after Render timeout recovery.
