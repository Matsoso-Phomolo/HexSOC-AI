# Collector Resilience

HexSOC Agent must continue operating through temporary backend, DNS, TLS, and Render timeout failures. Network calls are treated as unreliable boundaries and are converted into controlled `AgentNetworkError` failures instead of raw traceback crashes.

## Runtime Behavior

- Heartbeat failures log a warning and keep the service loop alive.
- Post-ingestion heartbeat failures log a warning and do not affect telemetry state.
- Telemetry ingestion failures are queued when offline queue is enabled.
- Queue flush failures remain in the queue and are retried later.
- Successful later calls log recovery and clear degraded state.

## Retry Policy

The agent supports JSON config and environment override controls:

- `request_timeout_seconds`
- `max_network_retries`
- `network_backoff_seconds`
- `AGENT_REQUEST_TIMEOUT_SECONDS`
- `AGENT_MAX_RETRIES`
- `AGENT_BACKOFF_SECONDS`

Retries use bounded exponential backoff with small jitter. API keys are never printed or stored in queue records.

## Operational Goal

The collector should degrade, retry, queue, and recover automatically. A transient HTTPS read timeout from Render must not stop the Windows scheduled task process.
