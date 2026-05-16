# Collector Fleet Management

HexSOC AI collector fleet management tracks endpoint telemetry collectors as operational infrastructure, not as browser-controlled local processes.

## Scope

The fleet layer provides:

- Health grouping: online, degraded, stale, offline, revoked
- Collector grouping by type, source label, operating system, and agent version
- Heartbeat freshness and last-seen age calculation
- Telemetry volume summary from recent collector reports
- Version drift visibility
- Bounded collector detail inspection
- Safe lifecycle actions: key rotation and revocation

## Safety Boundary

The cloud dashboard does not start or stop local endpoint agents. Local control remains on the endpoint through Windows Task Scheduler scripts and Desktop shortcuts. This avoids remote code execution, SSH/RDP control, and browser-to-local command execution.

## APIs

- `GET /api/collectors/fleet/summary`
- `GET /api/collectors/fleet/health`
- `GET /api/collectors/fleet/{collector_id}`
- `GET /api/collectors/fleet/offline`
- `GET /api/collectors/fleet/version-drift`

All fleet endpoints use bounded limits with a default of 100 and maximum of 500 collectors.

## Health Semantics

- `online`: recent heartbeat and no current error
- `degraded`: recent heartbeat with a reported last error
- `stale`: heartbeat older than the online window but not fully offline
- `offline`: no heartbeat or heartbeat older than the offline window
- `revoked`: inactive or revoked collector key

## Future Work

Future fleet management can add remote policy distribution and signed configuration updates. This phase intentionally avoids remote command execution and websocket command channels.
