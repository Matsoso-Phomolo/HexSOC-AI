# HexSOC AI

HexSOC AI is an enterprise cybersecurity and AI platform foundation for SOC operations, security analytics, AI-assisted detection, event streaming, and operational dashboards.

This repository is organized as a scalable monorepo with clear boundaries between the API backend, SOC dashboard frontend, machine learning workflows, data pipelines, infrastructure, scripts, documentation, and security content.

## Major Areas

- `backend/` - FastAPI service foundation for APIs, PostgreSQL persistence, Kafka event handling, AI detection services, WebSocket alerts, and security tool integrations.
- `frontend/` - React dashboard foundation for SOC workflows including alerts, incidents, detections, assets, and settings.
- `ml/` - Machine learning workspace for anomaly detection, graph neural network experiments, training jobs, inference, datasets, and model artifacts.
- `data-pipeline/` - Collectors and parsers for security telemetry such as packet captures, system logs, and alert feeds.
- `infrastructure/` - Deployment and runtime configuration for Docker, Kafka, PostgreSQL, Nginx, and monitoring.
- `security/` - Detection rules, response playbooks, policies, and threat models.
- `docs/` - Architecture, API, setup, and operations documentation.
- `scripts/` - Local automation and operational scripts.

## Getting Started

Start with:

1. `docs/architecture/system-overview.md` to understand the platform boundaries.
2. `.env.example` to define local environment variables.
3. `backend/app/main.py` to wire initial API routes.
4. `frontend/src/App.jsx` to shape the first dashboard shell.

## Status

This is a production-oriented foundation scaffold. It intentionally contains starter files only, leaving room for implementation once service contracts and product workflows are defined.

## Render Backend Deployment

Deploy the FastAPI backend as a Render Web Service connected to a Render PostgreSQL database. Keep secrets in Render environment variables; do not commit production credentials.

Render settings:

- Root Directory: `backend`
- Build Command: `pip install -r requirements.txt`
- Start Command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
- Runtime: Python 3

Required environment variables:

- `APP_ENV=production`
- `APP_NAME=HexSOC AI`
- `DATABASE_URL=<Render PostgreSQL internal database URL>`
- `FRONTEND_ORIGIN=https://hexsoc-ai.vercel.app`
- `CORS_ORIGINS=https://hexsoc-ai.vercel.app`
- `JWT_SECRET_KEY=<secure random production secret>`
- `JWT_ALGORITHM=HS256`
- `STARTUP_SCHEMA_SYNC=auto`

Optional environment variables:

- `API_PREFIX=/api`
- `KAFKA_BOOTSTRAP_SERVERS=<future production Kafka bootstrap servers>`
- `SHODAN_API_KEY=<future integration key>`
- `OPENAI_API_KEY=<future AI integration key>`

Admin recovery:

- Run `backend/scripts/create_admin_user.py` with `ADMIN_EMAIL`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`, and `ADMIN_FULL_NAME` to create or reactivate an admin user.
- Set `ADMIN_RESET_PASSWORD=true` only when intentionally resetting an existing admin password.

Production notes:

- The local PostgreSQL database name remains `hexsoc`.
- Render PostgreSQL will provide its own production database through `DATABASE_URL`.
- The backend reads `DATABASE_URL`, `FRONTEND_ORIGIN`, and `CORS_ORIGINS` from the environment at startup.
- The Vercel frontend must use `VITE_API_BASE_URL=<your Render backend URL>`.
- Render production start command must not use `--reload`: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`.
- Graph and SOC APIs use bounded query limits and GZip compression to reduce production memory pressure.
- Production startup uses a lightweight schema sync by default. Use `STARTUP_SCHEMA_SYNC=full` only for a planned maintenance run when legacy schema repair is needed.

## Roadmap Notes

HexSOC AI is evolving as an AI-native cyber operations platform:

```text
Telemetry Sources
-> Streaming / Queue Layer
-> Detection Engine
-> Threat Intelligence Feed Integrator
-> Threat Intel Enrichment Engine
-> Graph Investigation Engine
-> AI Correlation Engine
-> SOC Dashboard
-> Automation / Response
-> Continuous Learning Loop
```

Current engineering focus:

- Stabilize graph intelligence with bounded payloads, weighted relationships, cluster summaries, deduplication, and future timeline replay metadata.
- Build Phase 4A Threat Intelligence Feed Integrator as a modular subsystem with IOC models, schemas, routes, services, adapters, normalization, deduplication, scoring, TTL, and correlation links.

Current Phase 4A.1 threat intelligence foundation:

- IOC normalization for IP, domain, URL, hash, email, and CVE indicators.
- Source-independent IOC fingerprinting and deduplication.
- Local/mock feed ingestion before live provider API integration.
- IOC correlation results prepared for alert, event, asset, and graph relationships.
- Graph-native IOC relationship enrichment with weighted edges and bounded graph payloads.
- Dashboard IOC Investigation panel for search, bounded correlation, relationship summaries, and graph enrichment previews.
- Automated threat-intelligence correlation pipeline for IOC extraction, local matching, graph relationships, and risk amplification.
- Provider adapters remain modular for VirusTotal, AbuseIPDB, OTX, Shodan, GreyNoise, and MISP.

Current Phase 4B attack-chain intelligence foundation:

- Bounded attack-chain reconstruction from stored events, alerts, MITRE metadata, IOC links, and assets.
- Replay-ready timeline steps for future investigation playback.
- Lightweight campaign clustering by shared source IPs, users, assets, and MITRE techniques.
- Deterministic chain scoring for low, suspicious, high, and critical classifications.
- Dashboard visibility for rebuilds, risk-ranked chains, timeline previews, and campaign summaries.
- Persistent attack-chain storage with stable timeline lookup and investigation session foundations.

Current Phase 4C autonomous investigation foundation:

- Deterministic investigation recommendations for attack chains, campaigns, and bounded ad hoc context.
- Explainable SOC guidance for containment, evidence collection, escalation, MITRE context, analyst notes, and next steps.
- Automated incident escalation from critical attack chains, campaigns, and bounded context using idempotent incident markers.
- Incident investigation workspace linking escalated incidents to attack-chain/campaign context, timeline preview, recommendations, evidence checklist, and case workflow data.
- No external LLM calls or automated response actions yet.

Threat Intelligence Feed Integrator endpoints:

- `GET /api/threat-intel/iocs`
- `POST /api/threat-intel/iocs`
- `POST /api/threat-intel/iocs/bulk`
- `GET /api/threat-intel/search`
- `POST /api/threat-intel/feeds/normalize`
- `POST /api/threat-intel/correlate`
- `GET /api/threat-intel/sync-status`
- `POST /api/threat-intel/graph-enrich`
- `GET /api/threat-intel/relationship-summary`
- `GET /api/graph/ioc-relationships`
- `POST /api/threat-intel/auto-correlate`
- `GET /api/threat-intel/correlation-summary`
- `GET /api/threat-intel/risk-hotspots`

Attack Chain Intelligence endpoints:

- `GET /api/attack-chains`
- `GET /api/attack-chains/{chain_id}`
- `GET /api/attack-chains/{chain_id}/timeline`
- `GET /api/campaigns`
- `POST /api/attack-chains/rebuild`
- `PATCH /api/attack-chains/{chain_id}/status`
- `POST /api/investigations/from-attack-chain/{chain_id}`
- `GET /api/investigations`
- `PATCH /api/investigations/{session_id}`

Investigation Recommendation endpoints:

- `GET /api/investigation/recommendations/attack-chain/{chain_id}`
- `GET /api/investigation/recommendations/campaign/{campaign_id}`
- `POST /api/investigation/recommendations/context`

Automated Incident Escalation endpoints:

- `POST /api/incidents/escalate/attack-chain/{chain_id}`
- `POST /api/incidents/escalate/campaign/{campaign_id}`
- `POST /api/incidents/escalate/context`

Incident Investigation Workspace endpoints:

- `GET /api/incidents/{incident_id}/workspace`
- `POST /api/incidents/{incident_id}/workspace/evidence-checklist`

## Production Proof

Live deployment:

- Frontend: https://hexsoc-ai.vercel.app
- Backend: https://hexsoc-ai.onrender.com
- Swagger: https://hexsoc-ai.onrender.com/docs

Deployment architecture:

```text
Vercel React Frontend -> Render FastAPI Backend -> Render PostgreSQL
```

Local development:

```powershell
cd "C:\Users\windows 10\Desktop\Workshop\hexsoc-ai\backend"
uvicorn app.main:app --reload --host 127.0.0.1 --port 9000
```

```powershell
cd "C:\Users\windows 10\Desktop\Workshop\hexsoc-ai\frontend"
npm run dev
```

Seed demo data locally:

```powershell
cd "C:\Users\windows 10\Desktop\Workshop\hexsoc-ai\backend"
python scripts\seed_demo_data.py
```

Demo seeding API:

- Local/dev: `POST /api/demo/seed`
- Production: requires `DEMO_SEED_TOKEN` in the backend environment and the request header `X-Demo-Seed-Token`

The seeder is idempotent and skips demo records that already exist.

## Live Collector API Keys

HexSOC AI supports API-key authenticated collectors for external agents and scripts. Collector keys are for machines, not analysts.

Create a collector:

1. Login as an admin.
2. Open `Live Collectors`.
3. Create a collector with a name, type, and source label.
4. Copy the raw API key immediately. It is shown only once.

Collector security:

- Raw collector API keys are never stored.
- Only a hashed key and short prefix are stored.
- Rotate a key if it may have been exposed.
- Revoke a collector when it should no longer ingest telemetry.

Ingest normalized JSON with curl:

```powershell
curl.exe -X POST "http://127.0.0.1:9000/api/collectors/ingest/events/bulk?auto_detect=true" `
  -H "Content-Type: application/json" `
  -H "X-HexSOC-API-Key: <collector_api_key>" `
  --data-binary "@backend/samples/sysmon_sample_events.json"
```

Ingest Windows/Sysmon JSON with curl:

```powershell
curl.exe -X POST "http://127.0.0.1:9000/api/collectors/ingest/windows-events/bulk?auto_detect=true" `
  -H "Content-Type: application/json" `
  -H "X-HexSOC-API-Key: <collector_api_key>" `
  --data-binary "@backend/samples/windows_sysmon_sample.json"
```

Run the sample collector script:

```powershell
cd "C:\Users\windows 10\Desktop\Workshop\hexsoc-ai\backend"
$env:COLLECTOR_API_KEY="<collector_api_key>"
$env:HEXSOC_BACKEND_URL="http://127.0.0.1:9000"
python scripts\send_sample_collector_logs.py
```

## HexSOC Agent Prototype

The `agent/` folder contains a lightweight Python collector prototype that sends Windows/Sysmon sample telemetry to HexSOC AI with a collector API key.

Basic local flow:

1. Create a collector from the Live Collectors panel.
2. Copy the one-time API key.
3. Create `agent/config.local.json` from `agent/config.local.example.json`.
4. Run:

```powershell
cd "C:\Users\windows 10\Desktop\Workshop\hexsoc-ai\agent"
pip install -r requirements.txt
python hexsoc_agent.py --heartbeat-only
python hexsoc_agent.py --once
python hexsoc_agent.py --interval 60
```

The agent sends a heartbeat to `POST /api/collectors/heartbeat`, then submits Windows/Sysmon telemetry to `/api/collectors/ingest/windows-events/bulk?auto_detect=true`. Confirm the dashboard shows new events, alert detections, activity records, and an updated collector `last_seen_at`.

Long-running service mode repeats heartbeat, telemetry ingestion, post-ingestion heartbeat, and sleep until `Ctrl+C`. Use `--heartbeat-loop` for heartbeats only or `--telemetry-only` for ingestion without heartbeat.

Collector resilience settings can be supplied in config JSON or environment variables:

```json
{
  "request_timeout_seconds": 30,
  "max_network_retries": 3,
  "network_backoff_seconds": 5
}
```

```powershell
$env:AGENT_REQUEST_TIMEOUT_SECONDS="30"
$env:AGENT_MAX_RETRIES="3"
$env:AGENT_BACKOFF_SECONDS="5"
```

Transient HTTPS, DNS, TLS, and read-timeout failures are logged as degraded collector state. Heartbeat failures do not stop the service loop, and telemetry ingestion failures are stored in the offline queue when enabled.

Environment-specific runs load `config.local.json`, `config.staging.json`, or `config.production.json`:

```powershell
python hexsoc_agent.py --env local --interval 60
python hexsoc_agent.py --env staging --interval 60
python hexsoc_agent.py --env production --interval 60
```

Collector fleet health is available at `GET /api/collectors/health`. The Live Collectors panel displays online, stale, offline, and revoked counts, along with agent version, host name, OS details, heartbeat count, last heartbeat time, last event count, and last error.

## Windows Persistent Agent Mode

HexSOC Agent can run persistently through Windows Task Scheduler without NSSM or a packaged service binary.
The scheduled task launches with `pythonw.exe` when available so the collector runs silently without opening a visible console window. Runtime output continues to go to the configured log file.

Install the scheduled task:

```powershell
powershell -ExecutionPolicy Bypass -File agent\scripts\install_windows_task.ps1
```

Install with startup trigger instead of logon:

```powershell
powershell -ExecutionPolicy Bypass -File agent\scripts\install_windows_task.ps1 -TriggerType Startup
```

Operate the task:

```powershell
powershell -ExecutionPolicy Bypass -File agent\scripts\start_agent_task.ps1
powershell -ExecutionPolicy Bypass -File agent\scripts\stop_agent_task.ps1
powershell -ExecutionPolicy Bypass -File agent\scripts\status_agent_task.ps1
powershell -ExecutionPolicy Bypass -File agent\scripts\uninstall_windows_task.ps1
```

Create desktop control buttons:

```powershell
powershell -ExecutionPolicy Bypass -File agent\scripts\create_agent_shortcuts.ps1
```

This creates local Desktop shortcuts for installing, starting, stopping, checking, and uninstalling the `HexSOCAgent` scheduled task. The Vercel dashboard cannot directly start a local Windows process from the browser, so these shortcuts provide the safe local control surface for running `python agent\hexsoc_agent.py --env production` in the background.

The task runs:

```powershell
python agent\hexsoc_agent.py --env production --interval 60 --log-file logs/agent-production.log
```

The installer resolves this through a windowless Python runtime on Windows where possible. If `pythonw.exe` is unavailable, the installer warns and falls back to the regular `python.exe`.

Check local collector state and queue health:

```powershell
python agent\hexsoc_agent.py --env production --state-status
python agent\hexsoc_agent.py --env production --queue-status
```

Runtime logs are written to `logs/agent-production.log`. The agent rotates this log at roughly 5 MB and keeps one `.1` rotated copy.
