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

Optional environment variables:

- `API_PREFIX=/api`
- `KAFKA_BOOTSTRAP_SERVERS=<future production Kafka bootstrap servers>`
- `SHODAN_API_KEY=<future integration key>`
- `OPENAI_API_KEY=<future AI integration key>`

Production notes:

- The local PostgreSQL database name remains `hexsoc`.
- Render PostgreSQL will provide its own production database through `DATABASE_URL`.
- The backend reads `DATABASE_URL`, `FRONTEND_ORIGIN`, and `CORS_ORIGINS` from the environment at startup.
- The Vercel frontend must use `VITE_API_BASE_URL=<your Render backend URL>`.

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
3. Create `agent/config.json` from `agent/config.example.json`.
4. Run:

```powershell
cd "C:\Users\windows 10\Desktop\Workshop\hexsoc-ai\agent"
pip install -r requirements.txt
python hexsoc_agent.py --config config.json --heartbeat-only
python hexsoc_agent.py --config config.json --once
python hexsoc_agent.py --config config.json --interval 60
```

The agent sends a heartbeat to `POST /api/collectors/heartbeat`, then submits Windows/Sysmon telemetry to `/api/collectors/ingest/windows-events/bulk?auto_detect=true`. Confirm the dashboard shows new events, alert detections, activity records, and an updated collector `last_seen_at`.

Long-running service mode repeats heartbeat, telemetry ingestion, post-ingestion heartbeat, and sleep until `Ctrl+C`. Use `--heartbeat-loop` for heartbeats only or `--telemetry-only` for ingestion without heartbeat.

Collector fleet health is available at `GET /api/collectors/health`. The Live Collectors panel displays online, stale, offline, and revoked counts, along with agent version, host name, OS details, heartbeat count, last heartbeat time, last event count, and last error.
