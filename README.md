# HexSOC AI

HexSOC AI is an AI-native SOC/XDR platform prototype focused on telemetry ingestion, threat intelligence enrichment, attack-chain reconstruction, investigation workflows, endpoint collector monitoring, and AI-assisted security operations.

The platform is designed as a modular cyber-operations stack rather than a single dashboard. It combines collector-based telemetry, deterministic detection, MITRE ATT&CK mapping, IOC correlation, graph investigation, incident escalation, and analyst workflow support.

## Public Demo

- Frontend: [https://hexsoc-ai.vercel.app](https://hexsoc-ai.vercel.app)
- Backend: [https://hexsoc-ai.onrender.com](https://hexsoc-ai.onrender.com)
- API documentation: [https://hexsoc-ai.onrender.com/docs](https://hexsoc-ai.onrender.com/docs)

Production architecture:

```text
Vercel React Frontend -> Render FastAPI Backend -> Render PostgreSQL
```

## Platform Positioning

HexSOC AI is an industry-grade AI-native cyber operations platform prototype focused on:

- Telemetry ingestion and collector health monitoring
- Threat intelligence enrichment and IOC correlation
- Attack-chain reconstruction and campaign clustering
- Graph investigation and relationship mapping
- Incident investigation workflows
- Endpoint collector fleet monitoring
- AI-assisted SOC operations

## Architecture Flow

```text
Telemetry Sources
-> Streaming / Queue Layer
-> Detection Engine
-> Threat Intelligence Feed Integration
-> Threat Intel Enrichment Engine
-> Graph Investigation Engine
-> AI Correlation Engine
-> SOC Dashboard
-> Automation / Response
-> Continuous Learning Loop
```

## Current Capabilities

- SOC command dashboard for assets, events, alerts, incidents, cases, and activity timeline
- RBAC authentication with admin, analyst, viewer, and super-admin governance controls
- Permission-matrix enforcement for viewer, analyst, admin, and super-admin actions
- Telemetry ingestion through API-key authenticated collectors
- Windows/Sysmon-oriented collector prototype with heartbeat, offline queue, retry, and deduplication
- Collector fleet monitoring with health summaries, stale/offline detection, version visibility, and local-control guidance
- Deterministic detection engine for brute force, malware indicators, suspicious source frequency, and unusual admin activity
- MITRE ATT&CK mapping for normalized telemetry and generated alerts
- IOC normalization, deduplication, enrichment, search, and local correlation
- Provider-adapter foundation for threat intelligence sources such as VirusTotal, AbuseIPDB, OTX, MISP, Shodan, and GreyNoise
- Graph investigation and weighted relationship mapping
- Persistent attack-chain reconstruction and campaign clustering
- Deterministic investigation recommendations
- Automated incident escalation for high-risk chains and campaigns
- Incident investigation workspace with timeline preview, recommendations, notes, evidence, and report export foundations

## Repository Structure

- `backend/` - FastAPI backend, PostgreSQL models, detection, threat intelligence, graph, attack-chain, case, collector, and auth services
- `frontend/` - React SOC dashboard and analyst workflow interface
- `agent/` - Lightweight Python endpoint collector prototype
- `ml/` - Future machine learning workspace for anomaly detection and graph analytics
- `data-pipeline/` - Telemetry collector and parser foundations
- `infrastructure/` - Docker, Kafka, PostgreSQL, Nginx, and monitoring foundations
- `security/` - Policies, detection rules, playbooks, and threat models
- `docs/` - Architecture, decisions, roadmap, session notes, releases, and incident notes
- `scripts/` - Local automation and operational scripts

## API Documentation

The public README keeps API detail high-level. Full interactive API documentation is available through Swagger:

[https://hexsoc-ai.onrender.com/docs](https://hexsoc-ai.onrender.com/docs)

High-level API groups include:

- Authentication and RBAC APIs
- SOC asset, event, alert, incident, and activity APIs
- Detection and MITRE ATT&CK APIs
- Threat Intelligence APIs
- IOC correlation and graph relationship APIs
- Attack Chain and Campaign APIs
- Investigation Recommendation APIs
- Incident Escalation and Workspace APIs
- Collector Ingestion and Collector Fleet APIs

## Local Development

Backend:

```powershell
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 9000
```

Frontend:

```powershell
cd frontend
npm install
npm run dev
```

Agent:

```powershell
cd agent
pip install -r requirements.txt
python hexsoc_agent.py --env production --interval 60
```

Use `.env.example` and the config example files as templates. Do not commit real local configuration files or secrets.

## Deployment

### Render Backend

Deploy the backend as a Render Web Service connected to PostgreSQL.

Recommended Render settings:

- Root Directory: `backend`
- Build Command: `pip install -r requirements.txt`
- Start Command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
- Runtime: Python 3

Core production configuration should be stored in Render environment settings:

- Application environment and service name
- PostgreSQL connection URL
- Frontend origin and CORS origins
- JWT signing configuration
- Optional provider keys for threat intelligence adapters
- Optional demo-seeding token for controlled demonstration workflows

Production notes:

- Do not use `--reload` in production.
- Store all secrets in Render environment variables.
- Use Vercel environment variables for frontend backend URL configuration.
- Keep production keys out of the repository.

### Vercel Frontend

Deploy `frontend/` to Vercel and configure the backend API base URL with the deployed Render backend URL.

## Collector and Agent

HexSOC AI supports API-key authenticated collectors for external telemetry sources. Collector keys are for machines, not analysts.

Collector security model:

- Raw collector API keys are shown once.
- Collector keys are stored hashed.
- Keys can be rotated or revoked from the dashboard.
- Collector ingestion is separated from analyst JWT authentication.

The `agent/` folder contains a lightweight Python collector prototype that can send Windows/Sysmon-style telemetry to HexSOC AI.

Example continuous run:

```powershell
cd agent
python hexsoc_agent.py --env production --interval 60
```

Agent resilience includes:

- Heartbeats
- Retry and backoff for transient network failures
- Offline queue and dead-letter queue
- Event fingerprinting and duplicate prevention
- Environment-specific configuration
- Secret masking in terminal output
- Windows Task Scheduler operation
- Silent background mode using a windowless Python runtime where available

### Windows Task Scheduler Mode

Install the scheduled task:

```powershell
powershell -ExecutionPolicy Bypass -File agent\scripts\install_windows_task.ps1
```

Start, stop, and inspect the task:

```powershell
powershell -ExecutionPolicy Bypass -File agent\scripts\start_agent_task.ps1
powershell -ExecutionPolicy Bypass -File agent\scripts\stop_agent_task.ps1
powershell -ExecutionPolicy Bypass -File agent\scripts\status_agent_task.ps1
```

Create local desktop control shortcuts:

```powershell
powershell -ExecutionPolicy Bypass -File agent\scripts\create_agent_shortcuts.ps1
```

The cloud dashboard intentionally does not start or stop local endpoint agents. Local control remains on the endpoint through Task Scheduler scripts and shortcuts.

## Security Notice

- Do not commit `.env` files.
- Do not commit API keys, passwords, collector keys, signing keys, or production database URLs.
- Use `.env.example` and config example files only.
- Store production secrets in Render and Vercel environment settings.
- Collector API keys are shown once and stored hashed.
- Public repository content excludes production secrets.
- Rotate any key that may have been exposed.
- Elevated analyst/admin registration, privileged role grants, and user deletion are governed by super-admin controls.

## Public vs Internal Documentation

This public README summarizes product architecture, capabilities, and safe setup guidance. Detailed engineering session notes, troubleshooting logs, production repair notes, and internal operational runbooks should remain private or internal-only.

## Roadmap

Current platform direction:

- SOC command dashboard
- Threat intelligence lifecycle
- Graph investigation
- Attack-chain intelligence
- Autonomous investigation support
- Collector fleet management

Future roadmap:

- Advanced hunting workspace
- Multi-collector expansion
- Notification integrations
- Response automation framework
- Continuous learning layer
- Multi-tenant SaaS architecture
- Advanced AI security analytics

## License and Usage

HexSOC AI is currently a prototype and portfolio platform under active development. Review security, compliance, and operational requirements before adapting any part of the system for production SOC use.
