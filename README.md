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
