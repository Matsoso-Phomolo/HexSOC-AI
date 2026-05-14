# HexSOC AI Platform Overview

HexSOC AI is an enterprise cybersecurity and AI platform for SOC telemetry collection, detection, correlation, investigation, case management, and real-time analyst workflows.

## Current Architecture

```text
Windows Endpoint
  -> HexSOC Agent
  -> Offline Queue + Retry
  -> Agent State / Deduplication
  -> API-Key Authenticated Collector API
  -> FastAPI Backend
  -> PostgreSQL
  -> Detection Engine
  -> Threat Intelligence Feed Integrator
  -> Threat Intelligence Enrichment
  -> MITRE ATT&CK Mapping
  -> Graph Investigation
  -> AI Analyst Copilot
  -> Case Management
  -> SOC Dashboard
  -> WebSocket Realtime Updates
```

## Production Services

- Frontend: Vercel
- Backend: Render FastAPI service
- Database: PostgreSQL
- Endpoint runtime: Windows Task Scheduler running HexSOC Agent

## Platform Layers

### Endpoint Collection

The HexSOC Agent runs on Windows endpoints and sends telemetry through collector API keys. It supports environment-aware configuration, secret masking, persistent loop execution, heartbeat monitoring, offline queueing, dead-letter handling, and event fingerprinting for duplicate prevention.

### Collector API

Collector ingestion endpoints accept telemetry authenticated with `X-HexSOC-API-Key`. This separates machine-to-machine ingestion from analyst JWT sessions.

### Backend SOC Core

The FastAPI backend owns SOC records, authentication, RBAC, collector management, detection execution, threat intelligence feed ingestion, enrichment, correlation, MITRE mapping, graph generation, AI copilot summaries, cases, notes, evidence, and report export.

### Data Storage

PostgreSQL stores users, assets, events, alerts, incidents, activity logs, collectors, threat IOCs, IOC relationship links, cases, evidence, notes, and enrichment/correlation metadata.

### Threat Intelligence Feed Integrator

Phase 4A introduces a dedicated feed integrator subsystem instead of one-off API lookups. The subsystem stores normalized IOCs for IPs, domains, URLs, and hashes; deduplicates indicators by source, type, and normalized value; tracks confidence, risk, severity, classification, tags, raw payloads, and expiration; and creates relationship links back to events, alerts, and assets.

Feed adapters are separated behind a normalization boundary for VirusTotal, AbuseIPDB, AlienVault OTX, Shodan, GreyNoise, and generic/custom feeds. Current adapters normalize already-received payloads and are intentionally network-free; future workers can fetch provider feeds asynchronously before passing payloads into this layer.

### Analyst Experience

The React dashboard provides SOC workflows: live dashboard counters, activity timeline, alert and incident actions, ingestion controls, graph investigation, MITRE coverage, AI copilot, case management, report export, admin user management, and live collector health.

### Graph Intelligence

The investigation graph uses backend aggregation by default so repeated telemetry becomes analyst-readable clusters instead of raw node noise. It groups repeated events and alerts into cluster nodes, connects source IPs, assets, alert clusters, event clusters, incidents, and MITRE techniques, and returns graph statistics such as top source IPs, top techniques, most connected assets, relationship weights, and high-risk clusters. Dense graphs are summarized aggressively by source IP and detection family before rendering. The frontend applies focus mode, cluster expansion, progressive labels, edge visibility controls, and graph filters to support enterprise SOC investigation workflows. Graph responses include first-seen and last-seen metadata on clusters to prepare for future timeline replay.

### Realtime Layer

WebSocket events notify the dashboard when collectors heartbeat, telemetry is ingested, alerts change, MITRE mapping completes, graph data changes, cases update, or dashboard metrics should refresh.

## Current Engineering Direction

The platform is moving from sample telemetry into real endpoint collection with persistent Windows Event Log cursors, deeper Sysmon parsing, detection content pipelines, fleet management, and enterprise multi-tenant architecture.
