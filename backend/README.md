# Backend

FastAPI service foundation for HexSOC AI.

Responsibilities:

- Expose API routes for assets, events, alerts, incidents, detections, and health checks.
- Manage PostgreSQL persistence and migrations.
- Publish and consume Kafka security telemetry.
- Run risk, alert, detection, enrichment, and AI orchestration services.
- Provide WebSocket alert delivery to the SOC dashboard.
- Encapsulate integrations with external security tools and telemetry sources.
