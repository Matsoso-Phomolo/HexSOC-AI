# Data Flow

Security telemetry enters HexSOC AI through collectors, integrations, and API ingestion routes. Events are normalized, streamed through Kafka topics, persisted in PostgreSQL, enriched by services, scored by detection logic, and surfaced to analysts through APIs and WebSocket alerts.

Use this document to define ingestion contracts, topic ownership, storage boundaries, and alert lifecycle flow.
