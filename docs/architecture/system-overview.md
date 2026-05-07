# System Overview

HexSOC AI is structured around clear service boundaries:

- API services expose SOC workflows and platform administration.
- Streaming services move telemetry and detection events through Kafka.
- AI and ML services enrich, classify, and score security activity.
- The SOC dashboard presents operational views for analysts.
- Integrations connect external security tools and telemetry sources.

This document should become the source of truth for high-level platform architecture.
