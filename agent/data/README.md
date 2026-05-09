# Agent Runtime Data

The HexSOC Agent creates runtime queue files here when telemetry cannot be delivered.

- `offline_queue.jsonl` stores pending telemetry retries.
- `dead_letter_queue.jsonl` stores payloads that exceeded retry limits.
- `agent_state.json` stores deduplication fingerprints and send counters.

Runtime queue/state files are ignored by git and must not contain collector API keys.
