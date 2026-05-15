# Investigation Recommendation Engine

HexSOC AI Phase 4C.1 adds a deterministic SOC recommendation layer on top of persisted attack chains and campaign clusters.

## Purpose

The engine converts existing platform intelligence into explainable analyst guidance. It does not call external LLMs, trigger containment actions, or perform autonomous response.

## Inputs

- Persisted attack chains
- Campaign clusters
- Caller-supplied alert, incident, or raw investigation context
- Risk score and classification
- MITRE tactics and techniques
- Attack stages
- Affected assets
- Involved users
- IOC relationship metadata when available

## Outputs

The recommendation payload is bounded and deterministic:

- `summary`
- `priority`
- `recommended_actions`
- `evidence_to_collect`
- `escalation_required`
- `mitre_context`
- `analyst_next_steps`
- `analyst_notes`
- `response_priority`

## API

- `GET /api/investigation/recommendations/attack-chain/{chain_id}`
- `GET /api/investigation/recommendations/campaign/{campaign_id}`
- `POST /api/investigation/recommendations/context`

## Design Constraints

- No external LLM calls.
- No automated response actions.
- No endpoint isolation or shutdown behavior.
- No provider lookups.
- Bounded payloads and simple deterministic scoring.

This layer prepares HexSOC AI for future AI narrative generation, case guidance, response playbooks, and autonomous SOC copilot reasoning while keeping Phase 4C.1 production-safe.
