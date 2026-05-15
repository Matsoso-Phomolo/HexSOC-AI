# Persistent Attack Chain Storage

Phase 4B.2 moves HexSOC AI attack chains from computed-only API results into stable investigation objects.

## Problem

Computed attack chains used ephemeral IDs derived from the current event and alert membership. As telemetry changed, a chain visible in `GET /api/attack-chains` could fail lookup through `GET /api/attack-chains/{chain_id}/timeline`.

## Decision

Persist attack-chain intelligence after rebuild.

New persistence layer:

- `AttackChain`
- `AttackChainStep`
- `CampaignCluster`
- `InvestigationSession`

The rebuild flow now computes bounded candidates, upserts chains by stable fingerprint, replaces timeline steps for each chain, upserts campaign summaries, and returns database-backed chain IDs.

## Data Flow

```text
Stored events/alerts/MITRE/IOC links
→ attack_chain_engine
→ attack_chain_persistence_service
→ AttackChain + AttackChainStep
→ CampaignCluster
→ stable dashboard APIs
→ InvestigationSession
```

## Stable Identity

Each chain receives:

- a `chain_key` derived from source type/value, MITRE techniques, and users
- a `stable_fingerprint` derived from the chain key
- a database ID exposed as `chain_id` for dashboard compatibility

This keeps chain lookups stable while allowing version increments when membership changes.

## APIs

- `GET /api/attack-chains`
- `GET /api/attack-chains/{chain_id}`
- `GET /api/attack-chains/{chain_id}/timeline`
- `PATCH /api/attack-chains/{chain_id}/status`
- `POST /api/attack-chains/rebuild`
- `GET /api/campaigns`
- `POST /api/investigations/from-attack-chain/{chain_id}`
- `GET /api/investigations`
- `PATCH /api/investigations/{session_id}`

## Security

- Viewer, analyst, and admin can read attack-chain summaries through existing RBAC behavior.
- Analyst/admin can rebuild chains and create/update investigation sessions.
- No external threat provider calls occur during rebuild.
- Raw metadata remains bounded and does not expose secrets.

## Operational Safeguards

- Rebuilds use bounded computed candidates.
- Timeline responses are capped.
- List endpoints default to 50 and max at 200.
- Startup schema sync remains additive.

## Future Work

- Link attack chains directly into case management.
- Add timeline replay and AI narrative summaries.
- Add chain history and version diffing.
- Use persisted chains as first-class graph investigation nodes.
