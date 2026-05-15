# Automated Incident Escalation

HexSOC AI Phase 4C.2 adds deterministic incident escalation from high-risk attack-chain and campaign intelligence.

## Purpose

The escalation engine converts serious intelligence objects into persistent incident workflow records. It preserves analyst control and does not execute containment, isolation, blocking, or destructive response actions.

## Escalation Inputs

- Persisted attack chains
- Campaign clusters
- Caller-supplied bounded context
- Investigation recommendation payloads

## Escalation Criteria

- Attack-chain or campaign risk score is at least 75.
- Classification is `critical`.
- Stage combination includes Credential Access and Command and Control.
- Stage combination includes Lateral Movement and Credential Access.
- Recommendation says escalation is required.
- Multiple critical alerts are linked to the same context.

## Idempotency

Incidents include stable escalation markers in their description:

```text
[hexsoc-escalation:attack_chain:{id}]
[hexsoc-escalation:campaign:{id}]
```

The engine updates an existing open incident when the same marker exists, preventing duplicate incident spam.

## API

- `POST /api/incidents/escalate/attack-chain/{chain_id}`
- `POST /api/incidents/escalate/campaign/{campaign_id}`
- `POST /api/incidents/escalate/context`

## Safety Boundaries

- No endpoint containment.
- No host shutdown.
- No blocking actions.
- No external LLM calls.
- No provider lookups.
- Existing case management and analyst workflows remain authoritative.
