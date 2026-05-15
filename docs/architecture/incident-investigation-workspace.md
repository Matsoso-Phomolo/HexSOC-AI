# Incident Investigation Workspace

Phase 4C.3 connects escalated incidents back to the intelligence that created them.

## Purpose

An escalated incident should become an analyst workspace, not a disconnected ticket. The workspace links incident details to attack-chain or campaign context, timeline preview, deterministic recommendations, evidence checklist items, and existing case notes/evidence.

## API

- `GET /api/incidents/{incident_id}/workspace`
- `POST /api/incidents/{incident_id}/workspace/evidence-checklist`

## Workspace Payload

The workspace response is bounded:

- `incident`
- `linked_attack_chain`
- `linked_campaign`
- `timeline_preview`
- `recommendations`
- `evidence_checklist`
- `case_notes`
- `case_evidence`
- `summary`

## Linkage

The workspace parses escalation markers stored by Phase 4C.2:

```text
[hexsoc-escalation:attack_chain:{id}]
[hexsoc-escalation:campaign:{id}]
```

If no marker exists, the workspace still returns incident-driven deterministic guidance.

## Safety

- No graph rendering.
- No external provider calls.
- No LLM calls.
- No containment or destructive response actions.
- Evidence checklist creation only creates case evidence records.
