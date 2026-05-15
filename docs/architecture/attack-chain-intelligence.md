# Attack Chain Intelligence

HexSOC AI Phase 4B introduces bounded attack-chain reconstruction over stored SOC data. The goal is to move from isolated alert triage into chronological, multi-stage intrusion reasoning without introducing heavy graph layout or uncontrolled provider calls.

## Purpose

Attack Chain Intelligence correlates security events, alerts, MITRE mappings, IOC links, users, assets, and time proximity into compact chain candidates. The output is designed for future timeline replay, AI investigation summaries, campaign clustering, and graph investigation enrichment.

## Architecture

Telemetry and alerts are already stored in PostgreSQL. Phase 4B adds three service boundaries:

- `attack_chain_engine.py` computes bounded attack-chain candidates from recent events, alerts, assets, and IOC links.
- `attack_timeline_builder.py` converts related entities into replay-ready chronological timeline steps.
- `campaign_cluster_engine.py` groups related chains into lightweight campaign candidates.

No new persistent attack-chain tables are introduced in this pass. The API returns computed, bounded intelligence. Persistence is intentionally deferred to Phase 4B.1 after the scoring and workflow surface stabilize.

## Attack Stages

The engine maps telemetry and MITRE metadata into these supported stages:

- Initial Access
- Execution
- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Lateral Movement
- Command and Control
- Exfiltration
- Impact

## Scoring

Risk scoring is deterministic and capped at 100. It considers:

- number of observed attack stages
- highest severity observed
- MITRE tactic and technique diversity
- related IOC link count
- alert confidence
- credential access presence
- lateral movement presence
- command and control presence
- impact or malware indicators

Classifications:

- `0-24`: low
- `25-49`: suspicious
- `50-74`: high
- `75-100`: critical

## API

- `GET /api/attack-chains`
- `GET /api/attack-chains/{chain_id}`
- `GET /api/attack-chains/{chain_id}/timeline`
- `GET /api/campaigns`
- `POST /api/attack-chains/rebuild`

List endpoints use bounded limits. Default limit is 50 and maximum limit is 200.

## Safety

- No external threat provider calls occur during chain rebuild.
- No full graph layout is computed server-side.
- Queries are bounded with explicit limits.
- Correlation failure is isolated from dashboard-critical SOC CRUD behavior.

## Future Work

Phase 4B.1 should evaluate persistence for `AttackChain`, `AttackChainStep`, and `CampaignCluster` after computed results have been validated against real telemetry. Later phases can add timeline replay, graph attack paths, and AI copilot chain reasoning.
