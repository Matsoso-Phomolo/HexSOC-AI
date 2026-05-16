# Audit & Compliance Logging

HexSOC AI records security-relevant platform activity in a dedicated `audit_logs` table so governance, SOC operations, and investigation workflows remain traceable.

## Audit Scope

The audit layer captures high-risk and compliance-relevant actions first:

- Authentication: registration, successful login, failed login, blocked inactive/pending login.
- RBAC: permission-denied events from the centralized permission dependency.
- User governance: approval, disapproval, activation, deactivation, deletion, profile update, and role change.
- Collectors: creation, update, key rotation, revocation, and fleet-management actions.
- Alerts and incidents: alert creation/status changes, incident updates, escalation, and workspace activity.
- Attack chains: rebuild operations and status changes.
- Threat intelligence: IOC ingestion, feed normalization, correlation, graph enrichment, and provider enrichment requests.

## Record Shape

Each audit event stores:

- actor identity: user id, username, effective role where available
- action and category
- target type, id, and label
- outcome: `success`, `failure`, or `denied`
- request context: IP address, user-agent, request id
- bounded sanitized metadata
- creation timestamp

## Secret Handling

Audit metadata is sanitized before persistence. Sensitive keys such as passwords, JWT tokens, authorization headers, collector API keys, raw API keys, hashed passwords, and secrets are redacted. Metadata is bounded by depth, item count, and string length to avoid log amplification.

## Access Control

Audit APIs are protected by `audit.read`. Admin and super-admin users can view audit logs. Analysts and viewers cannot access audit logs.

## API Surface

- `GET /api/audit/logs`
- `GET /api/audit/logs/{audit_id}`
- `GET /api/audit/summary`

Audit list endpoints are bounded with a default limit of 50 and a maximum limit of 500.

## Operational Notes

The audit table is created additively during startup schema synchronization. Audit write failures should not block core SOC workflows unless the surrounding database transaction itself fails.
