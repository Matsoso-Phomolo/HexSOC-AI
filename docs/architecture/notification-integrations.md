# Notification Integrations

HexSOC AI notification integrations provide a safe outbound alerting foundation for high-value SOC and governance events.

## Goals

- Notify operators about critical incidents, degraded collectors, account lockouts, and critical attack-chain findings.
- Keep notification delivery optional and configurable.
- Avoid leaking secrets, raw API keys, JWTs, passwords, webhook URLs, or provider credentials.
- Ensure notification failures never roll back SOC workflow transactions.
- Rate-limit repeated events to avoid alert fatigue.

## Supported Channels

Initial Phase 4E.4 support includes:

- Generic webhook provider abstraction for Discord, Slack-style, or custom webhook receivers.
- Email provider placeholder for future SMTP or managed email integration.
- Notification delivery logs for operator visibility.

Webhook and email secrets are configured only through environment variables. The dashboard reports whether channels are configured but never displays secret targets.

## Event Types

The initial notification event taxonomy includes:

- `incident_escalated`
- `critical_attack_chain_detected`
- `collector_offline`
- `collector_degraded`
- `account_locked`
- `repeated_failed_login`
- `permission_denied_spike`
- `audit_failure`
- `threat_intel_provider_error`

Only bounded, sanitized metadata is included in notification payloads.

## Runtime Behavior

Notification delivery is handled by `backend/app/services/notification_service.py`.

The service:

- Builds provider-neutral notification events.
- Sanitizes payload metadata with the audit redaction helper.
- Applies event-level rate limiting.
- Sends configured webhook notifications when enabled.
- Records delivery outcomes in `notification_logs`.
- Fails safely and logs delivery errors without raising into SOC workflows.

## Configuration

Environment variables:

- `NOTIFICATIONS_ENABLED`
- `NOTIFICATION_WEBHOOK_URL`
- `NOTIFICATION_EMAIL_ENABLED`
- `NOTIFICATION_EMAIL_FROM`
- `NOTIFICATION_EMAIL_TO`
- `NOTIFICATION_RATE_LIMIT_SECONDS`

## API Surface

Admin and super-admin users can access:

- `GET /api/notifications/logs`
- `GET /api/notifications/summary`
- `POST /api/notifications/test`

These endpoints use existing audit-read governance permissions.

## Security Notes

- Webhook URLs are never returned through API responses.
- Raw secrets are redacted from metadata before storage.
- Notification logs are bounded through API limits.
- Delivery failure does not block incident creation, attack-chain rebuilds, collector health updates, or authentication workflows.
