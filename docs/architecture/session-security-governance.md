# Session Security & Access Governance

HexSOC AI session security adds server-side governance to analyst, admin, and super-admin access while preserving the existing JWT login flow.

## Goals

- Track active user sessions.
- Add session revocation and logout-all controls.
- Bind new JWTs to a server-side `jti` session record.
- Reject revoked, expired, or idle-timed-out sessions.
- Track failed and blocked login attempts.
- Temporarily lock identities/IPs after repeated failures.
- Surface session and login-attempt visibility in the dashboard.

## Data Models

### UserSession

`user_sessions` stores session lifecycle metadata:

- user id
- token jti/session id
- created, last seen, and expiration timestamps
- revocation timestamp and reason
- IP address and user-agent
- active flag

### LoginAttempt

`login_attempts` stores bounded authentication attempts:

- email or username
- IP address and user-agent
- outcome: `success`, `failure`, `blocked`, or `locked`
- reason
- timestamp

## JWT Compatibility

New tokens include `jti`. The auth dependency validates the token signature and expiration, then checks the server-side session if a `jti` exists. Legacy tokens without `jti` are allowed during transition but cannot be revoked individually.

## Governance Controls

APIs:

- `GET /api/auth/sessions`
- `POST /api/auth/sessions/revoke/{session_id}`
- `POST /api/auth/logout-all`
- `GET /api/auth/login-attempts`

Users can view and revoke their own sessions. Admin and super-admin users with `audit.read` can view broader session governance data.

## Lockout Behavior

Repeated failed login attempts within the configured lockout window produce a temporary lockout response. Lockout thresholds are configurable with:

- `MAX_FAILED_LOGIN_ATTEMPTS`
- `ACCOUNT_LOCKOUT_MINUTES`

## Configuration

- `ACCESS_TOKEN_EXPIRE_MINUTES`
- `SESSION_IDLE_TIMEOUT_MINUTES`
- `MAX_FAILED_LOGIN_ATTEMPTS`
- `ACCOUNT_LOCKOUT_MINUTES`

## Audit Integration

Audit records are written for:

- login success
- login failure
- account lockout
- blocked inactive/pending login
- session revocation
- logout-all
- permission-denied events

No passwords, raw JWTs, or secrets are logged.
