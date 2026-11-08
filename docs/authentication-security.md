# Authentication security

Atlas uses signed JWTs as opaque browser credentials and PostgreSQL as the
authoritative session and revocation store. A valid signature alone is not enough:
every authenticated request must reference an unexpired, unrevoked
`auth_sessions` row and an active user/tenant.

## Signing keys and rotation

`AUTH_SECRET_KEY` must contain at least 32 bytes, have reasonable character
diversity, and must not contain a known placeholder such as `replace-with` or
`change-me`. Startup fails when validation fails.

New tokens include `iss`, `aud`, `jti`, `iat`, `nbf`, `exp`, and a `kid` header.
Configure:

- `AUTH_KEY_ID` as the identifier of the current `AUTH_SECRET_KEY`;
- `AUTH_JWT_ISSUER` and `AUTH_JWT_AUDIENCE` for deployment-specific validation;
- `AUTH_PREVIOUS_KEYS` as a JSON object mapping old key IDs to old secrets.

During rotation, move the previous secret into `AUTH_PREVIOUS_KEYS`, configure a
new key ID and secret, restart all instances, and keep the old key until its last
session expires or is revoked. Never reuse the Tenant Domain Contract signing key.

## Browser request protection

Every state-changing `/api/` request must carry an `Origin` exactly listed in
`AUTH_ALLOWED_ORIGINS`. Requests with a missing or unapproved origin fail with
HTTP 403. Add only the real browser origins that serve Atlas; do not use `*` with
credentialed requests.

Responses include a restrictive Content Security Policy, clickjacking protection,
MIME sniffing protection, referrer and permissions policies, and HSTS whenever
`COOKIE_SECURE=true`. Production must use HTTPS and set `COOKIE_SECURE=true`.

## Throttling and lockout

Rate-limit state is stored in `auth_rate_limits`, so limits apply across workers
and restarts. Login attempts are limited by source address and normalized account
identifier. Registration, verification resend, and password-reset requests are
limited by both address and email.

Approved accounts are temporarily locked after five consecutive invalid passwords.
The lock increases from one minute to five minutes, fifteen minutes, and then one
hour. A successful login clears the counter. Error messages do not reveal whether
an unknown email exists.

## Email verification and password recovery

New registrations receive a random, one-time email-verification token and cannot
sign in until both email verification and administrator approval are complete.
Password-reset tokens expire after one hour. Successful password reset revokes all
existing sessions. Only SHA-256 token hashes are stored in PostgreSQL.

Set `AUTH_EMAIL_MODE=smtp` with `SMTP_HOST`, `SMTP_FROM`, and optional credentials
for deployment. `console` writes full links to application logs and is suitable
only for isolated local development. `disabled` creates tokens without delivering
them and should not be used for a live registration flow.

## Session management

Users can open `/account-security` from their workspace to review active sessions,
including browser, source address, issue time, and last activity. A user can revoke
an individual session or use **Log out all devices**. The API routes are:

- `GET /api/auth/sessions`
- `DELETE /api/auth/sessions/{session_id}`
- `POST /api/auth/logout-all`

Normal logout revokes the current server-side session before deleting the cookie.
Suspending an account, changing its role, or deactivating its tenant also revokes
all active sessions for the affected scope. Reactivation therefore requires a new
login and cannot silently restore an older browser session.

## Operational notes

- Set `AUTH_TRUST_PROXY=true` only behind a trusted proxy that overwrites
  `X-Forwarded-For`; otherwise the direct peer address is used.
- Expired sessions, tokens, and old rate-limit rows should be removed by a periodic
  maintenance job in production.
- Authentication email failures are logged without returning account-existence
  information to the requester.
- API responses use `Cache-Control: no-store`, include a generated `X-Request-ID`,
  and apply cross-origin opener/resource policies in addition to CSP and frame
  restrictions.
- `/api/health/live` proves the process can answer HTTP. `/api/health/ready`
  verifies PostgreSQL connectivity and returns HTTP 503 without exposing the
  underlying connection error when the dependency is unavailable.
