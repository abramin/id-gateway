# Auth Module (PRD-001, PRD-001B)

## Summary

The auth module is the front door to Credo. It handles how users prove who they are (authentication) and issues the digital passes (tokens) that let them access the system. It also provides administrative controls to remove users when needed for compliance or security.

## Why this matters (product view)

- Users can log in once and stay logged in across browser sessions without re-entering credentials.
- Applications get standardized tokens they can verify independently, reducing backend calls.
- Device fingerprinting detects when someone tries to use stolen credentials from a new device.
- Audit logs capture every login, token issuance, and deletion for compliance investigations.
- Admin deletion enables GDPR "right to erasure" requests to be fulfilled quickly.

## What was delivered

### Core Authentication Flow
- **OAuth 2.0 Authorization Code Flow**: Users authenticate via a two-step process (get code, exchange for tokens) that follows industry standards. This means integrators familiar with Google, Microsoft, or other OAuth providers will recognize the pattern.
- **JWT Access Tokens**: Short-lived (15 minutes) tokens that applications can verify without calling back to Credo. Contains user ID, session ID, client ID, and tenant ID.
- **ID Tokens**: OIDC-compliant tokens for user profile information (email, name).
- **Refresh Tokens**: Long-lived (30 days) tokens that let applications get new access tokens without bothering the user to log in again.

### Session Management
- **Device Fingerprinting**: Every session captures a hashed fingerprint of the browser and device. If someone tries to use a token from a different device, the system can detect and flag it.
- **Privacy-First Design**: We store hashed fingerprints, not raw browser data. Display-friendly metadata (like "Chrome on macOS") is stored separately for user-facing session lists.
- **Session Status**: Sessions can be "pending", "active", or "revoked", with clear lifecycle transitions.

### Administrative Controls
- **User Deletion**: Admin-only endpoint (`DELETE /admin/auth/users/{id}`) removes a user and all their sessions atomically.
- **Session Cleanup**: When a user is deleted, all their sessions are revoked first, ensuring no orphaned access.
- **Audit Trail**: Both `sessions_revoked` and `user_deleted` events are logged for compliance.

## Benefits

| Feature | Benefit | Who cares |
|---------|---------|-----------|
| Authorization code flow | Tokens never pass through browser URL bar | Security teams, compliance |
| Short-lived access tokens | Compromised tokens expire quickly | Security teams |
| Refresh token rotation | Old tokens become invalid after use | Security teams |
| Device fingerprinting | Detect credential theft from new devices | Security teams, users |
| Privacy-first fingerprints | No raw PII stored | Privacy officers, legal |
| Admin deletion | GDPR erasure in one API call | Legal, compliance |
| Per-tenant issuers | Each customer gets their own token issuer URL | Enterprise customers, compliance |

## Design decisions explained

### Why authorization codes instead of direct tokens?
The authorization code flow adds a step (get code, then exchange for tokens) but prevents tokens from appearing in browser history or logs. This matters because URLs are often logged, and tokens in URLs could be stolen.

### Why separate session, authorization code, and refresh token models?
These three concepts have very different lifetimes: codes last 10 minutes, access tokens 15 minutes, refresh tokens 30 days. Mixing them in one data structure would waste memory (dead fields) and make cleanup confusing. Separating them means each can be managed independently.

### Why hash device fingerprints?
Storing raw browser user-agent strings and IP addresses creates a privacy liability. By hashing, we can still compare "is this the same device?" without storing data that could identify someone.

### Why use per-tenant issuer URLs?
Enterprise customers often need to configure their applications to trust tokens from a specific issuer. By using `https://auth.credo.io/tenants/{tenant_id}` as the issuer, each tenant has a unique, verifiable source for their tokens.

### Why admin-only deletion?
Self-service deletion is complex (confirmation flows, cooling-off periods, downstream notifications). For Phase 0, we prioritized the compliance-critical path: an admin can delete a user when legally required. Self-service can be added later.

## Security highlights

- **Authorization code replay prevention**: Each code can only be used once. Reusing a code is rejected.
- **Redirect URI validation**: The return URL must exactly match what was registered for the client.
- **Token expiry**: Access tokens expire in 15 minutes; refresh tokens in 30 days.
- **JTI claim**: Every access token has a unique ID, enabling revocation list checks.
- **Audit logging**: Every authentication event is logged with timestamps and user IDs.

## Integration points

- Auth service uses `ClientResolver` from the tenant module to map `client_id` to tenant.
- Tokens include `tenant_id` and `client_id` claims for downstream authorization.
- HTTP endpoints:
  - `POST /auth/authorize` - Start login, get authorization code
  - `POST /auth/token` - Exchange code for tokens
  - `GET /auth/userinfo` - Get user profile
  - `DELETE /admin/auth/users/{id}` - Admin user deletion

## Known gaps / follow-ups

- Password authentication not implemented (email-only demo flow).
- Multi-factor authentication deferred to Phase 3 (PRD-021).
- Self-service account deletion deferred.
- Audit events should include email when available for deletion flows.
