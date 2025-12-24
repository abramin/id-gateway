# Token Lifecycle Module (PRD-016)

## Summary

The token lifecycle module manages how tokens live and die. It handles refreshing expired tokens, revoking compromised ones, and letting users see and manage their active sessions across devices. Think of it as the "session control panel" for both users and security teams.

## Why this matters (product view)

- Users stay logged in for weeks without re-entering credentials, improving the experience.
- Security teams can instantly revoke access when a device is stolen or credentials are compromised.
- Users can see all their active sessions ("Chrome on MacBook", "Safari on iPhone") and log out remotely.
- Token rotation means even if an attacker steals a refresh token, it becomes useless after one use.
- Compliance teams can demonstrate that revocation is immediate and auditable.

## What was delivered

### Refresh Token Flow
- **Long-lived sessions**: Refresh tokens last 30 days, letting users stay logged in without constant re-authentication.
- **Token rotation**: Every time a refresh token is used, a new one is issued and the old one is invalidated. This means stolen tokens can only be used once.
- **Replay detection**: If someone tries to use an old (already-used) refresh token, the entire session family is revoked. This catches attackers who replay stolen tokens.

### Token Revocation
- **Single logout**: Users can revoke their current session via `POST /auth/revoke`.
- **Remote session revocation**: Users can revoke specific sessions on other devices via `DELETE /auth/sessions/{id}`.
- **Revocation list**: Revoked access tokens are tracked in a list (with TTL matching token expiry) so they're rejected even before natural expiration.

### Session Management
- **Session listing**: Users can see all their active sessions via `GET /auth/sessions`, including device name and approximate location.
- **Current session indicator**: The API marks which session belongs to the current request.
- **Device metadata**: Each session shows user-friendly info like "Chrome on macOS" and "San Francisco, US" for session management UIs.

### Device Binding
- **Device ID cookie**: A stable, httpOnly cookie identifies the device across sessions.
- **Fingerprint validation**: Browser characteristics are hashed and compared to detect device changes.
- **Graceful degradation**: Works with legacy sessions that predate device tracking.

## Benefits

| Feature | Benefit | Who cares |
|---------|---------|-----------|
| 30-day refresh tokens | Users stay logged in for weeks | Users, UX team |
| Token rotation | Stolen tokens become useless after use | Security teams |
| Replay detection | Attackers using old tokens trigger full revocation | Security teams |
| Instant revocation | Compromised sessions are killed immediately | Security, compliance |
| Session listing | Users can audit their own access | Users, privacy advocates |
| Remote logout | Users can secure their account from anywhere | Users, support teams |
| Device binding | Tokens can't be used from different devices | Security teams |

## Design decisions explained

### Why rotate refresh tokens on every use?
If an attacker intercepts a refresh token, they might try to use it. With rotation, the legitimate user's next refresh will fail (because the attacker already used the token), alerting them to a problem. Without rotation, both attacker and user could use the same token indefinitely.

### Why a separate revocation list instead of just checking the database?
Access tokens are validated on every API request. Checking a database for every request would be slow. The revocation list is an in-memory structure with TTL matching token expiry, making checks fast. For production, this moves to Redis for multi-instance deployments.

### Why device ID cookies instead of IP binding?
IP addresses change constantly (VPNs, mobile networks, coffee shop WiFi). Blocking users because their IP changed would create terrible UX. A stable device ID cookie identifies the device reliably even when IPs change.

### Why hash fingerprints instead of storing raw data?
Storing raw user-agent strings and IP addresses creates privacy liability. Hashing lets us compare "is this the same device?" without storing identifying information.

### Why show approximate location in session list?
Users need to recognize their own sessions. "San Francisco, US" helps distinguish "my phone" from "suspicious login from another country". We derive this from IP at session creation time and store it for display.

## Security highlights

- **Token rotation**: Each refresh invalidates the old token.
- **Replay attack detection**: Reusing old tokens revokes the entire session family.
- **JTI tracking**: Every access token has a unique ID for revocation.
- **Device binding**: Tokens are bound to devices via cookie and fingerprint.
- **TTL-based cleanup**: Revocation list entries expire automatically when tokens would have expired anyway.

## Integration points

- Built on top of auth module's session and token models.
- Shares JWT service for token generation and validation.
- Uses same audit publisher for lifecycle events.
- HTTP endpoints:
  - `POST /auth/token` (grant_type=refresh_token) - Refresh access token
  - `POST /auth/revoke` - Revoke a token/session
  - `GET /auth/sessions` - List user's sessions
  - `DELETE /auth/sessions/{id}` - Revoke specific session

## Known gaps / follow-ups

- **Logout-all endpoint**: `POST /auth/logout-all` is specified but not yet implemented. Depends on password change flow (PRD-022) for "revoke all on password change" use case.
- **Concurrent session limits**: Specified as optional, not yet implemented.
- **Redis revocation list**: Currently in-memory; needs Redis for multi-instance deployments.
- **Key rotation drills**: Testing for key rotation scenarios not yet documented.
