# OAuth2 Demo Suite - Walkthrough Guide

This guide explains how to use the Credo OAuth2 demo pages to understand and test the complete OAuth2 authorization code flow.

## Overview

The demo suite consists of separate HTML pages that demonstrate a realistic OAuth2 authorization code flow with:

- **True browser redirects** (not simulated)
- **Separate pages** for authorization and callback
- **Explicit token exchange** requiring user action
- **Visible session and token lifecycle controls**
- **Raw API responses** for debugging

## Architecture

```
┌─────────────────┐
│  /demo/index    │  Landing page with links to all demos
└────────┬────────┘
         │
         v
┌─────────────────┐     redirect      ┌─────────────────┐
│ /demo/authorize │ ─────────────────> │ /demo/callback  │
└─────────────────┘   with code+state  └────────┬────────┘
                                                 │
                                                 v
                                        ┌────────────────┐
                                        │  Access Token  │
                                        └───┬────────┬───┘
                                            │        │
                              ┌─────────────┘        └──────────────┐
                              v                                     v
                      ┌──────────────┐                    ┌─────────────┐
                      │/demo/sessions│                    │/demo/tokens │
                      └──────────────┘                    └─────────────┘
```

## Demo Pages

### 1. Authorization Request (`/demo/authorize.html`)

**Purpose**: Initiate the OAuth2 authorization code flow

**How to use**:
1. Open http://localhost:3000/demo/authorize.html (or your demo URL)
2. Fill in the form:
   - **Email**: `alice@example.com` (or any demo user)
   - **Client ID**: `demo-client` (pre-filled)
   - **Redirect URI**: Auto-filled to callback page
   - **State**: Random value for CSRF protection (pre-generated)
   - **Scopes**: Select `openid` and/or `profile`
3. Click **"Authorize"**
4. You will be **redirected** to the callback page

**What happens**:
```http
POST /auth/authorize
Content-Type: application/json

{
  "email": "alice@example.com",
  "client_id": "demo-client",
  "redirect_uri": "http://localhost:3000/demo/callback.html",
  "state": "demo-state-abc123",
  "scopes": ["openid", "profile"]
}

Response 200 OK:
{
  "code": "authz_...",
  "redirect_uri": "http://localhost:3000/demo/callback.html?code=authz_...&state=demo-state-abc123"
}
```

The page then performs `window.location.href = redirect_uri` - a **real redirect**.

### 2. OAuth Callback (`/demo/callback.html`)

**Purpose**: Receive authorization code and exchange for tokens

**How to use**:
1. This page automatically loads after redirect from authorize
2. You'll see:
   - The **authorization code** from URL query params
   - The **state** parameter echoed back
3. Review the received parameters
4. Click **"Exchange Code for Tokens"**
5. View the token response with:
   - Raw JSON response
   - Decoded access token (JWT claims)
   - Decoded ID token (JWT claims)
   - Token expiry information

**What happens**:
```http
POST /auth/token
Content-Type: application/json

{
  "grant_type": "authorization_code",
  "code": "authz_...",
  "redirect_uri": "http://localhost:3000/demo/callback.html",
  "client_id": "demo-client"
}

Response 200 OK:
{
  "access_token": "eyJhbGci...",
  "id_token": "eyJhbGci...",
  "expires_in": 3600000000000,
  "token_type": "Bearer"
}
```

Tokens are stored in `sessionStorage` for use in other demo pages.

### 3. Session Management (`/demo/sessions.html`)

**Purpose**: View and manage active user sessions

**How to use**:
1. Paste your access token (or it auto-loads from previous step)
2. Click **"Load Sessions"**
3. View table of active sessions:
   - Device information
   - Location
   - Created/last seen timestamps
   - Current session indicator
4. Actions:
   - **Revoke** individual sessions
   - **Logout All Other Sessions**

**Note**: Session management endpoints may not be fully implemented yet. The page will show a helpful error message explaining the expected API contract.

**Expected API**:
```http
GET /auth/sessions
Authorization: Bearer {access_token}

Response 200 OK:
{
  "sessions": [
    {
      "id": "uuid",
      "device": "Chrome on macOS",
      "location": "San Francisco, CA",
      "created_at": "2025-12-13T10:00:00Z",
      "last_seen": "2025-12-13T11:30:00Z",
      "is_current": true
    }
  ]
}
```

### 4. Token Lifecycle (`/demo/tokens.html`)

**Purpose**: Manage token lifecycle - analyze, refresh, and revoke

**How to use**:
1. Paste your access token (or it auto-loads from previous step)
2. Click **"Analyze Token"** to see:
   - Subject, issuer, issued/expiry dates
   - Live countdown timer until expiry
   - Full JWT claims
3. Try token operations:
   - **Refresh Token**: Get new access token (requires refresh token)
   - **Revoke Token**: Invalidate current token

**Note**: Refresh and revocation endpoints may not be fully implemented yet. The page shows API contracts and gracefully handles missing endpoints.

### 5. Admin Operations (`/demo/admin.html`)

**Purpose**: Demonstrate admin-level destructive operations

**⚠️ WARNING**: This page performs destructive operations!

**How to use**:
1. Enter **Admin API Token** (from `ADMIN_API_TOKEN` env var)
2. Click **"Test Authentication"** to verify token
3. Enter **User ID** (UUID) to delete
4. Click **"Delete User"**
5. Review confirmation checklist:
   - User data will be permanently deleted
   - All sessions will be revoked
   - All refresh tokens will be invalidated
   - Action cannot be undone
6. Check all boxes and click **"⚠️ Confirm Deletion"**

**What happens**:
```http
DELETE /admin/auth/users/{user_id}
X-Admin-Token: {admin_token}

Response 204 No Content (success)
```

This exercises PRD-001B flows for user deletion.

## Complete Walkthrough

### Basic OAuth Flow

1. **Start**: Navigate to http://localhost:3000/demo/index.html
2. **Click**: "▶ Start Authorization Flow" button
3. **Authorize**: Fill form (use `alice@example.com`) and click "Authorize"
4. **Redirect**: Browser automatically redirects to callback page
5. **Exchange**: Click "Exchange Code for Tokens"
6. **Review**: Examine decoded JWT claims and expiry

### Session Management Flow

1. **Complete** the basic OAuth flow above
2. **Navigate**: Click "Manage tokens (refresh, revoke)" link
3. **Or go to**: http://localhost:3000/demo/sessions.html
4. **Load**: Sessions list (token auto-loaded from sessionStorage)
5. **Manage**: Revoke individual sessions or logout all others

### Token Lifecycle Flow

1. **Complete** the basic OAuth flow
2. **Navigate**: http://localhost:3000/demo/tokens.html
3. **Analyze**: View token metadata and expiry countdown
4. **Refresh**: Try refreshing the access token (if backend supports)
5. **Revoke**: Revoke token to logout

### Admin Flow

1. **Get**: Admin token from environment variable
2. **Navigate**: http://localhost:3000/demo/admin.html
3. **Authenticate**: Paste admin token and test
4. **Delete**: Enter user UUID and complete deletion workflow

## Key Differences from Legacy Demo

The new demo suite (`/demo/*`) differs from the legacy demo (`/demo.html`) in important ways:

| Feature | Legacy Demo | New Demo Suite |
|---------|-------------|----------------|
| **Redirect** | Simulated (fake) | Real browser redirect |
| **Pages** | Single page | Separate authorize & callback |
| **State** | Shared Alpine.js state | No shared state between pages |
| **Token storage** | Component scope only | sessionStorage |
| **OAuth semantics** | Simplified | Production-like |
| **Debugging** | Hidden details | All responses visible |

## Technical Details

### Stack

- **HTML**: Plain HTML5, no templating
- **CSS**: Tailwind CSS (CDN)
- **JS**: Alpine.js (CDN) + vanilla JS
- **Storage**: sessionStorage (page refresh clears state)
- **Routing**: None - each page is separate

### Shared Helpers

All pages use `/js/oauth-helpers.js` for common functions:

- `getAPIBase()` - Determine API URL based on environment
- `decodeJWT(token)` - Decode JWT and add readable timestamps
- `apiRequest(endpoint, options)` - Consistent fetch wrapper
- `formatExpiry(nanoseconds)` - Format expiry time
- `generateState()` - CSRF state generator
- `getStoredTokens()` / `storeTokens()` - sessionStorage helpers

### API Base URL Detection

The demos automatically detect the correct API base URL:

```javascript
function getAPIBase() {
  if (window.location.port === "3000") {
    return "/api";  // Docker nginx proxy
  }
  if (window.location.hostname === "localhost") {
    return "http://localhost:8080";  // Direct backend
  }
  return "";  // Same origin
}
```

### State Management

- **No persistence**: Page refresh clears all state
- **sessionStorage**: Used only for passing tokens between demo pages
- **No localStorage**: Explicitly avoided per requirements
- **Alpine.js scope**: Each page has isolated Alpine component

## Debugging Tips

### View Raw Responses

All demo pages show:
- Raw JSON responses
- HTTP status codes
- Request/response bodies
- Error details

### Browser DevTools

Open DevTools to see:
- Network tab: All HTTP requests
- Console: Any JavaScript errors
- Application tab: sessionStorage contents

### Common Issues

**Authorization fails with redirect error**:
- Check `ALLOWED_REDIRECT_SCHEMES` environment variable
- Ensure redirect URI uses allowed scheme (http/https)

**Token exchange fails**:
- Verify authorization code wasn't already used
- Check that redirect_uri matches exactly
- Confirm code hasn't expired (10 minute TTL)

**Session/token pages show "not implemented"**:
- These endpoints may not exist in current backend
- Pages show expected API contracts for reference
- Safe to ignore if testing basic OAuth flow

## Environment Variables

Required for demo functionality:

```bash
# Backend
ID_GATEWAY_ADDR=":8080"
REGULATED_MODE="false"
ALLOWED_REDIRECT_SCHEMES="http,https"  # Important!

# Admin operations
ADMIN_API_TOKEN="your-secret-admin-token"

# JWT
JWT_SIGNING_KEY="your-secret-key"
JWT_ISSUER="http://localhost:8080"
TOKEN_TTL="15m"
SESSION_TTL="24h"
```

## Running the Demo

### Docker Compose (Recommended)

```bash
# From project root
docker-compose -f docker-compose.demo.yml up

# Access demos at:
# http://localhost:3000/demo/index.html
```

### Local Development

```bash
# Terminal 1: Run backend
cd cmd/server
go run main.go

# Terminal 2: Serve frontend
cd frontend/public
python3 -m http.server 3000

# Access demos at:
# http://localhost:3000/demo/index.html
```

## Testing Checklist

Use this checklist to verify all functionality:

- [ ] Authorization initiates and redirects correctly
- [ ] Callback receives code and state parameters
- [ ] Code exchange returns valid JWT tokens
- [ ] Access token decodes and shows claims
- [ ] ID token decodes and shows user info
- [ ] Token expiry countdown updates live
- [ ] Session page loads or shows "not implemented"
- [ ] Token page loads or shows "not implemented"
- [ ] Admin authentication works with valid token
- [ ] Admin user deletion requires confirmation
- [ ] All pages show raw JSON responses
- [ ] Error messages are clear and helpful

## Non-Goals

This demo explicitly does NOT include:

- ❌ SPA routing or client-side navigation
- ❌ localStorage for token persistence
- ❌ PKCE (Proof Key for Code Exchange)
- ❌ Refresh token storage outside memory
- ❌ Production-grade styling or UX polish
- ❌ Mock data or fake responses
- ❌ OAuth client registration
- ❌ Multi-tenancy

## Future Enhancements

Potential additions (not currently implemented):

- Session management backend endpoints
- Token refresh endpoint
- Token revocation endpoint
- Consent management integration
- Device flow demonstration
- Client credentials flow
- OpenID Connect discovery

## Support

For issues or questions:

1. Check browser console for errors
2. Review "Raw API Response" sections in demo pages
3. Verify environment variables are set correctly
4. Check backend logs for detailed error messages

## References

- **PRD-001**: OAuth2 and OpenID Connect implementation
- **PRD-001B**: User lifecycle and deletion flows
- OAuth 2.0 RFC 6749: https://tools.ietf.org/html/rfc6749
- OpenID Connect Core: https://openid.net/specs/openid-connect-core-1_0.html
