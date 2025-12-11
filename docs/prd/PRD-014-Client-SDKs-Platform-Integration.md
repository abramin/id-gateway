# PRD-014: Client SDKs & Platform Integration

**Status:** Not Started
**Priority:** P1 (High - Developer Experience)
**Owner:** Engineering Team
**Dependencies:** PRD-001 (Authentication), PRD-002 (Consent), PRD-003 (Registry), PRD-004 (VCs), PRD-013 (Biometrics)
**Last Updated:** 2025-12-11

---

## 1. Overview

### Problem Statement

Current implementation provides HTTP APIs but no client SDKs, requiring developers to:
- Manually implement OAuth 2.0 flows (authorization code, token exchange)
- Handle JWT token lifecycle (refresh, expiry, storage)
- Build HTTP clients with proper error handling and retry logic
- Implement platform-specific integrations (web, iOS, Android)
- Manage session state across single-page apps and native apps

This creates friction for adoption and increases time-to-integration for partners and internal teams.

### Goals

**V1 (Basic SDK - Language-Agnostic Core):**
- TypeScript/JavaScript SDK for web applications
- Core SDK functionality: authentication, consent, VC verification
- OAuth 2.0 Authorization Code Flow implementation
- Token management (storage, refresh, expiry)
- HTTP client with automatic retry and error handling
- Example integration guides for React, Next.js, Express

**V2 (Production-Ready Multi-Platform SDKs):**
- Native mobile SDKs (Swift for iOS, Kotlin for Android)
- Cross-platform SDKs (React Native, Flutter)
- Backend SDKs (Go, Python, Java)
- Advanced features: WebAuthn, biometric integration, DIDComm
- Enterprise features: SSO, SAML bridge, Active Directory integration
- Developer portal with interactive API explorer

### Non-Goals

- UI component libraries (V1 - provide headless SDK only)
- Custom identity provider integrations (V1 - Credo gateway only)
- Mobile app distribution (developers package SDK in their apps)
- Hosted login pages (V1 - developers build their own UI)

---

## 2. User Stories

### V1 Stories

**As a web developer**
- I want to install `@credo/sdk` via npm
- So that I can integrate Credo authentication in 10 minutes

**As a React developer**
- I want to use `useCredoAuth()` hook
- So that I can manage authentication state declaratively

**As a backend developer**
- I want to verify Credo JWTs in my Node.js API
- So that I can protect my endpoints with Credo authentication

**As a mobile developer**
- I want example code for OAuth 2.0 in Swift/Kotlin
- So that I can implement native authentication flows

### V2 Stories

**As an iOS developer**
- I want to use CredoSDK CocoaPod with Face ID integration
- So that I can add biometric verification to my app

**As an Android developer**
- I want to use CredoSDK Gradle package with BiometricPrompt
- So that I can leverage native biometric hardware

**As a DevOps engineer**
- I want to use CredoSDK in CI/CD pipelines
- So that I can automate user provisioning and testing

---

## 3. SDK Architecture

### 3.1 Core SDK Design (Language-Agnostic)

```
┌─────────────────────────────────────────────────────────────┐
│                     Credo Client SDK                        │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │           Authentication Module                      │  │
│  │  ┌────────────┐  ┌────────────┐  ┌──────────────┐  │  │
│  │  │   OAuth    │  │   Token    │  │   Session    │  │  │
│  │  │   Client   │  │   Manager  │  │   Manager    │  │  │
│  │  └────────────┘  └────────────┘  └──────────────┘  │  │
│  └──────────────────────────────────────────────────────┘  │
│                         │                                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │            API Client Modules                        │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │  │
│  │  │ Consent  │  │ Registry │  │  Biometric       │  │  │
│  │  │ Client   │  │ Client   │  │  Client          │  │  │
│  │  └──────────┘  └──────────┘  └──────────────────┘  │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │  │
│  │  │    VC    │  │ Decision │  │  User Data       │  │  │
│  │  │  Client  │  │  Client  │  │  Client          │  │  │
│  │  └──────────┘  └──────────┘  └──────────────────┘  │  │
│  └──────────────────────────────────────────────────────┘  │
│                         │                                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │          Cross-Cutting Concerns                      │  │
│  │  ┌────────────┐  ┌────────────┐  ┌──────────────┐  │  │
│  │  │   HTTP     │  │   Error    │  │   Storage    │  │  │
│  │  │  Client    │  │  Handling  │  │   Adapter    │  │  │
│  │  └────────────┘  └────────────┘  └──────────────┘  │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
              ┌──────────────────────────────┐
              │     Credo Identity Gateway    │
              │       (HTTP REST API)         │
              └──────────────────────────────┘
```

### 3.2 Platform-Specific Wrappers

```
Core SDK (TypeScript)
       │
       ├──► Web (ES Modules, UMD)
       │      ├──► React Hook (useCredoAuth)
       │      ├──► Next.js Middleware
       │      └──► Express.js Middleware
       │
       ├──► Mobile (Transpiled to Native)
       │      ├──► React Native Module
       │      └──► Flutter Plugin (Dart bindings)
       │
       ├──► Native Mobile (Separate implementations)
       │      ├──► iOS (Swift Package)
       │      └──► Android (Kotlin/AAR)
       │
       └──► Backend (Language-specific)
              ├──► Go SDK
              ├──► Python SDK
              └──► Java SDK
```

---

## 4. Functional Requirements (V1)

### FR-1: TypeScript/JavaScript SDK

**Package:** `@credo/sdk`

**Installation:**

```bash
npm install @credo/sdk
# or
yarn add @credo/sdk
```

**Core API:**

```typescript
import { CredoClient } from '@credo/sdk';

// Initialize client
const credo = new CredoClient({
  gatewayUrl: 'https://gateway.example.com',
  clientId: 'demo-client',
  redirectUri: 'https://myapp.com/callback',
  scopes: ['openid', 'profile'],
  storage: localStorage, // or sessionStorage, custom adapter
});

// 1. Start authentication flow
const authUrl = await credo.auth.authorize({
  email: 'user@example.com',
  state: 'random-csrf-token',
});
// Redirect user to authUrl

// 2. Handle callback (after redirect)
const tokens = await credo.auth.handleCallback(window.location.href);
// Returns: { access_token, id_token, expires_in }

// 3. Get current user
const user = await credo.auth.getUser();
// Returns: { sub, email, name, ... }

// 4. Check authentication status
const isAuthenticated = credo.auth.isAuthenticated();

// 5. Logout
await credo.auth.logout();
```

**Consent Management:**

```typescript
// Grant consent
await credo.consent.grant(['registry_check', 'vc_issuance']);

// List consents
const consents = await credo.consent.list();

// Revoke consent
await credo.consent.revoke(['registry_check']);
```

**Verifiable Credentials:**

```typescript
// Issue VC
const vc = await credo.credentials.issue({
  type: 'AgeOver18',
  national_id: '123456789',
});

// Verify VC
const result = await credo.credentials.verify('vc_abc123');
```

**Biometric Verification:**

```typescript
// Face match
const result = await credo.biometric.faceMatch({
  selfie: selfieBlob,
  reference: idPhotoBlob,
  livenessRequired: true,
});

// Liveness check
const liveness = await credo.biometric.liveness(selfieBlob);
```

**Token Management:**

```typescript
// Automatic token refresh
credo.auth.on('token-refreshed', (tokens) => {
  console.log('Tokens refreshed:', tokens);
});

// Manual token refresh
const newTokens = await credo.auth.refreshTokens();

// Token expiry check
const expiresIn = credo.auth.getTokenExpiry(); // seconds
```

**Error Handling:**

```typescript
import { CredoError, ErrorCode } from '@credo/sdk';

try {
  await credo.consent.grant(['registry_check']);
} catch (error) {
  if (error instanceof CredoError) {
    switch (error.code) {
      case ErrorCode.MissingConsent:
        // Handle missing consent
        break;
      case ErrorCode.Unauthorized:
        // Re-authenticate
        break;
      default:
        // Generic error handling
    }
  }
}
```

---

### FR-2: React Integration

**Package:** `@credo/react`

**Installation:**

```bash
npm install @credo/sdk @credo/react
```

**Provider Setup:**

```tsx
import { CredoProvider } from '@credo/react';

function App() {
  return (
    <CredoProvider
      config={{
        gatewayUrl: 'https://gateway.example.com',
        clientId: 'demo-client',
        redirectUri: 'https://myapp.com/callback',
      }}
    >
      <YourApp />
    </CredoProvider>
  );
}
```

**Authentication Hook:**

```tsx
import { useCredoAuth } from '@credo/react';

function LoginButton() {
  const { login, logout, user, isAuthenticated, isLoading } = useCredoAuth();

  if (isLoading) return <div>Loading...</div>;

  if (isAuthenticated) {
    return (
      <div>
        <p>Welcome, {user.name}!</p>
        <button onClick={logout}>Logout</button>
      </div>
    );
  }

  return <button onClick={() => login('user@example.com')}>Login</button>;
}
```

**Protected Routes:**

```tsx
import { CredoProtectedRoute } from '@credo/react';

function App() {
  return (
    <Routes>
      <Route path="/public" element={<PublicPage />} />
      <Route
        path="/dashboard"
        element={
          <CredoProtectedRoute>
            <Dashboard />
          </CredoProtectedRoute>
        }
      />
    </Routes>
  );
}
```

**Consent Hook:**

```tsx
import { useCredoConsent } from '@credo/react';

function ConsentManager() {
  const { consents, grant, revoke, isLoading } = useCredoConsent();

  return (
    <div>
      {consents.map(consent => (
        <div key={consent.purpose}>
          <span>{consent.purpose}: {consent.status}</span>
          {consent.status === 'active' ? (
            <button onClick={() => revoke([consent.purpose])}>Revoke</button>
          ) : (
            <button onClick={() => grant([consent.purpose])}>Grant</button>
          )}
        </div>
      ))}
    </div>
  );
}
```

---

### FR-3: Backend JWT Verification (Node.js)

**Purpose:** Verify Credo access tokens in backend APIs

**Installation:**

```bash
npm install @credo/sdk
```

**Express.js Middleware:**

```typescript
import express from 'express';
import { CredoClient } from '@credo/sdk';

const app = express();

const credo = new CredoClient({
  gatewayUrl: 'https://gateway.example.com',
  clientId: 'backend-api',
});

// Middleware to verify JWT
app.use(async (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ error: 'Missing token' });
  }

  try {
    const decoded = await credo.auth.verifyToken(token);
    req.user = decoded; // Attach user to request
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
});

// Protected endpoint
app.get('/api/profile', (req, res) => {
  res.json({ user: req.user });
});
```

**Token Introspection:**

```typescript
// Verify token and get user info
const userInfo = await credo.auth.introspectToken(token);

// Returns:
// {
//   active: true,
//   sub: "user_123",
//   email: "user@example.com",
//   exp: 1234567890,
//   iat: 1234564290,
//   client_id: "demo-client"
// }
```

---

### FR-4: Mobile Example Code (Swift & Kotlin)

**iOS Example (Swift):**

```swift
import Foundation

class CredoAuth {
    let gatewayUrl = "https://gateway.example.com"
    let clientId = "mobile-app"
    let redirectUri = "credoapp://callback"

    // Start authorization flow
    func authorize(email: String) async throws -> URL {
        let url = URL(string: "\(gatewayUrl)/auth/authorize")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let body: [String: Any] = [
            "email": email,
            "client_id": clientId,
            "redirect_uri": redirectUri,
            "scopes": ["openid", "profile"],
            "state": UUID().uuidString
        ]

        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, _) = try await URLSession.shared.data(for: request)
        let response = try JSONDecoder().decode(AuthorizeResponse.self, from: data)

        return URL(string: response.redirect_uri)!
    }

    // Exchange authorization code for tokens
    func exchangeToken(code: String) async throws -> Tokens {
        let url = URL(string: "\(gatewayUrl)/auth/token")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let body: [String: Any] = [
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirectUri,
            "client_id": clientId
        ]

        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, _) = try await URLSession.shared.data(for: request)
        return try JSONDecoder().decode(Tokens.self, from: data)
    }
}

struct AuthorizeResponse: Codable {
    let code: String
    let redirect_uri: String
}

struct Tokens: Codable {
    let access_token: String
    let id_token: String
    let token_type: String
    let expires_in: Int
}
```

**Android Example (Kotlin):**

```kotlin
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject

class CredoAuth(
    private val gatewayUrl: String = "https://gateway.example.com",
    private val clientId: String = "mobile-app",
    private val redirectUri: String = "credoapp://callback"
) {
    private val client = OkHttpClient()
    private val jsonMediaType = "application/json; charset=utf-8".toMediaType()

    suspend fun authorize(email: String): String = withContext(Dispatchers.IO) {
        val json = JSONObject().apply {
            put("email", email)
            put("client_id", clientId)
            put("redirect_uri", redirectUri)
            put("scopes", JSONArray(listOf("openid", "profile")))
            put("state", java.util.UUID.randomUUID().toString())
        }

        val request = Request.Builder()
            .url("$gatewayUrl/auth/authorize")
            .post(json.toString().toRequestBody(jsonMediaType))
            .build()

        val response = client.newCall(request).execute()
        val responseBody = response.body?.string() ?: throw Exception("Empty response")

        val responseJson = JSONObject(responseBody)
        return@withContext responseJson.getString("redirect_uri")
    }

    suspend fun exchangeToken(code: String): Tokens = withContext(Dispatchers.IO) {
        val json = JSONObject().apply {
            put("grant_type", "authorization_code")
            put("code", code)
            put("redirect_uri", redirectUri)
            put("client_id", clientId)
        }

        val request = Request.Builder()
            .url("$gatewayUrl/auth/token")
            .post(json.toString().toRequestBody(jsonMediaType))
            .build()

        val response = client.newCall(request).execute()
        val responseBody = response.body?.string() ?: throw Exception("Empty response")

        return@withContext Tokens.fromJson(responseBody)
    }
}

data class Tokens(
    val accessToken: String,
    val idToken: String,
    val tokenType: String,
    val expiresIn: Int
) {
    companion object {
        fun fromJson(json: String): Tokens {
            val obj = JSONObject(json)
            return Tokens(
                accessToken = obj.getString("access_token"),
                idToken = obj.getString("id_token"),
                tokenType = obj.getString("token_type"),
                expiresIn = obj.getInt("expires_in")
            )
        }
    }
}
```

---

## 5. Technical Architecture (V1)

### TR-1: SDK Core Structure (TypeScript)

**Directory Structure:**

```
packages/
  @credo/sdk/              # Core SDK
    src/
      client.ts            # Main CredoClient class
      auth/
        oauth-client.ts    # OAuth 2.0 flow implementation
        token-manager.ts   # Token storage & refresh
        session-manager.ts # Session state management
      api/
        consent.ts         # Consent API client
        credentials.ts     # VC API client
        biometric.ts       # Biometric API client
        registry.ts        # Registry API client
        user.ts            # User data API client
      http/
        client.ts          # HTTP client with retry logic
        errors.ts          # Error types and handling
      storage/
        adapter.ts         # Storage interface
        local-storage.ts   # Browser localStorage adapter
        memory-storage.ts  # In-memory adapter
      types/
        index.ts           # TypeScript type definitions
    test/
      unit/
      integration/
    package.json

  @credo/react/            # React bindings
    src/
      provider.tsx         # CredoProvider context
      hooks/
        useCredoAuth.ts
        useCredoConsent.ts
        useCredoCredentials.ts
      components/
        ProtectedRoute.tsx
    package.json
```

### TR-2: OAuth 2.0 Implementation

**OAuthClient Class:**

```typescript
export class OAuthClient {
  constructor(
    private config: CredoConfig,
    private storage: StorageAdapter,
    private httpClient: HttpClient
  ) {}

  /**
   * Generate authorization URL with PKCE
   */
  async authorize(email: string, options?: AuthorizeOptions): Promise<string> {
    // Generate PKCE code verifier and challenge
    const codeVerifier = generateRandomString(128);
    const codeChallenge = await sha256(codeVerifier);

    // Store code verifier for token exchange
    await this.storage.set('pkce_verifier', codeVerifier);

    // Generate state for CSRF protection
    const state = options?.state || generateRandomString(32);
    await this.storage.set('oauth_state', state);

    // Call /auth/authorize endpoint
    const response = await this.httpClient.post('/auth/authorize', {
      email,
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      scopes: this.config.scopes || ['openid'],
      state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    });

    return response.redirect_uri; // Full URL with code and state
  }

  /**
   * Handle OAuth callback and exchange code for tokens
   */
  async handleCallback(callbackUrl: string): Promise<Tokens> {
    const url = new URL(callbackUrl);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');

    if (!code) throw new CredoError(ErrorCode.InvalidCallback, 'Missing authorization code');

    // Verify state (CSRF protection)
    const storedState = await this.storage.get('oauth_state');
    if (state !== storedState) {
      throw new CredoError(ErrorCode.InvalidState, 'State parameter mismatch');
    }

    // Retrieve code verifier for PKCE
    const codeVerifier = await this.storage.get('pkce_verifier');

    // Exchange code for tokens
    const tokens = await this.httpClient.post('/auth/token', {
      grant_type: 'authorization_code',
      code,
      redirect_uri: this.config.redirectUri,
      client_id: this.config.clientId,
      code_verifier: codeVerifier,
    });

    // Store tokens
    await this.storage.set('access_token', tokens.access_token);
    await this.storage.set('id_token', tokens.id_token);
    await this.storage.set('token_expiry', Date.now() + tokens.expires_in * 1000);

    // Clean up temporary storage
    await this.storage.remove('oauth_state');
    await this.storage.remove('pkce_verifier');

    return tokens;
  }

  /**
   * Refresh access token
   */
  async refreshToken(): Promise<Tokens> {
    const refreshToken = await this.storage.get('refresh_token');

    if (!refreshToken) {
      throw new CredoError(ErrorCode.NoRefreshToken, 'No refresh token available');
    }

    const tokens = await this.httpClient.post('/auth/token', {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: this.config.clientId,
    });

    // Update stored tokens
    await this.storage.set('access_token', tokens.access_token);
    await this.storage.set('token_expiry', Date.now() + tokens.expires_in * 1000);

    return tokens;
  }
}
```

### TR-3: HTTP Client with Retry Logic

```typescript
export class HttpClient {
  constructor(
    private baseUrl: string,
    private tokenManager: TokenManager,
    private options: HttpClientOptions = {}
  ) {}

  async request<T>(
    method: string,
    path: string,
    data?: any,
    options?: RequestOptions
  ): Promise<T> {
    const maxRetries = options?.retries ?? this.options.maxRetries ?? 3;
    let lastError: Error;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        // Get current access token
        const token = await this.tokenManager.getAccessToken();

        // Build request
        const url = new URL(path, this.baseUrl);
        const headers: Record<string, string> = {
          'Content-Type': 'application/json',
          ...(token && { Authorization: `Bearer ${token}` }),
          ...options?.headers,
        };

        const response = await fetch(url.toString(), {
          method,
          headers,
          body: data ? JSON.stringify(data) : undefined,
          ...options?.fetchOptions,
        });

        // Handle token expiry (401)
        if (response.status === 401 && attempt === 0) {
          // Try to refresh token and retry
          await this.tokenManager.refreshToken();
          continue; // Retry with new token
        }

        // Handle rate limiting (429)
        if (response.status === 429 && attempt < maxRetries) {
          const retryAfter = response.headers.get('Retry-After');
          const delay = retryAfter ? parseInt(retryAfter) * 1000 : this.getBackoffDelay(attempt);
          await sleep(delay);
          continue; // Retry after delay
        }

        // Handle server errors (5xx) with exponential backoff
        if (response.status >= 500 && attempt < maxRetries) {
          await sleep(this.getBackoffDelay(attempt));
          continue; // Retry with backoff
        }

        // Parse response
        const responseData = await response.json();

        // Handle error responses
        if (!response.ok) {
          throw CredoError.fromResponse(response.status, responseData);
        }

        return responseData as T;

      } catch (error) {
        lastError = error as Error;

        // Don't retry on client errors (except 401, 429)
        if (error instanceof CredoError && error.status >= 400 && error.status < 500) {
          throw error;
        }

        // Last attempt - throw error
        if (attempt === maxRetries) {
          throw error;
        }
      }
    }

    throw lastError!;
  }

  private getBackoffDelay(attempt: number): number {
    // Exponential backoff: 100ms, 200ms, 400ms, 800ms, ...
    return Math.min(100 * Math.pow(2, attempt), 5000);
  }

  async get<T>(path: string, options?: RequestOptions): Promise<T> {
    return this.request<T>('GET', path, undefined, options);
  }

  async post<T>(path: string, data?: any, options?: RequestOptions): Promise<T> {
    return this.request<T>('POST', path, data, options);
  }

  async delete<T>(path: string, options?: RequestOptions): Promise<T> {
    return this.request<T>('DELETE', path, undefined, options);
  }
}
```

### TR-4: Error Handling

```typescript
export enum ErrorCode {
  // Authentication errors
  Unauthorized = 'unauthorized',
  InvalidCallback = 'invalid_callback',
  InvalidState = 'invalid_state',
  NoRefreshToken = 'no_refresh_token',

  // Consent errors
  MissingConsent = 'missing_consent',
  ConsentExpired = 'consent_expired',

  // Validation errors
  InvalidRequest = 'invalid_request',
  ValidationError = 'validation_error',

  // Server errors
  ServerError = 'server_error',
  ServiceUnavailable = 'service_unavailable',

  // Network errors
  NetworkError = 'network_error',
  Timeout = 'timeout',
}

export class CredoError extends Error {
  constructor(
    public code: ErrorCode,
    public message: string,
    public status?: number,
    public details?: any
  ) {
    super(message);
    this.name = 'CredoError';
  }

  static fromResponse(status: number, data: any): CredoError {
    const errorCode = this.mapStatusToCode(status, data.error);
    return new CredoError(errorCode, data.error_description || data.message, status, data);
  }

  private static mapStatusToCode(status: number, error?: string): ErrorCode {
    if (error === 'missing_consent') return ErrorCode.MissingConsent;
    if (error === 'consent_expired') return ErrorCode.ConsentExpired;

    if (status === 401) return ErrorCode.Unauthorized;
    if (status === 400) return ErrorCode.ValidationError;
    if (status >= 500) return ErrorCode.ServerError;

    return ErrorCode.InvalidRequest;
  }

  isRetryable(): boolean {
    return this.status ? this.status >= 500 : false;
  }
}
```

---

## 6. Implementation Plan

### V1: TypeScript/JavaScript SDK (10-14 hours)

#### Phase 1: Core SDK (4-5 hours)

1. Project setup:
   - Initialize monorepo with `pnpm` workspaces
   - Setup TypeScript, ESLint, Prettier
   - Configure build pipeline (tsup for bundling)
2. Implement core classes:
   - `CredoClient` (main entry point)
   - `OAuthClient` (OAuth 2.0 flow)
   - `TokenManager` (token lifecycle)
   - `HttpClient` (HTTP client with retry)
3. Implement storage adapters:
   - `LocalStorageAdapter`
   - `SessionStorageAdapter`
   - `MemoryStorageAdapter`

#### Phase 2: API Clients (3-4 hours)

1. Implement API client modules:
   - `ConsentClient` (grant, revoke, list)
   - `CredentialsClient` (issue, verify VCs)
   - `BiometricClient` (face match, liveness)
   - `UserClient` (profile, data export)
2. Add TypeScript types for all API responses

#### Phase 3: React Bindings (2-3 hours)

1. Create `@credo/react` package:
   - `CredoProvider` context
   - `useCredoAuth` hook
   - `useCredoConsent` hook
   - `CredoProtectedRoute` component
2. Add React TypeScript types

#### Phase 4: Documentation & Examples (1-2 hours)

1. Write README with quick start guide
2. Create example apps:
   - Vanilla JS example
   - React SPA example
   - Next.js example
   - Express.js backend example
3. Generate API documentation (TypeDoc)

---

### V2: Multi-Platform SDKs (16-20 hours)

#### Phase 1: Native iOS SDK (5-6 hours)

1. Create Swift Package:
   - OAuth 2.0 client
   - Keychain token storage
   - Face ID/Touch ID integration
2. CocoaPods distribution
3. Example Xcode project

#### Phase 2: Native Android SDK (5-6 hours)

1. Create Kotlin library:
   - OAuth 2.0 client
   - SharedPreferences token storage
   - BiometricPrompt integration
2. Maven/Gradle distribution
3. Example Android Studio project

#### Phase 3: Cross-Platform SDKs (4-5 hours)

1. React Native module:
   - Bridge to native OAuth flows
   - Native biometric support
2. Flutter plugin:
   - Dart bindings for HTTP API
   - Platform channel for native features

#### Phase 4: Backend SDKs (2-3 hours)

1. Go SDK:
   - JWT verification
   - API client for backend operations
2. Python SDK:
   - Flask/FastAPI middleware
   - JWT verification

---

## 7. Testing Strategy

### Unit Tests (V1)

- [ ] OAuth 2.0 flow (authorization, callback, token exchange)
- [ ] PKCE code generation and verification
- [ ] Token refresh logic
- [ ] HTTP client retry logic (401, 429, 5xx)
- [ ] Error handling and error code mapping
- [ ] Storage adapters (localStorage, sessionStorage, memory)

### Integration Tests (V1)

- [ ] Complete auth flow against mock gateway
- [ ] Token expiry and automatic refresh
- [ ] Consent management integration
- [ ] VC issuance and verification
- [ ] Biometric API integration
- [ ] Error scenarios (network failure, server errors)

### Example App Tests (V1)

```bash
# Run example apps
cd examples/react-spa
npm install
npm start

cd examples/nextjs-app
npm install
npm run dev

cd examples/express-backend
npm install
npm start
```

### Manual Testing (V1)

```typescript
// 1. Initialize SDK
import { CredoClient } from '@credo/sdk';

const credo = new CredoClient({
  gatewayUrl: 'http://localhost:8080',
  clientId: 'demo-client',
  redirectUri: 'http://localhost:3000/callback',
});

// 2. Start auth flow
const authUrl = await credo.auth.authorize('user@example.com');
console.log('Redirect to:', authUrl);

// 3. Handle callback
const tokens = await credo.auth.handleCallback(window.location.href);
console.log('Tokens:', tokens);

// 4. Get user
const user = await credo.auth.getUser();
console.log('User:', user);

// 5. Grant consent
await credo.consent.grant(['registry_check', 'vc_issuance']);

// 6. Issue VC
const vc = await credo.credentials.issue({
  type: 'AgeOver18',
  national_id: '123456789',
});
console.log('VC:', vc);
```

---

## 8. Acceptance Criteria

### V1 Acceptance Criteria

- [ ] `@credo/sdk` installable via npm
- [ ] OAuth 2.0 authorization flow works end-to-end
- [ ] Token refresh happens automatically before expiry
- [ ] HTTP client retries on 429 and 5xx errors
- [ ] All API clients (consent, credentials, biometric) functional
- [ ] React hooks (`useCredoAuth`, `useCredoConsent`) work in example app
- [ ] TypeScript types exported for all API responses
- [ ] Error handling provides clear, actionable error messages
- [ ] Example apps run successfully (React, Next.js, Express)
- [ ] Documentation covers installation, quick start, and API reference
- [ ] Code passes linting and type checking
- [ ] Test coverage >80%

### V2 Acceptance Criteria (Future)

- [ ] iOS SDK available as Swift Package and CocoaPod
- [ ] Android SDK available via Maven Central
- [ ] React Native module supports iOS and Android
- [ ] Flutter plugin published to pub.dev
- [ ] Go SDK verifies JWTs and provides API client
- [ ] Python SDK integrates with Flask/FastAPI
- [ ] All SDKs have 1:1 feature parity with JS SDK
- [ ] Native biometric integration works (Face ID, Touch ID, BiometricPrompt)
- [ ] Developer portal with interactive API explorer
- [ ] Performance: <100ms overhead for SDK operations

---

## 9. Dependencies & Blockers

### Dependencies

- PRD-001: Authentication (OAuth 2.0 endpoints must be implemented)
- PRD-002: Consent Management (consent APIs must be functional)
- PRD-004: Verifiable Credentials (VC APIs must be functional)
- PRD-013: Biometric Verification (biometric APIs must be functional)

### External Dependencies (V1)

- None - pure HTTP client implementation

### External Dependencies (V2)

- iOS: Xcode, Swift Package Manager
- Android: Android Studio, Gradle
- React Native: React Native CLI
- Flutter: Flutter SDK, Dart

### Potential Blockers

- **V1:** None identified (SDK can be developed in parallel with gateway features)
- **V2:** Platform-specific tooling setup and expertise

---

## 10. Future Enhancements (V2+)

### Developer Experience

- **Interactive API Explorer** (Swagger UI-like interface)
- **SDK Playground** (Try APIs without setup)
- **Code Generation** (OpenAPI → SDK clients)
- **CLI Tool** (`credo-cli` for testing and automation)

### Enterprise Features

- **Single Sign-On (SSO)** bridges:
  - SAML 2.0 adapter
  - Active Directory integration
  - Okta/Auth0 federation
- **Admin SDK**:
  - User provisioning API
  - Organization management
  - Bulk operations
- **Multi-tenancy Support**:
  - Tenant isolation
  - Custom branding per tenant

### Advanced Capabilities

- **WebAuthn Integration**:
  - Passwordless authentication
  - Platform authenticators (Face ID, Windows Hello)
- **DIDComm Messaging**:
  - Peer-to-peer encrypted messaging
  - Credential exchange protocol
- **Offline Support**:
  - Local credential caching
  - Sync when online
- **GraphQL API**:
  - Alternative to REST
  - Efficient data fetching

### Mobile Enhancements

- **Biometric Capture UI**:
  - Camera overlay for face capture
  - Liveness instruction animations
- **NFC Support**:
  - Read ePassports
  - Verify NFC-enabled ID cards
- **Push Notifications**:
  - Credential revocation alerts
  - Consent expiry reminders

---

## 11. Success Metrics

### Adoption Metrics (V1)

- npm downloads per week
- Number of integrated applications
- GitHub stars and community contributions
- Developer onboarding time (target: <30 minutes)

### Technical Metrics (V1)

- SDK bundle size (<50kb gzipped)
- API call success rate (>99.9%)
- Token refresh success rate (>99%)
- Error rate (<0.1%)

### Developer Experience Metrics (V1)

- Time to first successful authentication (<10 minutes)
- Documentation clarity rating (>4.5/5)
- Issue resolution time (<48 hours)
- Community support responsiveness

---

## 12. Documentation Requirements

### For Developers

**Quick Start Guide:**
- Installation steps
- Basic authentication flow (5 lines of code)
- Common use cases (consent, VCs, biometrics)

**API Reference:**
- TypeDoc-generated documentation
- All methods, parameters, return types
- Code examples for each API

**Integration Guides:**
- React integration (hooks, provider)
- Next.js integration (middleware, server components)
- Express.js backend (JWT verification)
- Mobile integration (Swift, Kotlin examples)

**Migration Guides:**
- Upgrading between SDK versions
- Breaking changes and deprecations

### For Product Managers

- Feature comparison matrix
- Platform support matrix
- Roadmap and release schedule

---

## 13. Open Questions

1. **V1 Scope:** Should we support refresh tokens in V1, or defer to V2?
   - **Recommendation:** Defer to V2 - simplifies V1, access tokens can be long-lived initially

2. **Browser Support:** What browsers should we target for V1?
   - **Recommendation:** Modern browsers only (Chrome/Edge/Safari/Firefox last 2 versions)

3. **Package Naming:** Should we use `@credo/*` or `@credo-auth/*`?
   - **Recommendation:** `@credo/*` for simplicity

4. **Monorepo Strategy:** Should all SDKs live in one monorepo?
   - **Recommendation:** JS SDKs in monorepo, native SDKs in separate repos

5. **Versioning:** Should we use semantic versioning or date-based?
   - **Recommendation:** Semantic versioning (1.0.0, 1.1.0, etc.)

---

## 14. References

- [OAuth 2.0 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- [OAuth 2.0 PKCE RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)
- [Auth0 JavaScript SDK](https://github.com/auth0/auth0-spa-js) - Reference implementation
- [AWS Amplify JavaScript](https://github.com/aws-amplify/amplify-js) - SDK architecture inspiration
- [React Authentication Patterns](https://reactjs.org/docs/context.html)
- [TypeScript Handbook](https://www.typescriptlang.org/docs/handbook/)

---

## Revision History

| Version | Date       | Author           | Changes                                           |
| ------- | ---------- | ---------------- | ------------------------------------------------- |
| 1.0     | 2025-12-11 | Engineering Team | Initial PRD - V1 (JS/TS) and V2 (multi-platform)  |
