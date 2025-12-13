# Credo

<img width="120" height="120" alt="credo" src="https://github.com/user-attachments/assets/cc9f2d5a-6b70-4f92-a9e7-8f3ab1315181" />

Credo is a modular identity and evidence platform. It exercises the full journey defined in the PRDs: OIDC-style auth, consent, registry evidence, verifiable credentials, decisioning/policy, audit/compliance, token lifecycle, user data rights, and operational controls.

## What’s inside

- Platform: config loader, logging, metrics, HTTP server, and demo wiring.
- Auth: users, sessions, token issuance/refresh/revocation, device binding, admin session/user deletion.
- Consent: purpose-based consent lifecycle and consent revocation.
- Evidence: registry lookups (citizen, sanctions) plus verifiable credential issuance/verification.
- Decision/Policy: rules engine and Cerbos-based authorization experiments.
- Audit/Compliance: audit publisher, storage, append-only worker, and data rights flows.
- Transport & demos: HTTP router/handlers, OpenAPI docs, and browser demos exercising the PRDs.

## Documentation

- [Architecture overview](docs/architecture.md)
- [Product requirements](docs/prd/README.md) - (links to PRDs for auth, consent, registry, VC, decision, audit, and user data rights).
- OpenAPI docs (hosted): https://abramin.github.io/Credo/openapi

## Product scope & PRD roadmap

Credo now tracks the full stack of identity, security, and operations capabilities via 33 PRDs. Progress is maintained manually; tick checkboxes and update the count as requirements are delivered.

Progress: `[XX------------------]` 4/33 PRDs marked complete

- [x] [PRD-001: Authentication & Session Management](docs/prd/PRD-001-Authentication-Session-Management.md)
- [x] [PRD-001B: Admin User Deletion](docs/prd/PRD-001B-Admin-User-Deletion.md)
- [x] [PRD-002: Consent Management](docs/prd/PRD-002-Consent-Management.md)
- [ ] [PRD-003: Registry Integration](docs/prd/PRD-003-Registry-Integration.md)
- [ ] [PRD-004: Verifiable Credentials](docs/prd/PRD-004-Verifiable-Credentials.md)
- [ ] [PRD-004B: Enhanced Verifiable Credentials](docs/prd/PRD-004B-Enhanced-Verifiable-Credentials.md)
- [ ] [PRD-005: Decision Engine](docs/prd/PRD-005-Decision-Engine.md)
- [ ] [PRD-005B: Cerbos Authorization](docs/prd/PRD-005B-Cerbos-Authorization.md)
- [ ] [PRD-006: Audit & Compliance](docs/prd/PRD-006-Audit-Compliance.md)
- [ ] [PRD-006B: Cryptographic Audit](docs/prd/PRD-006B-Cryptographic-Audit.md)
- [ ] [PRD-007: User Data Rights](docs/prd/PRD-007-User-Data-Rights.md)
- [ ] [PRD-007B: ML Risk Scoring](docs/prd/PRD-007B-ML-Risk-Scoring.md)
- [ ] [PRD-008: GDPR/CCPA Automation](docs/prd/PRD-008-GDPR-CCPA-Automation.md)
- [ ] [PRD-009: Decentralized Identity (DIDs)](docs/prd/PRD-009-Decentralized-Identity-DIDs.md)
- [ ] [PRD-010: Zero-Knowledge Proofs](docs/prd/PRD-010-Zero-Knowledge-Proofs.md)
- [ ] [PRD-011: Internal TCP Event Ingester](docs/prd/PRD-011-Internal-TCP-Event-Ingester.md)
- [ ] [PRD-012: Cloud Connectors (Audit/Identity Event Export)](docs/prd/PRD-012-Cloud-Connectors-Credo-Audit-Identity-Event-Export.md)
- [ ] [PRD-013: Biometric Verification](docs/prd/PRD-013-Biometric-Verification.md)
- [ ] [PRD-014: Client SDKs & Platform Integration](docs/prd/PRD-014-Client-SDKs-Platform-Integration.md)
- [ ] [PRD-015: Credo Policy Engine](docs/prd/PRD-015-Credo-Policy-Engine.md)
- [x] [PRD-016: Token Lifecycle & Revocation](docs/prd/PRD-016-Token-Lifecycle-Revocation.md)
- [ ] [PRD-017: Rate Limiting & Abuse Prevention](docs/prd/PRD-017-Rate-Limiting-Abuse-Prevention.md)
- [ ] [PRD-018: Notification Service](docs/prd/PRD-018-Notification-Service.md)
- [ ] [PRD-019: API Versioning & Lifecycle](docs/prd/PRD-019-API-Versioning-Lifecycle.md)
- [ ] [PRD-020: Operational Readiness (SRE)](docs/prd/PRD-020-Operational-Readiness-SRE.md)
- [ ] [PRD-021: Multi-Factor Authentication](docs/prd/PRD-021-Multi-Factor-Authentication.md)
- [ ] [PRD-022: Account Recovery Credentials](docs/prd/PRD-022-Account-Recovery-Credentials.md)
- [ ] [PRD-023: Fraud Detection & Security Intelligence](docs/prd/PRD-023-Fraud-Detection-Security-Intelligence.md)
- [ ] [PRD-024: Data Residency & Sovereignty](docs/prd/PRD-024-Data-Residency-Sovereignty.md)
- [ ] [PRD-025: Developer Sandbox & Testing](docs/prd/PRD-025-Developer-Sandbox-Testing.md)
- [ ] [PRD-026: Admin Dashboard & Operations UI](docs/prd/PRD-026-Admin-Dashboard-Operations-UI.md)
- [ ] [PRD-026A: Tenant & Client Management](docs/prd/PRD-026A-Tenant-Client-Management.md)
- [ ] [PRD-027: Risk-Based Adaptive Authentication](docs/prd/PRD-027-Risk-Based-Adaptive-Authentication.md)

## Run it

### Quick Start with Docker (Recommended)

Run both frontend and backend together:

```bash
docker-compose up --build
```

Access the application:

- **Frontend UI:** http://localhost:3000
- **Backend API:** http://localhost:8080
- **OpenAPI docs (local):** http://localhost:8081 (Swagger UI for `docs/openapi/auth.yaml`)

#### Demo mode (isolated, in-memory)

To run the ring-fenced demo environment (no real secrets or external services):

```bash
docker compose --env-file .env.demo -f docker-compose.yml -f docker-compose.demo.yml up --build
```

You should see `CRENE_ENV=demo — starting isolated demo environment` on startup. Health checks remain at `/health`, and `/demo/info` returns demo metadata (`env: "demo"`, in-memory stores, demo issuer).

### Development Mode

Run backend only:

```bash
make dev  # hot reload if available
# or
go run ./cmd/server
```

Run frontend separately:

```bash
cd frontend/public
python3 -m http.server 8000
# Visit http://localhost:8000
```

## Demo UI

The project includes demo web interfaces:

https://abramin.github.io/Credo/

### OAuth2 Demo Suite

A comprehensive OAuth2 authorization code flow demo with true browser redirects:

- **Demo Home**: http://localhost:3000/demo/index.html
- **Authorization Flow**: `/demo/authorize.html` → `/demo/callback.html`
- **Session Management**: `/demo/sessions.html`
- **Token Lifecycle**: `/demo/tokens.html`
- **Admin Operations**: `/demo/admin.html`

See [OAuth Demo README](frontend/OAUTH_DEMO_README.md) for complete walkthrough.

### Other Demos

See [Frontend Readme](frontend/README.md) for details on other demo interfaces.

## Testing

- Unit/integration tests: `go test ./...`
- Contract-style E2E API tests: `go test -v ./e2e --godog.tags=@normal` (uses [godog](https://github.com/cucumber/godog) Cucumber-style features)
- Latest Main e2e runs can be viewed here - [E2E Test Results](https://abramin.github.io/Credo/e2e/)

## API quick reference

Core backend endpoints (JWT-protected unless noted):

- `POST /auth/authorize` (public) – issue an authorization code for the login flow.
- `POST /auth/token` (public) – exchange the code for an access token.
- `GET /auth/userinfo` – return the authenticated user's profile.
- `POST /auth/consent` – grant consent for one or more purposes (login, registry check, VC issuance, decision evaluation).
- `POST /auth/consent/revoke` – revoke consent for one or more purposes.
- `GET /auth/consent?status=<active|expired|revoked>&purpose=<purpose>` – list consents with optional filters.
