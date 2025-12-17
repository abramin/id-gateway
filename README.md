# Credo 
<img width="160" height="160" alt="credo" src="https://github.com/user-attachments/assets/cc9f2d5a-6b70-4f92-a9e7-8f3ab1315181" />

_Modular identity and evidence platform covering auth, consent, registry evidence, VCs, policy, and audit._

## What is it?
- OIDC-lite auth: users, sessions, token issuance/refresh/revocation, device binding, admin deletion.
- Consent: purpose-based grant/revoke/list with enforcement hooks.
- Evidence: registry lookups (citizen, sanctions) and verifiable credential issuance/verification.
- Decision/Policy: rules engine + Cerbos experiments.
- Audit/Compliance: audit publisher/storage, data-rights flows.
- Ops: metrics, logging, HTTP server/middleware, demo wiring.

## Docs
- [Product requirements](docs/prd/README.md)
- [Architecture](docs/architecture.md)
- [OpenAPI](https://abramin.github.io/Credo/openapi)
- [OAuth demo README](frontend/OAUTH_DEMO_README.md)
- [Frontend demos](frontend/README.md)

## Status (PRDs)
Progress: `5/33` complete.
- ✅ PRD-001 Auth & Session Management
- ✅ PRD-001B Admin User Deletion
- ✅ PRD-002 Consent Management (TR-6 projections deferred post-Postgres)
- ✅ PRD-016 Token Lifecycle & Revocation
- ✅ PRD-026A Tenant & Client Management
- ➡️ Full index: see [PRD index](docs/prd/README.md)

## Quick start
### Docker (backend + demos)
```bash
docker compose up --build
# Demo UI:     http://localhost:3000
# API:         http://localhost:8080
# Swagger UI:  http://localhost:8081
```
Demo mode (all in-memory):
```bash
docker compose --env-file .env.demo \
  -f docker-compose.yml -f docker-compose.demo.yml up --build
# /demo/info shows demo metadata
```

### Local dev
```bash
# Backend
go run ./cmd/server

# Frontend demo (static)
cd frontend/public
python3 -m http.server 8000  # http://localhost:8000
```

## Demos
- Hosted: https://abramin.github.io/Credo/
- Local OAuth2 suite:
  - Home: http://localhost:3000/demo/index.html
  - Auth flow: /demo/authorize.html → /demo/callback.html
  - Sessions: /demo/sessions.html
  - Tokens: /demo/tokens.html
  - Admin: /demo/admin.html

## Testing
- Unit/integration: `go test ./...`
- E2E (godog): `go test -v ./e2e -- -godog.tags=@normal`
- Latest E2E results: https://abramin.github.io/Credo/e2e/

## API quick reference
- `POST /auth/authorize` – issue authorization code
- `POST /auth/token` – exchange code/refresh token
- `GET /auth/userinfo` – current user profile
- `POST /auth/consent` – grant consent (login, registry_check, vc_issuance, decision_evaluation)
- `POST /auth/consent/revoke` – revoke consent
- `GET /auth/consent` – list consents (`status`, `purpose` filters)
