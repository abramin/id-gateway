# Credo

<img width="160" height="160" alt="credo" src="https://github.com/user-attachments/assets/cc9f2d5a-6b70-4f92-a9e7-8f3ab1315181" />

_Modular identity and evidence platform covering auth, consent, registry evidence, VCs, policy, and audit._

## Attack Lab (OAuth Security)

- Live: https://abramin.github.io/Credo/lab/
- Repo: [lab/](lab/) (Alpine.js static modules: Control Panel, Dual Perspective, Request Forge)
- Auto-deployed on pushes to `main` via GitHub Pages.

## What is it?

- OIDC-lite auth: users, sessions, token issuance/refresh/revocation, device binding, admin deletion.
- Consent: purpose-based grant/revoke/list with enforcement hooks.
- Evidence: registry lookups (citizen, sanctions) and verifiable credential issuance/verification.
- Decision/Policy: rules engine + Cerbos experiments.
- Audit/Compliance: audit publisher/storage, data-rights flows.
- Ops: metrics, logging, HTTP server/middleware, demo wiring.

## Docs

- [Product requirements](docs/prd/README.md)
- [Architecture](docs/engineering/architecture.md)
- [OpenAPI](https://abramin.github.io/Credo/openapi)
- [Frontend demos](frontend/README.md)

## Status (PRDs)

Progress: `11/53` complete (Phases 0-1 done).

- ✅ PRD-001 Auth & Session Management
- ✅ PRD-001B Admin User Deletion
- ✅ PRD-002 Consent Management (TR-6 projections deferred post-Postgres)
- ✅ PRD-003 Registry Integration
- ✅ PRD-004 Verifiable Credentials
- ✅ PRD-005 Decision Engine
- ✅ PRD-006 Audit & Compliance Baseline
- ✅ PRD-016 Token Lifecycle & Revocation
- ✅ PRD-017 Rate Limiting & Abuse Prevention (MVP)
- ✅ PRD-026A Tenant & Client Management
- ✅ PRD-026B Tenant & Client Lifecycle
- ➡️ Full index: see [PRD index](docs/prd/README.md)

## Project plan

![Credo project implementation Gantt chart](assets/images/credo-gantt.png)

- Phase 0 (Foundation) is done after a 4–7 week ramp, establishing the base platform pieces.
- Phases 1–3 (Core Identity, Operational Baseline, Production Hardening) extend the critical path for roughly 8–17 weeks, culminating in the MVP milestone (~week 15) and a production baseline (~week 20).
- Phases 4–7 layer optional product packs over weeks 20–35: base pack, decentralized identity features, integrations pack, and a differentiation layer, each with their own estimation ranges for sizing uncertainty.

## Quick start

### Docker (backend + demos)

```bash
docker compose up --build
# Demo UI:     http://localhost:3000
# API:         http://localhost:8080
# Swagger UI:  http://localhost:8081
```

Demo mode (Postgres-backed):

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
- In-memory stores/caches remain available for unit and E2E tests; runtime wiring uses Postgres/Redis.

## API quick reference

Auth:
- `POST /auth/authorize` – issue authorization code
- `POST /auth/token` – exchange code/refresh token
- `POST /auth/revoke` – revoke access/refresh token
- `GET /auth/userinfo` – current user profile
- `GET /auth/sessions` – list active sessions
- `DELETE /auth/sessions/{session_id}` – revoke session
- `POST /auth/logout-all` – revoke all sessions

Consent:
- `POST /auth/consent` – grant consent (login, registry_check, vc_issuance, decision_evaluation)
- `POST /auth/consent/revoke` – revoke consent
- `POST /auth/consent/revoke-all` – revoke all consents
- `GET /auth/consent` – list consents (`status`, `purpose` filters)
- `DELETE /auth/consent` – delete all consents (GDPR)

Registry:
- `POST /registry/citizen` – citizen lookup
- `POST /registry/sanctions` – sanctions screening

VC:
- `POST /vc/issue` – issue AgeOver18 credential
- `POST /vc/verify` – verify credential

Decision:
- `POST /decision/evaluate` – evaluate decision

Tenant/Admin (requires `X-Admin-Token`):
- `POST /admin/tenants` – create tenant
- `GET /admin/tenants/{id}` – tenant details
- `POST /admin/tenants/{id}/deactivate` – deactivate tenant
- `POST /admin/tenants/{id}/reactivate` – reactivate tenant
- `POST /admin/clients` – register client
- `GET /admin/clients/{id}` – client details
- `PUT /admin/clients/{id}` – update client
- `POST /admin/clients/{id}/deactivate` – deactivate client
- `POST /admin/clients/{id}/reactivate` – reactivate client
- `POST /admin/clients/{id}/rotate-secret` – rotate client secret
