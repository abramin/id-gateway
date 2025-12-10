# Credo

<img width="120" height="120" alt="credo" src="https://github.com/user-attachments/assets/cc9f2d5a-6b70-4f92-a9e7-8f3ab1315181" />

Identity verification gateway built as a modular monolith. It simulates OIDC-style auth, consent, registry evidence, VC issuance/verification, decisions, and audit logging.

## What’s inside

- Platform: config loader, logger, HTTP server setup.
- Auth: users and sessions.
- Consent: purpose-based consent lifecycle.
- Evidence: registry lookups (citizen/sanctions) and verifiable credentials.
- Decision: rules engine that evaluates identity, sanctions, and VC signals.
- Audit: publisher/worker with append-only storage.
- Transport: HTTP router/handlers that delegate to the services.

## Documentation

- [Architecture overview](docs/architecture.md)
- [Product requirements](docs/prd/README.md) - (links to PRDs for auth, consent, registry, VC, decision, audit, and user data rights).
- OpenAPI docs (hosted): https://abramin.github.io/Credo

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

See [Frontend Readme](frontend/README.md) for details.

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
