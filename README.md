# ID Gateway

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
- Architecture overview: `docs/architecture.md`
- Product requirements: `docs/prd/README.md` (links to PRDs for auth, consent, registry, VC, decision, audit, and user data rights).

## Run it

### Quick Start with Docker (Recommended)

Run both frontend and backend together:

```bash
docker-compose up --build
```

Access the application:
- **Frontend UI:** http://localhost:3000
- **Backend API:** http://localhost:8080

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

The project includes two web interfaces:

1. **User Portal** (`/index.html`) - Login, consent management, identity verification, VCs, decisions, GDPR data rights
2. **Admin Dashboard** (`/admin.html`) - Real-time monitoring, audit logs, decision tracking, compliance overview

See `frontend/README.md` for details.
