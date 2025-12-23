# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Development Commands

```bash
# Run the server
go run ./cmd/server
make run

# Build binary
make build

# Run all tests
make test
go test ./...

# Run a single test
make test-one t=TestName
go test -run "TestName" ./...

# Run with coverage
make test-cover

# Find slowest tests
make test-slow              # Top 10 slowest
make test-slow n=5          # Top N slowest

# E2E tests (godog/cucumber)
make e2e                    # All E2E tests
make e2e-normal             # Normal flow tests only (@normal tag)
make e2e-security           # Security simulation tests (@security tag)
cd e2e && go test -v        # Direct execution

# Linting and formatting
make lint                   # golangci-lint
make fmt                    # go fmt + go vet
make imports                # goimports

# Protobuf
make proto-gen              # Generate Go code from .proto files
make proto-check            # Verify generated files are up to date

# Docker
docker compose up --build   # Full stack (backend:8080, frontend:3000)
make docker-demo            # Demo mode with .env.demo

# OpenAPI
make openapi-lint           # Lint OpenAPI specs
make openapi-build          # Build HTML documentation
```

## Architecture Overview

Credo is a **modular monolith** with hexagonal architecture (ports and adapters). Service boundaries are designed for potential microservices extraction.

### Module Responsibilities

- **auth** (`internal/auth/`): Users, sessions, OAuth 2.0 tokens, device binding
- **consent** (`internal/consent/`): Purpose-based consent lifecycle (grant/revoke/require)
- **evidence** (`internal/evidence/`): Registry lookups (citizen, sanctions) and VC issuance
- **decision** (`internal/decision/`): Rules engine combining evidence and consent
- **audit** (`internal/audit/`): Event publishing and persistence
- **ratelimit** (`internal/ratelimit/`): Per-IP/user rate limiting with sliding window
- **tenant** (`internal/tenant/`): Multi-tenancy and client management
- **admin** (`internal/admin/`): Administrative operations (user deletion, session management)
- **platform** (`internal/platform/`): Cross-cutting concerns (config, logger, middleware, metrics)

### Module Structure

Each module under `internal/` follows this layout:
- `handler/` – HTTP handlers (parse requests, call services, map responses)
- `service/` – Business logic, depends on ports (interfaces)
- `store/` – Persistence implementations
- `models/` – Domain models and entities
- `ports/` – Interfaces for external dependencies
- `adapters/` – Implementations of external service ports

### Key Patterns

- **Handlers** parse HTTP, call services, map responses. No business logic.
- **Services** own all business logic, depend on interfaces (ports).
- **Stores** implement persistence behind interfaces. Return domain models, never persistence structs.
- **Contracts** (`contracts/registry/`): PII-light DTOs for cross-module boundaries.

### Data Flow

```
HTTP Handler → Service → Store (persistence)
                ↓
              Ports → Adapters (gRPC/in-process)
                ↓
              Audit Publisher
```

## Coding Rules

These rules are enforced project-wide:

- No business logic in handlers
- No globals
- Services own orchestration and domain behavior
- Domain entities do not contain API input rules
- Stores return domain models, never persistence structs
- Internal errors are never exposed to clients
- All multi-write operations must be atomic
- Domain state checks must use intent-revealing methods (e.g., `IsPending()`, `CanTransitionTo()`), not direct comparisons

## Testing Philosophy

**Feature-driven (primary)**: Gherkin feature files in `e2e/features/` are the authoritative contracts. Cucumber tests define correctness.

**Integration tests (secondary)**: Only for behavior that can't be expressed in Gherkin (concurrency, timing, partial failure).

**Unit tests (tertiary)**: Only for invariants, edge cases unreachable via integration, error propagation, or pure functions. Every unit test must answer: "What invariant would break if this test were removed?"

- Avoid mocks by default; use them only to induce failure modes
- No duplication across test layers without justification
- Use `testify/assert` and `require`

## Error Handling

Two error packages with clear boundaries:

- **Sentinel errors** (`pkg/platform/sentinel`): Infrastructure facts returned by stores only (`ErrNotFound`, `ErrExpired`, `ErrAlreadyUsed`, `ErrInvalidState`, `ErrUnavailable`)
- **Domain errors** (`pkg/domain-errors`): Business-meaningful errors for services, models, and handlers

**Boundary rule**: Stores return sentinel errors. Services translate them to domain errors at their boundary. Never leak internal error details to clients.

## Review Agents (AGENTS.md)

This repo uses focused review agents for code review. Each has a narrow scope:

1. **Testing Agent**: Contracts, behavior verification, scenario coverage
2. **DDD Patterns Agent**: Domain model clarity, aggregates, boundary hygiene
3. **Performance Agent**: Scalability, measurement-first optimizations
4. **Security Agent**: AuthN/AuthZ, secret handling, threat-focused review
5. **Secure-by-Design Agent**: Trust boundaries, domain primitives, lifecycle safety
6. **Complexity Agent**:
   Readability and Cognitive Complexity

**Conflict resolution (tie-breakers)**:

1. Correctness beats performance
2. Security beats convenience
3. Contracts beat implementation details
4. If agents disagree, prefer the smallest change that satisfies both

## Regulated Mode

`REGULATED_MODE=true` enforces GDPR data minimization:

- Registry records strip PII, keep only `Valid` flag
- VC claims remove `full_name`, `national_id`, `date_of_birth`
- Decision engine receives derived identity flags (`IsOver18`, `CitizenValid`), not raw PII

## Two HTTP Servers

- **Port 8080**: Public API (OAuth, consent, user endpoints)
- **Port 8081**: Admin API (requires `X-Admin-Token` header)

## Key Files

- `AGENTS.md`: Review agent definitions and conflict resolution
- `docs/architecture.md`: Full architecture documentation
- `docs/conventions.md`: Engineering conventions
- `docs/prd/`: Product requirements by feature
