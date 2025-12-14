# Credo Agent Rules (Authoritative)

This file defines **non-negotiable rules** that all code generated or modified by agents must follow.
If a rule here conflicts with any other document, this file wins.

---

## Non-negotiable rules

- No business logic in handlers.
- No globals.
- Services own orchestration and domain behavior.
- Domain entities do not contain API input rules.
- Stores return domain models, never persistence structs.
- Internal errors are never exposed to clients.
- All multi-write operations must be atomic.

---

## Module structure

### Handlers

- Handle HTTP concerns only: parsing, request validation, response mapping.
- Always accept and pass through `context.Context`.

### Services

- All business logic lives in services.
- Depend only on interfaces.
- Validate domain invariants.
- Perform orchestration and error mapping.

### Models

- Domain models represent persisted state.
- No API input rules on domain entities.
- Request/command structs may contain `Validate()` methods.

### Stores

- Interfaces only.
- Must be swappable (in-memory, SQL, etc.).
- Return domain models.

---

## Validation placement

### Domain invariants

- Rules that must _always_ hold for an entity.
- Violations mean corrupted state.
- Enforced via constructors or persistence boundaries.

### API input rules

- Rules specific to an API, flow, or version.
- May change without data migration.
- Enforced on request/command structs or in services.

**Rule of thumb**  
If a rule can change without invalidating stored data, it is an API input rule.

Example:  
A `Client` must always have a non-nil `TenantID` (domain invariant), but redirect URI scheme rules are API input rules.

---

## Entity state

- Entity lifecycle state (e.g. Session status) must be modeled using
  closed sets (typed constants or value objects), never magic strings
  or booleans. State transitions are enforced in services or entities.

## Error handling

- Use domain error codes via `pkg/domain-errors`.
- Map store or infra errors to domain errors at the service boundary.
- Never leak internal error details.

---

## Transactions

- Use `RunInTx` for multi-store writes.
- Avoid partial persistence on failure.
- Token, session, and audit updates must be atomic.

---

## Testing (hard rules)

- Unit tests for all service logic.
- Handlers are tested only for wiring and HTTP behavior.
- Integration tests cover PRD journeys only.

### Additional conventions

- see docs/conventions.md
