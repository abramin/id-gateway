# Credo Module Conventions

Credo is a modular identity and evidence platform composed of small, isolated APIs. Each module follows consistent structural, testing, and implementation conventions to maximise clarity, testability, and interchangeability.

---

## Module Structure

### 1. Handlers

- Handle HTTP concerns only: parsing, validation, and response mapping.
- No business logic.
- Always accept and pass through `context.Context`.

### 2. Services

- All business logic lives in the service layer.
- Services depend on stores, clients, and publishers via interfaces.
- Services handle orchestration, domain validation, and error mapping.
- Designed for unit testing via explicit dependency injection.
- No globals.

### 3. Models

- Pure data structures only.
- No business logic.
- Keep domain models separate from transport types where appropriate.

### 4. Stores

- Interfaces only.
- Allow multiple implementations (in-memory, SQL, etc.).
- For SQL persistence, use **sqlc** to generate queries.
- Stores return domain models, not DB-specific structs.

---

## Testing

### Unit Testing

- **gomock**

  - Used for mocking stores, clients, publishers, and external dependencies.
  - Mocks live under `internal/<module>/mocks`.

- **testify**

  - Use `assert` and `require` for clarity.

- **BDD-style structure**

  - Tests follow `Given / When / Then`.

- **Test suite layout**

  - One test suite per exported function or method.
  - Use subtests to cover behaviors and edge cases.
  - Prefer table tests for pure validation logic.
  - Keep default test contexts minimal.

### Integration Testing

- Validate end-to-end flows required by PRDs.
- One integration suite per PRD journey.
- Use subtests for error cases (400, 401, 404, 500).
- Do not duplicate unit test coverage.
- Focus on HTTP wiring, persistence, middleware, and cross-component interaction.

### Feature Flags

- Feature flags are disabled by default.
- Enable flags only in tests that exercise the feature.
- Use functional options, not globals.

---

## Implementation Patterns

### Service Construction

- Constructors accept required config plus functional options.
- Validate required dependencies and critical config at construction time.
- Apply sensible defaults for optional fields (e.g. TTLs).

### Error Handling

- Use domain error codes via `pkg/domain-errors`.
- Wrap errors with `dErrors.New` or `dErrors.Wrap`.
- Map store-specific errors to domain errors at the service boundary.
- Never expose internal implementation details to clients.

### Audit & Observability

- Emit audit events at key lifecycle transitions.
- Audit publishing happens in services, not handlers.
- Include contextual fields where available:

  - `user_id`, `session_id`, `client_id`, `request_id`

- Use structured logging (`slog`) with context.
- Emit security events to both logs and audit streams.

### Context & Middleware

- Middleware attaches request metadata (IP, user agent, device ID) to `context.Context`.
- Services read request-scoped metadata from context.
- Do not store sensitive data in context.

### Transactions & State Management

- Use `RunInTx` for multi-store writes.
- Update related state atomically:

  - session timestamps
  - token persistence
  - code or refresh token consumption

- Avoid partial persistence on failure.

### Mocks & Interfaces

- Interfaces live with their consuming module.
- Include `//go:generate mockgen` directives with interface definitions.
- Regenerate mocks after interface changes and commit together.

---

## References

- `docs/architecture.md`
- `prd/` directory for feature-specific requirements
