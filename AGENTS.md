# AGENTS.md

## Purpose

This repo uses small, focused review agents. Each agent has a narrow scope and a consistent output format so reviews stay actionable and do not turn into debates.

## How to use

- Pick the smallest set of agents for the task.
- Give each agent the same input (PR link, diff, file paths, or spec excerpt).
- Ask for a short review using the agent's output format.
- If agents disagree, apply the conflict rules below.

## Shared non-negotiables

All review agents inherit these rules. Individual agents should not repeat them; they reference this section.

1. **No business logic in handlers** — handlers parse, call services, map responses.
2. **Domain state checks as intent-revealing methods** — use `IsPending()`, `CanRotate()`, not `status == X`.
3. **Validation at trust boundaries via Parse\*/constructors** — strict ordering: Origin → Size → Lexical → Syntax → Semantics.
4. **No Must\*/panic in production code** — test-only if needed.
5. **No internal errors exposed to clients** — safe messages + stable codes.
6. **Atomic multi-write operations** — no partial writes; use transactions/RunInTx.
7. **Prefer type aliases + Parse\* over struct wrappers for IDs** — e.g., `type UserID uuid.UUID`.
8. **Interfaces at consumer site** — only when 2+ implementations or a hard boundary exists.

## When to use which agent

Use this decision tree to select the right agent:

| Question                               | Agent                       |
| -------------------------------------- | --------------------------- |
| "Is this too complicated to read?"     | **complexity-review**       |
| "Is this doing too many things?"       | **balance-review** (PASS A) |
| "Is the model/aggregate design right?" | **ddd-review**              |
| "Is there a security gap?"             | **secure-design-agent**     |
| "Is there unnecessary indirection?"    | **balance-review** (PASS C) |
| "Is there harmful duplication?"        | **balance-review** (PASS B) |
| "Where's the I/O hiding?"              | **balance-review** (PASS D) |
| "Will this scale?"                     | **performance-review**      |
| "Are the tests right?"                 | **testing-review**          |

## Agent roster

### 1) Testing Agent

**Scope:** contracts and behavior verification.

- Prefers contract-first integration tests over mocks.
- Focuses on scenario coverage, determinism, and avoiding duplicate test layers.
- Will only discuss architecture when it affects testability or behavioral contracts.

### 2) DDD Patterns Agent

**Scope:** domain model clarity.

- Aggregates, invariants, value objects, domain primitives, transitions.
- Boundary hygiene between transport, application, domain, persistence.
- Avoids framework-specific styling unless it impacts domain integrity.
- **Typed IDs:** Prefer custom ID types (e.g., `UserID`, `SessionID`) over raw `uuid.UUID` or `string`. This prevents mixing up identifiers across aggregates and makes function signatures self-documenting.

### 3) Performance Agent

**Scope:** scalability and predictability under load.

- Measurement-first (p95, error rate, saturation), backpressure, timeouts, bounded retries.
- DB access patterns, cache correctness, queue/stream throughput patterns.
- Will not propose “speed” changes that weaken correctness or security.

### 4) Secure-by-Design Agent (Combined Security)

**Scope:** security through design and concrete controls.

- Trust boundaries, boundary translations, and ordered validation.
- Domain primitives, constructors/factories, immutability, safe failure modeling.
- AuthN/AuthZ checks, secret handling, logging safety.
- Lifecycle safety (identity, tokens/sessions, consents/permissions).
- Threat-focused review of endpoints, queues, caches, webhooks, uploads.
- Rejects patches that do not change unsafe structure; prefers design-level refactors.

### 5) Complexity Review Agent

**Scope:** readability and cognitive complexity.

- Simplify long functions, deep nesting, and unclear naming.
- Preserve behavior while reducing mental stack.
- For extraction trade-offs, see balance-review PASS B.

### 6) Balance Review Agent

**Scope:** Go idioms, abstraction/duplication balance, and structural cohesion.

- Pass A: simplify over-abstraction, non-idiomatic layering, and mixed responsibilities (incorporates former srp-review).
- Pass B: reduce harmful repetition with minimal, local helpers.
- Pass C: enforce hop budget and eliminate boomerang flows.
- Pass D: verify effects visibility (where's the I/O?).
- Avoids clever indirection; favors concrete types and clear control flow.

## Conflict resolution rules (tie-breakers)

1. **Correctness beats performance.**
2. **Security beats convenience.**
3. **Contracts beat implementation details.**
4. If two agents disagree, prefer the smallest change that satisfies both.
5. If a tradeoff is real, document it explicitly:
   - what you gain
   - what risk you accept
   - how you will test or monitor it

## Default review order

1. Secure-by-Design (if changing boundaries, auth, lifecycles, primitives, exposed surfaces, config, deps)
2. DDD (if changing domain logic or service boundaries)
3. Performance (if changing hot paths, concurrency, caching, DB access)
4. Balance (if abstraction/duplication/cohesion tradeoffs are in play — includes responsibility analysis)
5. Complexity (if readability or cognitive load is high)
6. Testing (if changing behavior, contracts, or refactoring internals)

## Output expectations

All agents should:

- Keep reviews short and ranked by impact.
- Prefer refactors that simplify.
- Provide “next step” changes you can do in one sitting.

## Comment rules

- Add detailed comments for exported methods and types, especially for complex methods that perform various processing steps or state changes.
- For very simple methods that do a single thing that is clear from method name, skip comments.
