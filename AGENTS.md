# AGENTS.md

## Purpose

This repo uses small, focused review agents. Each agent has a narrow scope and a consistent output format so reviews stay actionable and do not turn into debates.

## How to use

- Pick the smallest set of agents for the task.
- Give each agent the same input (PR link, diff, file paths, or spec excerpt).
- Ask for a short review using the agent’s output format.
- If agents disagree, apply the conflict rules below.

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

### 6) SRP Review Agent

**Scope:** single responsibility and cohesion.

- Flags mixed concerns across packages, types, and functions.
- Prefers small, same-package helpers over new layers or interfaces.
- Keeps validation/auth boundaries explicit.

### 7) Balance Review Agent

**Scope:** Go idioms and abstraction/duplication balance.

- Pass A: simplify over-abstraction and non-idiomatic layering.
- Pass B: reduce harmful repetition with minimal, local helpers.
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
4. SRP (if responsibility/cohesion is unclear)
5. Complexity (if readability or cognitive load is high)
6. Balance (if abstraction/duplication tradeoffs are in play)
7. Testing (if changing behavior, contracts, or refactoring internals)

## Output expectations

All agents should:

- Keep reviews short and ranked by impact.
- Prefer refactors that simplify.
- Provide “next step” changes you can do in one sitting.

## Comment rules

- Add comments only when they provide information not already obvious from names or structure.
- Do not comment to restate self-documenting methods or code.
