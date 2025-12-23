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

### 4) Security Agent

**Scope:** concrete application security controls and misuse cases.

- AuthN/AuthZ checks, secret handling, dependency/config risks, logging safety.
- Threat-focused review of endpoints, queues, caches, webhooks, uploads.
- Suggests mitigations that fit the current design constraints.

### 5) Secure-by-Design Review Agent

**Scope:** architectural security via modeling and invariants.

- Trust boundaries and boundary translations.
- Domain primitives, constructors/factories, immutability, safe failure modeling.
- Lifecycle safety (identity, tokens/sessions, consents/permissions) in generic terms.
- Rejects patches that do not change unsafe structure.

### 6) Complexity Review Agent

**Scope:** readability and cognitive complexity.

- Simplify long functions, deep nesting, and unclear naming.
- Preserve behavior while reducing mental stack.

### 7) SRP Review Agent

**Scope:** single responsibility and cohesion.

- Flags mixed concerns across packages, types, and functions.
- Prefers small, same-package helpers over new layers or interfaces.
- Keeps validation/auth boundaries explicit.

### 8) Balance Review Agent

**Scope:** Go idioms and abstraction/duplication balance.

- Pass A: simplify over-abstraction and non-idiomatic layering.
- Pass B: reduce harmful repetition with minimal, local helpers.
- Avoids clever indirection; favors concrete types and clear control flow.

## Overlap boundaries (to prevent conflicts)

- **Security Agent** asks: “What can go wrong and what controls prevent it?”
- **Secure-by-Design Agent** asks: “Is the design shaped so whole classes of bugs cannot exist?”
- If both are used, Secure-by-Design sets the design constraints, Security proposes controls that fit them.

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

1. Secure-by-Design (only if changing boundaries, auth, lifecycles, primitives)
2. DDD (if changing domain logic or service boundaries)
3. Security (if changing exposed surfaces, auth, config, deps)
4. Performance (if changing hot paths, concurrency, caching, DB access)
5. SRP (if responsibility/cohesion is unclear)
6. Complexity (if readability or cognitive load is high)
7. Balance (if abstraction/duplication tradeoffs are in play)
8. Testing (if changing behavior, contracts, or refactoring internals)

## Output expectations

All agents should:

- Keep reviews short and ranked by impact.
- Prefer refactors that simplify.
- Provide “next step” changes you can do in one sitting.

## Comment rules

- Add comments only when they provide information not already obvious from names or structure.
- Do not comment to restate self-documenting methods or code.
