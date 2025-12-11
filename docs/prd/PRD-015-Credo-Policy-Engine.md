# PRD-015: Credo Policy Engine (Cerbos-Like)

**Status:** Not Started
**Priority:** P2 (Exploratory/Strategic)
**Owner:** Engineering Team
**Dependencies:** PRD-005 (Decision Engine), PRD-005B (Cerbos Authorization), PRD-006 (Audit)
**Last Updated:** 2025-12-08

---

## 1. Overview

### Problem Statement
Relying solely on a third-party PDP (e.g., Cerbos) reduces control over platform-specific features (evidence signals, consent
state, regulated mode). Building an in-house policy engine would let Credo tailor authorization and decision policies to identity
domains while keeping interoperability with external policy-as-code workflows.

### Goals
- Deliver a lightweight, embeddable PDP with a Cerbos-compatible API surface (checkResources) for drop-in replacement.
- Support policy-as-code authoring (YAML/JSON) with versioning, tests, and clear error reporting.
- Enable tight integration with consent state, decision evidence, and audit logging (policy version stamped on decisions).
- Provide plug-in evaluators so domain-specific predicates (e.g., cryptographic credential validity) can be added without forking
  the core engine.

### Non-Goals
- Full ABAC/PBAC feature parity with Cerbos; start with the subset needed by Credo decisions.
- UI for policy editing (stick to files + code review for now).
- Multi-tenant PDP control plane (single-tenant, per-environment deployment).

---

## 2. User Stories

**As a platform engineer**
- I want to run a PDP that understands Credo-specific attributes (consent, risk signals) without upstream changes.

**As a compliance reviewer**
- I want signed, versioned policy bundles so I can attest which rules were enforced for a decision.

**As a backend engineer**
- I want to write and test policies locally with fast feedback, and deploy them alongside services via CI.

---

## 3. Functional Requirements

### FR-1: Policy Model & Bundles
- Policies defined in YAML/JSON stored under `deploy/credo-policies/`.
- Schema supports: resources (sessions, credentials, decisions), actions, roles/attributes, conditional expressions, and
  obligations (e.g., "re-collect credential").
- Policies bundled with version metadata (git SHA + semantic version) and signed manifest for integrity.

### FR-2: Evaluation API (Cerbos-Compatible)
- Expose `POST /api/check` mirroring Cerbos `checkResources` request/response to ease migration.
- Accept subject attributes (user role, consent flags, risk score), resource attributes, and contextual metadata (purpose,
  regulated mode).
- Response includes allow/deny, effect reasons, obligations, and policy version hash.

### FR-3: Embedded + Remote Modes
- **Embedded:** Go library (`pkg/credope`) usable inside monolith for zero-latency local decisions.
- **Remote PDP:** gRPC/HTTP server mode for cross-service calls; horizontally scalable stateless pods.
- Hot-reload policy bundles from disk; explicit reload endpoint for remote mode.

### FR-4: Policy Tests & CI
- Provide golden test runner (`credope test`) to execute policy fixtures; integrate into CI.
- Include fixtures for consent-required flows, sanctions hits, expired credentials, and regulated mode escalation.

### FR-5: Observability & Audit
- Emit structured logs with decision latency, matched policy, and obligation outputs.
- Export Prometheus metrics (decision count, latency histogram, load errors) in remote mode.
- Audit events include policy bundle version and evaluation outcome; compatible with PRD-006 Elasticsearch index.

---

## 4. Technical Approach
- **Rule Engine:** Simple expression language (CEL or similar) compiled to Go for performance; plug-in registry for domain
  predicates (e.g., `has_active_consent`, `vc_age_over_18`).
- **Storage:** Policies stored in git; runtime loads from local disk or object store. In-memory cache with checksum validation;
  optional Redis/DynamoDB backing for remote mode if object store unavailable.
- **Extensibility:** Adapter layer to translate Cerbos YAML into Credo policy schema for partial compatibility.
- **Safety:** Default fail-closed; feature flag to fail-open in local/dev. Validation step rejects policies missing required
  metadata (version, owners, test coverage).

---

## 5. Acceptance Criteria
- PDP accepts Cerbos `checkResources` payloads and returns equivalent decisions for existing test fixtures.
- Embedded mode usable inside the monolith with sub-2ms p99 evaluation latency for cached policy bundles.
- Policy test runner integrated into CI and fails the build on policy regressions.
- Audit trail stamps each decision with policy bundle version/hash for export and search.

