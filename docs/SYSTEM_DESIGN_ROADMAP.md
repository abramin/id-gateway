# Credo: System Design Roadmap

This roadmap describes how Credo will evolve from a secure, correct core into a fully articulated system-design showcase. Each phase highlights specific engineering principles: scalability, resilience, performance, observability, and operational clarity. The goal is not to build a production identity platform, but to demonstrate the reasoning and tradeoffs behind one.

## Phase 1: Core Gateway (Security and Correctness)

See main [Architecture document](architecture.md)

## Phase 2: Modular Service Boundaries

The next step introduces internal decomposition. Identity systems grow easier to reason about when concerns are separated.

### Planned Components

- **auth-service**: login, consent, code issuance
- **token-service**: exchange, introspection, refresh
- **session-store**: sessions, device binding
- **audit-log-service**: append-only security events

### Design Focus

- Clearly documented internal APIs (OpenAPI)
- Sync vs async communication choices
- Start using a lightweight event bus for audit and session-change events

This phase demonstrates boundary design, blast radius control, and the rationale behind dividing services.

## Phase 3: High-Load Read Path and Caching Strategy

Token verification and session introspection are the highest-volume operations for an ID gateway. This phase showcases performance reasoning.

### Additions

- Fast introspection endpoint
- Local in-memory caching for token and session reads
- Optional distributed cache (Redis) for shared state

### Tradeoffs to Document

- Latency vs correctness
- Cache invalidation strategies
- Memory footprint vs throughput
- Handling partial failures (cache miss storms, Redis failover)

The code changes themselves are modest; the value lies in the documented reasoning.

## Phase 4: Storage Architecture and Consistency Model

Identity systems mix durable identity data with ephemeral authorization data.

### Storage Model

- **Postgres**: identity records requiring strong consistency
- **Redis**: volatile, high-throughput token/session state

### Design Notes

- Schema design and migrations
- Rationale for separating durable vs ephemeral storage
- Failure-mode analysis: what happens when Redis fails, or Postgres fails over
- Consistency guarantees and where they matter

This phase demonstrates that storage choices reflect reliability goals, not convenience.

## Phase 5: Containerization and Multi-Service Runtime

At this point, the gateway splits into multiple running services.

### Deliverables

- Docker Compose environment running all components
- Health and readiness checks
- Reverse proxy or API gateway layer for routing and rate limiting

### Design Topics

- Readiness vs liveness semantics
- Graceful shutdown and in-flight request handling
- Local dev parity with future Kubernetes deployments

This shows operability thinking: how services behave under start, stop, failure and load.

## Phase 6: Kubernetes + Terraform

The system moves into a realistic orchestration model.

### Kubernetes Additions

- Deployments and Services per component
- Ingress controller for routing
- HPA configuration with reasoning (CPU, RPS, token ops)
- StatefulSet for Postgres
- Secret management strategy (sealed-secrets or external-secrets)

### Terraform

- Infrastructure as code for cluster, network, storage and IAM primitives
- Modular structure reflecting cloud-native design

This phase shows system-design maturity: scheduling, scaling, service discovery, and secret hygiene.

## Phase 7: Observability and Reliability Engineering

An identity service must be observable and measurable.

### Additions

- Prometheus metrics (auth success rate, latency distribution, token refresh behaviour)
- Structured logs with correlation IDs
- Grafana dashboards visualising flow health
- Defined SLOs and error budgets
- Simple chaos experiments (kill a pod, observe recovery)

This phase demonstrates the ability to think in terms of reliability rather than raw uptime.

## Phase 8: Final Architectural Narrative

The project concludes with a formal system design document tailored for interviews and portfolio review.

### Document Sections

- Architecture overview and key decision rationale
- Scaling model and capacity estimate
- Caching and consistency analysis
- Failure modes and mitigations
- Security model and threat analysis
- Testing strategy (BDD, contract tests, attack-path demos)
- Deployment evolution from local to k8s
- Extension roadmap (OIDC federation, MFA, device identity)
