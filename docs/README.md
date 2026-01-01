# Credo Documentation

Quick navigation for core docs in this repo.

## Quick Links

- **[Architecture](engineering/architecture.md)** - System design and service boundaries
- **[API Reference](openapi/index.html)** - Interactive OpenAPI browser
- **[Product Summary](overview/summary.md)** - High-level platform briefing

---

## Documentation Index

### Overview (Project & Product)

| Document | Audience | Description |
|----------|----------|-------------|
| [Summary](overview/summary.md) | All | High-level platform briefing |
| [Strategy](overview/strategy.md) | Product | Strategic positioning and differentiation |
| [Roadmap](overview/ROADMAP.md) | All | Delivery tracks and planned phases |
| [Wishlist](overview/requirements-wishlist.md) | Product | Future backlog items |

### Engineering

| Document | Audience | Description |
|----------|----------|-------------|
| [Architecture](engineering/architecture.md) | Engineers | System design, data models, flows |
| [C4 Diagrams](architecture/c4/README.md) | Engineers | Interactive C4 architecture diagrams (Structurizr DSL) |
| [DDD in Credo](engineering/ddd.md) | Engineers | DDD overview and module examples |
| [Conventions](engineering/conventions.md) | Engineers | Code style, patterns, best practices |
| [Testing](engineering/testing.md) | Engineers | Testing doctrine, layer definitions |

### Security

| Document | Audience | Description |
|----------|----------|-------------|
| [Device Binding](security/DEVICE_BINDING.md) | Engineers | Device ID, fingerprinting, rollout |
| [Security Playbook](security/SECURITY_ASSURANCE_PLAYBOOK.md) | Security | Threat modeling, assurance workflow |
| [Compliance Mapping](security/compliance.md) | Compliance | GDPR/CCPA target-state mapping |

### Migrations (One-Time Guides)

| Document | Audience | Description |
|----------|----------|-------------|
| [Hexagonal Migration](migrations/GRPC_ARCHITECTURE_MIGRATION.md) | Engineers | Ports/adapters, future gRPC path |

### API Specifications

| Spec | Description |
|------|-------------|
| [Auth](openapi/auth.yaml) | OAuth2/OIDC-lite authentication |
| [Consent](openapi/consent.yaml) | Purpose-based consent management |
| [Registry](openapi/registry.yaml) | Identity verification, sanctions |
| [Tenant](openapi/tenant.yaml) | Multi-tenant administration |
| [Rate Limiting](openapi/ratelimit.yaml) | Admin allowlist and rate limit resets |

**[Browse all APIs](openapi/index.html)**

### Product Requirements

See **[prd/README.md](prd/README.md)** for all PRDs.
