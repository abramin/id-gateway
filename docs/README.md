# Credo Documentation

Quick navigation for all technical documentation.

## Quick Links

- **[Architecture](architecture.md)** - System design and service boundaries
- **[API Reference](openapi/index.html)** - Interactive OpenAPI browser

---

## Documentation Index

### Core Design

| Document | Audience | Description |
|----------|----------|-------------|
| [Architecture](architecture.md) | Engineers | System design, data models, flows |
| [Hexagonal Migration](GRPC_ARCHITECTURE_MIGRATION.md) | Engineers | Ports/adapters, future gRPC path |

### Engineering Guidelines

| Document | Audience | Description |
|----------|----------|-------------|
| [Conventions](conventions.md) | Engineers | Code style, patterns, best practices |
| [Testing](testing.md) | Engineers | Testing doctrine, layer definitions |

### Security

| Document | Audience | Description |
|----------|----------|-------------|
| [Device Binding](DEVICE_BINDING.md) | Engineers | Device ID, fingerprinting, risk scoring |
| [Security Playbook](SECURITY_ASSURANCE_PLAYBOOK.md) | Security | Threat modeling, compliance |

### Roadmap & Planning

| Document | Audience | Description |
|----------|----------|-------------|
| [Roadmap](ROADMAP.md) | All | Production features, tracks, module bundles |
| [Wishlist](requirements-wishlist.md) | Product | Future backlog items |

### API Specifications

| Spec | Description |
|------|-------------|
| [Auth](openapi/auth.yaml) | OAuth2/OIDC-lite authentication |
| [Consent](openapi/consent.yaml) | Purpose-based consent management |
| [Registry](openapi/registry.yaml) | Identity verification, sanctions |
| [Tenant](openapi/tenant.yaml) | Multi-tenant administration |

**[Browse all APIs](openapi/index.html)**

### Product Requirements

See **[prd/README.md](prd/README.md)** for all PRDs.
