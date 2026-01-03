# C4 Architecture Diagrams for Credo

This directory contains comprehensive C4 architecture diagrams for the Credo Identity Verification Gateway, written in [Structurizr DSL](https://docs.structurizr.com/dsl).

## Quick Start

### Option 1: Structurizr Lite (Recommended for Local Development)

```bash
cd docs/architecture/c4
docker-compose up
```

Open http://localhost:8082 to view and interact with the diagrams.

### Option 2: Structurizr CLI (Export to PNG/SVG)

```bash
# Install CLI (macOS)
brew install structurizr/tap/structurizr-cli

# Export all views as PNG
structurizr-cli export -workspace workspace.dsl -format png -output images/

# Export as PlantUML
structurizr-cli export -workspace workspace.dsl -format plantuml -output images/
```

### Option 3: Structurizr Cloud (Team Sharing)

1. Create account at https://structurizr.com
2. Create a new workspace
3. Upload using CLI:
```bash
structurizr-cli push -id WORKSPACE_ID -key API_KEY -secret API_SECRET -workspace workspace.dsl
```

## C4 Model Overview

The [C4 model](https://c4model.com) describes software architecture at four levels of abstraction:

| Level | View | Description |
|-------|------|-------------|
| 1 | **System Context** | Credo in relation to users and external systems |
| 2 | **Container** | Major modules (containers) and their relationships |
| 3 | **Component** | Internal structure of each module |
| 4 | **Code** | Key interfaces defining module boundaries |

## Available Views

### Level 1: System Context

**View: `SystemContext`**

Shows Credo as a single system with:
- **End Users** - Authenticate, manage consent, receive VCs
- **OAuth Clients** - External applications using OAuth 2.0
- **Admin Operators** - System administrators (port 8081)
- **Citizen Registry** - Government identity verification
- **Sanctions Registry** - PEP/sanctions screening

### Level 2: Container Views

| View | Description |
|------|-------------|
| `Containers` | All 10 modules and their relationships |
| `Containers_PublicAPI` | Modules serving port 8080 |
| `Containers_AdminAPI` | Modules serving port 8081 |

**Modules (Containers):**
- `publicAPI` / `adminAPI` - HTTP servers
- `authModule` - OAuth 2.0, sessions, device binding
- `consentModule` - Purpose-based consent lifecycle
- `registryModule` - Multi-provider citizen/sanctions lookups
- `vcModule` - Verifiable credential issuance
- `decisionModule` - Rules engine
- `ratelimitModule` - Rate limiting and DDoS protection
- `tenantModule` - Multi-tenancy, client management
- `adminModule` - Administrative queries
- `platformModule` - Cross-cutting infrastructure

### Level 3: Component Views

Each module has a dedicated component view showing internal structure:

| View | Components |
|------|------------|
| `Components_Auth` | AuthHandler, AuthService, Stores (User, Session, AuthCode, RefreshToken, Revocation), DeviceService, CleanupWorker, RateLimitAdapter |
| `Components_Consent` | ConsentHandler, ConsentService, ConsentStore |
| `Components_Registry` | RegistryHandler, RegistryService, Cache, Orchestrator, ProviderRegistry, CitizenProvider, SanctionsProvider, ConsentAdapter |
| `Components_VC` | VCHandler, VCService, VCStore, ConsentAdapter, RegistryAdapter |
| `Components_Decision` | DecisionService, RegistryAdapter |
| `Components_RateLimit` | Limiter, RequestLimitService, AuthLockoutService, GlobalThrottleService, ClientLimitService, Stores |
| `Components_Tenant` | TenantHandler, TenantService, TenantStore, ClientStore |
| `Components_Admin` | AdminHandler, AdminService |
| `Components_Platform` | ConfigLoader, Logger, JWTService, AuditPublisher, AuditStore, MetricsRegistry |
| `Components_PublicAPI` | Middleware stack (Request, Device, Metadata, RateLimit, Auth) |
| `Components_AdminAPI` | Middleware stack (Request, AdminToken, RateLimit) |

### Level 4: Code Views (Ports & Adapters with Key Methods)

These views highlight the hexagonal architecture boundaries, showing port interfaces with their key method signatures, adapter implementations, and domain aggregates:

| View | Focus |
|------|-------|
| `Code_Auth_Ports` | RateLimitPort, ClientResolver, AuditPublisher - auth service dependencies |
| `Code_Registry_Ports` | ConsentPort adapter, HTTP adapters for external citizen/sanctions registries |
| `Code_VC_Ports` | Dual-port architecture: ConsentPort and RegistryPort for credential issuance |
| `Code_Decision_Ports` | Triple-port rules engine: Consent, Registry, and VC dependencies |
| `Code_RateLimit_Ports` | Five store interfaces: BucketStore, AllowlistStore, AuthLockoutStore, GlobalThrottleStore, ClientLookup |
| `Code_Tenant_Ports` | TenantStore, ClientStore, UserCounter - multi-tenancy persistence |
| `Code_Platform_Audit` | AuditPublisher interface with tri-publisher implementation |

**What's shown in Level 4 views:**
- Port interfaces with key method signatures (e.g., `RequireConsent(userID, purpose)`)
- Adapters that implement each port
- Domain aggregates with state-transition methods
- Cross-module call relationships

## Key Architectural Patterns Visualized

### 1. Hexagonal Architecture (Ports & Adapters)

The diagrams show clear separation between:
- **Ports** (interfaces) - Define module boundaries
- **Adapters** - Implement ports (in-process today, gRPC-ready)

### 2. Two HTTP Servers

- **Port 8080** - Public API (OAuth, consent, registry, VC)
- **Port 8081** - Admin API (X-Admin-Token protected)

### 3. Module Dependencies via Ports

```
Auth ──RateLimitPort──> RateLimit
Auth ──ClientLookup──> Tenant
Registry ──ConsentPort──> Consent
VC ──ConsentPort──> Consent
VC ──RegistryPort──> Registry
Decision ──ConsentPort──> Consent
Decision ──RegistryPort──> Registry
```

### 4. Cross-Cutting Platform

All domain modules depend on `platformModule` for:
- Configuration loading
- Structured logging
- JWT signing/validation
- Audit event publishing
- Prometheus metrics

## Color Legend (Modern Design System)

| Color | Hex | Element Type |
|-------|-----|--------------|
| Indigo | `#4F46E5` | Persons |
| Purple | `#6366F1` | Software Systems |
| Slate | `#64748B` | External Systems |
| Emerald | `#059669` | API Gateways (HTTP servers) |
| Violet | `#7C3AED` | Domain Modules (Hexagon) |
| Slate | `#475569` | Infrastructure |
| Rose | `#FB7185` | Handlers |
| Sky | `#38BDF8` | Services |
| Lavender | `#C4B5FD` | Stores (Cylinder) |
| Mint | `#34D399` | Adapters |
| Amber | `#FCD34D` | Middleware |
| Orange | `#FB923C` | Workers |
| Cream | `#FEF3C7` | Ports (Interfaces, dashed border) |
| Light Blue | `#DBEAFE` | Domain Aggregates |

**Relationship Colors:**
- `#10B981` (green) - "implements" relationships
- `#8B5CF6` (purple, dashed) - "depends on" relationships
- `#3B82F6` (blue) - "calls" relationships

## File Structure

```
docs/architecture/c4/
├── workspace.dsl           # Structurizr DSL workspace (source of truth)
├── docker-compose.yaml     # Structurizr Lite local setup
├── README.md               # This file
└── images/                 # Exported diagrams (generated)
    └── .gitkeep
```

## Maintenance Guidelines

### Adding a New Module

1. Add container definition in the model section
2. Define components within the container
3. Add relationships to other containers/components
4. Create a component view for the new module
5. Apply appropriate tags for styling

### Updating Dependencies

When module dependencies change:
1. Update relationship definitions in the model
2. Verify the views still render correctly
3. Export updated diagrams if using static images

### Keeping Diagrams in Sync

The workspace.dsl should be updated when:
- New modules are added
- Module responsibilities change
- Inter-module dependencies are modified
- New external systems are integrated

## Related Documentation

- [Architecture Overview](../engineering/architecture.md)
- [DDD Patterns](../engineering/ddd.md)
- [Engineering Conventions](../engineering/conventions.md)

## References

- [C4 Model](https://c4model.com)
- [Structurizr DSL Reference](https://docs.structurizr.com/dsl/language)
- [Structurizr Lite](https://docs.structurizr.com/lite)
- [Structurizr CLI](https://docs.structurizr.com/cli)
