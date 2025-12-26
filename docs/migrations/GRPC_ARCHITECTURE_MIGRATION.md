# Hexagonal Architecture Migration Guide

**Date:** 2025-12-11
**Version:** 2.0
**Author:** Engineering Team

---

## Executive Summary

The system currently runs as a monolith with in-process adapters. Credo will be upgraded to use **hexagonal architecture** (ports-and-adapters) with clear module boundaries. GRPC will be used for interservice communication.

### Key Changes

1. ✅ **Port Interfaces** - Domain layer depends only on interfaces
2. ✅ **In-Process Adapters** - Implement ports for current monolith
3. ✅ **Protobuf API Contracts** - Defined in `api/proto/` (for future gRPC)
4. ✅ **Architecture Documentation** - Updated with hexagonal diagrams
5. ✅ **Build System** - Makefile targets for proto generation (future)
6. ⏳ **PRD Updates** - Add interservice communication sections (pending)

---

## Architecture Overview

### Before: Direct Service Dependencies

```
Registry Service
    │
    ├─> import "internal/consent"
    └─> consentService.Require(ctx, userID, purpose)
```

**Problems:**

- Tight coupling between modules
- Hard to test (requires full consent service)
- Cannot extract services to microservices
- Circular dependency risks

### After: Hexagonal Architecture with In-Process Adapters (Phase 0)

```
Registry Service (Domain)
    │
    ├─> Depends on: ports.ConsentPort (interface)
    │
    └─> Injected: adapters.ConsentAdapter (in-process)
            │
            └─> Direct call to Consent Service (same process)
```

**Benefits:**

- Loose coupling via interfaces
- Easy to mock for testing
- Ready for microservices migration (swap adapters)
- No gRPC overhead while in monolith
- Clear module boundaries enforced by ports

---

## Protobuf API Contracts (For Future gRPC)

Protobuf definitions exist in `api/proto/` for future microservices migration. These define the contracts between services when they are eventually split. For now, they are not actively used.

**Future Use:**
- When splitting into microservices, gRPC adapters will use these contracts
- Proto generation via `make proto-gen` (when needed)
- Type-safe, versioned API contracts

---

## Port Interfaces (Domain Layer)

### ConsentPort (`internal/registry/ports/consent.go`)

Defines the interface for consent operations needed by the registry service.

**Key Points:**

- No infrastructure imports (gRPC, HTTP, database)
- Pure domain interface
- Easy to mock for testing
- Implementation-agnostic

```go
type ConsentPort interface {
    HasConsent(ctx context.Context, userID string, purpose string) (bool, error)
    RequireConsent(ctx context.Context, userID string, purpose string) error
}
```

### RegistryPort (`internal/decision/ports/registry.go`)

Defines the interface for registry operations needed by the decision engine.

**Key Points:**

- No infrastructure imports
- Uses port-specific domain models (not database or protobuf models)
- Supports both individual and combined checks

```go
type RegistryPort interface {
    CheckCitizen(ctx context.Context, nationalID string) (*CitizenRecord, error)
    CheckSanctions(ctx context.Context, nationalID string) (*SanctionsRecord, error)
    Check(ctx context.Context, nationalID string) (*CitizenRecord, *SanctionsRecord, error)
}
```

---

## In-Process Adapters (Current)

### ConsentAdapter (`internal/registry/adapters/consent_adapter.go`)

In-process adapter that implements `ports.ConsentPort` by directly calling the consent service.

**Responsibilities:**

- Implement port interface
- Call consent service directly (same process)
- Translate between port models and service models if needed
- No network overhead

**Future Migration:**
When splitting into microservices, replace with `grpc.ConsentClient` - zero changes to registry domain layer.

### RegistryAdapter (`internal/decision/adapters/registry_adapter.go`)

In-process adapter that implements `ports.RegistryPort` by directly calling the registry service.

**Responsibilities:**

- Implement port interface
- Call registry service directly (same process)
- Translate between port models and service models
- No network overhead

**Future Migration:**
When splitting into microservices, replace with `grpc.RegistryClient` - zero changes to decision domain layer.

---

## Dependency Injection (Wiring)

### Main.go Pattern (Current - In-Process)

```go
package main

import (
	"credo/internal/consent/service"
	"credo/internal/decision/adapters"
	"credo/internal/registry/adapters"
	// ...
)

func main() {
	// 1. Create stores
	consentStore := consent.NewInMemoryStore()
	registryStore := registry.NewCacheStore()

	// 2. Create domain services
	consentService := service.NewService(consentStore, auditor, ttl)
	registryService := registry.NewService(citizens, sanctions, registryStore, regulated)

	// 3. Create in-process adapters (implement ports)
	consentAdapter := adapters.NewConsentAdapter(consentService)
	registryAdapter := adapters.NewRegistryAdapter(registryService)

	// 4. Inject adapters into services that need them
	// Registry depends on consent
	registryServiceWithConsent := registry.NewService(
		store,
		consentAdapter, // <-- Implements ports.ConsentPort
	)

	// Decision depends on registry
	decisionService := decision.NewService(
		registryAdapter, // <-- Implements ports.RegistryPort
		policyEngine,
	)

	// 5. HTTP handlers use same services
	httpHandler := transport.NewHandler(
		consentService,
		registryServiceWithConsent,
		decisionService,
		// ...
	)

	// 6. Start HTTP server (no gRPC servers needed yet)
	http.ListenAndServe(":8080", httpHandler)
}
```

### Future Main.go Pattern (After Microservices Split)

When splitting into microservices, only the wiring changes - domain code stays the same:

```go
package main

func main() {
	// 1. Create domain service (consent service example)
	consentService := service.NewService(store, auditor, ttl)

	// 2. Create gRPC server adapter
	consentGRPCServer := grpc.NewConsentServer(consentService)

	// 3. Start gRPC server
	lis, _ := net.Listen("tcp", ":9091")
	grpcServer := grpc.NewServer()
	consentpb.RegisterConsentServiceServer(grpcServer, consentGRPCServer)
	grpcServer.Serve(lis)
}
```

Gateway service:

```go
func main() {
	// 1. Create gRPC client adapters
	consentClient, _ := grpc.NewConsentClient("consent-service:9091")
	registryClient, _ := grpc.NewRegistryClient("registry-service:9092")

	// 2. Inject gRPC adapters (same ports.ConsentPort interface)
	registryService := registry.NewService(
		store,
		consentClient, // <-- Still implements ports.ConsentPort, now via gRPC
	)

	// 3. HTTP handlers
	httpHandler := transport.NewHandler(registryService, ...)
	http.ListenAndServe(":8080", httpHandler)
}
```

---

## Build System Updates

### Makefile Targets

#### Generate Proto Files

```bash
make proto-gen
```

**What it does:**

- Runs `protoc` on all `.proto` files
- Generates `.pb.go` (message types) and `_grpc.pb.go` (service stubs)
- Output: `api/proto/common/commonpb/*.pb.go`, etc.

#### Check Proto Files

```bash
make proto-check
```

**What it does:**

- Verifies generated files match proto definitions
- Fails if proto files were modified but not regenerated
- Used in CI to prevent stale generated code

#### Clean Proto Files

```bash
make proto-clean
```

**What it does:**

- Removes all generated `.pb.go` files
- Useful before full rebuild

### Installation Requirements

```bash
# Install protoc compiler
brew install protobuf  # macOS
apt install protobuf-compiler  # Ubuntu

# Install Go plugins
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Verify installation
protoc --version  # Should be 3.x or higher
which protoc-gen-go protoc-gen-go-grpc  # Should find both
```

---

## Migration Path to Microservices

### Phase 0: Monolith with Hexagonal Architecture (Current)

```
┌────────────────────────────────────┐
│       Single Process (Port 8080)   │
│                                    │
│  ┌──────────┐   ┌──────────────┐  │
│  │ Consent  │   │  Registry    │  │
│  │ Service  │   │  Service     │  │
│  └────┬─────┘   └──────┬───────┘  │
│       │                │           │
│       └────────────────┘           │
│    In-process adapters             │
│    (implement ports)               │
└────────────────────────────────────┘
```

**Current State:**
- All services in single process
- Port interfaces define module boundaries
- In-process adapters implement ports
- No gRPC overhead
- Ready to split when needed

### Phase 1: Extract Consent Service (Future)

```
┌─────────────────────┐      ┌──────────────────────┐
│  Consent Service    │      │  Gateway Service     │
│  (Port 9091)        │◄─────│  (Port 8080)         │
│                     │ gRPC │                      │
│  ┌──────────────┐   │      │  ┌────────────────┐  │
│  │  Consent     │   │      │  │  Registry      │  │
│  │  Service     │   │      │  │  Service       │  │
│  └──────────────┘   │      │  └────────────────┘  │
└─────────────────────┘      └──────────────────────┘
```

**Steps:**

1. Generate protobuf code: `make proto-gen`
2. Implement gRPC server adapter for consent service
3. Implement gRPC client adapter for registry service
4. Start consent service as separate process
5. Update main.go to use `grpc.NewConsentClient("consent-service:9091")`
6. **Zero changes to domain logic** - just swap adapters in main.go
7. Deploy both services
8. Verify gRPC health checks

### Phase 2: Full Microservices (Future)

```
┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│   Auth       │   │  Consent     │   │  Registry    │
│   :9090      │   │  :9091       │   │  :9092       │
└──────┬───────┘   └──────┬───────┘   └──────┬───────┘
       │                  │                  │
       └──────────────────┴──────────────────┘
                      gRPC
                       │
                       ▼
              ┌────────────────────┐
              │  API Gateway       │
              │  (HTTP → gRPC)     │
              └────────────────────┘
```

---

### Interservice Communication Model

**Internal API (gRPC):**

- Protocol: gRPC over HTTP/2
- Serialization: Protocol Buffers
- Auth: Metadata propagation (future: mTLS)
- Location: `api/proto/consent.proto`

**External API (HTTP):**

- Protocol: HTTP/1.1
- Serialization: JSON
- Auth: Bearer tokens (JWT)
- Location: `internal/transport/http/`

**Hexagonal Architecture:**

- Domain layer depends on port interfaces
- gRPC adapters implement ports
- Easy to swap implementations (gRPC, HTTP, in-memory)
- Ready for microservices migration

**Example (Registry → Consent):**

```go
// Domain layer (registry service)
type Service struct {
    consentPort ports.ConsentPort // <-- Interface, not concrete type
}

// Adapter layer (gRPC client)
type ConsentClient struct {
    client consentpb.ConsentServiceClient
}

func (c *ConsentClient) RequireConsent(ctx, userID, purpose) error {
    // Translate domain → proto
    resp, err := c.client.RequireConsent(ctx, &consentpb.RequireConsentRequest{...})
    // Translate proto → domain error
    return mapGRPCError(err)
}

// Wiring (main.go)
consentClient := grpc.NewConsentClient("localhost:9091")
registryService := registry.NewService(store, consentClient)
```

**Future Enhancements:**

- Async background workers (pub/sub)
- Event-driven orchestration (Kafka, NATS)
- Circuit breakers for external services
- Service mesh (Istio, Linkerd) for mTLS and observability

---

## Common Issues & Solutions

### Issue: `protoc: command not found`

**Solution:**

```bash
# macOS
brew install protobuf

# Ubuntu
sudo apt-get install protobuf-compiler

# Verify
protoc --version
```

### Issue: `protoc-gen-go: program not found`

**Solution:**

```bash
# Install Go plugins
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Add to PATH
export PATH="$PATH:$(go env GOPATH)/bin"

# Verify
which protoc-gen-go protoc-gen-go-grpc
```

### Issue: Generated files import wrong packages

**Solution:**
Check `option go_package` in `.proto` files:

```protobuf
option go_package = "github.com/credo/gateway/api/proto/consent;consentpb";
```

### Issue: Circular imports between services

**Solution:**
Use port interfaces, not direct imports:

```go
// ❌ Bad: Direct import
import "internal/consent"
type Service struct {
    consent *consent.Service
}

// ✅ Good: Port interface
import "internal/registry/ports"
type Service struct {
    consentPort ports.ConsentPort
}
```

---

## Best Practices

### 1. Keep Domain Layer Clean

**❌ Don't:**

```go
import consentpb "api/proto/consent"

type Service struct {
    client consentpb.ConsentServiceClient
}
```

**✅ Do:**

```go
import "internal/registry/ports"

type Service struct {
    consentPort ports.ConsentPort
}
```

### 2. Translate at Adapter Boundary

**❌ Don't:** Use protobuf types in domain

```go
func (s *Service) Citizen(ctx, req *registrypb.CheckCitizenRequest) (*registrypb.CitizenRecord, error)
```

**✅ Do:** Use domain models

```go
func (s *Service) Citizen(ctx context.Context, nationalID string) (*models.CitizenRecord, error)
```

### 3. Handle Errors Properly

Map gRPC errors to domain errors:

```go
func mapGRPCError(err error) error {
    st, ok := status.FromError(err)
    if !ok {
        return errors.NewGatewayError(errors.CodeInternal, "internal error", err)
    }

    switch st.Code() {
    case codes.InvalidArgument:
        return errors.NewGatewayError(errors.CodeInvalidArgument, st.Message(), err)
    case codes.NotFound:
        return errors.NewGatewayError(errors.CodeNotFound, st.Message(), err)
    case codes.PermissionDenied:
        return errors.NewGatewayError(errors.CodeMissingConsent, st.Message(), err)
    default:
        return errors.NewGatewayError(errors.CodeInternal, st.Message(), err)
    }
}
```

### 4. Add Timeouts and Retries

```go
func (c *ConsentClient) RequireConsent(ctx, userID, purpose) error {
    // Add timeout
    ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
    defer cancel()

    // Add retry logic (exponential backoff)
    var lastErr error
    for attempt := 0; attempt < 3; attempt++ {
        resp, err := c.client.RequireConsent(ctx, req)
        if err == nil {
            return nil
        }

        // Don't retry on client errors
        if st, ok := status.FromError(err); ok {
            if st.Code() == codes.InvalidArgument || st.Code() == codes.PermissionDenied {
                return mapGRPCError(err)
            }
        }

        lastErr = err
        time.Sleep(time.Duration(attempt*100) * time.Millisecond)
    }
    return lastErr
}
```

### 5. Propagate Metadata

```go
func (c *ConsentClient) addMetadata(ctx context.Context) context.Context {
    requestID, _ := ctx.Value("request_id").(string)

    md := metadata.Pairs(
        "request-id", requestID,
        "timestamp", time.Now().Format(time.RFC3339),
    )
    return metadata.NewOutgoingContext(ctx, md)
}
```

---

## Next Steps

### Current Phase (Phase 0 - Monolith)

- [x] Add port interfaces
- [x] Implement in-process adapters
- [x] Update architecture documentation
- [x] Create protobuf definitions (for future)
- [x] Add Makefile targets
- [ ] Update PRD-001, PRD-002, PRD-003 with interservice communication sections
- [ ] Generate gomock mocks for ports
- [ ] Add integration tests using port interfaces

### Phase 1 (First Microservice Split)

When ready to split consent service:

- [ ] Generate protobuf code: `make proto-gen`
- [ ] Implement gRPC server adapter for consent
- [ ] Implement gRPC client adapter for registry
- [ ] Add gRPC health checks
- [ ] Add retry logic with exponential backoff
- [ ] Implement circuit breakers
- [ ] Add gRPC interceptors for logging/metrics
- [ ] Deploy consent service separately
- [ ] Update main.go wiring (zero domain changes)

### Phase 2 (Full Microservices)

- [ ] Extract registry service
- [ ] Extract auth service
- [ ] Extract decision service
- [ ] Add API gateway (gRPC-Web, Envoy)
- [ ] Use mTLS for production
- [ ] Add service discovery (Consul, etcd)
- [ ] Implement service mesh (Istio)
- [ ] Add distributed tracing (Jaeger, Zipkin)

---

## References

- **Architecture:** [docs/engineering/architecture.md](../engineering/architecture.md)
- **Protobuf Docs:** https://protobuf.dev/
- **gRPC Go Tutorial:** https://grpc.io/docs/languages/go/
- **Hexagonal Architecture:** https://alistair.cockburn.us/hexagonal-architecture/
- **Consent Module README:** [internal/consent/README.md](../internal/consent/README.md)

---

## Revision History

| Version | Date       | Author           | Changes                                                      |
| ------- | ---------- | ---------------- | ------------------------------------------------------------ |
| 1.0     | 2025-12-11 | Engineering Team | Initial gRPC + hexagonal architecture migration guide        |
| 2.0     | 2025-12-11 | Engineering Team | Updated to reflect Phase 0 (monolith with in-process adapters) |
