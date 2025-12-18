# PRD-003: Registry Integration (Citizen & Sanctions)

**Status:** In Progress
**Priority:** P0 (Critical)
**Owner:** Engineering Team
**Last Updated:** 2025-12-18
**Version:** 1.3

---

## 1. Overview

### Problem Statement

Credo needs to integrate with external government and financial registries to verify user identity and screen for sanctions/PEP status. These registries:

- Contain Personally Identifiable Information (PII)
- Have latency (network calls to external systems)
- Should be cached to reduce costs and improve performance
- Must respect data minimization principles (GDPR Article 5)

### Goals

- Integrate with **Citizen Registry** (population/national ID database)
- Integrate with **Sanctions/PEP Registry** (watchlists)
- Implement caching layer with TTL to minimize external calls
- Support **Regulated Mode** where PII is minimized after processing
- Provide HTTP endpoints for on-demand registry lookups
- Handle registry errors gracefully (timeouts, unavailable)

### Non-Goals

- Real external registry integration (use mocks for MVP)
- Batch registry lookups
- Registry synchronization/replication
- Multiple registry providers (single mock per type)
- Historical registry snapshots
- Real-time registry webhooks

---

## 2. User Stories

**As a** compliance officer
**I want to** verify user identity against national databases
**So that** I can comply with KYC regulations

**As a** risk analyst
**I want to** screen users against sanctions lists
**So that** I can identify high-risk individuals

**As a** system operator
**I want to** cache registry responses
**So that** I reduce costs and improve performance

**As a** privacy officer
**I want to** minimize PII retention in regulated mode
**So that** I comply with GDPR data minimization

---

## 3. Functional Requirements

### FR-1: Citizen Registry Lookup

**Endpoint:** `POST /registry/citizen`

**Description:** Lookup citizen record from national population registry. Returns identity attributes including full name, date of birth, and validation status.

**Input:**

```json
{
  "national_id": "123456789"
}
```

**Output (Success - 200, Non-Regulated Mode):**

```json
{
  "national_id": "123456789",
  "full_name": "Alice Marie Johnson",
  "date_of_birth": "1990-05-15",
  "address": "123 Main Street, Springfield, IL 62701",
  "valid": true,
  "checked_at": "2025-12-03T10:00:00Z"
}
```

**Output (Success - 200, Regulated Mode):**

```json
{
  "national_id": "123456789",
  "valid": true,
  "checked_at": "2025-12-03T10:00:00Z"
}
```

**Business Logic:**

1. Extract user from bearer token
2. Require consent for `ConsentPurposeRegistryCheck`
3. Validate national_id format (non-empty, alphanumeric)
4. Check cache for recent citizen record (<5 min old)
5. If cache miss:
   - Call MockCitizenClient.Check(nationalID)
   - Store result in cache with TTL
6. If regulated mode:
   - Call MinimizeCitizenRecord() to strip PII
7. Emit audit event
8. Return record

**Validation:**

- national_id required and non-empty
- national_id matches pattern: `^[A-Z0-9]{6,20}$`

**Error Cases:**

- 401 Unauthorized: Invalid bearer token
- 403 Forbidden: Missing consent
- 400 Bad Request: Invalid national_id format
- 504 Gateway Timeout: Registry unavailable or timeout
- 500 Internal Server Error: Cache or store failure

**Audit Event:**

```json
{
  "action": "registry_citizen_checked",
  "user_id": "user_123",
  "purpose": "registry_check",
  "decision": "checked",
  "reason": "identity_verification"
}
```

---

### FR-2: Sanctions/PEP Lookup

**Endpoint:** `POST /registry/sanctions`

**Description:** Screen user against sanctions lists and PEP databases. Returns whether user is flagged and the source of the flag.

**Input:**

```json
{
  "national_id": "123456789"
}
```

**Output (Success - 200):**

```json
{
  "national_id": "123456789",
  "listed": false,
  "source": "mock_sanctions_db",
  "checked_at": "2025-12-03T10:00:00Z"
}
```

**Output (User is Sanctioned - 200):**

```json
{
  "national_id": "987654321",
  "listed": true,
  "source": "EU Sanctions List",
  "checked_at": "2025-12-03T10:00:00Z"
}
```

**Business Logic:**

1. Extract user from bearer token
2. Require consent for `ConsentPurposeRegistryCheck`
3. Validate national_id format
4. Check cache for recent sanctions record (<5 min old)
5. If cache miss:
   - Call MockSanctionsClient.Check(nationalID)
   - Store result in cache with TTL
6. Emit audit event (always log sanctions checks)
7. Return record

**Note:** Sanctions records do NOT contain PII (only boolean flag), so no minimization needed.

**Error Cases:**

- 401 Unauthorized: Invalid bearer token
- 403 Forbidden: Missing consent
- 400 Bad Request: Invalid national_id format
- 504 Gateway Timeout: Registry unavailable
- 500 Internal Server Error: Cache or store failure

**Audit Event:**

```json
{
  "action": "registry_sanctions_checked",
  "user_id": "user_123",
  "purpose": "sanctions_screening",
  "decision": "not_listed", // or "listed"
  "reason": "aml_ctf_compliance"
}
```

---

### FR-3: Combined Registry Check (Internal Service)

**Function:** `registryService.Check(ctx, nationalID)`

**Description:** Internal service method that performs both citizen and sanctions lookups in one call. Used by decision engine to gather all registry evidence.

**Usage Example:**

```go
citizen, sanctions, err := h.registryService.Check(ctx, nationalID)
if err != nil {
    return err
}
// Use both records for decision
```

**Returns:**

- `*CitizenRecord` - Full citizen data
- `*SanctionsRecord` - Sanctions/PEP status
- `error` - Any registry or network error

**Business Logic:**

1. Call `Citizen()` and `Sanctions()` concurrently using a shared `context.Context` (errgroup preferred) with early cancel on first failure or timeout (5s max).
2. Capture per-call latency and cache hit/miss metadata for traces/metrics.
3. If either fails, return error; otherwise return both records as a single evidence bundle.

### Identity Evidence Orchestration

- The registry service acts as an identity-evidence aggregator that sequences registry lookups alongside other verification methods (e.g., document checks) to produce a combined evidence package.
- The orchestration layer selects lookup paths per configuration/consent and is extendable to additional registry families (civil registry, driver license APIs, digital ID wallets, biometric matches) without changing callers.
- Multi-source correlation rules (e.g., reconcile conflicting name/address, merge confidence scores) are implemented so combined evidence can be weighted per provider and regulatory regime.

**Implementation Status:** The provider abstraction architecture has been implemented with the following components:

- **Provider Interface**: Universal contract for all evidence sources with capability negotiation
- **Protocol Adapters**: Pluggable support for HTTP, SOAP, and gRPC protocols via adapter pattern
- **Error Taxonomy**: Normalized failure categories (timeout, bad_data, authentication, provider_outage, contract_mismatch, not_found, rate_limited, internal) with automatic retry semantics
- **Orchestrator**: Multi-source coordination with four lookup strategies (primary, fallback, parallel, voting)
- **Correlation Rules**: Pluggable rules for merging evidence from multiple sources (CitizenNameRule, WeightedAverageRule)
- **Contract Testing**: Framework for validating provider API compatibility and detecting breaking changes

---

## 4. Technical Requirements

### TR-1: Data Models

**CitizenRecord** (Location: `internal/evidence/registry/models.go`)

```go
type CitizenRecord struct {
    NationalID  string    // Unique national identifier
    FullName    string    // Full legal name
    DateOfBirth string    // Format: YYYY-MM-DD
    Address     string    // Full address (street, city, postal, country)
    Valid       bool      // Whether record is valid/active
    CheckedAt   time.Time // When this record was fetched
}
```

**SanctionsRecord** (Location: `internal/evidence/registry/models.go`)

```go
type SanctionsRecord struct {
    NationalID string    // Unique national identifier
    Listed     bool      // Whether person is on sanctions/PEP list
    Source     string    // Source of the flag (e.g., "EU Sanctions List")
    CheckedAt  time.Time // When this record was fetched
}
```

### TR-2: Registry Clients (Mocks)

**CitizenRegistryClient Interface** (Location: `internal/evidence/registry/client_citizen.go`)

```go
type CitizenClient interface {
    Check(ctx context.Context, nationalID string) (*CitizenRecord, error)
}

type MockCitizenClient struct {
    latency      time.Duration // Simulated network latency
    regulated    bool          // Whether to minimize data
}

func (c *MockCitizenClient) Check(ctx context.Context, nationalID string) (*CitizenRecord, error) {
    // 1. Sleep for latency (simulate network call)
    // 2. Generate deterministic test data based on nationalID hash
    // 3. Return CitizenRecord
}
```

**SanctionsRegistryClient Interface** (Location: `internal/evidence/registry/client_sanctions.go`)

```go
type SanctionsClient interface {
    Check(ctx context.Context, nationalID string) (*SanctionsRecord, error)
}

type MockSanctionsClient struct {
    latency time.Duration // Simulated network latency
    listed  bool          // Whether to return listed=true (for testing)
}

func (c *MockSanctionsClient) Check(ctx context.Context, nationalID string) (*SanctionsRecord, error) {
    // 1. Sleep for latency
    // 2. Return SanctionsRecord with configurable listed flag
}
```

**Mock Data Generation:**

- Use hash of nationalID to deterministically generate data
- Example: Hash(nationalID) % 100 determines age
- Example: Hash(nationalID) % 10 determines if PEP

### TR-3: Cache Store

**RegistryCacheStore Interface** (Location: `internal/evidence/registry/store.go`)

```go
type RegistryCacheStore interface {
    SaveCitizen(ctx context.Context, record *CitizenRecord) error
    FindCitizen(ctx context.Context, nationalID string) (*CitizenRecord, error)
    SaveSanction(ctx context.Context, record *SanctionsRecord) error
    FindSanction(ctx context.Context, nationalID string) (*SanctionsRecord, error)
    ClearAll(ctx context.Context) error
}
```

**InMemoryCache** (Location: `internal/evidence/registry/store_memory.go`)

```go
type InMemoryCache struct {
    mu        sync.RWMutex
    citizens  map[string]*CitizenRecord
    sanctions map[string]*SanctionsRecord
    ttl       time.Duration // From config.RegistryCacheTTL
}

func (c *InMemoryCache) FindCitizen(ctx context.Context, nationalID string) (*CitizenRecord, error) {
    // 1. Check if record exists
    // 2. Check if time.Since(record.CheckedAt) < c.ttl
    // 3. If expired, return ErrNotFound
    // 4. Otherwise return record
}
```

**Cache TTL:** `config.RegistryCacheTTL = 5 * time.Minute`

### TR-4: Service Layer

**RegistryService** (Location: `internal/evidence/registry/service.go`)

```go
type Service struct {
    citizenClient   CitizenClient
    sanctionsClient SanctionsClient
    cache           RegistryCacheStore
    auditor         audit.Publisher
    regulatedMode   bool
    now             func() time.Time
}

func (s *Service) Check(ctx context.Context, nationalID string) (*CitizenRecord, *SanctionsRecord, error)
func (s *Service) Citizen(ctx context.Context, nationalID string) (*CitizenRecord, error)
func (s *Service) Sanctions(ctx context.Context, nationalID string) (*SanctionsRecord, error)
// Check MUST execute citizen + sanctions lookups in parallel (errgroup or equivalent), propagate context cancellation, and annotate spans/metrics with cache outcomes and per-call latency.
```

### TR-5: Data Minimization

**MinimizeCitizenRecord Function** (Location: `internal/evidence/registry/models.go`)

```go
func MinimizeCitizenRecord(record *CitizenRecord, regulatedMode bool) *CitizenRecord {
    if !regulatedMode {
        return record // Return full record
    }
    // In regulated mode, keep only non-PII fields
    return &CitizenRecord{
        NationalID: record.NationalID,
        Valid:      record.Valid,
        CheckedAt:  record.CheckedAt,
        // FullName, DateOfBirth, Address are cleared
    }
}
```

**When to Apply:**

- After fetching from registry client
- Before returning in HTTP response
- Before storing in cache (store full, minimize on read)

### TR-6: Partner Registry Integration Model

**Provider Abstraction Architecture** (Implemented in `internal/evidence/registry/providers/`)

The registry module implements a provider abstraction layer that enables pluggable, multi-source evidence aggregation:

**Core Components:**

- **Provider Interface**: All registry sources implement a universal Provider interface with ID, Capabilities, Lookup, and Health methods. This enables protocol-agnostic integration regardless of whether the provider uses HTTP, SOAP, or gRPC.

- **Capability Negotiation**: Each provider declares its capabilities including protocol type, evidence type, supported fields, API version, and available filters. This metadata enables dynamic routing and compatibility checking.

- **Error Taxonomy**: All provider errors are normalized into eight categories with explicit retry semantics. Timeout, provider outage, and rate-limited errors are automatically retryable, while authentication, bad data, and contract mismatch errors are not.

- **Protocol Adapters**: HTTP, SOAP, and gRPC adapters handle protocol-specific concerns (serialization, authentication, transport) while presenting a uniform Provider interface to callers. Custom response parsers convert provider-specific formats into normalized Evidence structures.

- **Evidence Structure**: All providers return a generic Evidence container with provider metadata, confidence scores, structured data map, timestamps, and trace information. This allows heterogeneous evidence from different sources to be handled uniformly.

**Orchestration Layer** (Implemented in `internal/evidence/registry/orchestrator/`)

The orchestrator coordinates multi-source evidence gathering with:

- **Provider Registry**: Central registry maintaining all registered providers with lookup by ID or type

- **Lookup Strategies**: Four strategies support different use cases - Primary (fast, single source), Fallback (resilient, tries alternatives), Parallel (comprehensive, queries all), Voting (high confidence, uses consensus)

- **Provider Chains**: Configurable fallback sequences per evidence type with timeout and retry policies

- **Correlation Rules**: Pluggable rules merge conflicting evidence from multiple sources, reconcile field discrepancies, and compute weighted confidence scores

**Contract Testing Framework** (Implemented in `internal/evidence/registry/providers/contract/`)

Maintains provider compatibility through:

- **Contract Suites**: Validate provider outputs against expected schema and behavior
- **Capability Tests**: Verify declared capabilities match actual provider behavior
- **Error Contract Tests**: Ensure errors follow the normalized taxonomy
- **Snapshot Tests**: Detect unintended API changes through regression testing

This architecture satisfies all TR-6 requirements while providing a foundation for future registry integrations.

---

## 5. API Specifications

### Endpoint Summary

| Endpoint              | Method | Auth Required | Consent Required | Purpose             |
| --------------------- | ------ | ------------- | ---------------- | ------------------- |
| `/registry/citizen`   | POST   | Yes           | `registry_check` | Citizen lookup      |
| `/registry/sanctions` | POST   | Yes           | `registry_check` | Sanctions screening |

### Mock Client Configuration

**Environment Variables:**

```bash
CITIZEN_REGISTRY_LATENCY=100ms   # Simulated latency
SANCTIONS_REGISTRY_LATENCY=50ms  # Simulated latency
REGULATED_MODE=true              # Enable data minimization
```

### Cache Behavior

**Cache Hit:**

- Record found in cache
- CheckedAt < 5 minutes ago
- Return cached record (no external call)
- Latency: <1ms

**Cache Miss:**

- Record not in cache OR expired
- Call external client
- Store in cache with current timestamp
- Return fresh record
- Latency: 50-200ms (simulated)

---

## 6. Security Requirements

### SR-1: Data Minimization (GDPR Article 5)

In regulated mode:

- Strip FullName, DateOfBirth, Address from citizen records
- Keep only Valid flag and NationalID
- Apply minimization before storing in logs
- Apply minimization before returning to client

### SR-2: Cache Security

- Cache TTL must be enforced (5 minutes max)
- Cache must be cleared on user data deletion request
- Cache should not persist to disk (in-memory only)
- Cache keys should not leak in logs

### SR-3: Registry Call Authorization

- All registry calls require valid bearer token
- All registry calls require consent
- Rate limiting per user (future: 10 requests/minute)

### Threat Model Snapshot

- Replay attacks on registry endpoints (mitigate with nonce/timestamp validation and TLS-only transport).
- Enumeration of national IDs via brute-force requests (mitigate with rate limiting, anomaly detection, and consent gating).
- Cache poisoning altering registry responses (mitigate with integrity checks and scoped cache keys).
- Leakage of provider credentials or API keys (mitigate with secret rotation, scoped permissions, and access logging).

---

## 7. Performance Requirements

### PR-1: Latency

- Cache hit: <5ms p99
- Cache miss (mock client): <250ms p99
- Combined check (parallel): <300ms p99

### PR-2: Cache Hit Rate

- Target: >80% cache hit rate for repeated lookups
- Monitor cache expiry impact on hit rate

### PR-3: Timeout Handling

- Client timeout: 5 seconds
- If registry unreachable, fail fast
- Return 504 Gateway Timeout to client

### PR-4: Real-time Availability and Latency SLOs

- Target registry availability SLO: 99.9% monthly for combined registry orchestration.
- External registry calls should meet p95 latency of 300ms and p99 latency of 500ms; combined citizen+sanctions flows should meet p95 400ms and p99 700ms including cache misses.
- Define fallback strategies (use cached responses, switch to alternate providers, or short-circuit with manual review) when provider health degrades or latency budgets are exceeded.

---

## 8. Observability Requirements

### Logging

**Events to Log:**

- Registry call started (debug)
- Registry call completed (debug, include latency)
- Cache hit/miss (debug)
- Registry timeout (warning)
- Registry error (error)
- Citizen checked (audit)
- Sanctions checked (audit)

### Metrics

- Registry calls total (counter, labeled by type: citizen/sanctions)
- Cache hit rate (gauge, labeled by type)
- Registry latency (histogram, labeled by type)
- Registry timeouts (counter, labeled by type)
- Registry errors (counter, labeled by type)

### Dashboards and Failure Taxonomy

- Per-provider dashboards showing request volume, latency percentiles, error codes, and cache effectiveness; include drilldowns for capability gaps per provider.
- Standardized failure taxonomy: timeout, bad/invalid data, authentication failure, dependency outage, contract/version mismatch.
- Correlate registry evidence with user verification flows (link trace IDs to user/session IDs in decision engine dashboards).
- Regulator-facing audit trail dashboards summarizing consent status, evidence provenance, and data minimization state.

### Tracing

- All registry flows **MUST** emit distributed traces using an internal tracer interface (do not depend directly on OpenTelemetry APIs). The interface **MUST** support `Start(ctx, name, attrs...) (context.Context, Span)` and `Span.End(err error)` so spans can record failures without panics.
- `Service.Check` **MUST** start a parent span named `registry.check` with attributes for `national_id` (hashed or redacted) and `regulated_mode`. Child spans **MUST** wrap `Citizen` and `Sanctions` calls (`registry.citizen` and `registry.sanctions`) and annotate cache hits/misses via span attributes (`cache.hit`, `cache.ttl_remaining_ms`).
- Mock clients **MUST** start spans for outbound calls (`registry.citizen.call`, `registry.sanctions.call`) and include attributes for simulated latency and deterministic test data branches (e.g., `listed`, `age_bucket`).
- Emit a span event named `audit.emitted` after audit publishing to show ordering of compliance logging versus registry calls.
- Provide a **no-op tracer** for tests and **inject** the tracer into `Service` and mock clients so tracing is optional but configurable. Production wiring should use OpenTelemetry to satisfy the interface.
- Apply sampling rules that retain failure/error spans at 100% and downsample successful calls while keeping exemplars for p99 latency; ensure spans satisfy eIDAS/ISO/ITF audit traceability expectations where applicable.

---

## 9. Testing Requirements

### Unit Tests

- [ ] Test MinimizeCitizenRecord in regulated mode
- [ ] Test MinimizeCitizenRecord in non-regulated mode
- [ ] Test cache hit (recent record)
- [ ] Test cache miss (no record)
- [ ] Test cache expiry (old record)
- [ ] Test mock client data generation (deterministic)

### Integration Tests

- [ ] Test citizen lookup with cache miss
- [ ] Test citizen lookup with cache hit
- [ ] Test sanctions lookup with cache
- [ ] Test combined Check() in parallel
- [ ] Test regulated mode minimization end-to-end
- [ ] Test consent enforcement (403 without consent)

### Performance Tests

- [ ] Test cache hit latency (<5ms)
- [ ] Test mock client latency (~100ms)
- [ ] Test parallel Check() latency (<300ms)

### Manual Testing

```bash
# 1. Grant consent first
curl -X POST http://localhost:8080/auth/consent \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"purposes": ["registry_check"]}'

# 2. Lookup citizen (non-regulated mode)
REGULATED_MODE=false make run

curl -X POST http://localhost:8080/registry/citizen \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"national_id": "123456789"}'

# Expected: Full citizen data with name, DOB, address

# 3. Lookup citizen (regulated mode)
REGULATED_MODE=true make run

curl -X POST http://localhost:8080/registry/citizen \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"national_id": "123456789"}'

# Expected: Only valid flag, no PII

# 4. Lookup sanctions
curl -X POST http://localhost:8080/registry/sanctions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"national_id": "123456789"}'

# Expected: {"listed": false, "source": "mock_sanctions_db"}

# 5. Test cache (call same ID twice quickly)
curl -X POST http://localhost:8080/registry/citizen \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"national_id": "123456789"}'

# Note timestamp, then immediately call again

curl -X POST http://localhost:8080/registry/citizen \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"national_id": "123456789"}'

# Second call should be much faster (cache hit)
# checked_at timestamp should be same (cached)

# 6. Test without consent (should fail)
curl -X POST http://localhost:8080/auth/consent/revoke \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"purposes": ["registry_check"]}'

curl -X POST http://localhost:8080/registry/citizen \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"national_id": "123456789"}'

# Expected: 403 Forbidden
```

---

## 10. Implementation Steps

### Phase 1: Service Layer Enhancement (1-2 hours)

1. Update `RegistryService` in `internal/evidence/registry/service.go`
2. Implement `Citizen()`:
   - Check cache first
   - Call client on miss
   - Store in cache
   - Apply minimization if regulated mode
   - Return record
3. Implement `Sanctions()`:
   - Similar logic to Citizen()
4. Implement `Check()`:
   - Call Citizen() and Sanctions() in parallel
   - Use goroutines + channels or errgroup
   - Return both records

### Phase 2: HTTP Handlers (1-2 hours)

1. Implement `handleRegistryCitizen`:
   - Extract user from token
   - Require consent
   - Parse national_id from body
   - Call service.Citizen()
   - Emit audit event
   - Return JSON
2. Implement `handleRegistrySanctions`:
   - Similar to handleRegistryCitizen
   - Call service.Sanctions()

### Phase 3: Mock Clients Enhancement (30 min)

1. Update `MockCitizenClient.Check()`:
   - Add configurable latency (sleep)
   - Generate deterministic test data
2. Update `MockSanctionsClient.Check()`:
   - Add configurable latency
   - Support configurable listed flag

### Phase 4: Testing (1-2 hours)

1. Unit tests for service methods
2. Integration tests for cache behavior
3. Manual testing with curl
4. Performance testing (cache hit latency)

---

## 11. Coverage Model

- Maintain a mapping from region or ID format to registry provider (e.g., national IDs → civil registry mock, passports → unsupported, driver license → future provider).
- Support configurable fallback chains (preferred provider → secondary provider → manual review) when primary registries are unavailable or lack fields.
- Allow configuration for unsupported IDs to short-circuit with user-friendly errors and compliance logging instead of opaque failures.
- Track coverage percentage of the active user base by registry method to guide expansion and onboarding of new providers.

---

## 12. Acceptance Criteria

- [ ] Citizen lookup returns full data in non-regulated mode
- [ ] Citizen lookup returns minimized data in regulated mode
- [ ] Sanctions lookup returns listed status
- [ ] Cache reduces latency on repeated lookups
- [ ] Cache expires after 5 minutes
- [ ] Combined Check() runs citizen + sanctions in parallel with shared context cancellation and traces/metrics for each call
- [ ] Operations require consent (403 without)
- [ ] All lookups emit audit events
- [ ] Mock clients simulate realistic latency
- [ ] Registry timeouts return 504
- [ ] Code passes `make test` and `make lint`

---

## 13. Dependencies & Blockers

### Dependencies

- PRD-001: Authentication & Session Management (for user extraction)
- PRD-002: Consent Management (for consent checks)
- `internal/evidence/registry/store_memory.go` - ✅ Implemented
- `internal/evidence/registry/models.go` - ✅ Implemented
- `pkg/errors` - ✅ Implemented

### Potential Blockers

- None identified

---

## 14. Future Enhancements (Out of Scope)

- Real external registry integration (SOAP/REST APIs)
- Batch registry lookups (check multiple IDs)
- Registry webhooks (real-time updates)
- Multiple registry providers (failover)
- Historical registry snapshots (time travel queries)
- Persistent cache (Redis, Memcached)
- Cache warming (pre-populate frequently accessed records)
- Rate limiting per user/IP
- Retry logic with exponential backoff
- Circuit breaker for registry failures
- Biometric pipeline compatibility: optional hooks for face match scores and liveness evidence treated as standardized confidence inputs alongside registry checks.
- Bringing registry logic in-house: replace mocks with internally maintained registry connectors (caching, SLA monitoring, schema validation, resilience patterns) to reduce third-party dependency and limit downtime blast radius.

### Registry Integration Readiness Checklist (Appendix)

- Contract tests executed against provider sandbox and recorded for CI.
- Privacy and consent review completed (data minimization, hashing/pseudonymization plans documented).
- Latency budget analysis for provider endpoints and combined orchestration paths.
- Permission model verified (API keys/credentials scoped by environment and role).
- Consent flow validation and audit logging verified end-to-end.
- Partner onboarding steps complete (API keys provisioned, sandbox/live toggles, error contract signed-off).

---

## 15. Regulatory Considerations

### GDPR Compliance (Article 5: Data Minimization)

- ✅ Collect only necessary data (national ID for lookup)
- ✅ Retain full data only in cache (5 min TTL)
- ✅ Return minimized data in regulated mode
- ✅ Clear cache on user data deletion

### KYC/AML Compliance

- ✅ Verify identity against authoritative source
- ✅ Screen against sanctions/PEP lists
- ✅ Audit all checks for compliance evidence
- ✅ Cache to reduce costs while maintaining freshness

### Regulatory Adaptability and Privacy Constraints

- Support eIDAS 2.0/European digital identity wallet alignment by accepting verifiable credentials as registry evidence inputs where available.
- Store proof of consent (purpose, timestamp, jurisdiction) and link to audit events; enforce jurisdiction-specific retention policies.
- Hash or pseudonymize national identifiers in traces/logs; keep PII separated from result sets in regulated deployments.
- Make data retention configurable by jurisdiction and purpose, with default minimization for regulated environments.

---

## 16. References

- [GDPR Article 5: Principles relating to processing](https://gdpr-info.eu/art-5-gdpr/)
- Tutorial: `docs/TUTORIAL.md` Section 3
- Architecture: `docs/architecture.md`
- Existing Implementation: `internal/evidence/registry/`

---

## 17. Secure-by-Design Requirements

- Value objects: `NationalID`, `TenantID`, `ConsentPurpose`, `RegistryRequest` must be constructed via validated constructors (Origin → Size → Lexical → Syntax → Semantics). Raw maps are not accepted at service boundaries.
- Default deny: Missing consent, invalid regulated-mode config, or registry adapter misconfiguration results in audited denial (no implicit allow).
- Immutability: Registry responses are immutable snapshots; regulated-mode minimization yields a distinct minimized type that cannot be re-expanded.
- Fail-fast connectors: Registry adapters fail fast on bad endpoints/credentials and return typed results (found/missing/stale/error) rather than generic errors.
- Sensitive data: National IDs and raw registry payloads are never logged; traces/audit use hashed/pseudonymous identifiers. Secrets/credentials are read-once and zeroized after use.
- Least privilege: Separate interfaces for lookup and cache mutation; workers only receive the minimal interface they require.

## 18. Testing Requirements

- Feature/integration tests assert default-deny when consent or config is missing and verify audited denial.
- Validation-order tests reject oversize/lexically invalid national IDs before downstream calls.
- Regulated-mode tests ensure PII is stripped and minimized responses are used downstream.
- Adapter tests cover typed results and fail-fast behavior on bad config/credentials.
- Redaction tests ensure national IDs/PII do not appear in logs or audit events.

---

## Revision History

| Version | Date       | Author           | Changes                                                                                                                                          |
| ------- | ---------- | ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1.4     | 2025-12-18 | Security Eng     | Added secure-by-design and testing requirements (value objects, default-deny, immutability, typed results)                                       |
| 1.3     | 2025-12-13 | Engineering Team | Clarify concurrent Check() requirements (errgroup + context cancel), add tracing/metrics expectations, update acceptance criteria                |
| 1.2     | 2025-12-11 | Engineering Team | Document provider abstraction architecture implementation, add orchestration details, expand TR-6 with capability negotiation and error taxonomy |
| 1.1     | 2025-12-10 | Engineering Team | Add tracing requirements                                                                                                                         |
| 1.0     | 2025-12-03 | Product Team     | Initial PRD                                                                                                                                      |
