# PRD-003: Registry Integration (Citizen & Sanctions)

**Status:** Implementation Required
**Priority:** P0 (Critical)
**Owner:** Engineering Team
**Last Updated:** 2025-12-03

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

1. Call Citizen() and Sanctions() in parallel (use goroutines)
2. Wait for both to complete or timeout (5 second max)
3. If either fails, return error
4. Return both records

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

## 11. Acceptance Criteria

- [ ] Citizen lookup returns full data in non-regulated mode
- [ ] Citizen lookup returns minimized data in regulated mode
- [ ] Sanctions lookup returns listed status
- [ ] Cache reduces latency on repeated lookups
- [ ] Cache expires after 5 minutes
- [ ] Combined Check() calls both registries in parallel
- [ ] Operations require consent (403 without)
- [ ] All lookups emit audit events
- [ ] Mock clients simulate realistic latency
- [ ] Registry timeouts return 504
- [ ] Code passes `make test` and `make lint`

---

## 12. Dependencies & Blockers

### Dependencies

- PRD-001: Authentication & Session Management (for user extraction)
- PRD-002: Consent Management (for consent checks)
- `internal/evidence/registry/store_memory.go` - ✅ Implemented
- `internal/evidence/registry/models.go` - ✅ Implemented
- `pkg/errors` - ✅ Implemented

### Potential Blockers

- None identified

---

## 13. Future Enhancements (Out of Scope)

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

---

## 14. Regulatory Considerations

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

---

## 15. References

- [GDPR Article 5: Principles relating to processing](https://gdpr-info.eu/art-5-gdpr/)
- Tutorial: `docs/TUTORIAL.md` Section 3
- Architecture: `docs/architecture.md`
- Existing Implementation: `internal/evidence/registry/`

---

## Revision History

| Version | Date       | Author       | Changes     |
| ------- | ---------- | ------------ | ----------- |
| 1.0     | 2025-12-03 | Product Team | Initial PRD |
