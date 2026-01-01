# PRD-004: Verifiable Credentials

**Status:** ✅ Complete
**Priority:** P0 (Critical)
**Owner:** Engineering Team
**Last Updated:** 2026-01-01
**Version:** 1.2

---

## 1. Overview

### Problem Statement

Users need portable, verifiable proof of identity attributes (like age) without repeatedly querying registries or exposing raw PII. Verifiable Credentials (VCs) solve this by creating signed attestations that can be verified later without re-fetching source data.

### Goals

- Issue "AgeOver18" verifiable credentials based on citizen registry data
- Store issued credentials for later verification
- Support credential verification without re-fetching registry data
- Apply data minimization to credential claims in regulated mode
- Provide revocation capability (future: real revocation registry)

### Non-Goals

- Real cryptographic signatures (use mock for MVP)
- Multiple credential types beyond AgeOver18
- Credential presentation protocol (W3C VP)
- Selective disclosure (BBS+ signatures)
- Credential schemas/templates
- Credential expiry (assume permanent for MVP)

---

## 2. Functional Requirements

### FR-1: Issue Verifiable Credential

**Endpoint:** `POST /vc/issue`

**Description:** Issue an "AgeOver18" credential after verifying user's date of birth from citizen registry.

**Input:**

```json
{
  "type": "AgeOver18",
  "national_id": "123456789"
}
```

**Output (Success - 200, Non-Regulated):**

```json
{
  "credential_id": "vc_abc123xyz",
  "type": "AgeOver18",
  "subject": "user_def456",
  "issuer": "credo",
  "issued_at": "2025-12-03T10:00:00Z",
  "claims": {
    "is_over_18": true,
    "verified_via": "national_registry"
  }
}
```

**Output (Success - 200, Regulated):**

```json
{
  "credential_id": "vc_abc123xyz",
  "type": "AgeOver18",
  "issued_at": "2025-12-03T10:00:00Z",
  "claims": {
    "is_over_18": true
  }
}
```

**Business Logic:**

1. Extract user from bearer token
2. Require consent for `ConsentPurposeVCIssuance`
3. Validate credential type is "AgeOver18"
4. Fetch citizen record: `registryService.Citizen(nationalID)`
5. If citizen.Valid == false, return 400 "Invalid citizen record"
6. Parse citizen.DateOfBirth (YYYY-MM-DD format)
7. Calculate age: `now.Year() - dob.Year()`
8. If age < 18, return 400 "User does not meet age requirement"
9. Create credential:
   - ID: "vc\_" + uuid
   - Type: "AgeOver18"
   - Subject: userID
   - Issuer: "credo"
   - IssuedAt: now
   - Claims: {"is_over_18": true, "verified_via": "national_registry"}
10. If regulated mode, minimize claims (remove "verified_via")
11. Save to VCStore
12. Emit audit event
13. Return credential

**Error Cases:**

- 401 Unauthorized: Invalid bearer token
- 403 Forbidden: Missing consent
- 400 Bad Request: Invalid credential type
- 400 Bad Request: National ID not provided
- 400 Bad Request: Citizen record invalid
- 400 Bad Request: User under 18
- 504 Gateway Timeout: Registry unavailable
- 500 Internal Server Error: Store failure

---

### FR-2: Verify Credential

**Endpoint:** `POST /vc/verify`

**Description:** Verify a previously issued credential by ID. Returns validity status and claims.

**Input:**

```json
{
  "credential_id": "vc_abc123xyz"
}
```

**Output (Success - 200):**

```json
{
  "valid": true,
  "credential_id": "vc_abc123xyz",
  "type": "AgeOver18",
  "subject": "user_def456",
  "issued_at": "2025-12-03T10:00:00Z",
  "claims": {
    "is_over_18": true
  }
}
```

**Output (Not Found - 404):**

```json
{
  "valid": false,
  "reason": "credential_not_found"
}
```

**Business Logic:**

1. Validate credential_id is provided
2. Retrieve credential from VCStore
3. If not found, return 404
4. Check if revoked (future: check revocation registry)
5. Return credential details with valid=true

**Error Cases:**

- 400 Bad Request: Missing credential_id
- 404 Not Found: Credential doesn't exist
- 500 Internal Server Error: Store failure

---

## 3. Technical Requirements

### TR-1: Data Models

**Location:** `internal/evidence/vc/models.go`

```go
type IssueRequest struct {
    UserID     string
    Type       string // "AgeOver18"
    Claims     map[string]any
}

type IssueResult struct {
    CredentialID string
    Issued       bool
    Reason       string
}

type VerifyRequest struct {
    CredentialID string
}

type VerifyResult struct {
    Valid  bool
    Claims map[string]any
    Reason string
}

type VerifiableCredential struct {
    ID        string
    Type      string
    Subject   string // UserID
    Issuer    string // "credo"
    IssuedAt  time.Time
    Claims    map[string]any
    Revoked   bool
}
```

### TR-2: Service Layer

**Location:** `internal/evidence/vc/service.go`

```go
type Service struct {
    store     Store
    lifecycle *VCLifecycle
    auditor   audit.Publisher
}

func (s *Service) Issue(ctx context.Context, req IssueRequest) (*VerifiableCredential, error)
func (s *Service) Verify(ctx context.Context, credID string) (*VerifyResult, error)
```

### TR-3: Data Minimization

**MinimizeClaims Function:**

```go
func MinimizeClaims(claims map[string]any, regulatedMode bool) map[string]any {
    if !regulatedMode {
        return claims
    }
    // Remove PII keys
    minimized := make(map[string]any)
    for k, v := range claims {
        if k == "full_name" || k == "national_id" || k == "date_of_birth" || k == "verified_via" {
            continue // Skip PII
        }
        minimized[k] = v
    }
    return minimized
}
```

### TR-4: HTTP Handlers

**Location:** `internal/transport/http/handlers_evidence.go`

```go
func (h *Handler) handleVCIssue(w http.ResponseWriter, r *http.Request)
func (h *Handler) handleVCVerify(w http.ResponseWriter, r *http.Request)
```

---

## 4. Implementation Steps

1. **Phase 1:** Update VCService.Issue() to fetch citizen data and validate age (1-2 hours)
2. **Phase 2:** Implement handleVCIssue with consent check and audit (1 hour)
3. **Phase 3:** Implement handleVCVerify (30 min)
4. **Phase 4:** Add MinimizeClaims logic for regulated mode (30 min)
5. **Phase 5:** Testing - unit, integration, manual (1 hour)

## 4.5 Secure-by-Design Requirements

- Value objects: `NationalID`, `CredentialType`, `TenantID`, and `VCID` must be constructed via validated constructors (Origin → Size → Lexical → Syntax → Semantics). Raw maps are rejected at service boundaries.
- Default deny: Missing consent, missing/invalid registry evidence, or invalid config results in audited denial (no implicit allow).
- Immutability: Issued credentials are immutable; minimized (regulated) claims are a distinct type that cannot be re-expanded.
- Fail-fast connectors: Registry/evidence adapters fail fast on bad config/credentials and return typed results (found/missing/stale/error) instead of generic errors.
- Sensitive data: National IDs and raw registry payloads are never logged; signing keys/secrets are read-once and zeroized after use.
- Least privilege: Separate interfaces for issuing vs verifying; stores expose read/write facets explicitly.

---

## 5. Acceptance Criteria

- [x] Users can issue AgeOver18 VC after registry verification
- [x] Issuance fails if user under 18
- [x] Issuance requires consent for vc_issuance
- [x] Credentials can be verified by ID
- [x] Regulated mode minimizes claims (no PII)
- [x] All operations emit audit events (vc_issued, vc_verified)
- [x] Code passes tests and lint
- [x] E2E test coverage via `e2e/features/vc_issuance.feature` and `e2e/features/vc_verification.feature`

---

## 6. Testing

- Security-focused tests:
  - Default-deny when consent/evidence/config is missing, with audited denial.
  - Validation order rejects oversize/lexically invalid national IDs before registry calls.
  - Regulated-mode issuance strips PII and returns minimized claims only.
  - Adapter tests cover typed results and fail-fast on bad config/credentials.
  - Redaction tests confirm national IDs/PII absent from logs/audit.

```bash
# Issue VC (requires consent first)
curl -X POST http://localhost:8080/auth/consent \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"purposes": ["registry_check", "vc_issuance"]}'

curl -X POST http://localhost:8080/vc/issue \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type": "AgeOver18", "national_id": "123456789"}'

# Expected: {"credential_id": "vc_...", "claims": {"is_over_18": true}}

# Verify VC
curl -X POST http://localhost:8080/vc/verify \
  -H "Content-Type: application/json" \
  -d '{"credential_id": "vc_abc123xyz"}'

# Expected: {"valid": true, "claims": {...}}
```

---

## 7. Future Enhancements

- Real JWT/VC signatures (JOSE, BBS+)
- Multiple credential types (EmailVerified, PhoneVerified, etc.)
- Credential expiry and renewal
- Revocation registry (track revoked credentials)
- Selective disclosure (reveal only specific claims)
- Credential schemas (JSON-LD contexts)

---

## References

- [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/)
- Tutorial: `docs/TUTORIAL.md` Section 4
- Existing Code: `internal/evidence/vc/`

---

## Revision History

| Version | Date       | Author         | Changes                                                           |
| ------- | ---------- | -------------- | ----------------------------------------------------------------- |
| 1.2     | 2026-01-01 | Engineering    | PRD marked complete; all acceptance criteria verified             |
| 1.1     | 2025-12-18 | Security Eng   | Added secure-by-design requirements and security-focused testing  |
| 1.0     | 2025-12-03 | Product Team   | Initial PRD                                                       |
