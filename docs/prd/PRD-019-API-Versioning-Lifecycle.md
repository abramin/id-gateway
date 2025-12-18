# PRD-019: API Versioning & Lifecycle Management

**Status:** Not Started
**Priority:** P0 (Critical)
**Owner:** Engineering Team
**Dependencies:** None (policy decision)
**Last Updated:** 2025-12-12

---

## 1. Overview

### Problem Statement

Without a versioning strategy, any breaking API changes will break partner integrations. We need a clear versioning policy **before** partners build on our APIs.

### Goals

- Define versioning scheme (URL-based: `/v1/`, `/v2/`)
- Establish backwards compatibility guarantees
- Create deprecation policy with timelines
- Provide migration guides for breaking changes
- Support version negotiation for gRPC
- Enable feature flags for gradual rollout

### Non-Goals

- Supporting more than 2 major versions simultaneously
- Per-endpoint versioning
- Client-driven version selection (header-based)

---

## 2. Versioning Strategy

### URL-Based Versioning

**Format:** `/v{major}/resource`

**Examples:**

```
/v1/auth/authorize
/v1/consent
/v2/consent
```

### Version Support Policy

- **Current version (v2):** Fully supported, receives new features
- **Previous version (v1):** Supported for 12 months after v2 release
- **Deprecated versions:** 6-month sunset period after end-of-support announcement

### Backwards Compatibility Rules

**Non-breaking changes (patch/minor within major version):**

- Adding optional fields to requests
- Adding fields to responses
- Adding new endpoints
- Relaxing validation rules
- Performance improvements

**Breaking changes (require major version bump):**

- Removing fields from responses
- Changing field types
- Making optional fields required
- Renaming fields
- Changing error codes
- Removing endpoints

---

## 3. Implementation

### Route Versioning

```go
// internal/transport/http/router.go
func SetupRoutes(r *mux.Router, handlers *Handlers) {
    // V1 routes
    v1 := r.PathPrefix("/v1").Subrouter()
    v1.HandleFunc("/auth/authorize", handlers.AuthorizeV1).Methods("POST")
    v1.HandleFunc("/consent", handlers.ConsentV1).Methods("POST")

    // V2 routes (enhanced)
    v2 := r.PathPrefix("/v2").Subrouter()
    v2.HandleFunc("/auth/authorize", handlers.AuthorizeV2).Methods("POST")
    v2.HandleFunc("/consent", handlers.ConsentV2).Methods("POST")

    // Default (no version) routes to latest
    r.HandleFunc("/auth/authorize", handlers.AuthorizeV2).Methods("POST")
}
```

### Deprecation Warnings

**Response Header:**

```
Deprecation: true
Sunset: Sat, 31 Dec 2026 23:59:59 GMT
Link: </docs/migration/v1-to-v2>; rel="deprecation"
```

### Migration Guides

**Location:** `docs/migrations/v1-to-v2.md`

**Contents:**

- What changed
- Breaking changes list
- Code examples (before/after)
- Timeline
- Support contact

### Secure-by-Design Guardrails

- Default deny on unknown or missing version prefixes; no implicit upgrade/downgrade without explicit contract.
- Schema-diff gates: breaking changes require a signed migration manifest and approval; CI blocks unsafe diffs without manifest.
- Deprecation headers must include security impact notes; migrations that remove controls must ship with compensating safeguards.
- Versioned auth/claims: tokens include API version audience/claim; handlers validate version match to prevent cross-version replay.
- Rollback drills and revocation: every versioned deployment includes a tested rollback path and the ability to revoke a versioned manifest.

---

## 4. Acceptance Criteria

- [ ] All routes include version prefix
- [ ] Deprecation headers added to old versions
- [ ] Migration guides published
- [ ] API changelog maintained
- [ ] Version support policy documented

---

## Revision History

| Version | Date       | Author       | Changes     |
| ------- | ---------- | ------------ | ----------- |
| 1.1     | 2025-12-18 | Security Eng | Added secure-by-design guardrails (default-deny, signed manifests, versioned claims) |
| 1.0     | 2025-12-12 | Product Team | Initial PRD |
