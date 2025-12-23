# PRD-XXX: <Title>

**Status:** Draft
**Priority:** P<0|1|2>
**Owner:** <Team/Owner>
**Dependencies:** <PRD-###, RFCs, external systems> (optional)
**Last Updated:** <YYYY-MM-DD>

---

## 1. Overview

### Problem Statement

<What problem exists today? Why does it matter? Who is impacted?>

### Goals

- <Goal 1>
- <Goal 2>

### Non-Goals

- <Explicit exclusions>

---

## 2. User Stories

**As a** <persona>
**I want to** <capability>
**So that** <outcome>

---

## 3. Functional Requirements

### FR-1: <Title>

**Endpoint/Scope:** <Endpoint or scope>

**Description:** <Short description>

**Input:**

```json
{
  "example": "value"
}
```

**Output (Success - 200):**

```json
{
  "example": "value"
}
```

**Authentication/Authorization:**

- <Auth requirements>

**Business Logic:**

1. <Step>
2. <Step>

**Error Cases:**

- 400 Bad Request: <Reason>
- 401 Unauthorized: <Reason>
- 403 Forbidden: <Reason>
- 429 Too Many Requests: <Reason>
- 500 Internal Server Error: <Reason>

**Audit Event:** (optional)

```json
{
  "action": "<event>",
  "subject_id": "<id>",
  "metadata": {
    "key": "value"
  }
}
```

**Metrics:** (optional)

- <Counter/Gauge/Histogram>

---

## 4. Technical Requirements

### TR-1: Data Models

- <Entities, fields, invariants>
- <Type definitions and domain primitives>

### TR-2: Storage Interfaces

- <Store interfaces and error contracts>

### TR-3: Service Layer

- <Core service methods and responsibilities>

### TR-4: HTTP Handlers / API Layer

- <Route handlers and middleware integration>

### TR-5: Configuration

- <Config keys, defaults, env vars>

### TR-6: Background Jobs / Workers (optional)

- <Schedulers, cleanup, async workers>

---

## 5. API Specifications (optional)

### Endpoint Summary

| Endpoint | Method | Description | Auth  | Status Codes  |
| -------- | ------ | ----------- | ----- | ------------- |
| <path>   | <verb> | <summary>   | <Y/N> | <200,400,500> |

### Error Response Format

```json
{
  "error": "<code>",
  "message": "<human readable>",
  "details": {
    "field": "reason"
  }
}
```

---

## 6. Security Requirements / Considerations

- <Input validation>
- <AuthZ constraints>
- <Sensitive data handling>
- <Threats mitigated>

---

## 7. Observability Requirements

### Logging

- <Key events and fields>

### Metrics

- <Counters, gauges, histograms>

### Tracing (optional)

- <Span names, attributes>

---

## 8. Testing Requirements / Strategy

### Unit Tests

- <Core logic + edge cases>

### Integration Tests

- <Store + API contracts>

### Load/Stress Tests (optional)

- <Targets, p95, concurrency>

### Manual Testing

- <Step-by-step scenarios>

---

## 9. Implementation Steps

### Phase 1: <Phase name> (<time estimate>)

- <Tasks>

### Phase 2: <Phase name> (<time estimate>)

- <Tasks>

---

## 10. Acceptance Criteria

- <Criteria 1>
- <Criteria 2>

---

## 11. Dependencies & Blockers

### Dependencies

- <Dependency>

### Potential Blockers

- <Blocker>

### Related PRDs

- <PRD-###>

---

## 12. Future Enhancements (Out of Scope)

- <Deferred items>

---

## 13. Regulatory / Privacy Considerations (optional)

- <GDPR/HIPAA/industry constraints>
- <PII handling rules>

---

## 14. Open Questions

- <Question>

---

## 15. References

- <Docs, RFCs, external links>

---

## Revision History

| Date         | Version | Notes | Author |
| ------------ | ------- | ----- | ------ |
| <YYYY-MM-DD> | v0.1    | Draft | <Name> |
