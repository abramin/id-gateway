# PRD-034: Privacy-Preserving Audit Logging

**Status:** Not Started
**Priority:** P2 (Medium)
**Owner:** Engineering Team
**Dependencies:** PRD-017 (Rate Limiting), PRD-006 (Audit & Compliance)

---

## 1. Overview

### Problem Statement

While PRD-017 implements IP anonymization for operational logs (truncating IPs to /24 prefixes), security teams require the ability to correlate events and identify specific bad actors during incident response. True anonymization prevents this correlation entirely.

This PRD defines a tiered logging architecture that balances:
- **GDPR compliance** through data minimization and retention controls
- **Security forensics** through pseudonymized audit logs with controlled access
- **Operational visibility** through anonymized metrics and logs

### Goals

- Implement three-tier logging architecture for rate limit events
- Provide pseudonymized (hashed) IPs in security audit logs
- Enforce strict retention policies with automated deletion
- Enable time-limited re-identification for active security incidents
- Maintain full GDPR compliance with documented legitimate interest

### Non-Goals

- Real-time alerting on pseudonymized data
- Cross-tenant correlation of anonymized data
- Retention beyond documented periods
- Sharing pseudonymized data with third parties

---

## 2. Architecture

### Three-Tier Logging Model

```
┌─────────────────────────────────────────────────────────────────┐
│                     Rate Limit Event                            │
└─────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
    ┌─────────────────┐ ┌───────────────┐ ┌─────────────────────┐
    │  Security Audit │ │ Operational   │ │  Analytics/Metrics  │
    │  (Restricted)   │ │ Log           │ │                     │
    ├─────────────────┤ ├───────────────┤ ├─────────────────────┤
    │ Pseudonymized   │ │ Anonymized IP │ │ No IP, only counts  │
    │ IP (HMAC hash   │ │ (truncated    │ │ by endpoint class   │
    │ with rotating   │ │ /24 prefix)   │ │                     │
    │ key)            │ │               │ │                     │
    │                 │ │               │ │                     │
    │ Retention: 7d   │ │ Retention: 30d│ │ Retention: 1 year   │
    │ Access: SecOps  │ │ Access: DevOps│ │ Access: All         │
    │ Encrypted: Yes  │ │ Encrypted: No │ │ Encrypted: No       │
    └─────────────────┘ └───────────────┘ └─────────────────────┘
```

### Tier Definitions

| Tier | Purpose | PII Handling | Retention | Access Control |
|------|---------|--------------|-----------|----------------|
| **Security Audit** | Incident response, forensics | HMAC-SHA256 with rotating key | 7 days | Security team only |
| **Operational** | Debugging, monitoring | Truncated to /24 | 30 days | DevOps, on-call |
| **Analytics** | Capacity planning, trends | None (counts only) | 1 year | All engineering |

---

## 3. Functional Requirements

### FR-1: Pseudonymization Service

**Description:** Service for generating consistent pseudonymous identifiers from PII.

```go
type PseudonymizationService interface {
    // PseudonymizeIP returns a consistent hash for the same IP within the current key period
    PseudonymizeIP(ctx context.Context, ip string) (string, error)

    // ReidentifyIP recovers the original IP from a pseudonym (requires security clearance)
    ReidentifyIP(ctx context.Context, pseudonym string, key []byte) (string, error)

    // RotateKey triggers key rotation (automated daily)
    RotateKey(ctx context.Context) error
}
```

**Key Rotation:**
- Daily automatic rotation at 00:00 UTC
- Previous keys retained for 7 days (matching audit log retention)
- Keys stored in HSM/KMS (AWS KMS, HashiCorp Vault)

### FR-2: Tiered Log Emitter

**Description:** Component that routes events to appropriate log tiers.

```go
func (s *Service) logRateLimitEvent(ctx context.Context, ip string, event string, attrs ...any) {
    // Tier 1: Security audit log (pseudonymized, restricted)
    if s.securityAuditEnabled {
        pseudonym, _ := s.pseudonymizer.PseudonymizeIP(ctx, ip)
        s.securityLogger.Info(event,
            append(attrs, "ip_pseudonym", pseudonym, "tier", "security")...)
    }

    // Tier 2: Operational log (anonymized)
    s.logger.Info(event,
        append(attrs, "ip_prefix", privacy.AnonymizeIP(ip), "tier", "operational")...)

    // Tier 3: Metrics (no PII)
    s.metrics.IncrementRateLimitEvent(event, class)
}
```

### FR-3: Retention Enforcement

**Description:** Automated deletion of logs past retention period.

**Implementation:**
- Elasticsearch ILM (Index Lifecycle Management) policies
- Or: PostgreSQL partitioning with `pg_partman` for automatic partition drops
- Daily cron job to verify retention compliance

**Audit Trail:**
- Log deletion events are themselves logged (without PII)
- Compliance dashboard shows retention status per tier

### FR-4: Access Control

**Description:** Role-based access to different log tiers.

| Role | Security Audit | Operational | Analytics |
|------|----------------|-------------|-----------|
| Security Engineer | ✓ | ✓ | ✓ |
| DevOps/SRE | ✗ | ✓ | ✓ |
| Developer | ✗ | ✗ | ✓ |
| Product | ✗ | ✗ | ✓ |

**Implementation:**
- Separate log indices/tables per tier
- IAM policies enforcing role-based access
- Audit logging of security tier access

---

## 4. Technical Requirements

### TR-1: Key Management

**Requirements:**
- HMAC keys stored in HSM/KMS
- Automatic daily rotation
- 7-day key retention window
- Secure key deletion after retention period

**Configuration:**
```yaml
privacy:
  pseudonymization:
    enabled: true
    key_provider: "aws-kms"  # or "vault", "local-dev"
    key_rotation_hours: 24
    key_retention_days: 7
```

### TR-2: Log Separation

**Requirements:**
- Security audit logs to dedicated Elasticsearch index or PostgreSQL schema
- Operational logs to standard application log stream
- Metrics to Prometheus/InfluxDB

### TR-3: Compliance Reporting

**Requirements:**
- Monthly report of retention compliance
- Alert on retention policy violations
- Audit trail of re-identification requests

---

## 5. Implementation Steps

### Phase 1: Infrastructure (Future)
1. Set up key management (KMS integration)
2. Configure separate log indices with retention policies
3. Implement access control policies

### Phase 2: Pseudonymization Service (Future)
1. Implement `PseudonymizationService` interface
2. Add key rotation automation
3. Implement re-identification with audit trail

### Phase 3: Integration (Future)
1. Update rate limit service to use tiered logging
2. Add compliance dashboard
3. Document re-identification procedures

---

## 6. Acceptance Criteria

- [ ] Pseudonymized IPs in security audit tier
- [ ] Same IP produces same pseudonym within key period
- [ ] Key rotation occurs daily without service interruption
- [ ] Security audit logs automatically deleted after 7 days
- [ ] Operational logs automatically deleted after 30 days
- [ ] Access to security tier requires security team role
- [ ] Re-identification creates audit trail entry
- [ ] Monthly compliance report generated automatically

---

## 7. GDPR Considerations

### Legal Basis

Security audit logging with pseudonymized IPs is justified under GDPR Article 6(1)(f) - **Legitimate Interest**:

1. **Purpose:** Detection and prevention of security threats
2. **Necessity:** Cannot achieve security goals with fully anonymized data
3. **Balance:** Short retention (7 days), pseudonymization, strict access controls

### Data Subject Rights

- **Right to Access:** Pseudonymized logs do not allow practical identification
- **Right to Deletion:** Automatic deletion after 7 days
- **Right to Portability:** Not applicable (security logs, not user data)

### Documentation

Maintain records of:
- Legitimate interest assessment
- Retention policy enforcement
- Access control audits
- Re-identification events

---

## 8. References

- PRD-017: Rate Limiting & Abuse Prevention (Section 10: GDPR/Privacy Compliance)
- PRD-006: Audit & Compliance Logging
- GDPR Article 6(1)(f) - Legitimate Interest
- CJEU Breyer Ruling (C-582/14) - IP Addresses as Personal Data

---

## Revision History

| Version | Date       | Author       | Changes            |
| ------- | ---------- | ------------ | ------------------ |
| 1.0     | 2025-12-19 | Engineering  | Initial PRD        |
