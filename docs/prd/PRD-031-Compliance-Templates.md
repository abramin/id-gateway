# PRD-031: Compliance-as-Code Templates

**Status:** Draft
**Priority:** P2 (Strategic)
**Owner:** Engineering Team
**Dependencies:** PRD-002 (Consent Management), PRD-006 (Audit & Compliance), PRD-007 (User Data Rights)

---

## 1. Overview

### Problem Statement

Configuring identity systems for regulatory compliance is complex:

- **GDPR** requires specific consent flows, retention periods, and data rights
- **CCPA** has different opt-out models and disclosure requirements
- **HIPAA** mandates PHI encryption and access logging
- **PCI-DSS** requires cardholder data isolation and audit trails

Each regulation requires different configurations across consent, audit, retention, and data handling. Startups often get this wrong, leading to compliance failures.

### Goals

- Provide **pre-built compliance templates** for major regulations
- Enable **one-click compliance setup** for new tenants
- Support **template composition** (e.g., GDPR + PCI for EU fintech)
- Allow **customization** while maintaining compliance baselines
- Expose **compliance status endpoint** showing current configuration

### Non-Goals

- Legal advice or compliance certification
- Automated compliance auditing/reporting
- Region-specific template variations (e.g., GDPR-DE vs GDPR-FR)
- Real-time compliance monitoring

---

## 2. User Stories

**As a** startup founder
**I want to** select "GDPR" and have my system configured correctly
**So that** I don't have to research compliance requirements

**As a** compliance officer
**I want to** see which compliance templates are active
**So that** I can verify our regulatory posture

**As a** fintech developer
**I want to** combine GDPR and PCI-DSS templates
**So that** I meet both EU privacy and payment card requirements

**As an** enterprise admin
**I want to** customize template defaults for my organization
**So that** I can adapt to specific business requirements

---

## 3. Functional Requirements

### FR-1: List Available Templates

**Endpoint:** `GET /admin/compliance/templates`

**Output (Success - 200):**
```json
{
  "templates": [
    {
      "id": "gdpr-eu",
      "name": "GDPR (European Union)",
      "description": "General Data Protection Regulation compliance",
      "version": "2.0",
      "regions": ["EU", "EEA"],
      "configures": ["consent", "retention", "data_rights", "audit"]
    },
    {
      "id": "ccpa-us",
      "name": "CCPA (California)",
      "description": "California Consumer Privacy Act compliance",
      "version": "1.0",
      "regions": ["US-CA"],
      "configures": ["consent", "retention", "data_rights"]
    },
    {
      "id": "hipaa",
      "name": "HIPAA",
      "description": "Health Insurance Portability and Accountability Act",
      "version": "1.0",
      "regions": ["US"],
      "configures": ["encryption", "access_logs", "retention", "audit"]
    },
    {
      "id": "pci-dss-v4",
      "name": "PCI-DSS v4.0",
      "description": "Payment Card Industry Data Security Standard",
      "version": "4.0",
      "regions": ["global"],
      "configures": ["encryption", "access_logs", "retention", "audit"]
    },
    {
      "id": "soc2-type2",
      "name": "SOC 2 Type II",
      "description": "Service Organization Control 2",
      "version": "1.0",
      "regions": ["global"],
      "configures": ["access_logs", "audit", "retention"]
    }
  ]
}
```

### FR-2: Apply Compliance Template

**Endpoint:** `POST /admin/compliance/apply`

**Input:**
```json
{
  "templates": ["gdpr-eu", "pci-dss-v4"],
  "overrides": {
    "retention_days": 730,
    "dpo_email": "privacy@example.com"
  }
}
```

**Output (Success - 200):**
```json
{
  "applied": ["gdpr-eu", "pci-dss-v4"],
  "configuration": {
    "consent": {
      "default_purposes": ["login", "service_delivery"],
      "explicit_consent_required": ["marketing", "analytics", "third_party_sharing"],
      "consent_expiry_days": 365,
      "withdrawal_immediate": true
    },
    "retention": {
      "default_days": 730,
      "pii_fields": ["email", "name", "address"],
      "auto_deletion": true
    },
    "data_rights": {
      "export_enabled": true,
      "deletion_enabled": true,
      "portability_format": "json",
      "response_deadline_days": 30
    },
    "audit": {
      "log_all_access": true,
      "log_retention_years": 7,
      "tamper_evident": true
    },
    "encryption": {
      "pii_at_rest": "aes-256-gcm",
      "pii_in_transit": "tls-1.3"
    }
  },
  "conflicts": [],
  "warnings": [
    "GDPR requires 30-day data rights response; you have 30 days configured (compliant)"
  ]
}
```

### FR-3: Get Current Compliance Status

**Endpoint:** `GET /admin/compliance/status`

**Output (Success - 200):**
```json
{
  "active_templates": ["gdpr-eu", "pci-dss-v4"],
  "configuration_hash": "sha256:abc123...",
  "last_updated": "2025-12-17T10:00:00Z",
  "compliance_summary": {
    "gdpr-eu": {
      "status": "compliant",
      "checks": {
        "consent_explicit": true,
        "retention_configured": true,
        "export_enabled": true,
        "deletion_enabled": true,
        "dpo_contact": true
      }
    },
    "pci-dss-v4": {
      "status": "partial",
      "checks": {
        "encryption_at_rest": true,
        "access_logging": true,
        "key_rotation": false
      },
      "warnings": ["Key rotation not configured (required for full compliance)"]
    }
  }
}
```

### FR-4: Template Definition Format

**Template YAML Structure:**
```yaml
id: gdpr-eu
name: GDPR (European Union)
version: "2.0"
description: General Data Protection Regulation compliance

consent:
  default_purposes:
    - login
    - service_delivery
  explicit_consent_required:
    - marketing
    - analytics
    - third_party_sharing
    - profiling
  consent_expiry_days: 365
  withdrawal_immediate: true
  proof_of_consent_required: true

retention:
  default_days: 1095  # 3 years
  pii_fields:
    - email
    - name
    - address
    - phone
    - date_of_birth
    - national_id
  auto_deletion: true
  deletion_grace_period_days: 30

data_rights:
  export:
    enabled: true
    formats: [json, csv]
  deletion:
    enabled: true
    cascade: true
  portability:
    enabled: true
    format: json
  response_deadline_days: 30

audit:
  log_all_access: true
  log_pii_access: true
  log_retention_years: 7
  tamper_evident: true

required_contacts:
  - dpo_email  # Data Protection Officer

validations:
  - name: consent_before_processing
    description: Verify consent exists before processing PII
    severity: error
  - name: retention_not_exceeded
    description: Data not retained beyond configured period
    severity: warning
```

---

## 4. Technical Requirements

### TR-1: Template Storage

```
compliance_templates
├── id (PK)
├── name
├── version
├── definition (YAML/JSON)
├── regions []
├── created_at
└── deprecated_at

tenant_compliance
├── tenant_id (PK)
├── templates [] (FK)
├── overrides (JSONB)
├── effective_config (JSONB, computed)
├── applied_at
└── applied_by
```

### TR-2: Template Loader

- Load templates from `internal/compliance/templates/`
- Validate YAML schema on startup
- Support template versioning (tenants can pin versions)

### TR-3: Configuration Application

- Merge multiple templates (later template wins conflicts)
- Apply overrides on top of merged config
- Validate final config against template requirements
- Store effective configuration for fast runtime access

### TR-4: Runtime Enforcement

Integrate with existing services:
- **Consent Service:** Apply consent rules from template
- **Audit Service:** Apply logging rules from template
- **Data Rights Service:** Apply export/deletion rules from template
- **Encryption:** Apply encryption requirements

---

## 5. Acceptance Criteria

- [ ] 5 templates available: GDPR, CCPA, HIPAA, PCI-DSS, SOC2
- [ ] Templates can be applied to tenant via admin API
- [ ] Multiple templates can be composed without conflicts
- [ ] Overrides can customize template defaults
- [ ] Compliance status endpoint shows current configuration
- [ ] Warnings generated for partial compliance
- [ ] Template changes logged in audit trail
- [ ] Templates versioned and pinnable

---

## 6. Dependencies & Risks

### Dependencies
- PRD-002 (Consent) - Consent configuration application
- PRD-006 (Audit) - Audit configuration application
- PRD-007 (Data Rights) - Data rights configuration application

### Risks
- **False sense of security:** Templates don't guarantee compliance
  - *Mitigation:* Clear documentation, "helps with" not "ensures"
- **Template conflicts:** Overlapping requirements from multiple templates
  - *Mitigation:* Conflict detection, merge strategy documentation

---

## Revision History

| Version | Date       | Author      | Changes       |
| ------- | ---------- | ----------- | ------------- |
| 1.0     | 2025-12-17 | Engineering | Initial draft |
