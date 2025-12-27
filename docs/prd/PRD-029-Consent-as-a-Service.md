# PRD-029: Consent-as-a-Service Platform

**Status:** Draft
**Priority:** P2 (Strategic)
**Owner:** Engineering Team
**Dependencies:** PRD-002 (Consent Management), PRD-018 (Notifications)

---

## 1. Overview

### Problem Statement

Every application handling user data needs consent management for GDPR/CCPA compliance. Currently, each application builds its own consent UI and storage, leading to:

- **Fragmented user experience** - Users manage consent separately in each app
- **Duplicated engineering effort** - Every app reinvents consent storage
- **Inconsistent compliance** - Quality of consent implementation varies
- **No cross-service visibility** - Users can't see all their consents in one place

### Goals

- Position Credo as a **consent hub** that third-party applications integrate with
- Provide users with a **unified consent dashboard** across all integrated apps
- Enable **delegated consent management** where apps request consent through Credo
- Support **cross-service consent revocation** from a single interface
- Offer **GDPR Article 7 compliance-as-a-service** for integrated applications

### Non-Goals

- Consent UI components (apps build their own UIs using our API)
- Legal advice or consent text generation
- Cookie consent management (browser-specific, out of scope)
- Consent for non-data-processing purposes

---

## 2. User Stories

**As a** user of multiple apps
**I want to** see all my consents in one place
**So that** I can understand and manage my data permissions

**As a** user
**I want to** revoke consent across all services at once
**So that** I don't have to visit each app individually

**As an** app developer
**I want to** delegate consent management to Credo
**So that** I don't have to build GDPR-compliant consent infrastructure

**As a** compliance officer
**I want to** audit consent across all integrated applications
**So that** I can demonstrate organization-wide GDPR compliance

---

## 3. Functional Requirements

### FR-1: App Registration for Consent Delegation

**Endpoint:** `POST /admin/consent-delegation/apps`

**Description:** Register an application to use Credo as its consent provider.

**Input:**
```json
{
  "app_id": "my-app-123",
  "app_name": "My Application",
  "purposes": ["marketing", "analytics", "personalization"],
  "callback_url": "https://myapp.com/consent-callback",
  "privacy_policy_url": "https://myapp.com/privacy"
}
```

**Output (Success - 201):**
```json
{
  "delegation_id": "del_abc123",
  "app_id": "my-app-123",
  "api_key": "cdk_live_xxx...",
  "purposes": ["marketing", "analytics", "personalization"],
  "created_at": "2025-12-17T10:00:00Z"
}
```

### FR-2: Delegated Consent Request

**Endpoint:** `POST /consent/delegate`

**Description:** App requests consent on behalf of a user through Credo.

**Input:**
```json
{
  "app_id": "my-app-123",
  "user_id": "user_456",
  "purposes": ["marketing", "analytics"],
  "context": {
    "request_reason": "Enable personalized recommendations",
    "data_categories": ["browsing_history", "preferences"]
  }
}
```

**Output (Success - 200):**
```json
{
  "consent_request_id": "cr_xyz789",
  "status": "pending",
  "consent_url": "https://credo.app/consent/cr_xyz789",
  "expires_at": "2025-12-17T11:00:00Z"
}
```

### FR-3: Unified Consent Dashboard

**Endpoint:** `GET /me/consents/all`

**Description:** User retrieves all consents across all delegated applications.

**Output (Success - 200):**
```json
{
  "consents": [
    {
      "app_id": "my-app-123",
      "app_name": "My Application",
      "purposes": [
        {
          "purpose": "marketing",
          "status": "active",
          "granted_at": "2025-12-01T10:00:00Z",
          "expires_at": "2026-12-01T10:00:00Z"
        },
        {
          "purpose": "analytics",
          "status": "revoked",
          "granted_at": "2025-12-01T10:00:00Z",
          "revoked_at": "2025-12-15T14:00:00Z"
        }
      ]
    },
    {
      "app_id": "other-app",
      "app_name": "Other Application",
      "purposes": [...]
    }
  ],
  "total_apps": 2,
  "total_active_consents": 5
}
```

### FR-4: Cross-Service Consent Revocation

**Endpoint:** `POST /me/consents/revoke-all`

**Description:** User revokes a specific purpose across all applications.

**Input:**
```json
{
  "purpose": "marketing",
  "apps": ["all"] // or specific app_ids
}
```

**Output (Success - 200):**
```json
{
  "revoked": [
    {"app_id": "my-app-123", "purpose": "marketing"},
    {"app_id": "other-app", "purpose": "marketing"}
  ],
  "notifications_sent": 2
}
```

### FR-5: Consent Change Webhooks

**Description:** Notify delegated apps when consent changes.

**Webhook Payload:**
```json
{
  "event": "consent.revoked",
  "timestamp": "2025-12-17T14:00:00Z",
  "data": {
    "user_id": "user_456",
    "purpose": "marketing",
    "previous_status": "active",
    "new_status": "revoked"
  },
  "signature": "sha256=..."
}
```

### FR-6: Consent Cascading/Dependencies (Future)

**Status:** Not Implemented (identified gap from module README)

**Description:** Support hierarchical consent relationships where revoking a parent consent automatically revokes dependent child consents.

**Use Cases:**
- Revoking "data_processing" consent should cascade to revoke "marketing", "analytics", and "personalization" (which all depend on data processing)
- Parent-child consent for minors: revoking parental consent cascades to child's consents
- Organizational consent bundles: revoking the bundle revokes all included purposes

**Proposed Model:**
```
consent_dependencies
├── parent_purpose (string)
├── child_purpose (string)
├── cascade_on_revoke (boolean)
├── cascade_on_expire (boolean)
└── created_at (timestamp)
```

**Behavior:**
- When parent consent is revoked, automatically revoke all child consents where `cascade_on_revoke = true`
- Emit audit events for both parent and cascaded child revocations
- Webhook notifications sent for each cascaded revocation
- Prevent granting child consent without active parent consent
- Support configurable cascade depth limits to prevent infinite loops

**API Extensions:**
- `POST /admin/consent/dependencies` - Define parent-child relationships
- `GET /admin/consent/dependencies` - List all dependency rules
- `DELETE /admin/consent/dependencies/{id}` - Remove dependency rule
- `GET /consent/{purpose}/dependencies` - Get dependency tree for a purpose

---

## 4. Technical Requirements

### TR-1: Data Model

```
consent_delegations
├── delegation_id (PK)
├── app_id (unique)
├── app_name
├── api_key_hash
├── purposes []
├── callback_url
├── privacy_policy_url
├── created_at
└── status (active, suspended, revoked)

delegated_consents
├── consent_id (PK)
├── delegation_id (FK)
├── user_id
├── purpose
├── status (pending, active, revoked, expired)
├── granted_at
├── expires_at
├── revoked_at
└── metadata (JSONB)
```

### TR-2: API Security

- All delegated consent APIs require app API key authentication
- Webhook signatures use HMAC-SHA256 with app-specific secret
- User-facing APIs require standard Credo authentication

### TR-3: Webhook Delivery

- Retry failed webhooks with exponential backoff (3 attempts)
- Log all webhook deliveries for audit
- Timeout: 10 seconds per delivery attempt

---

## 5. Acceptance Criteria

- [ ] Apps can register for consent delegation via admin API
- [ ] Apps can request consent through Credo API
- [ ] Users can view all consents across apps in unified dashboard
- [ ] Users can revoke consent across all apps for a purpose
- [ ] Apps receive webhooks when consent changes
- [ ] All consent changes are logged in audit trail
- [ ] API keys are securely hashed and rotatable

---

## 6. Dependencies & Risks

### Dependencies
- PRD-002 (Consent Management) - Core consent model
- PRD-018 (Notifications) - Webhook delivery infrastructure

### Risks
- **Adoption risk:** Apps may not want to delegate consent to third party
  - *Mitigation:* Position as compliance service, not control transfer
- **Scale risk:** Many apps × many users = high webhook volume
  - *Mitigation:* Queue-based webhook delivery, rate limiting

---

## Revision History

| Version | Date       | Author      | Changes       |
| ------- | ---------- | ----------- | ------------- |
| 1.1     | 2025-12-27 | Engineering | Added FR-6: Consent Cascading/Dependencies (identified gap from README) |
| 1.0     | 2025-12-17 | Engineering | Initial draft |
