# PRD-033: Federated Trust Network

**Status:** Draft
**Priority:** P2 (Strategic)
**Owner:** Engineering Team
**Dependencies:** PRD-004 (Verifiable Credentials), PRD-009 (DIDs), PRD-010 (Zero-Knowledge Proofs)

---

## 1. Overview

### Problem Statement

Traditional identity verification is centralized and expensive:

- **High cost:** Each verification (KYC, sanctions check) costs $2-10
- **Cold start problem:** New users have no history to leverage
- **Privacy concerns:** Users share full identity for simple verifications
- **Centralization risk:** Single points of failure for identity

Social trust (knowing someone verified) could supplement formal verification, but current systems can't leverage peer relationships while maintaining privacy.

### Goals

- Create a **web of trust** where verified users can vouch for others
- Enable **ZKP vouches** that prove relationship without revealing identity
- Implement **weighted trust scoring** based on voucher reputation
- Support **conditional verification** (N vouches = verified for purpose X)
- Reduce **verification costs** by using social trust for low-risk operations

### Non-Goals

- Replacing formal identity verification for high-risk operations
- Social network features (friend lists, messaging)
- Public trust graphs (all relationships private)
- Vouching for specific credentials (only general trustworthiness)

---

## 2. User Stories

**As a** verified user
**I want to** vouch for people I know
**So that** they can access services faster

**As a** new user
**I want to** leverage my trusted contacts
**So that** I don't have to fully verify on every platform

**As a** service operator
**I want to** accept trust network vouches for low-risk operations
**So that** I can reduce verification costs

**As a** privacy-conscious user
**I want to** vouch without revealing my relationship
**So that** my social graph stays private

---

## 3. Functional Requirements

### FR-1: Create Vouch

**Endpoint:** `POST /trust-network/vouch`

**Description:** Verified user vouches for another user.

**Input:**
```json
{
  "vouchee_id": "user_456",
  "relationship": "professional", // personal, professional, business
  "relationship_duration_months": 24,
  "confidence": "high", // low, medium, high
  "context": "Worked together at Acme Corp"
}
```

**Output (Success - 201):**
```json
{
  "vouch_id": "vouch_abc123",
  "voucher_id": "user_123",
  "vouchee_id": "user_456",
  "vouch_weight": 0.85,
  "status": "active",
  "created_at": "2025-12-17T10:00:00Z",
  "expires_at": "2026-12-17T10:00:00Z"
}
```

### FR-2: Get Trust Network Status

**Endpoint:** `GET /me/trust-network`

**Description:** User views their trust network status.

**Output (Success - 200):**
```json
{
  "trust_network_score": 72,
  "vouches_received": {
    "count": 5,
    "total_weight": 3.2,
    "by_relationship": {
      "professional": 3,
      "personal": 2
    }
  },
  "vouches_given": {
    "count": 8,
    "active": 7,
    "revoked": 1
  },
  "verification_level": {
    "via_network": "medium",
    "requirements_met": ["basic_access", "standard_operations"],
    "requirements_unmet": ["high_value_transactions"]
  }
}
```

### FR-3: ZKP Vouch Proof

**Endpoint:** `POST /trust-network/proof`

**Description:** Generate proof that user has N vouches without revealing who vouched.

**Input:**
```json
{
  "min_vouches": 3,
  "min_total_weight": 2.0,
  "relationship_types": ["professional", "personal"],
  "audience": "service_xyz"
}
```

**Output (Success - 200):**
```json
{
  "proof": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9...",
  "statement": {
    "vouches_count": ">=3",
    "total_weight": ">=2.0",
    "relationship_types": ["professional", "personal"]
  },
  "issued_at": "2025-12-17T10:00:00Z",
  "expires_at": "2025-12-17T11:00:00Z"
}
```

### FR-4: Verify Trust Proof

**Endpoint:** `POST /trust-network/verify`

**Description:** Service verifies a trust network proof.

**Input:**
```json
{
  "proof": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9..."
}
```

**Output (Success - 200):**
```json
{
  "valid": true,
  "user_id": "user_456",
  "statement": {
    "vouches_count": ">=3",
    "total_weight": ">=2.0"
  },
  "proof_timestamp": "2025-12-17T10:00:00Z"
}
```

### FR-5: Configure Trust Requirements

**Endpoint:** `PUT /admin/trust-network/requirements`

**Description:** Configure what trust network vouches can unlock.

**Input:**
```json
{
  "requirements": [
    {
      "operation": "basic_access",
      "min_vouches": 1,
      "min_weight": 0.5,
      "or_conditions": ["email_verified"]
    },
    {
      "operation": "standard_operations",
      "min_vouches": 3,
      "min_weight": 2.0,
      "or_conditions": ["kyc_verified"]
    },
    {
      "operation": "high_value_transactions",
      "min_vouches": 5,
      "min_weight": 4.0,
      "and_conditions": ["kyc_verified"]
    }
  ]
}
```

---

## 4. Technical Requirements

### TR-1: Vouch Data Model

```
vouches
├── vouch_id (PK)
├── voucher_id (FK users)
├── vouchee_id (FK users)
├── relationship_type
├── relationship_duration_months
├── confidence_level
├── weight (computed)
├── status (active, revoked, expired)
├── created_at
├── expires_at
└── revoked_at

trust_network_scores
├── user_id (PK)
├── vouches_received_count
├── total_weight
├── network_score
├── last_calculated_at
└── calculation_version
```

### TR-2: Weight Calculation

```
vouch_weight = base_weight
             × voucher_trust_score_factor
             × relationship_duration_factor
             × confidence_factor

base_weight = {personal: 0.6, professional: 0.8, business: 1.0}
voucher_factor = voucher_trust_score / 100
duration_factor = min(1.0, duration_months / 24)
confidence_factor = {low: 0.5, medium: 0.75, high: 1.0}
```

### TR-3: Vouch as Verifiable Credential

```json
{
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "type": ["VerifiableCredential", "TrustVouchCredential"],
  "issuer": "did:key:voucher_user_123",
  "issuanceDate": "2025-12-17T10:00:00Z",
  "credentialSubject": {
    "id": "did:key:vouchee_user_456",
    "vouchType": "professional_trust",
    "confidence": "high"
  },
  "proof": {...}
}
```

### TR-4: ZKP Circuit Requirements

Prove in zero-knowledge:
- User has >= N vouches
- Total weight >= threshold
- Vouchers have trust scores >= minimum
- Without revealing: who vouched, exact counts, specific weights

### TR-5: Fraud Prevention

- Vouchers can only vouch for users they've interacted with (via consent or shared service)
- Circular vouching detected and penalized
- Vouch velocity limits (max 5 vouches per day)
- Vouch revocation propagates to dependent verifications

---

## 5. Acceptance Criteria

- [ ] Verified users can vouch for other users
- [ ] Vouches have calculated weights based on multiple factors
- [ ] Users can view their trust network status
- [ ] ZKP proofs can be generated for trust threshold claims
- [ ] Services can configure trust requirements for operations
- [ ] Trust network score integrates with overall Trust Score (PRD-030)
- [ ] Circular vouching is detected and prevented
- [ ] Vouches can be revoked with cascading effects

---

## 6. Dependencies & Risks

### Dependencies
- PRD-004 (Verifiable Credentials) - Vouch as VC format
- PRD-009 (DIDs) - User identifiers for vouching
- PRD-010 (Zero-Knowledge Proofs) - Privacy-preserving proofs

### Risks
- **Sybil attacks:** Fake accounts vouching for each other
  - *Mitigation:* Require formal verification for vouchers, weight based on voucher trust
- **Social pressure:** Users feel obligated to vouch
  - *Mitigation:* Private vouching, no notification that someone didn't vouch
- **Trust inflation:** Everyone vouches for everyone
  - *Mitigation:* Velocity limits, weight decay, voucher reputation at stake

---

## Revision History

| Version | Date       | Author      | Changes       |
| ------- | ---------- | ----------- | ------------- |
| 1.0     | 2025-12-17 | Engineering | Initial draft |
