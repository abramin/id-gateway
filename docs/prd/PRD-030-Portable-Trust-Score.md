# PRD-030: Portable Trust Score

**Status:** Draft
**Priority:** P2 (Strategic)
**Owner:** Engineering Team
**Dependencies:** PRD-004 (Verifiable Credentials), PRD-005 (Decision Engine), PRD-010 (Zero-Knowledge Proofs)

---

## 1. Overview

### Problem Statement

When users join a new service, they start from zero trust regardless of their verified history elsewhere. This creates friction:

- **For users:** Repeated identity verification on each new platform
- **For services:** High onboarding costs, can't leverage existing trust
- **For the ecosystem:** No portable reputation, trust stays siloed

### Goals

- Create a **Portable Trust Score** that travels with users across services
- Enable **ZKP-provable score** - prove "score > threshold" without revealing exact score
- Build trust from **verified credentials, behavior history, and attestations**
- Support **score decay over time** to reflect current trustworthiness
- Integrate with **Decision Engine** as evidence for authorization

### Non-Goals

- Credit scoring or financial risk assessment
- Social media reputation aggregation
- Public leaderboards or visible scores
- Scores for unauthenticated users

---

## 2. User Stories

**As a** user with verified credentials
**I want to** carry my trust reputation to new services
**So that** I don't have to re-verify everywhere

**As a** new user
**I want to** prove I'm trustworthy without revealing my history
**So that** I can access services while maintaining privacy

**As a** service operator
**I want to** require minimum trust scores for sensitive operations
**So that** I can reduce fraud risk without full verification

**As a** returning user
**I want to** see how my actions affect my trust score
**So that** I can maintain good standing

---

## 3. Functional Requirements

### FR-1: Trust Score Calculation

**Components:**
| Component | Weight | Description |
|-----------|--------|-------------|
| Identity Verification | 30% | Registry checks passed, KYC level |
| Credential Age | 20% | How long verified credentials held |
| Behavior History | 25% | Consent compliance, no fraud flags |
| Attestation Count | 15% | Third-party vouches (see PRD-033) |
| Account Age | 10% | Time since account creation |

**Score Range:** 0-100

**Decay:** Score decays 5% per year of inactivity; reverified credentials reset decay.

### FR-2: Get User's Trust Score

**Endpoint:** `GET /me/trust-score`

**Output (Success - 200):**
```json
{
  "score": 78,
  "components": {
    "identity_verification": 25,
    "credential_age": 18,
    "behavior_history": 20,
    "attestations": 8,
    "account_age": 7
  },
  "level": "high",
  "last_updated": "2025-12-17T10:00:00Z",
  "next_decay_at": "2026-12-17T10:00:00Z"
}
```

### FR-3: ZKP Score Proof Generation

**Endpoint:** `POST /me/trust-score/proof`

**Description:** Generate a zero-knowledge proof that score meets threshold.

**Input:**
```json
{
  "threshold": 70,
  "comparison": "gte",
  "audience": "service_xyz",
  "expires_in": 3600
}
```

**Output (Success - 200):**
```json
{
  "proof": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9...",
  "statement": "trust_score >= 70",
  "audience": "service_xyz",
  "issued_at": "2025-12-17T10:00:00Z",
  "expires_at": "2025-12-17T11:00:00Z",
  "verification_url": "https://credo.app/verify/proof/abc123"
}
```

### FR-4: Verify Score Proof

**Endpoint:** `POST /trust-score/verify`

**Description:** Service verifies a ZKP score proof.

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
  "statement": "trust_score >= 70",
  "user_id": "user_456",
  "issued_at": "2025-12-17T10:00:00Z",
  "expires_at": "2025-12-17T11:00:00Z"
}
```

### FR-5: Trust Score as Verifiable Credential

**Description:** Issue trust score as a self-signed VC for offline verification.

**VC Structure:**
```json
{
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "type": ["VerifiableCredential", "TrustScoreCredential"],
  "issuer": "did:web:credo.app",
  "issuanceDate": "2025-12-17T10:00:00Z",
  "expirationDate": "2025-12-18T10:00:00Z",
  "credentialSubject": {
    "id": "did:key:user_456",
    "trustScoreRange": "70-80",
    "level": "high"
  },
  "proof": {...}
}
```

---

## 4. Technical Requirements

### TR-1: Score Storage

```
trust_scores
├── user_id (PK)
├── score (0-100)
├── components (JSONB)
├── level (low, medium, high, very_high)
├── calculated_at
├── decay_factor
└── last_activity_at

trust_score_history
├── id (PK)
├── user_id
├── previous_score
├── new_score
├── change_reason
├── timestamp
└── evidence_ids []
```

### TR-2: ZKP Circuit

- Use Bulletproofs for range proofs (no trusted setup)
- Prove: `score >= threshold` without revealing exact score
- Proof generation: <1 second
- Proof verification: <100ms

### TR-3: Decision Engine Integration

Register Trust Score as evidence type:
```go
type TrustScoreEvidence struct {
    Score     int    `json:"score"`
    Level     string `json:"level"`
    ValidUntil time.Time `json:"valid_until"`
}
```

---

## 5. Acceptance Criteria

- [ ] Trust score calculated from 5 components
- [ ] Score decays over time without activity
- [ ] Users can view their score and components
- [ ] ZKP proofs can be generated for threshold comparisons
- [ ] Services can verify ZKP proofs without learning exact score
- [ ] Trust score available as VC for offline verification
- [ ] Decision engine can use trust score as evidence
- [ ] Score history maintained for audit

---

## 6. Dependencies & Risks

### Dependencies
- PRD-004 (Verifiable Credentials) - VC issuance format
- PRD-005 (Decision Engine) - Evidence integration
- PRD-010 (Zero-Knowledge Proofs) - ZKP infrastructure

### Risks
- **Gaming risk:** Users may try to artificially inflate scores
  - *Mitigation:* Decay, attestation verification, fraud detection
- **Privacy risk:** Score correlation could reveal identity
  - *Mitigation:* Audience-bound proofs, short expiry, no exact score in proof

---

## Revision History

| Version | Date       | Author      | Changes       |
| ------- | ---------- | ----------- | ------------- |
| 1.0     | 2025-12-17 | Engineering | Initial draft |
