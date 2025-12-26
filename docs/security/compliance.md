## Credo System Compliance Report: GDPR & CCPA

### 1. Introduction and Purpose
- Documents Credo controls mapped to GDPR/CCPA obligations using PRD-specified features.
- Audience: Compliance officers, DPOs, internal auditors; evidence sourced from official PRDs only.
- **Status:** Target-state mapping. Not all items are implemented in the current codebase.

**Implementation notes (current gaps):**
- `/me/data-export` and `/me` delete handlers are stubbed.
- Merkle-tree audit and automated compliance checks are not implemented.
- Data residency and cross-border routing are not implemented.

---

### 2. Lawfulness of Processing: Consent and Transparency
- Consent enforced before sensitive operations (PRD-003/004/013/005).
- Automated checks (PRD-008 Policies 2.x) verify consent gating for registry lookups, VC issuance, decision evaluation, and biometrics.

**Consent Matrix**

| Action                                   | Consent Purpose                   | Source PRD |
| ---------------------------------------- | --------------------------------- | ---------- |
| Registry lookups (citizen/sanctions)     | ConsentPurposeRegistryCheck       | PRD-003    |
| Verifiable Credential issuance           | ConsentPurposeVCIssuance          | PRD-004    |
| Biometric verification (Art. 9 data)     | ConsentPurposeBiometricVerification| PRD-013    |
| Decision evaluation                      | ConsentPurposeDecision            | PRD-005    |

---

### 3. Data Minimization and Purpose Limitation
- Regulated Mode minimizes PII in registry and VC flows (PRD-003/004); `MinimizeCitizenRecord` strips FullName/DOB/Address.
- Decision Engine uses derived, non-PII attributes (e.g., `IsOver18`) instead of raw DOB (PRD-005).
- Compliance checks (PRD-008 Policies 4.x) confirm PII stripping and derived-attribute usage.

---

### 4. Data Subject Rights
**4.1 Right of Access (GDPR Art. 15)**
- `GET /me/data-export` returns full user data in JSON (PRD-007).
- Service fans out concurrent reads across audit, consent, session, VC, registry cache for completeness.
- SLA: 72h internal target (PRD-008 Policy 3.1).

**4.2 Right to Erasure (GDPR Art. 17)**
- `DELETE /me` triggers comprehensive delete/pseudonymize (PRD-007); monitored by PRD-008 Policy 3.2 (24h target).

| Data Store     | Action                  | Justification                                      |
| -------------- | ----------------------- | -------------------------------------------------- |
| UserStore      | Deleted                 | Direct PII                                         |
| SessionStore   | Deleted                 | Linked to identity                                 |
| ConsentStore   | Deleted                 | Linked to identity                                 |
| VCStore        | Deleted                 | Contains/refers to PII                             |
| RegistryCache  | Deleted                 | Contains PII (name, DOB)                           |
| AuditStore     | Retained & pseudonymized| Legal retention (6y); userID hashed to break link  |

---

### 5. Accountability, Integrity, and Governance
**5.1 Integrity & Records of Processing (GDPR Art. 30)**
- Tamper-evident audit log via Merkle tree (PRD-006B); root hash as fingerprint.
- Automated completeness checks (PRD-008 Policies 5.x) for consent, access, modification events.

**5.2 Storage Limitation (GDPR Art. 5(1)(e))**
- User data post-delete: max 30 days (Policy 1.1).
- Audit logs: 6 years (Policy 1.2).
- Inactive sessions: 30 days (Policy 1.3).
- Cached registry data: 24h (Policy 1.4).

**5.3 Data Residency and Sovereignty**
- Regional data stores and routed processing (PRD-024).
- Cross-border transfers logged for auditability.

---

### 6. Conclusion
- Credo embeds privacy-by-design: consent gating, minimization, user rights execution, and cryptographic auditability.
- PRD-backed controls provide verifiable alignment with GDPR/CCPA and support operation in highly regulated environments.
