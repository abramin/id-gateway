# Credo Module Bundles

**Version:** 2.0
**Last Updated:** 2025-12-12

This map explains how to consume the platform as composable modules while keeping a cohesive identity/evidence core.

---

## Core Identity Plane (MVP)

**Phase 0-2: Foundation → Operational Baseline**

- PRD-001: Authentication & Session Management ✅
- PRD-016: Token Lifecycle & Revocation 🆕
- PRD-017: Rate Limiting & Abuse Prevention 🆕
- PRD-002: Consent Management
- PRD-003: Registry Integration (evidence orchestrator, provider chains)
- PRD-004 / 004B: Verifiable Credentials issuance/validation
- PRD-005: Decision Engine
- PRD-006: Audit & Compliance Baseline
- PRD-007: User Data Rights (GDPR)

**Use when:** You need the foundational identity workflow end-to-end.

---

## Infrastructure Layer (Production Prerequisites)

**Phase 0-3: Operational readiness and security**

- PRD-017: Rate Limiting & Abuse Prevention 🆕
- PRD-018: Notification Service (Email/SMS/Webhooks) 🆕
- PRD-019: API Versioning & Lifecycle Management 🆕
- PRD-020: Operational Readiness & SRE 🆕
- PRD-021: Multi-Factor Authentication 🆕
- PRD-022: Account Recovery & Credential Management 🆕
- PRD-015: Credo Policy Engine (Internal PDP)
- PRD-005B: Cerbos Authorization (External PDP)

**Use when:** Deploying to production, need operational maturity and security hardening.

---

## Assurance Pack (Risk & Compliance)

**Phase 4: Regulated industries, high-assurance requirements**

- PRD-013: Biometric Verification
- PRD-023: Fraud Detection & Security Intelligence 🆕
- PRD-006B: Cryptographic Audit (Merkle trees)
- PRD-007B: ML Risk Scoring
- PRD-008: GDPR/CCPA Automation
- PRD-024: Data Residency & Sovereignty 🆕

**Use when:** You need higher assurance, fraud/risk scoring, and automated compliance.

---

## Decentralized Identity Pack

**Phase 5: Web3, privacy-preserving identity**

- PRD-004B: Enhanced VCs (BBS+, Status List)
- PRD-009: Decentralized Identifiers (DIDs)
- PRD-010: Zero-Knowledge Proofs

**Use when:** Your trust model requires DIDs/ZKPs or privacy-preserving proofs.

---

## Integrations & Developer Experience Pack

**Phase 6: Ecosystem, partner integrations, operations UI**

- PRD-011: Internal TCP Event Ingester
- PRD-012: Cloud Connectors / Audit & Identity Event Export (Enhanced with webhooks)
- PRD-014: Client SDKs & Platform Integration
- PRD-025: Developer Sandbox & Testing 🆕
- PRD-026: Admin Dashboard & Operations UI 🆕

**Use when:** Building partner ecosystem, improving developer experience, or need operations tooling.

---

## Adoption Guidance

### Minimal Viable Product (9-12 days)

**Phase 0-2:** Core Identity Plane (PRDs 1, 16, 17, 2, 3, 4, 5, 6, 19, 20, 7)

- Complete identity workflow with operational basics
- Deployable to staging environment

### Production Baseline (15-20 days total)

**Phase 3:** Add Infrastructure Layer (PRDs 18, 21, 22, 15, 5B)

- Security hardening (MFA, rate limiting, token revocation)
- User-facing flows (notifications, account recovery)
- Internal policy engine for control

### Full Production (22-30 days total)

**Phase 4:** Add Assurance Pack (PRDs 13, 23, 6B, 7B, 8, 24)

- High-assurance verification (biometrics, fraud detection)
- Compliance automation (GDPR, data residency)
- Cryptographic audit trails

### Advanced Features (30-46 days total)

**Phase 5-6:** Add Decentralized + Integrations Packs

- Web3 identity (DIDs, ZKPs, enhanced VCs)
- Developer experience (sandbox, SDKs, admin UI)
- Partner integrations (webhooks, cloud connectors)

---

## Revision History

| Version | Date       | Author           | Changes                                                                             |
| ------- | ---------- | ---------------- | ----------------------------------------------------------------------------------- |
| 1.0     | 2025-12-10 | Engineering Team | Initial module bundle documentation                                                 |
| 2.0     | 2025-12-12 | Engineering Team | Added Infrastructure Layer; reordered PRDs by dependency; added 11 new PRDs (16-26) |
