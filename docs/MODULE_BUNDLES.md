# Credo Module Bundles

This map explains how to consume the platform as composable modules while keeping a cohesive identity/evidence core.

## Core Identity Plane
- PRD-001: Authentication & Session Management
- PRD-002: Consent Management
- PRD-003: Registry Integration (evidence orchestrator, provider chains)
- PRD-004 / 004B: Verifiable Credentials issuance/validation
- PRD-005: Decision Engine
- PRD-006: Audit & Compliance Baseline

Use when you need the foundational identity workflow end-to-end.

## Assurance Pack (Risk & Compliance)
- PRD-006B: Cryptographic Audit (Merkle trees)
- PRD-007B: ML Risk Scoring
- PRD-008: GDPR/CCPA Automation
- PRD-013: Biometric Verification

Add when you need higher assurance, fraud/risk scoring, and automated compliance.

## Decentralized Identity Pack
- PRD-009: Decentralized Identifiers (DIDs)
- PRD-010: Zero-Knowledge Proofs

Add when you need decentralized identity trust models or privacy-preserving proofs.

## Integrations & Delivery Pack
- PRD-011: Internal TCP Event Ingester
- PRD-012: Cloud Connectors / Audit & Identity Event Export
- PRD-014: Client SDKs & Platform Integration

Add for operational plumbing, exports, and client developer experience.

## Adoption Guidance
- Start with the Core Identity Plane for minimal viable identity flows.
- Layer the Assurance Pack if you must satisfy risk/compliance bars.
- Layer the Decentralized Pack if your trust model requires DIDs/ZKPs.
- Layer the Integrations Pack to fit existing observability, data, and client ecosystems.

## Alignment With Architecture
- The evidence orchestrator (provider registry, strategies, correlation rules) embodies the modular approach in code: providers and rules are injected, not hard-wired.
- Each pack corresponds to isolated PRDs and can be delivered as separate services or Go packages wired through interfaces and handlers per AGENTS.md conventions.
