---
marp: true
title: "Phase 0 - Foundation (MVP Prerequisites)"
paginate: true
size: 16:9
---

# Phase 0: Foundation (MVP Prerequisites)

Dates: YYYY-MM-DD to YYYY-MM-DD (Duration)
Owner: <Name>
PRDs: PRD-001, PRD-001B, PRD-016, PRD-026A, PRD-017, PRD-002

---

## Problem

- MVP needs secure auth, consent, tenant foundations, and admin controls.
- Baseline abuse prevention is required to protect public endpoints.

---

## Approach

- Implement OIDC-lite auth code flow, sessions, and token lifecycle controls.
- Add consent management with audit coverage and idempotency.
- Add tenant/client management and admin-only GDPR delete.
- Define rate limiting and abuse prevention requirements.

---

## Result

- Auth code flow with session tracking and device metadata.
- Refresh token rotation, revocation list, and session management.
- Consent grant/revoke/list with audit events and idempotency.
- Tenant and client admin APIs with strict redirect URI validation.
- Admin-only user deletion with audit events.
- Rate limiting spec ready; implementation pending.

---

## Evidence

- Tests: make test, make lint; manual curl flows for auth/consent.
- Metrics: Audit events across auth/consent/token lifecycle.
- Demo: <link or path>

---

## Risks and Gaps

- Rate limiting implementation and load tests pending (PRD-017).
- Logout-all and password-change global revocation pending (PRD-016/022).
- Admin capability 403 enforcement deferred to PRD-026.
- Consent projection path (TR-6) pending.
- Mitigations: track as Phase 0 follow-ups before Phase 1 rollout.

---

## Next

- Next phase: Phase 1 - Registry Integration, Verifiable Credentials, Decision Engine, Audit Compliance.
- Asks: confirm remaining Phase 0 scope and prioritize PRD-017 implementation and verification.
