# Requirements Wishlist

Status: Living document
Last Updated: 2025-12-13
Scope: Non-committed future requirements for evaluation and scheduling.

Tags: auth, sessions, tokens, consent, audit, ops, performance, security, privacy, DX, infra

---

## Backlog Items

### Concurrent Session Limits

- Summary: Cap active sessions per user (and optionally per device/tenant). Enforce policy when creating or refreshing sessions.
- Motivation: Reduce account sharing and improve security posture; contain risk across devices.
- Scope: Auth service/session store, admin policy controls, API enforcement; audit + metrics.
- Dependencies: PRD-001 (Session Management), PRD-016 (Token Lifecycle & Revocation)
- Proposed Acceptance Criteria:
  - Configurable `max_active_sessions` globally; support optional per-user override.
  - On session creation if limit exceeded, evict oldest session (policy A) or deny new session (policy B) — configurable.
  - Audit events: `session_evicted_due_to_limit`, `session_limit_denied`.
  - Metrics: `session_evictions`, `active_sessions_capped`.
  - Transactional enforcement to avoid race (list+evict within `RunInTx`).
- Risk/Tradeoffs: Possible user friction; need clear UX messaging; recovery flows for legitimate device changes.
- Tags: sessions, security, ops
- Status: Proposed
- Link Targets: Will promote to PRD when scoped (e.g., PRD-0XX-Concurrent-Session-Limits)

### Refresh Token Binding to Device (Candidate)

- Summary: Bind refresh tokens to device context more strictly to reduce theft replay, beyond current device ID and fingerprint.
- Motivation: Strengthen long-lived token protections.
- Scope: Token issuance/validation, device context hashing, enforcement, audit.
- Tags: tokens, security, privacy
- Status: Proposed

### Session Anomaly Detection (Candidate)

- Summary: Detect anomalous session behavior (velocity, impossible travel) and flag/revoke.
- Motivation: Reduce account takeover dwell time.
- Scope: Signals pipeline, thresholds, audit, optional auto-revoke.
- Tags: security, ops
- Status: Researching

---

## Evaluation Queue

- Items actively being assessed for PRD promotion and scheduling.

---

## Changelog

- 2025-12-13: Initial wishlist created; added Concurrent Session Limits item.

---

## Governance

- Items move to PRD when:
  - Motivations and acceptance criteria are clear and testable
  - Cross-team review confirms scope and sequencing
- Review cadence: Weekly triage; track status per item.
