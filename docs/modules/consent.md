# Consent Module (PRD-002)

## Summary

The consent module tracks what users have agreed to let the system do with their data. Before Credo can look up someone's citizen record or issue a credential, the user must explicitly grant permission. This isn't just good practice - it's legally required under GDPR and similar regulations.

## Why this matters (product view)

- Regulatory compliance: GDPR requires specific, informed, and revocable consent before processing personal data.
- User trust: People can see exactly what they've agreed to and revoke permissions anytime.
- Legal protection: When regulators ask "did this user consent to this data use?", we can prove it with timestamps and audit logs.
- Operational clarity: Developers don't have to guess whether they can use someone's data - the consent check tells them.

## What was delivered

### Consent Lifecycle
- **Purpose-based consent**: Users consent to specific purposes (login, registry_check, vc_issuance, decision_evaluation), not blanket agreements.
- **Time-bound consent**: Each consent expires after 1 year by default. No perpetual permissions.
- **Revocable anytime**: Users can revoke consent instantly via API. Revocation takes effect immediately.
- **Clear status**: Every consent is either "active", "expired", or "revoked" - no ambiguity.

### Grant and Revoke Operations
- **Multi-purpose grants**: Grant consent for multiple purposes in one request.
- **Idempotent grants**: Requesting the same consent twice within 5 minutes returns the existing consent without creating duplicates or audit noise.
- **TTL extension**: Re-granting after 5 minutes extends the expiry date (supports long-running sessions).
- **ID reuse**: Consent records are reused (updated) rather than creating multiple records per user+purpose.

### Enforcement
- **Require() method**: Internal API that handlers call before processing data. Returns error if consent is missing, expired, or revoked.
- **403 Forbidden**: Operations that need consent but don't have it return clear error messages.
- **Audit on check failure**: When a consent check fails, it's logged for compliance review.

### Bulk Operations
- **Revoke all**: `POST /auth/consent/revoke-all` revokes all active consents for a user (cleanup, admin use).
- **Delete all**: `DELETE /auth/consent` permanently removes all consent records (GDPR right to erasure).

## Benefits

| Feature | Benefit | Who cares |
|---------|---------|-----------|
| Purpose-specific consent | Users know exactly what they're agreeing to | Legal, privacy advocates |
| 1-year expiry | No perpetual permissions; forces re-consent | Compliance, legal |
| Instant revocation | Users can withdraw consent immediately | Users, privacy regulators |
| Audit trail | Proof of consent at time of data processing | Compliance, legal, auditors |
| Idempotent grants | No duplicate records or audit noise from UI retries | Operations, developers |
| GDPR deletion | Full erasure when legally required | Legal, compliance |

## Design decisions explained

### Why purpose-based rather than blanket consent?
GDPR requires consent to be "specific" - users must know exactly what they're agreeing to. A single "I agree to everything" checkbox doesn't meet this standard. By breaking consent into purposes, we prove the user understood each specific use of their data.

### Why a 5-minute idempotency window?
Users might double-click a consent button, or a mobile app might retry a failed request. Without idempotency, this would create duplicate audit entries and confuse compliance reviews. The 5-minute window absorbs these retries while still allowing legitimate TTL extensions for long sessions.

### Why reuse consent IDs instead of creating new records?
A user might grant, revoke, and re-grant consent for the same purpose multiple times. Creating a new record each time would clutter the database. By reusing IDs and tracking history through the audit log, we keep the consent store clean while maintaining full history.

### Why enforce consent in the service layer, not handlers?
If consent checks were in handlers, a developer might forget to add one. By putting the `Require()` check in the service layer, it's enforced consistently regardless of how the service is called (HTTP handler, CLI, test, future job).

### Why 1 year expiry instead of indefinite?
GDPR encourages time-limited consent that forces periodic review. Indefinite consent can become stale (user forgets they granted it, circumstances change). Annual renewal ensures consent remains current and meaningful.

## Security highlights

- **No data processing without consent**: All data operations check consent first.
- **Immediate revocation**: Revoked consent takes effect instantly for subsequent requests.
- **Audit coverage**: Every grant, revoke, and failed check is logged with timestamps.
- **User-only access**: Users can only manage their own consents (extracted from JWT).

## Integration points

- Handlers call `consentService.Require()` before processing sensitive data.
- All consent changes publish to audit system.
- HTTP endpoints:
  - `POST /auth/consent` - Grant consent for purposes
  - `POST /auth/consent/revoke` - Revoke specific consents
  - `POST /auth/consent/revoke-all` - Revoke all consents
  - `DELETE /auth/consent` - Delete all consents (GDPR)
  - `GET /auth/consent` - List user's consents

## Known gaps / follow-ups

- **CQRS projection path (TR-6)**: Deferred until after Postgres migration. Currently reads from same store as writes; high-volume deployments may need optimized read models.
- **Per-purpose expiry**: Currently all purposes have 1-year TTL. Future enhancement could allow different TTLs per purpose.
- **Consent cascading**: No support for "purpose A requires purpose B" dependencies yet.
