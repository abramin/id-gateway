# PRD-040: OIDC Metadata & Key Management

**Status:** Not Started  
**Priority:** P0 (Security)  
**Owner:** Security Engineering  
**Dependencies:** PRD-001, PRD-026A, PRD-028  
**Last Updated:** 2025-12-24

---

## 1. Purpose

Implement per-tenant OpenID Connect metadata and robust signing key management
to support production-grade issuer isolation and key rotation.

## 2. Scope

- RS256/ES256 signing keys (replace HS256 for production).
- Per-tenant signing keys and key versioning.
- Per-tenant JWKS endpoint.
- Per-tenant OIDC discovery endpoint.
- Per-tenant audience values.
- Key rotation windows and rollback procedures.

## 3. Non-Scope

- Token introspection or PKCE (PRD-041).
- SSO/federation (PRD-042).

## 4. Functional Requirements

1. **OIDC Discovery**
   - `GET /tenants/{tenant_id}/.well-known/openid-configuration`
   - Includes issuer, jwks_uri, supported algs, endpoints.

2. **JWKS**
   - `GET /tenants/{tenant_id}/.well-known/jwks.json`
   - Active + previous keys during rotation window.

3. **Key Management**
   - Per-tenant keys with version IDs.
   - Rotation schedule and rollback process documented.
   - Optional HSM-backed storage for production.

4. **Audience Controls**
   - Per-tenant audience allowlist.
   - Validation enforced in token verification.

## 5. Acceptance Criteria

- Tokens are signed with RS256 or ES256 and validated against JWKS.
- OIDC discovery returns correct per-tenant metadata.
- Rotation does not break active tokens during grace period.
- Per-tenant audiences are enforced in verification.

## 6. References

- RFC 8414: Authorization Server Metadata
- OIDC Core 1.0

---

## Revision History

| Version | Date       | Author       | Changes       |
| ------- | ---------- | ------------ | ------------- |
| 1.0     | 2025-12-24 | Security Eng | Initial draft |
