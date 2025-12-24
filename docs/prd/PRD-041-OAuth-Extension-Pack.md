# PRD-041: OAuth Extension Pack

**Status:** Not Started  
**Priority:** P1 (Protocol)  
**Owner:** Engineering  
**Dependencies:** PRD-001, PRD-016, PRD-026A  
**Last Updated:** 2025-12-24

---

## 1. Purpose

Add OAuth/OIDC extensions deferred from core auth and token PRDs.

## 2. Scope

- PKCE support for public clients (RFC 7636).
- Token introspection endpoint (RFC 7662).
- Token exchange (RFC 8693) for service-to-service.
- Client credentials grant for confidential clients.

## 3. Non-Scope

- OIDC discovery/JWKS (PRD-040).
- Enterprise SSO/federation (PRD-042).

## 4. Functional Requirements

1. **PKCE**
   - Require `code_challenge` on public client authorize requests.
   - Validate `code_verifier` on token exchange.

2. **Token Introspection**
   - `POST /oauth/introspect` with client auth.
   - Returns active/expired, subject, scopes, tenant_id.

3. **Token Exchange**
   - `POST /oauth/token` with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`.
   - Enforce audience and actor/subject constraints.

4. **Client Credentials**
   - Enforce confidential client requirement.
   - Scopes restricted to pre-registered allowlist.

## 5. Acceptance Criteria

- PKCE enforced for public clients and optional for confidential clients.
- Introspection responds with RFC-compliant payloads.
- Token exchange rejects invalid audiences or unauthorized actors.
- Client credentials grant is gated by client type and scopes.

## 6. References

- RFC 7636 (PKCE)
- RFC 7662 (Token Introspection)
- RFC 8693 (Token Exchange)

---

## Revision History

| Version | Date       | Author      | Changes       |
| ------- | ---------- | ----------- | ------------- |
| 1.0     | 2025-12-24 | Engineering | Initial draft |
