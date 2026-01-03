# ADR-001: Token Signing and Rotation Strategy

- **Status:** Accepted
- **Date:** 2026-01-01
- **Owners:** Security & Platform

## Context
- The current architecture signs access tokens with HS256 in `internal/jwt_token` using a configurable signing key and validates them via `RequireAuth` middleware. There is no JWKS exposure or `kid` support today.
- Token lifecycle management exists (refresh tokens + TRL), but key rotation remains a manual operation that must be coordinated with revocation.
- The production roadmap calls for migrating to asymmetric signing (RS256/ES256) and standard OIDC key management.

## Decision
- **Phase 0 (current):** Continue HS256 signing with a single environment-provided key. Tokens include `iss`/`aud` claims and are validated by middleware. No implicit fallback secrets are allowed.
- **Rotation (current):** Rotation is manual: replace the signing key and coordinate revocation and session cleanup. No JWKS or `kid` support yet.
- **Phase 1 (planned):** Migrate to asymmetric signing (RS256 by default; ES256 where required) with JWKS publishing and OIDC discovery. Introduce key IDs, overlap windows, and automated rotation once the asymmetric migration is scheduled.

## Consequences
- Keep HS256-only validation in `internal/jwt_token` until the asymmetric migration lands; token validation remains local to the gateway.
- Operational runbooks must coordinate key replacement with token revocation and session cleanup to avoid lingering access.
- When RS256/ES256 is introduced, add JWKS publishing, key versioning, and rotation automation, and update middleware to resolve `kid` from JWKS.
