# ADR-001: Token Signing and Rotation Strategy

- **Status:** Accepted
- **Date:** 2026-01-01
- **Owners:** Security & Platform

## Context
- Current signing uses a single HS256 secret with permissive defaults and an optional dev fallback. There is no JWKS exposure, no key identifiers, and no rotation path, so a leaked secret compromises every token until manual redeploy.
- External resource servers and downstream services need a stable way to validate tokens without sharing symmetric secrets.
- Rollout guidance in the roadmap calls for a dual-issuer migration (HS256 ➜ RS256) with JWKS exposure and explicit retirement of legacy keys.

## Decision
- Adopt asymmetric signing (RS256 by default; ES256 allowed for FIPS environments) with **per-environment signing keysets** managed via KMS/HSM-backed storage. Each key is versioned and annotated with `kid`, `alg`, `created_at`, and `expires_at` metadata.
- Publish public keys via a **tenant-aware JWKS endpoint** (`/.well-known/jwks.json`) and embed `kid` in every signed token. Resource servers must validate `iss`, `aud`, and `kid` against JWKS.
- Enforce a **90-day rotation cadence** with automated key generation. Rotation follows a dual-signing window: new keys are added to JWKS, tokens are signed with the newest active key while previous active keys remain valid for verification for 30 days, then are retired and removed from signing use.
- Isolate key usage per token class: **access tokens** and **refresh tokens** use distinct keysets to reduce blast radius; administrative API tokens are signed by a separate administrative issuer.
- Store signing configuration in the platform config layer (no defaults that silently succeed). Startup fails closed if required keys are missing or expired; local/dev runs load explicit fixture keys instead of generating new secrets implicitly.

## Consequences
- Implement JWKS publishing and `kid` resolution in `internal/jwt_token` and surface issuer metadata in OIDC discovery. Update middleware to reject tokens signed with unknown or expired keys and to enforce audience/client binding during validation.
- Add operational runbooks for rotation (preflight checks, dual-signing window, validation dashboards) and incident response for key compromise (key revocation, token revocation sweep, cache invalidation).
- CI/CD must provision KMS keys per environment and supply them to the service via secure configuration (env/secret manager). Integration tests will rely on dedicated fixture keys and local JWKS documents.
