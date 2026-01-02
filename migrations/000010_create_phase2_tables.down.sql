-- Migration rollback: Drop Postgres-backed cache and rate limit tables

DROP INDEX IF EXISTS idx_tenants_name_ci;

DROP TABLE IF EXISTS global_throttle;
DROP TABLE IF EXISTS auth_lockouts;
DROP TABLE IF EXISTS rate_limit_allowlist;
DROP TABLE IF EXISTS rate_limit_events;
DROP TABLE IF EXISTS token_revocations;
DROP TABLE IF EXISTS vc_credentials;
DROP TABLE IF EXISTS sanctions_cache;
DROP TABLE IF EXISTS citizen_cache;
