-- Migration: Add functional index for case-insensitive tenant name lookups
--
-- Problem: FindByName uses lower(name) = lower($1) but the existing index is on raw name.
-- This causes a full table scan on every case-insensitive tenant name lookup.
--
-- Solution: Create a functional index on lower(name) that PostgreSQL can use for the query.
-- We also need to update the unique constraint to be on lower(name) to prevent
-- case-variant duplicates ("MyTenant" vs "MYTENANT").

-- Drop the old index that wasn't being used for case-insensitive lookups
DROP INDEX IF EXISTS idx_tenants_name;

-- Create a functional index on lower(name) for efficient case-insensitive lookups
-- This index will be used by queries like: WHERE lower(name) = lower($1)
CREATE UNIQUE INDEX idx_tenants_name_lower ON tenants(lower(name));

-- Note: The unique constraint on lower(name) also prevents case-variant duplicates,
-- e.g., creating "MyTenant" when "MYTENANT" already exists will fail.

COMMENT ON INDEX idx_tenants_name_lower IS 'Case-insensitive unique index for tenant name lookups and uniqueness enforcement.';
