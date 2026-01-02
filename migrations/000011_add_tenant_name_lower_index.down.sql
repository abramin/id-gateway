-- Rollback: Restore original tenant name index

-- Drop the functional index
DROP INDEX IF EXISTS idx_tenants_name_lower;

-- Restore the original index on raw name
CREATE UNIQUE INDEX idx_tenants_name ON tenants(name);
