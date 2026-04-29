-- =============================================================================
-- V1__Public_schema.sql
-- Schema-per-tenant: global tables in 'public' schema
-- EUDI-063: replaces V1__Initial_schema.sql (legacy 'issuer' schema)
--
-- Tenant rows are NOT seeded from this migration. Tenant onboarding is owned
-- by the (future) tenant-onboarding service; until then, rows are inserted
-- manually or via `seed-tenants*.sql` from `eudistack-platform-dev`.
-- The column `schema_name` stores the tenant id (e.g. 'sandbox'); each
-- service derives its physical schema by appending its own suffix
-- (Issuer -> '<tenant>_issuer').
-- =============================================================================

-- =============================================================================
-- tenant_registry: lists all tenants with status and metadata
-- =============================================================================
CREATE TABLE IF NOT EXISTS public.tenant_registry (
    schema_name   VARCHAR(64)  PRIMARY KEY,
    display_name  VARCHAR(255) NOT NULL,
    tenant_type   VARCHAR(20)  NOT NULL DEFAULT 'simple',
    status        VARCHAR(20)  NOT NULL DEFAULT 'active',
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);
