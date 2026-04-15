-- =============================================================================
-- V1__Public_schema.sql
-- EBW: global tables in 'public' schema (shared with Issuer DB or standalone)
-- =============================================================================

CREATE TABLE IF NOT EXISTS public.tenant_registry (
    schema_name   VARCHAR(64)  PRIMARY KEY,
    display_name  VARCHAR(255) NOT NULL,
    tenant_type   VARCHAR(20)  NOT NULL DEFAULT 'simple',
    status        VARCHAR(20)  NOT NULL DEFAULT 'active',
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Seed: same tenants as Issuer (dev/stg)
INSERT INTO public.tenant_registry (schema_name, display_name, tenant_type) VALUES
    ('platform', 'EUDIStack Platform', 'platform'),
    ('sandbox',  'Sandbox',            'multi_org'),
    ('dome',     'DOME',               'multi_org'),
    ('kpmg',     'KPMG',               'simple')
ON CONFLICT (schema_name) DO NOTHING;
