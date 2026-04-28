-- =============================================================================
-- V2__Add_tenant_config.sql
-- Per-tenant configuration table for EBW.
-- Mirrors the pattern from eudistack-core-issuer (EUDI-063/075).
-- Tenant-specific values (allowed domains, mail-from, …) are seeded here
-- instead of being injected as global env vars.
-- =============================================================================

CREATE TABLE IF NOT EXISTS tenant_config (
    id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    config_key   VARCHAR(255) NOT NULL UNIQUE,
    config_value TEXT         NOT NULL,
    description  VARCHAR(500),
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Seed placeholder values overridden per-tenant in seed-tenants[.stg].sql
INSERT INTO tenant_config (config_key, config_value, description) VALUES
    ('ebw.mail_from',               'noreply@eudistack.com',    'Sender address used for transactional emails (OTP, registration)'),
    ('ebw.allowed_credential_formats', 'dc+sd-jwt,jwt_vc_json', 'Comma-separated list of accepted credential formats, or * for all')
ON CONFLICT (config_key) DO NOTHING;
