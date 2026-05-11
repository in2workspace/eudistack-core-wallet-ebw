-- =============================================================================
-- V2__Create_tenant_wallet_config.sql
-- EUDISTACK-412: wallet discovery plane — global table mapping tenant host to
-- wallet_mode (browser vs server).
--
-- Sibling of public.tenant_registry (V1__Public_schema.sql) and owned the same
-- way: created by the EBW Flyway migrator on startup against the `public` schema
-- (TenantSchemaFlywayMigrator#migratePublicSchema). See feature-design §4.2
-- "Reuse-before-invention".
--
-- Read path: EUDIW on bootstrap via GET /business-wallet/.well-known/wallet-tenant-config.
-- Write path: POST /business-wallet/admin/wallet-tenant-config (UPSERT, bumps version).
--
-- Column set mirrors WalletTenantConfigEntity and the UPSERT in
-- WalletTenantConfigR2dbcAdapter exactly. `supported_credentials` is NOT
-- persisted in US-01 (the mapper returns an empty list on read); it will be
-- introduced in US-02/03.
--
-- Idempotent (CREATE TABLE IF NOT EXISTS) — mirrors the V1 style. The Issuer
-- (core-issuer) may also declare this table later in its own migration set.
-- =============================================================================

CREATE TABLE IF NOT EXISTS public.tenant_wallet_config (
    schema_name           VARCHAR(64)  PRIMARY KEY
        REFERENCES public.tenant_registry (schema_name) ON DELETE CASCADE,
    host                  VARCHAR(255) NOT NULL UNIQUE,
    wallet_mode           VARCHAR(50)  NOT NULL,
    key_manager           VARCHAR(50),
    natural_persons_only  BOOLEAN      NOT NULL DEFAULT FALSE,
    version               BIGINT       NOT NULL DEFAULT 1,
    updated_by            VARCHAR(255),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT chk_twc_wallet_mode CHECK (wallet_mode IN ('browser', 'server')),
    -- Values are kebab-case, matching KeyManager#getValue() — 'db-tde', not 'db_tde'.
    CONSTRAINT chk_twc_key_manager CHECK (
        key_manager IS NULL OR key_manager IN ('db-tde', 'hybrid', 'hsm', 'qtsp')
    ),
    -- FR-20: browser-mode tenants always have key_manager = NULL.
    CONSTRAINT chk_twc_browser_no_key_manager CHECK (
        NOT (wallet_mode = 'browser' AND key_manager IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_tenant_wallet_config_host
    ON public.tenant_wallet_config (host);
