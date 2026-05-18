-- =============================================================================
-- V4__Wallet_operational_config.sql
-- Story: EUDISTACK-414 (US-03 — plano operativo per-tenant db-tde con
--        procedimiento documentado, auditado y atómico)
-- Feature: EUDISTACK-411 (Wallet Tenant Configuration)
-- Tech-design: docs/EUDISTACK-411-wallet-tenant-configuration/EUDISTACK-414/tech-design.md §4
--
-- Aplicado por Flyway en cada schema de tenant (db/tenant/) — NO en public.
-- Gestionado por TenantSchemaFlywayMigrator#migrateTenantSchema al arrancar el EBW
-- para cada tenant activo registrado en la tabla public.tenants.
--
-- Idempotente: CREATE TABLE IF NOT EXISTS / CREATE UNIQUE INDEX IF NOT EXISTS.
--
-- AD-S5/D-S1 (DB role aplicativo dedicado): pendiente. REVOKE/GRANT no se aplica
-- en US-03 — escalado al PM, ver tech-design §3.5.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Tabla raíz: wallet_operational_config
--
-- Una fila por key_manager (UNIQUE). Solo una fila puede estar activa al mismo
-- tiempo por key_manager (índice parcial uidx_woc_active_key_manager).
-- La cross-field CHECK garantiza que activation_status='active' implica que
-- connectivity_verified_at no es NULL (AC-5 — probe antes de activar).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS wallet_operational_config (
    id                          UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    key_manager                 VARCHAR(16)     NOT NULL,
    activation_status           VARCHAR(16)     NOT NULL DEFAULT 'pending-spi',
    is_active                   BOOLEAN         NOT NULL DEFAULT false,
    connectivity_verified_at    TIMESTAMPTZ     NULL,
    version                     BIGINT          NOT NULL DEFAULT 0,
    updated_by                  VARCHAR(255)    NOT NULL,
    updated_at                  TIMESTAMPTZ     NOT NULL DEFAULT now(),
    CONSTRAINT chk_woc_key_manager
        CHECK (key_manager IN ('db-tde', 'hybrid', 'hsm', 'qtsp')),
    CONSTRAINT chk_woc_activation_status
        CHECK (activation_status IN ('active', 'pending-spi')),
    CONSTRAINT chk_woc_active_requires_probe
        CHECK (
            (activation_status = 'active'      AND connectivity_verified_at IS NOT NULL)
            OR (activation_status = 'pending-spi' AND connectivity_verified_at IS NULL)
        )
);

-- Índice parcial: solo una fila activa por key_manager.
-- Ej.: dos filas db-tde no pueden tener is_active=true simultáneamente.
CREATE UNIQUE INDEX IF NOT EXISTS uidx_woc_active_key_manager
    ON wallet_operational_config (key_manager)
    WHERE is_active = true;

-- ---------------------------------------------------------------------------
-- Sub-tabla: wallet_operational_config_db_tde
--
-- Extiende la fila raíz con los campos específicos de key_manager='db-tde'.
-- PK = FK ON DELETE CASCADE → si se borra la fila raíz, la sub-tabla se borra.
-- wrapped_dek: almacenado como bytea; nunca descifrado en el plano operativo
-- (la desencriptación la hace el consumidor columnar en US-05+).
-- Las sub-tablas hsm/qtsp/hybrid se añaden en US-05/US-06/US-07.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS wallet_operational_config_db_tde (
    config_id                   UUID            PRIMARY KEY
                                                    REFERENCES wallet_operational_config(id)
                                                    ON DELETE CASCADE,
    column_encryption_key_arn   VARCHAR(2048)   NOT NULL,
    wrapped_dek                 BYTEA           NOT NULL,
    algorithm                   VARCHAR(32)     NOT NULL,
    created_at                  TIMESTAMPTZ     NOT NULL DEFAULT now(),
    CONSTRAINT chk_woc_db_tde_algorithm
        CHECK (algorithm IN ('AES-256-GCM')),
    CONSTRAINT chk_woc_db_tde_wrapped_dek_not_empty
        CHECK (octet_length(wrapped_dek) > 0)
);
