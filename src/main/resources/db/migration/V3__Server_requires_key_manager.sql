-- =============================================================================
-- V3__Server_requires_key_manager.sql
-- EUDISTACK-413 (US-02): wallet discovery plane — CHECK constraint enforcing
-- that server-mode tenants always carry a key_manager value (FR-21).
--
-- This is a FORWARD migration — it does NOT amend V2__Create_tenant_wallet_config.sql
-- (V2 is already applied in all environments; amending it would break Flyway's
-- checksum validation — AD-S1 in EUDISTACK-413 tech-design §3.5).
--
-- Constraint relationship:
--   V2 supplies: chk_twc_browser_no_key_manager  (NOT (wallet_mode='browser' AND key_manager IS NOT NULL)) — FR-20
--   V3 supplies: chk_twc_server_requires_key_manager (NOT (wallet_mode='server' AND key_manager IS NULL))  — FR-21 (this file)
-- Together the two CHECKs enforce the full pairing invariant:
--   browser => key_manager IS NULL  AND  server => key_manager IS NOT NULL
--
-- Applied by the EBW Flyway migrator on startup against the `public` schema
-- (TenantSchemaFlywayMigrator#migratePublicSchema) — same path as V1 and V2.
--
-- Collision note: db/tenant/V3__Wallet_config_audit.sql is a DIFFERENT Flyway
-- migration location (db/tenant/, separate flyway_schema_history). The two V3
-- files coexist without collision (R-3 in EUDISTACK-413 tech-design §3.7).
--
-- Pre-deployment pre-check (document in runbook):
--   SELECT count(*) FROM public.tenant_wallet_config
--   WHERE wallet_mode='server' AND key_manager IS NULL;
-- Expected: 0. If > 0, correct the data before deploying this migration.
--
-- Reversible:
--   ALTER TABLE public.tenant_wallet_config DROP CONSTRAINT IF EXISTS chk_twc_server_requires_key_manager;
-- =============================================================================

ALTER TABLE public.tenant_wallet_config
    ADD CONSTRAINT chk_twc_server_requires_key_manager
        CHECK (NOT (wallet_mode = 'server' AND key_manager IS NULL));
