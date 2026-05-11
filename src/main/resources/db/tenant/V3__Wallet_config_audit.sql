-- =============================================================================
-- V3__Wallet_config_audit.sql
-- EUDISTACK-412: per-tenant append-only audit trail for wallet configuration
-- changes. Lands in each `<tenant>_business_wallet` schema (created by the EBW
-- Flyway migrator — TenantSchemaFlywayMigrator#migrateTenantSchema).
--
-- Written by TenantConfigAuditR2dbcAdapter (INSERT only). Column set mirrors the
-- INSERT in that adapter exactly. The adapter casts :event::text, :plane::text,
-- :outcome::text — VARCHAR columns accept those casts; no enum types needed.
--
-- Append-only: a BEFORE UPDATE OR DELETE trigger raises an exception so the
-- table can only ever grow (feature-design §3.1 — "trigger append-only que
-- bloquea UPDATE/DELETE"). Retention (≥ 12 months, NFR-04) is handled at the
-- RDS/operational level, not here.
--
-- Idempotent (CREATE TABLE IF NOT EXISTS / CREATE OR REPLACE FUNCTION /
-- DROP TRIGGER IF EXISTS) — mirrors the db/tenant V2 style.
-- =============================================================================

CREATE TABLE IF NOT EXISTS wallet_config_audit (
    id             UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    actor          VARCHAR(255)  NOT NULL,
    event          VARCHAR(50)   NOT NULL,
    plane          VARCHAR(50)   NOT NULL,
    field_changes  JSONB         NOT NULL DEFAULT '{}'::jsonb,
    outcome        VARCHAR(20)   NOT NULL,
    reason         VARCHAR(1000),
    correlation_id VARCHAR(255),
    occurred_at    TIMESTAMPTZ   NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_wallet_config_audit_occurred_at
    ON wallet_config_audit (occurred_at);

-- Append-only enforcement: reject any UPDATE or DELETE on this table.
CREATE OR REPLACE FUNCTION wallet_config_audit_append_only()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'wallet_config_audit is append-only; % not allowed', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_wallet_config_audit_append_only ON wallet_config_audit;

CREATE TRIGGER trg_wallet_config_audit_append_only
    BEFORE UPDATE OR DELETE ON wallet_config_audit
    FOR EACH ROW EXECUTE FUNCTION wallet_config_audit_append_only();
