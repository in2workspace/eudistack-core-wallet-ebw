-- =============================================================================
-- V6__create_wallet_activity.sql
-- Server-side copy of the Holder's wallet activity history (issued / presented /
-- deleted credential events), kept as source of truth for cross-device recovery
-- and sync (EUD-141). Row `id` is client-generated (crypto.randomUUID() in the
-- PWA's ActivityService) so sync writes can be idempotent (INSERT ... ON CONFLICT
-- DO NOTHING keyed by id) when a device retries/replays the same event.
-- EUD-14 — Actividad del Wallet (modo server, FR-14/FR-15/FR-16)
-- =============================================================================

CREATE TABLE wallet_activity (
    id                 UUID          PRIMARY KEY,
    user_id            UUID          NOT NULL REFERENCES wallet_user(id),
    type               VARCHAR(20)   NOT NULL,
    credential_name    VARCHAR(255)  NOT NULL,
    counterparty       VARCHAR(1024) NOT NULL,
    details            TEXT,
    shared_attributes  JSONB,
    created_at         TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_wallet_activity_type
        CHECK (type IN ('ISSUED', 'PRESENTED', 'DELETED'))
);

CREATE INDEX idx_activity_user_recent
    ON wallet_activity (user_id, created_at DESC);

REVOKE ALL ON wallet_activity FROM PUBLIC;

DO $$
BEGIN
    GRANT SELECT, INSERT ON wallet_activity TO ebw_app_role;
EXCEPTION
    WHEN undefined_object THEN NULL;
END
$$;
