-- =============================================================================
-- V12__wallet_instance.sql
-- Wallet Instances (EUD-334, feature EUD-15 design §5) and the email changes of
-- the registration and access to the wallet (feature EUD-8 design §2.8, §5):
--   - wallet_instance: one row per Wallet App and account, without keys. Revoked
--     rows are kept for the trace and to answer instance_revoked; deleted with
--     the account.
--   - refresh_token.wallet_instance_id: the instance the session (token family)
--     is bound to. Copied on every rotation of the family.
--   - refresh_token.passkey_notice_pending: a passkey was added to an account that
--     already had one; the email goes when the session binds or registers an
--     instance, or when the session ends (AD-11). Copied on every rotation.
--   - wallet_user.locale: language of the holder's emails (AD-10).
--
-- The design names this migration V11; V11 was taken by the onboarding ticket
-- (EUD-315), so it is V12.
-- =============================================================================

CREATE TABLE wallet_instance (
    id                     UUID         PRIMARY KEY,
    user_id                UUID         NOT NULL REFERENCES wallet_user (id) ON DELETE CASCADE,
    display_name           VARCHAR(50)  NOT NULL,
    device_type            VARCHAR(16)  NOT NULL,
    status                 VARCHAR(16)  NOT NULL,
    created_at             TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_used_at           TIMESTAMPTZ,
    revoked_at             TIMESTAMPTZ,
    revoked_by             VARCHAR(16),
    -- Passkey of the session that registered it. No foreign key: the passkey may be
    -- deleted and the value stays for "it was not me" and for the trace.
    registered_passkey_id  UUID         NOT NULL,

    CONSTRAINT chk_wallet_instance_device_type CHECK (device_type IN ('MOBILE', 'TABLET', 'DESKTOP')),
    CONSTRAINT chk_wallet_instance_status CHECK (status IN ('ACTIVE', 'REVOKED')),
    CONSTRAINT chk_wallet_instance_revoked_by CHECK (revoked_by IS NULL OR revoked_by IN ('HOLDER', 'INACTIVITY', 'DISAVOWAL')),
    CONSTRAINT chk_wallet_instance_revocation CHECK ((status = 'ACTIVE' AND revoked_at IS NULL AND revoked_by IS NULL)
        OR (status = 'REVOKED' AND revoked_at IS NOT NULL AND revoked_by IS NOT NULL))
);

CREATE INDEX idx_wallet_instance_user ON wallet_instance (user_id, status);
CREATE INDEX idx_wallet_instance_registered_passkey ON wallet_instance (registered_passkey_id);
CREATE INDEX idx_wallet_instance_inactive ON wallet_instance (coalesce(last_used_at, created_at)) WHERE status = 'ACTIVE';

ALTER TABLE refresh_token ADD COLUMN wallet_instance_id UUID REFERENCES wallet_instance (id);
ALTER TABLE refresh_token ADD COLUMN passkey_notice_pending BOOLEAN NOT NULL DEFAULT false;
CREATE INDEX idx_refresh_token_wallet_instance ON refresh_token (wallet_instance_id);
CREATE INDEX idx_refresh_token_passkey_notice_pending ON refresh_token (session_id) WHERE passkey_notice_pending;

ALTER TABLE wallet_user ADD COLUMN locale VARCHAR(8);
ALTER TABLE wallet_user
    ADD CONSTRAINT chk_wallet_user_locale CHECK (locale IS NULL OR locale IN ('es', 'ca', 'en'));

REVOKE ALL ON wallet_instance FROM PUBLIC;

DO $$
BEGIN
    GRANT SELECT, INSERT, UPDATE, DELETE ON wallet_instance TO ebw_app_role;
EXCEPTION
    WHEN undefined_object THEN NULL;
END
$$;
