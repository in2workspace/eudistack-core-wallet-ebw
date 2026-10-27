-- =============================================================================
-- V10__onboarding_ticket.sql
-- Onboarding ticket and onboarding mode (EUD-315, feature EUD-8 design §2.6, §5):
--   - onboarding_preregistration: email and credential offer sent by an authorized
--     system, until the first passkey is registered or the ticket expires. Only the
--     SHA-256 of the ticket is stored. Physically deleted when the account is created,
--     when the redemption finds an account with passkeys, or by the hourly cleanup.
--   - onboarding_disavowal: single-use "it was not me" token of the new-account email,
--     7 days. Only its SHA-256 is stored.
--   - registration_ticket: may belong to a pre-registration instead of an account
--     (the account is created when the passkey is registered).
--   - user_passkey.onboarding_preregistration_id: passkey registered with an
--     onboarding ticket. No foreign key: the pre-registration is deleted, the value
--     stays for the audit trail and to find the accounts created with a ticket.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- onboarding_preregistration
-- webauthn_user_handle: PROVISIONAL (EUD-315 decision P2, pending Tech Lead; design §5
-- does not cover it). Generated when a ticket of an email without account is
-- redeemed, sent as user.id in the registration options and copied to wallet_user
-- when the account is created with the passkey.
-- -----------------------------------------------------------------------------
CREATE TABLE onboarding_preregistration (
    id                   UUID          PRIMARY KEY,
    token_hash           VARCHAR(64)   NOT NULL,
    email                VARCHAR(254)  NOT NULL,
    credential_offer     VARCHAR(2048),
    requested_by         VARCHAR(255)  NOT NULL,
    webauthn_user_handle BYTEA,
    expires_at           TIMESTAMPTZ   NOT NULL,
    redeemed_at          TIMESTAMPTZ,
    created_at           TIMESTAMPTZ   NOT NULL DEFAULT now(),

    CONSTRAINT uq_onboarding_preregistration_token_hash UNIQUE (token_hash),
    CONSTRAINT chk_onboarding_preregistration_user_handle_len
        CHECK (webauthn_user_handle IS NULL OR octet_length(webauthn_user_handle) = 32)
);

CREATE INDEX idx_onboarding_preregistration_expires_at ON onboarding_preregistration (expires_at);

-- -----------------------------------------------------------------------------
-- onboarding_disavowal
-- passkey_id: SET NULL if the holder removes the passkey before using the link.
-- -----------------------------------------------------------------------------
CREATE TABLE onboarding_disavowal (
    id            UUID         PRIMARY KEY,
    token_hash    VARCHAR(64)  NOT NULL,
    user_id       UUID         NOT NULL REFERENCES wallet_user (id) ON DELETE CASCADE,
    passkey_id    UUID         REFERENCES user_passkey (id) ON DELETE SET NULL,
    requested_by  VARCHAR(255) NOT NULL,
    registered_at TIMESTAMPTZ  NOT NULL,
    expires_at    TIMESTAMPTZ  NOT NULL,
    consumed_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT uq_onboarding_disavowal_token_hash UNIQUE (token_hash)
);

CREATE INDEX idx_onboarding_disavowal_expires_at ON onboarding_disavowal (expires_at);

-- -----------------------------------------------------------------------------
-- registration_ticket: an account, a pre-registration, or both (account without
-- passkeys). Deleting the pre-registration deletes its tickets.
-- -----------------------------------------------------------------------------
ALTER TABLE registration_ticket ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE registration_ticket
    ADD COLUMN preregistration_id UUID REFERENCES onboarding_preregistration (id) ON DELETE CASCADE;
ALTER TABLE registration_ticket
    ADD CONSTRAINT chk_registration_ticket_owner CHECK (user_id IS NOT NULL OR preregistration_id IS NOT NULL);

-- -----------------------------------------------------------------------------
-- user_passkey: passkey registered with an onboarding ticket
-- -----------------------------------------------------------------------------
ALTER TABLE user_passkey ADD COLUMN onboarding_preregistration_id UUID;

REVOKE ALL ON onboarding_preregistration FROM PUBLIC;
REVOKE ALL ON onboarding_disavowal FROM PUBLIC;

DO $$
BEGIN
    GRANT SELECT, INSERT, UPDATE, DELETE ON onboarding_preregistration TO ebw_app_role;
    GRANT SELECT, INSERT, UPDATE, DELETE ON onboarding_disavowal TO ebw_app_role;
EXCEPTION
    WHEN undefined_object THEN NULL;
END
$$;
