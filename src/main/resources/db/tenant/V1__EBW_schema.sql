-- =============================================================================
-- V1__EBW_schema.sql
-- Per-tenant EBW schema: all wallet tables.
-- Consolidated from V001-V006 (legacy db/migration single-schema approach).
-- EUDI-040/041/042/044: wallet_user, passkeys, credentials, auth.
-- =============================================================================

-- =============================================================================
-- wallet_user: registered wallet users
-- =============================================================================
CREATE TABLE wallet_user (
    id         UUID PRIMARY KEY,
    email      VARCHAR(254) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- email_verification: OTP codes for registration / re-verification
-- =============================================================================
CREATE TABLE email_verification (
    id         UUID PRIMARY KEY,
    user_email VARCHAR(254) NOT NULL,
    code_hash  VARCHAR(255) NOT NULL,
    attempts   INT          NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ  NOT NULL,
    used       BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_verification_email_active
    ON email_verification (user_email, used, expires_at);

-- =============================================================================
-- user_passkey: WebAuthn passkeys registered per user
-- =============================================================================
CREATE TABLE user_passkey (
    id            UUID          PRIMARY KEY,
    user_id       UUID          NOT NULL REFERENCES wallet_user(id),
    credential_id VARCHAR(1024) NOT NULL,
    display_name  VARCHAR(100)  NOT NULL,
    user_agent    VARCHAR(512),
    created_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    last_used_at  TIMESTAMPTZ,

    UNIQUE (user_id, credential_id)
);

CREATE INDEX idx_passkey_user_id ON user_passkey (user_id);

-- =============================================================================
-- refresh_token: long-lived tokens for session renewal
-- =============================================================================
CREATE TABLE refresh_token (
    id         UUID         PRIMARY KEY,
    user_id    UUID         NOT NULL REFERENCES wallet_user(id),
    passkey_id UUID         REFERENCES user_passkey(id) ON DELETE SET NULL,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ  NOT NULL,
    revoked    BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_refresh_token_hash ON refresh_token (token_hash);

-- =============================================================================
-- audit_log: immutable record of security-relevant events
-- =============================================================================
CREATE TABLE audit_log (
    id          UUID        PRIMARY KEY,
    entity_type VARCHAR(50) NOT NULL,
    entity_id   UUID        NOT NULL,
    action      VARCHAR(50) NOT NULL,
    actor_id    UUID,
    metadata    TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_entity ON audit_log (entity_type, entity_id);

-- =============================================================================
-- wallet_credential: verifiable credentials stored per user
-- =============================================================================
CREATE TABLE wallet_credential (
    id                   UUID          PRIMARY KEY,
    user_id              UUID          NOT NULL REFERENCES wallet_user(id),
    credential_raw       TEXT          NOT NULL,
    format               VARCHAR(50)   NOT NULL,
    credential_config_id VARCHAR(255)  NOT NULL,
    kid                  VARCHAR(512)  NOT NULL,
    credential_type      VARCHAR(255)  NOT NULL,
    vct                  VARCHAR(255),
    issuer               VARCHAR(1024) NOT NULL,
    subject              VARCHAR(1024),
    issuance_date        TIMESTAMPTZ   NOT NULL,
    expiration_date      TIMESTAMPTZ,
    status               VARCHAR(20)   NOT NULL DEFAULT 'VALID',
    issuer_metadata      JSONB,
    created_at           TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_credential_user_id     ON wallet_credential (user_id);
CREATE INDEX idx_credential_user_status ON wallet_credential (user_id, status);
CREATE INDEX idx_credential_user_config ON wallet_credential (user_id, credential_config_id);
