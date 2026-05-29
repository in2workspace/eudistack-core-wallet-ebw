-- =============================================================================
-- V1__Schema.sql
-- Per-tenant EBW schema — full consolidated baseline.
-- Combines: EBW_schema (auth/credentials), tenant_config, tenant_wallet_profile,
--           holder_key (EUDISTACK-119 key-manager module).
-- Applied by TenantSchemaFlywayMigrator on startup for each active tenant.
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

-- =============================================================================
-- tenant_config: per-tenant key-value configuration
-- =============================================================================
CREATE TABLE IF NOT EXISTS tenant_config (
    id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    config_key   VARCHAR(255) NOT NULL UNIQUE,
    config_value TEXT         NOT NULL,
    description  VARCHAR(500),
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);

INSERT INTO tenant_config (config_key, config_value, description) VALUES
    ('ebw.mail_from',                  'noreply@eudistack.com',    'Sender address used for transactional emails (OTP, registration)'),
    ('ebw.allowed_credential_formats', 'dc+sd-jwt,jwt_vc_json',   'Comma-separated list of accepted credential formats, or * for all')
ON CONFLICT (config_key) DO NOTHING;

-- =============================================================================
-- tenant_wallet_profile: wallet mode + key-manager config per tenant
-- (EUDISTACK-412 — drives wallet discovery and key-manager routing)
-- =============================================================================
CREATE TABLE IF NOT EXISTS tenant_wallet_profile (
    tenant       VARCHAR(255) NOT NULL,
    wallet_mode  VARCHAR(20)  NOT NULL,
    key_manager  VARCHAR(20),
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT pk_tenant_wallet_profile
        PRIMARY KEY (tenant),

    CONSTRAINT chk_wallet_profile_mode_manager CHECK (
        (wallet_mode = 'browser' AND key_manager IS NULL)
        OR
        (wallet_mode = 'server' AND key_manager IS NOT NULL
            AND key_manager IN ('db', 'hybrid', 'hsm', 'qtsp'))
    )
);

REVOKE ALL ON tenant_wallet_profile FROM PUBLIC;

DO $$
BEGIN
    GRANT SELECT ON tenant_wallet_profile TO ebw_app_role;
EXCEPTION
    WHEN undefined_object THEN NULL;
END
$$;

DO $$
BEGIN
    GRANT SELECT, INSERT, UPDATE ON tenant_wallet_profile TO config_manager_role;
EXCEPTION
    WHEN undefined_object THEN NULL;
END
$$;

-- =============================================================================
-- holder_key: one key pair per (tenant_id, holder_id, credential_id)
-- Private key stored as raw BYTEA; at-rest protection by RDS TDE (ADR-099).
-- EUDISTACK-119 — key-manager module (US-02)
-- =============================================================================
CREATE TABLE IF NOT EXISTS holder_key (
    key_id         VARCHAR(36)  NOT NULL,
    holder_id      VARCHAR(255) NOT NULL,
    credential_id  VARCHAR(255) NOT NULL,
    tenant_id      VARCHAR(255) NOT NULL,
    private_key    BYTEA        NOT NULL,
    public_jwk     JSONB        NOT NULL,
    algorithm      VARCHAR(20)  NOT NULL,
    format         VARCHAR(30)  NOT NULL,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    revoked_at     TIMESTAMPTZ,

    CONSTRAINT pk_holder_key
        PRIMARY KEY (key_id),

    CONSTRAINT uq_holder_key_tenant_holder_credential
        UNIQUE (tenant_id, holder_id, credential_id),

    CONSTRAINT chk_holder_key_private_key_nonempty
        CHECK (octet_length(private_key) > 0),

    CONSTRAINT chk_holder_key_algorithm
        CHECK (algorithm IN ('ES256', 'ES384', 'EdDSA')),

    CONSTRAINT chk_holder_key_format
        CHECK (format IN ('dc+sd-jwt', 'jwt_vc_json'))
);

CREATE INDEX IF NOT EXISTS idx_holder_key_holder_id
    ON holder_key (holder_id);

CREATE INDEX IF NOT EXISTS idx_holder_key_active
    ON holder_key (holder_id, credential_id)
    WHERE revoked_at IS NULL;

REVOKE ALL ON holder_key FROM PUBLIC;

DO $$
BEGIN
    GRANT SELECT, INSERT ON holder_key TO ebw_app_role;
EXCEPTION
    WHEN undefined_object THEN NULL;
END
$$;
