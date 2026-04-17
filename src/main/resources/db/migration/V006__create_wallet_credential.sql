CREATE TABLE wallet_credential (
    id                      UUID PRIMARY KEY,
    user_id                 UUID NOT NULL REFERENCES wallet_user(id),
    credential_raw          TEXT NOT NULL,
    format                  VARCHAR(50) NOT NULL,
    credential_config_id    VARCHAR(255) NOT NULL,
    kid                     VARCHAR(512) NOT NULL,
    credential_type         VARCHAR(255) NOT NULL,
    vct                     VARCHAR(255),
    issuer                  VARCHAR(1024) NOT NULL,
    subject                 VARCHAR(1024),
    issuance_date           TIMESTAMPTZ NOT NULL,
    expiration_date         TIMESTAMPTZ,
    status                  VARCHAR(20) NOT NULL DEFAULT 'VALID',
    issuer_metadata         TEXT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_credential_user_id ON wallet_credential(user_id);
CREATE INDEX idx_credential_user_status ON wallet_credential(user_id, status);
CREATE INDEX idx_credential_user_config ON wallet_credential(user_id, credential_config_id);
