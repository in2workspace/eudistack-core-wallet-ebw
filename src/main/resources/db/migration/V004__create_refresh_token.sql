CREATE TABLE refresh_token (
    id         UUID PRIMARY KEY,
    user_id    UUID         NOT NULL REFERENCES wallet_user(id),
    passkey_id UUID         REFERENCES user_passkey(id) ON DELETE SET NULL,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ  NOT NULL,
    revoked    BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_refresh_token_hash ON refresh_token (token_hash);
