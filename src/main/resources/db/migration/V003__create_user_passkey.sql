CREATE TABLE user_passkey (
    id            UUID PRIMARY KEY,
    user_id       UUID          NOT NULL REFERENCES wallet_user(id),
    credential_id VARCHAR(1024) NOT NULL,
    display_name  VARCHAR(100)  NOT NULL,
    user_agent    VARCHAR(512),
    created_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    last_used_at  TIMESTAMPTZ,

    UNIQUE (user_id, credential_id)
);

CREATE INDEX idx_passkey_user_id ON user_passkey (user_id);
