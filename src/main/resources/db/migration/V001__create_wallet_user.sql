CREATE TABLE wallet_user (
    id         UUID PRIMARY KEY,
    email      VARCHAR(254) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
