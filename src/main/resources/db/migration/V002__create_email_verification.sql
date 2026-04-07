CREATE TABLE ebw.email_verification (
    id         UUID PRIMARY KEY,
    user_email VARCHAR(254) NOT NULL,
    code_hash  VARCHAR(255) NOT NULL,
    attempts   INT          NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ  NOT NULL,
    used       BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_verification_email_active
    ON ebw.email_verification (user_email, used, expires_at);
