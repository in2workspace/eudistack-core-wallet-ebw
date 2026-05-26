-- =============================================================================
-- V4__Holder_key.sql
-- Per-tenant holder key table: stores the AES-256-GCM encrypted private key
-- for each holder credential pair managed by the EBW key-manager module.
--
-- Architecture ref: docs/EUDISTACK-5-ebw-key-management/specs/architecture.md §6.2
-- Story: EUDISTACK-116
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Table: holder_key
--
-- One row per (holder_id, credential_id) pair. The encrypted_private_key column
-- holds a raw AES-256-GCM blob: nonce (12 bytes) || ciphertext || tag (16 bytes).
-- The tenant_id column is stored to serve as AAD during decryption — the cipher
-- adapter verifies that the tenantId matches what was used at encryption time,
-- providing cryptographic binding equivalent to KMS EncryptionContext.
--
-- The UNIQUE constraint on (holder_id, credential_id) enforces the one-key-per-
-- credential invariant (ADR-021): a holder may have N credentials, each with its
-- own key pair.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS holder_key (
    key_id                VARCHAR(36)  NOT NULL,
    holder_id             VARCHAR(255) NOT NULL,
    credential_id         VARCHAR(255) NOT NULL,
    tenant_id             VARCHAR(255) NOT NULL,
    encrypted_private_key BYTEA        NOT NULL,
    public_jwk            JSONB        NOT NULL,
    algorithm             VARCHAR(20)  NOT NULL,
    format                VARCHAR(30)  NOT NULL,
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    revoked_at            TIMESTAMPTZ,

    CONSTRAINT pk_holder_key
        PRIMARY KEY (key_id),

    CONSTRAINT uq_holder_key_holder_credential
        UNIQUE (holder_id, credential_id),

    CONSTRAINT chk_holder_key_encrypted_nonempty
        CHECK (octet_length(encrypted_private_key) > 0),

    CONSTRAINT chk_holder_key_algorithm
        CHECK (algorithm IN ('ES256', 'ES384', 'ES512')),

    CONSTRAINT chk_holder_key_format
        CHECK (format IN ('dc+sd-jwt', 'jwt_vc_json'))
);

-- Lookup by holder (list all keys for a holder)
CREATE INDEX IF NOT EXISTS idx_holder_key_holder_id
    ON holder_key (holder_id);

-- Active-keys lookup (skips revoked rows)
CREATE INDEX IF NOT EXISTS idx_holder_key_active
    ON holder_key (holder_id, credential_id)
    WHERE revoked_at IS NULL;

-- -----------------------------------------------------------------------------
-- ACL: Revoke default public access, then grant least-privilege per role matrix.
--
-- ebw_app_role : SELECT + INSERT only — the EBW runtime reads and writes holder
--               keys. UPDATE and DELETE are intentionally omitted: revocation sets
--               revoked_at via INSERT of a new row (append-only) in a future US.
-- -----------------------------------------------------------------------------
REVOKE ALL ON holder_key FROM PUBLIC;

DO $$
BEGIN
    GRANT SELECT, INSERT ON holder_key TO ebw_app_role;
EXCEPTION
    WHEN undefined_object THEN
        NULL;
END
$$;