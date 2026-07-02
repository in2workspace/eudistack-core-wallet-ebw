-- =============================================================================
-- V3__create_hybrid_prf_salt.sql
-- Stores the per-credential PRF salt used to derive the hybrid key-wrapping key.
-- Salt is 32-byte random value written once at issuance and never updated.
-- PK (holder_id, credential_id) enforces uniqueness invariant AD-3.
-- EUDISTACK-537 — hybrid PRF salt storage (NFR-S-537-04)
-- =============================================================================

CREATE TABLE hybrid_prf_salt (
    holder_id     UUID         NOT NULL REFERENCES wallet_user(id) ON DELETE RESTRICT,
    credential_id VARCHAR(255) NOT NULL,
    prf_salt      BYTEA        NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT pk_hybrid_prf_salt
        PRIMARY KEY (holder_id, credential_id),

    CONSTRAINT chk_hybrid_prf_salt_length
        CHECK (octet_length(prf_salt) = 32)
);

REVOKE ALL ON hybrid_prf_salt FROM PUBLIC;

DO $$
BEGIN
    GRANT SELECT, INSERT ON hybrid_prf_salt TO ebw_app_role;
EXCEPTION
    WHEN undefined_object THEN NULL;
END
$$;
