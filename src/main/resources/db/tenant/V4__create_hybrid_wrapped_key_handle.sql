-- =============================================================================
-- V4__create_hybrid_wrapped_key_handle.sql
-- Hybrid key handle table — stores the AES-256-GCM-wrapped holder private key
-- per (holder_id, credential_id) composite key.
--
-- No-custody invariant (ADR-014, ADR-099):
--   - The table has NO column for the holder private key in clear or the wrap key.
--   - wrapped_blob contains AES-256-GCM ciphertext; the wrap key lives only in
--     the holder's authenticator (Passkey PRF output) and never reaches the server.
--   - CHECK constraints enforce blob coherence (GCM tag 16B + key >= 32B -> >= 48B)
--     and IV width (12 bytes), providing a physical floor against malformed blobs.
--   - cnf_jwk stores the holder's public confirmation JWK (TEXT, not a key secret).
--
-- ACL (AD-1, NFR-05):
--   - GRANT SELECT, INSERT ON hybrid_wrapped_key_handle TO ebw_app_role
--   - GRANT UPDATE (last_used_at) ON hybrid_wrapped_key_handle TO ebw_app_role
--   - No GRANT UPDATE (table-level), no GRANT DELETE.
--     last_used_at is the sole mutable column; all crypto columns are immutable
--     by absence of privilege.
--
-- Spec gap note (EUDISTACK-535 / US-03):
--   - technical-design.md §3.2.1 does not list cnf_jwk in its DDL reference.
--     US-02 (EUDISTACK-534) added cnf_jwk to WrappedKeyHandleRow and the R2DBC
--     adapter before US-03 merged. This column is included here to match the
--     application layer already shipped in main. The spec should be updated to
--     reflect this addition (tracked in handoff, no separate ticket opened per
--     team convention).
--
-- Dependencies (ordered before this migration):
--   - wallet_user (V1__Schema.sql, EUDISTACK-36): FK holder_id -> wallet_user(id)
--   - hybrid_prf_salt (V3__create_hybrid_prf_salt.sql, EUDISTACK-537/US-05):
--       composite FK (holder_id, credential_id) -> hybrid_prf_salt
--
-- EUDISTACK-535 — US-03 Persistencia del wrapped key handle con invariantes de no-custodia
-- =============================================================================

CREATE TABLE hybrid_wrapped_key_handle (
    holder_id     UUID         NOT NULL,
    credential_id VARCHAR(255) NOT NULL,
    wrapped_blob  BYTEA        NOT NULL,
    iv            BYTEA        NOT NULL,
    tag           BYTEA        NOT NULL,
    kdf_algo      VARCHAR(32)  NOT NULL,
    kdf_version   INT          NOT NULL,
    cnf_jwk       TEXT         NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ,

    CONSTRAINT pk_hybrid_wrapped_key_handle
        PRIMARY KEY (holder_id, credential_id),

    CONSTRAINT fk_hwkh_wallet_user
        FOREIGN KEY (holder_id)
        REFERENCES wallet_user (id) ON DELETE RESTRICT,

    CONSTRAINT fk_hwkh_prf_salt
        FOREIGN KEY (holder_id, credential_id)
        REFERENCES hybrid_prf_salt (holder_id, credential_id),

    -- Physical no-custody barriers (defensa en profundidad, see ADR-014):
    --   wrapped_blob >= 48 bytes: AES-256-GCM tag (16B) + wrapped key (>=32B)
    --   iv = 12 bytes: AES-GCM nonce canonical width
    --   tag = 16 bytes: AES-GCM authentication tag
    CONSTRAINT chk_hwkh_blob_min_len CHECK (octet_length(wrapped_blob) >= 48),
    CONSTRAINT chk_hwkh_iv_len       CHECK (octet_length(iv) = 12),
    CONSTRAINT chk_hwkh_tag_len      CHECK (octet_length(tag) = 16)
);

REVOKE ALL ON hybrid_wrapped_key_handle FROM PUBLIC;

-- =============================================================================
-- ACL: immutability except last_used_at; no DELETE (AD-1)
-- Wrapped in DO/EXCEPTION to tolerate role absence in environments where
-- ebw_app_role is created separately (mirrors V1__Schema.sql pattern).
-- =============================================================================

DO $$
BEGIN
    GRANT SELECT, INSERT ON hybrid_wrapped_key_handle TO ebw_app_role;
EXCEPTION
    WHEN undefined_object THEN NULL;
END
$$;

DO $$
BEGIN
    GRANT UPDATE (last_used_at) ON hybrid_wrapped_key_handle TO ebw_app_role;
EXCEPTION
    WHEN undefined_object THEN NULL;
END
$$;
