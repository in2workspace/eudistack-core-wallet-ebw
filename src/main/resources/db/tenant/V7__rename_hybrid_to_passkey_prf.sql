-- =============================================================================
-- V7__rename_hybrid_to_passkey_prf.sql
-- Renames the "hybrid" key manager to "passkey-prf" (holder key wrapped with the
-- passkey's PRF output).
--   - tenant_wallet_profile.key_manager: 'hybrid' -> 'passkey-prf'
--   - hybrid_prf_salt            -> passkey_prf_salt
--   - hybrid_wrapped_key_handle  -> passkey_prf_wrapped_key_handle
-- Table renames keep their GRANTs, constraints and FKs; only the object names
-- that contain "hybrid" are renamed explicitly.
-- The HKDF info label "hybrid-wrap-v1" is NOT touched: it is a frozen value
-- already used to derive the wrap keys of existing rows.
-- EUD-309
-- =============================================================================

ALTER TABLE tenant_wallet_profile
    DROP CONSTRAINT chk_wallet_profile_mode_manager;

UPDATE tenant_wallet_profile
   SET key_manager = 'passkey-prf'
 WHERE key_manager = 'hybrid';

ALTER TABLE tenant_wallet_profile
    ADD CONSTRAINT chk_wallet_profile_mode_manager CHECK (
        (wallet_mode = 'browser' AND key_manager IS NULL)
        OR
        (wallet_mode = 'server' AND key_manager IS NOT NULL
            AND key_manager IN ('db', 'passkey-prf', 'hsm', 'qtsp'))
    );

ALTER TABLE hybrid_prf_salt RENAME TO passkey_prf_salt;
ALTER TABLE passkey_prf_salt RENAME CONSTRAINT pk_hybrid_prf_salt TO pk_passkey_prf_salt;
ALTER TABLE passkey_prf_salt RENAME CONSTRAINT chk_hybrid_prf_salt_length TO chk_passkey_prf_salt_length;

ALTER TABLE hybrid_wrapped_key_handle RENAME TO passkey_prf_wrapped_key_handle;
ALTER TABLE passkey_prf_wrapped_key_handle
    RENAME CONSTRAINT pk_hybrid_wrapped_key_handle TO pk_passkey_prf_wrapped_key_handle;
