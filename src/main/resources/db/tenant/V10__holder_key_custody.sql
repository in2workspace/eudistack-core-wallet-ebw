-- =============================================================================
-- V10__holder_key_custody.sql
-- Holder key custody (EUD-11 design 1.1.0, EUD-326):
--   - passkey custody derives the key on the device on every signature; the service only
--     keeps the passkey, the salt and the public key (passkey_prf_salt). The encrypted-key
--     model is removed (AD-5): its attestations, their salts and the
--     passkey_prf_wrapped_key_handle table are deleted.
--   - wallet_credential.custody_mode records the mode an attestation was obtained with.
--   - deleting an attestation deletes its key material, so holder_key and passkey_prf_salt
--     gain DELETE.
--   - hsm and qtsp leave the key_manager values (AD-6).
-- =============================================================================

-- 1. Attestations obtained with the encrypted key, their salts and the table (AD-5).
DELETE FROM wallet_credential c
 USING passkey_prf_wrapped_key_handle h
 WHERE h.holder_id = c.user_id
   AND h.credential_id = c.holder_key_id;

CREATE TEMPORARY TABLE encrypted_key_salt ON COMMIT DROP AS
    SELECT holder_id, credential_id FROM passkey_prf_wrapped_key_handle;

DROP TABLE passkey_prf_wrapped_key_handle;

DELETE FROM passkey_prf_salt s
 USING encrypted_key_salt d
 WHERE s.holder_id = d.holder_id
   AND s.credential_id = d.credential_id;

-- 2. Salt, public key and passkey of an attestation obtained with passkey custody.
ALTER TABLE passkey_prf_salt
    ADD COLUMN passkey_id UUID REFERENCES user_passkey (id) ON DELETE SET NULL,
    ADD COLUMN public_jwk JSONB,
    ADD COLUMN algorithm  VARCHAR(20) NOT NULL DEFAULT 'ES256',
    ADD CONSTRAINT chk_passkey_prf_salt_algorithm CHECK (algorithm = 'ES256');

DO $$
BEGIN
    GRANT DELETE ON passkey_prf_salt TO ebw_app_role;
    GRANT UPDATE (public_jwk) ON passkey_prf_salt TO ebw_app_role;
    GRANT DELETE ON holder_key TO ebw_app_role;
EXCEPTION
    WHEN undefined_object THEN NULL;
END
$$;

-- 3. Custody mode of the stored attestations; null when the attestation is not bound.
ALTER TABLE wallet_credential
    ADD COLUMN custody_mode VARCHAR(16),
    ADD CONSTRAINT chk_wallet_credential_custody_mode CHECK (custody_mode IN ('server', 'passkey'));

UPDATE wallet_credential
   SET custody_mode = 'server'
 WHERE bound
   AND EXISTS (SELECT 1 FROM tenant_wallet_profile WHERE key_manager = 'db');

-- Bound attestations of a passkey custody tenant that had no encrypted key: they keep the mode
-- but have no public key, so no session receives their salt.
UPDATE wallet_credential
   SET custody_mode = 'passkey'
 WHERE bound
   AND custody_mode IS NULL
   AND EXISTS (SELECT 1 FROM tenant_wallet_profile WHERE key_manager = 'passkey-prf');

-- 4. hsm and qtsp are implementations of the Key Service, not custody modes (AD-6).
ALTER TABLE tenant_wallet_profile
    DROP CONSTRAINT chk_wallet_profile_mode_manager;

ALTER TABLE tenant_wallet_profile
    ADD CONSTRAINT chk_wallet_profile_mode_manager CHECK (
        (wallet_mode = 'browser' AND key_manager IS NULL)
        OR
        (wallet_mode = 'server' AND key_manager IS NOT NULL
            AND key_manager IN ('db', 'passkey-prf'))
    );
