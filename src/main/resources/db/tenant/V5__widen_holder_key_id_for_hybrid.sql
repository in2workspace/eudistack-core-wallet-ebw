-- EUDISTACK-536: widen wallet_credential.holder_key_id to store hybrid credential_id values.
ALTER TABLE wallet_credential
    ALTER COLUMN holder_key_id TYPE VARCHAR(512);
