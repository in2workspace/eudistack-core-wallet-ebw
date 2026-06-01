-- =============================================================================
-- V2__add_holder_key_id_to_wallet_credential.sql
-- Adds holder_key_id (nullable) to wallet_credential.
-- Links a stored credential to the server-side key used to sign the proof.
-- EUDISTACK-502 — server key-storage provider (US-02)
-- =============================================================================

ALTER TABLE wallet_credential
    ADD COLUMN IF NOT EXISTS holder_key_id VARCHAR(36);
