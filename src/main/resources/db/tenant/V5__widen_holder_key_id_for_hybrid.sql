-- =============================================================================
-- V5__widen_holder_key_id_for_hybrid.sql
-- Widens wallet_credential.holder_key_id from VARCHAR(36) to VARCHAR(512).
--
-- holder_key_id is the SPI-generic "key reference" for a wallet_credential row.
-- In db mode it holds a UUID (holder_key.key_id, 36 chars). In hybrid mode there
-- is no server-side holder_key row — the wrapped key material lives in
-- hybrid_wrapped_key_handle, keyed by (holder_id, credential_id). The Wallet PWA
-- stores the real credential_id string here instead (format:
-- "<credentialIssuer>:<credentialConfigurationId>") so buildPresentationJws can
-- resolve keyId -> credentialId round-trip via GET /api/v1/credentials without
-- a separate lookup table. 512 matches the credential_id length constraint
-- already enforced by PrepareSignRequest (@Size(max = 512)).
--
-- No FK/UNIQUE constraint on this column (see V2) — widening is backward
-- compatible; existing UUID values (<=36 chars) remain valid unchanged.
--
-- EUDISTACK-536 — US-04 signing_input design correction (2026-07-03)
-- =============================================================================

ALTER TABLE wallet_credential
    ALTER COLUMN holder_key_id TYPE VARCHAR(512);
