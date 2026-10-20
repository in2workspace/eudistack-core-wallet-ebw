-- =============================================================================
-- V9__credential_passkey_binding.sql
-- Attestations of the session's passkey (EUD-308, feature EUD-11 FR-13/FR-14):
--   - passkey_id: passkey of the session that obtained a bound attestation.
--     ON DELETE SET NULL: when a passkey is deleted from the account, its
--     attestations stay stored but are no longer listed in passkey custody
--     tenants (a bound attestation without passkey is hidden).
--   - bound: whether the attestation is cryptographically bound to the holder
--     (has cnf). Existing rows: bound when they have a holder key. The service always
--     sets it; the default (false) is only a safety net for rows written by scripts that
--     do not list the column, such as the DOME migration (dev-tools/scripts/dome-migration).
--     It has no effect outside passkey custody, the only mode that filters by it.
-- =============================================================================

ALTER TABLE wallet_credential
    ADD COLUMN passkey_id UUID REFERENCES user_passkey (id) ON DELETE SET NULL,
    ADD COLUMN bound      BOOLEAN;

UPDATE wallet_credential SET bound = (holder_key_id IS NOT NULL);

ALTER TABLE wallet_credential ALTER COLUMN bound SET NOT NULL;
ALTER TABLE wallet_credential ALTER COLUMN bound SET DEFAULT FALSE;

CREATE INDEX idx_credential_user_passkey ON wallet_credential (user_id, passkey_id);
