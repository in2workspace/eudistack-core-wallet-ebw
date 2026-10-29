package com.eudistack.ebw.integration;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The DOME migration scripts (dev-tools/scripts/dome-migration) insert into {@code wallet_credential}
 * without the columns added by V9. Those rows must still be accepted: {@code bound} defaults to
 * false and {@code passkey_id} stays empty.
 */
class WalletCredentialMigrationIT extends IntegrationTestBase {

    @Test
    void insert_withoutBoundNorPasskey_asTheDomeMigrationDoes_defaultsToUnbound() {
        // Arrange
        var userId = UUID.randomUUID();
        var credentialId = UUID.randomUUID();
        sql("INSERT INTO wallet_user (id, email) VALUES ('" + userId + "', 'dome-migration-" + System.nanoTime()
                + "@example.com')");

        // Act: the column list of build_wallet_credential_insert in generate_migration.py
        sql("INSERT INTO wallet_credential (id, user_id, holder_key_id, credential_raw, format, "
                + "credential_config_id, kid, credential_type, vct, issuer, subject, issuance_date, "
                + "expiration_date, status, issuer_metadata, created_at, updated_at) VALUES ('" + credentialId
                + "', '" + userId + "', NULL, 'raw', 'jwt_vc_json', 'learcredential.employee.w3c.1', 'kid', "
                + "'learcredential.employee.w3c.1', NULL, 'issuer', 'subject', now(), NULL, 'VALID', NULL, "
                + "now(), now())");

        // Assert
        var rows = query("SELECT bound, passkey_id FROM wallet_credential WHERE id = '" + credentialId + "'");
        assertThat(rows).singleElement().satisfies(row -> assertThat(row)
                .containsEntry("bound", false)
                .containsEntry("passkey_id", null));
    }

    @Test
    void insert_asTheDomeMigrationDoes_acceptsAUserWithoutWebAuthnHandle() {
        // Arrange
        var userId = UUID.randomUUID();

        // Act
        sql("INSERT INTO wallet_user (id, email) VALUES ('" + userId + "', 'dome-user-" + System.nanoTime()
                + "@example.com')");

        // Assert: V8 gives every account a random 32-byte user handle even when the writer omits it
        var rows = query("SELECT octet_length(webauthn_user_handle) AS len FROM wallet_user WHERE id = '"
                + userId + "'");
        assertThat(rows).singleElement().satisfies(row -> assertThat(row).containsEntry("len", 32));
    }
}
