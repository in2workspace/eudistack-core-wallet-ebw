package com.eudistack.ebw.keymanager.infrastructure.persistence;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * V10 (EUD-11 design 1.1.0, EUD-326): the attestations obtained with the encrypted key, their salts and the
 * table are removed (AD-5); the remaining attestations get their custody mode; {@code hsm} and {@code qtsp}
 * stop being key managers (AD-6); {@code passkey_prf_salt} gains the passkey and the public key (AD-3).
 *
 * <p>The tenant schema is migrated to V9, filled with the data of the previous model and then migrated to
 * the latest version.
 */
@Tag("integration")
@Testcontainers
class HolderKeyCustodyMigrationIT {

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:17-alpine")
                    .withDatabaseName("custody_migration_it")
                    .withUsername("test")
                    .withPassword("test");

    private String schema;
    private String jdbcUrl;
    private UUID userId;
    private UUID passkeyId;

    @BeforeEach
    void setUp() throws SQLException {
        jdbcUrl = postgres.getJdbcUrl();
        schema = "custody_" + UUID.randomUUID().toString().replace("-", "");
        userId = UUID.randomUUID();
        passkeyId = UUID.randomUUID();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE ebw_app_role; EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE config_manager_role; EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute("CREATE SCHEMA " + schema);
        }
        flyway().target("9").load().migrate();
        sql("INSERT INTO wallet_user (id, email) VALUES ('" + userId + "', 'custody@test.local')");
        sql("INSERT INTO user_passkey (id, user_id, credential_id, display_name, attested_credential_data, "
                + "sign_count, uv_initialized, backup_eligible, backup_state, prf_enabled) VALUES ('" + passkeyId + "', '"
                + userId + "', 'webauthn-1', 'test', decode('00', 'hex'), 0, true, false, false, true)");
    }

    @Test
    void migrate_passkeyTenant_removesAttestationsWithEncryptedKeyAndTheirSalts() throws SQLException {
        // Arrange
        profile("passkey-prf");
        seedEncryptedKeyAttestation("old-key");
        seedBoundAttestation("no-handle-key");
        seedUnboundAttestation();

        // Act
        flyway().load().migrate();

        // Assert
        assertThat(rows("SELECT 1 FROM wallet_credential WHERE holder_key_id = 'old-key'")).isEmpty();
        assertThat(rows("SELECT 1 FROM passkey_prf_salt WHERE credential_id = 'old-key'")).isEmpty();
        assertThat(rows("SELECT 1 FROM wallet_credential")).hasSize(2);
        assertThat(rows("SELECT to_regclass('passkey_prf_wrapped_key_handle') AS t").get(0)[0]).isNull();
    }

    @Test
    void migrate_passkeyTenant_marksTheRemainingBoundAttestationsAsPasskeyAndLeavesUnboundOnesEmpty() throws SQLException {
        // Arrange
        profile("passkey-prf");
        seedBoundAttestation("no-handle-key");
        seedUnboundAttestation();

        // Act
        flyway().load().migrate();

        // Assert
        assertThat(rows("SELECT custody_mode FROM wallet_credential WHERE bound").get(0)[0]).isEqualTo("passkey");
        assertThat(rows("SELECT custody_mode FROM wallet_credential WHERE NOT bound").get(0)[0]).isNull();
    }

    @Test
    void migrate_serverTenant_marksBoundAttestationsAsServer() throws SQLException {
        // Arrange
        profile("db");
        seedBoundAttestation("server-key");
        seedUnboundAttestation();

        // Act
        flyway().load().migrate();

        // Assert
        assertThat(rows("SELECT custody_mode FROM wallet_credential WHERE bound").get(0)[0]).isEqualTo("server");
        assertThat(rows("SELECT custody_mode FROM wallet_credential WHERE NOT bound").get(0)[0]).isNull();
    }

    @Test
    void migrate_hsmKeyManager_isRejectedByTheCheckConstraint() {
        // Arrange
        flyway().load().migrate();

        // Act + Assert
        assertThatThrownBy(() -> sql("INSERT INTO tenant_wallet_profile (tenant, wallet_mode, key_manager) "
                + "VALUES ('t', 'server', 'hsm')"))
                .isInstanceOf(SQLException.class)
                .hasMessageContaining("chk_wallet_profile_mode_manager");
    }

    @Test
    void migrate_saltOfAPasskey_staysWhenThePasskeyIsDeletedButLosesItsPasskey() throws SQLException {
        // Arrange
        flyway().load().migrate();
        sql("INSERT INTO passkey_prf_salt (holder_id, credential_id, passkey_id, prf_salt) VALUES ('" + userId
                + "', 'cred-1', '" + passkeyId + "', decode(repeat('00', 32), 'hex'))");

        // Act
        sql("DELETE FROM user_passkey WHERE id = '" + passkeyId + "'");

        // Assert
        assertThat(rows("SELECT passkey_id FROM passkey_prf_salt WHERE credential_id = 'cred-1'").get(0)[0]).isNull();
    }

    @Test
    void migrate_saltAlgorithm_onlyAcceptsEs256() {
        // Arrange
        flyway().load().migrate();

        // Act + Assert
        assertThatThrownBy(() -> sql("INSERT INTO passkey_prf_salt (holder_id, credential_id, prf_salt, algorithm) "
                + "VALUES ('" + userId + "', 'cred-2', decode(repeat('00', 32), 'hex'), 'ES384')"))
                .isInstanceOf(SQLException.class)
                .hasMessageContaining("chk_passkey_prf_salt_algorithm");
    }

    // ------------------------------------------------------------------ seed

    private void profile(String keyManager) throws SQLException {
        sql("INSERT INTO tenant_wallet_profile (tenant, wallet_mode, key_manager) VALUES ('t', 'server', '"
                + keyManager + "')");
    }

    private void seedEncryptedKeyAttestation(String holderKeyId) throws SQLException {
        sql("INSERT INTO passkey_prf_salt (holder_id, credential_id, prf_salt) VALUES ('" + userId + "', '"
                + holderKeyId + "', decode(repeat('00', 32), 'hex'))");
        sql("INSERT INTO passkey_prf_wrapped_key_handle (holder_id, credential_id, wrapped_blob, iv, tag, kdf_algo, "
                + "kdf_version, cnf_jwk) VALUES ('" + userId + "', '" + holderKeyId + "', decode(repeat('00', 48), 'hex'), "
                + "decode(repeat('00', 12), 'hex'), decode(repeat('00', 16), 'hex'), 'HKDF-SHA-256', 1, '{}')");
        seedBoundAttestation(holderKeyId);
    }

    private void seedBoundAttestation(String holderKeyId) throws SQLException {
        insertAttestation(holderKeyId, true);
    }

    private void seedUnboundAttestation() throws SQLException {
        insertAttestation(null, false);
    }

    private void insertAttestation(String holderKeyId, boolean bound) throws SQLException {
        sql("INSERT INTO wallet_credential (id, user_id, credential_raw, format, credential_config_id, kid, "
                + "credential_type, issuer, issuance_date, holder_key_id, passkey_id, bound) VALUES ('"
                + UUID.randomUUID() + "', '" + userId + "', 'raw', 'dc+sd-jwt', 'cfg', 'kid', 'Type', 'iss', now(), "
                + (holderKeyId == null ? "NULL" : "'" + holderKeyId + "'") + ", "
                + (bound ? "'" + passkeyId + "'" : "NULL") + ", " + bound + ")");
    }

    // ------------------------------------------------------------------ helpers

    private org.flywaydb.core.api.configuration.FluentConfiguration flyway() {
        return Flyway.configure()
                .dataSource(jdbcUrl, "test", "test")
                .locations("classpath:db/tenant")
                .defaultSchema(schema)
                .schemas(schema)
                .table("flyway_schema_history");
    }

    private void sql(String statement) throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute("SET search_path TO " + schema);
            conn.createStatement().execute(statement);
        }
    }

    private java.util.List<Object[]> rows(String query) throws SQLException {
        var result = new java.util.ArrayList<Object[]>();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute("SET search_path TO " + schema);
            try (var rs = conn.createStatement().executeQuery(query)) {
                int columns = rs.getMetaData().getColumnCount();
                while (rs.next()) {
                    var row = new Object[columns];
                    for (int i = 0; i < columns; i++) {
                        row[i] = rs.getObject(i + 1);
                    }
                    result.add(row);
                }
            }
        }
        return result;
    }
}
