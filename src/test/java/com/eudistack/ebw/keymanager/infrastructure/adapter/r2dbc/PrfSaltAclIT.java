package com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc;

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
import static org.assertj.core.api.Assertions.fail;

/**
 * Integration tests verifying the ACL on {@code hybrid_prf_salt} as defined in
 * the Flyway migration {@code V3__create_hybrid_prf_salt.sql}:
 * only {@code SELECT} and {@code INSERT} are granted to {@code ebw_app_role};
 * {@code UPDATE} and {@code DELETE} are explicitly not granted.
 *
 * <p>Tests use a shared Testcontainers PostgreSQL instance. Setup creates
 * {@code ebw_app_role} (group role) and a matching login user {@code ebw_app_user}
 * whose active role is set via {@code SET ROLE} after connection, mirroring production.
 * Each test method uses its own UUID-suffix schema to avoid state leakage.
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>AC-03 / ES-03 — {@code ebw_app_role} UPDATE on {@code hybrid_prf_salt}
 *       is denied (SQLSTATE 42501)</li>
 *   <li>ES-03 — {@code ebw_app_role} DELETE on {@code hybrid_prf_salt}
 *       is denied (SQLSTATE 42501)</li>
 *   <li>NFR-S-537-04 — salt row remains intact after both rejected attempts</li>
 *   <li>Positive: SELECT and INSERT work for {@code ebw_app_role}</li>
 * </ul>
 *
 * <p>Spec: EUDISTACK-537 T11; AC-03, ES-03, NFR-S-537-04.</p>
 */
@Tag("integration")
@Testcontainers
class PrfSaltAclIT {

    /** SQLSTATE for insufficient_privilege in PostgreSQL. */
    private static final String SQLSTATE_INSUFFICIENT_PRIVILEGE = "42501";

    private static final String EBW_APP_USER = "prf_ebw_app_user";
    private static final String USER_PASSWORD = "testpass";

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("prf_salt_acl_it")
                    .withUsername("test")
                    .withPassword("test");

    /** Per-test schema to avoid state leakage. */
    private String testSchema;
    private String jdbcUrl;

    /** A holder UUID that is pre-inserted into wallet_user for FK compliance. */
    private UUID holderUuid;

    @BeforeEach
    void setUp() throws SQLException {
        jdbcUrl = postgres.getJdbcUrl();
        testSchema = "acl_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        holderUuid = UUID.randomUUID();
        provisionRolesAndMigrate();
    }

    // ------------------------------------------------------------------ helpers

    private void provisionRolesAndMigrate() throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            // Group role (non-login)
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE ebw_app_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE config_manager_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");

            // Login user — member of ebw_app_role
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE " + EBW_APP_USER
                    + " LOGIN PASSWORD '" + USER_PASSWORD + "'; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute(
                    "DO $$ BEGIN GRANT ebw_app_role TO " + EBW_APP_USER + "; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");

            // Schema + USAGE
            conn.createStatement().execute("CREATE SCHEMA IF NOT EXISTS " + testSchema);
            conn.createStatement().execute(
                    "GRANT USAGE ON SCHEMA " + testSchema + " TO ebw_app_role");
        }

        // Apply all tenant migrations — V3 creates hybrid_prf_salt and GRANTs SELECT, INSERT
        Flyway.configure()
                .dataSource(jdbcUrl, "test", "test")
                .locations("classpath:db/tenant")
                .defaultSchema(testSchema)
                .schemas(testSchema)
                .table("flyway_schema_history")
                .baselineOnMigrate(true)
                .load()
                .migrate();

        // Seed a wallet_user row (FK target for hybrid_prf_salt.holder_id)
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + testSchema + ".wallet_user (id, email) "
                    + "VALUES ('" + holderUuid + "', 'acl@test.com')");
        }
    }

    /**
     * Opens a JDBC connection as {@code ebw_app_user} and activates {@code ebw_app_role},
     * mirroring the production service account setup.
     */
    private Connection ebwAppConnection() throws SQLException {
        String baseUrl = jdbcUrl.replaceFirst("\\?.*", "");
        Connection conn = DriverManager.getConnection(baseUrl, EBW_APP_USER, USER_PASSWORD);
        conn.createStatement().execute("SET ROLE ebw_app_role");
        conn.createStatement().execute("SET search_path TO " + testSchema);
        return conn;
    }

    /** Inserts a salt row via the superuser connection (bypasses ACL to set up test state). */
    private void seedSaltRow(String credentialId, byte[] salt) throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + testSchema + ".hybrid_prf_salt "
                    + "(holder_id, credential_id, prf_salt) "
                    + "VALUES ('" + holderUuid + "', '" + credentialId + "', "
                    + "decode('" + bytesToHex(salt) + "', 'hex'))");
        }
    }

    /** Reads the salt for a given credential directly via superuser connection. */
    private byte[] readSaltDirect(String credentialId) throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test");
             var rs = conn.createStatement().executeQuery(
                     "SELECT prf_salt FROM " + testSchema + ".hybrid_prf_salt "
                     + "WHERE credential_id = '" + credentialId + "'")) {
            assertThat(rs.next()).isTrue();
            return rs.getBytes("prf_salt");
        }
    }

    // ------------------------------------------------------------------ positive: SELECT

    @Test
    void ebwAppRole_canSelect_fromHybridPrfSalt() throws SQLException {
        String credId = "cred-acl-select-1";
        byte[] salt = new byte[32];
        salt[0] = 0x11;
        seedSaltRow(credId, salt);

        try (Connection conn = ebwAppConnection();
             var rs = conn.createStatement().executeQuery(
                     "SELECT prf_salt FROM hybrid_prf_salt "
                     + "WHERE holder_id = '" + holderUuid + "' AND credential_id = '" + credId + "'")) {
            assertThat(rs.next()).as("ebw_app_role must be able to SELECT").isTrue();
            byte[] readSalt = rs.getBytes("prf_salt");
            assertThat(readSalt).hasSize(32);
        }
    }

    // ------------------------------------------------------------------ positive: INSERT

    @Test
    void ebwAppRole_canInsert_intoHybridPrfSalt() throws SQLException {
        String credId = "cred-acl-insert-1";
        byte[] salt = new byte[32];
        salt[1] = 0x22;

        try (Connection conn = ebwAppConnection()) {
            // Must not throw
            conn.createStatement().execute(
                    "INSERT INTO hybrid_prf_salt (holder_id, credential_id, prf_salt) "
                    + "VALUES ('" + holderUuid + "', '" + credId + "', "
                    + "decode('" + bytesToHex(salt) + "', 'hex'))");
        }

        // Verify the row was persisted
        byte[] stored = readSaltDirect(credId);
        assertThat(stored).hasSize(32);
    }

    // ------------------------------------------------------------------ AC-03 / ES-03: UPDATE denied

    @Test
    void ebwAppRole_update_denied_withInsufficientPrivilege() throws SQLException {
        String credId = "cred-acl-upd-1";
        byte[] originalSalt = new byte[32];
        originalSalt[2] = 0x33;
        seedSaltRow(credId, originalSalt);

        try (Connection conn = ebwAppConnection()) {
            try {
                byte[] newSalt = new byte[32];
                newSalt[2] = (byte) 0xFF;
                conn.createStatement().execute(
                        "UPDATE hybrid_prf_salt SET prf_salt = "
                        + "decode('" + bytesToHex(newSalt) + "', 'hex') "
                        + "WHERE credential_id = '" + credId + "'");
                fail("Expected SQLSTATE 42501 for UPDATE as ebw_app_role");
            } catch (SQLException ex) {
                assertThat(ex.getSQLState())
                        .as("UPDATE must be denied with SQLSTATE 42501 (insufficient_privilege)")
                        .isEqualTo(SQLSTATE_INSUFFICIENT_PRIVILEGE);
            }
        }

        // NFR-S-537-04: salt row must remain intact
        byte[] afterAttempt = readSaltDirect(credId);
        assertThat(afterAttempt).isEqualTo(originalSalt);
    }

    // ------------------------------------------------------------------ ES-03: DELETE denied

    @Test
    void ebwAppRole_delete_denied_withInsufficientPrivilege() throws SQLException {
        String credId = "cred-acl-del-1";
        byte[] originalSalt = new byte[32];
        originalSalt[3] = 0x44;
        seedSaltRow(credId, originalSalt);

        try (Connection conn = ebwAppConnection()) {
            try {
                conn.createStatement().execute(
                        "DELETE FROM hybrid_prf_salt WHERE credential_id = '" + credId + "'");
                fail("Expected SQLSTATE 42501 for DELETE as ebw_app_role");
            } catch (SQLException ex) {
                assertThat(ex.getSQLState())
                        .as("DELETE must be denied with SQLSTATE 42501 (insufficient_privilege)")
                        .isEqualTo(SQLSTATE_INSUFFICIENT_PRIVILEGE);
            }
        }

        // NFR-S-537-04: salt row must remain intact after rejected DELETE
        byte[] afterAttempt = readSaltDirect(credId);
        assertThat(afterAttempt).isEqualTo(originalSalt);
    }

    // ------------------------------------------------------------------ helpers

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
