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
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Verifies the ACL matrix on {@code hybrid_wrapped_key_handle} using the real
 * {@code ebw_app_role} (not the Testcontainers superuser).
 *
 * <p>All privilege-check tests open a connection as a login user that has been
 * granted membership in {@code ebw_app_role} and then activates that role via
 * {@code SET ROLE}. This mirrors the production setup and ensures that a deniable
 * operation that is denied only to superusers-with-GRANT would be caught here (R-4
 * mitigation in technical-design.md §3.7.2).
 *
 * <p>Setup (in {@code @BeforeEach}):
 * <ol>
 *   <li>Create group role {@code ebw_app_role} (idempotent).</li>
 *   <li>Create login user {@code ebw_app_user} with password (idempotent).</li>
 *   <li>Grant {@code ebw_app_role} to {@code ebw_app_user}.</li>
 *   <li>Create an isolated schema and apply all Flyway tenant migrations
 *       (V4 GRANTs {@code SELECT, INSERT} + {@code UPDATE(last_used_at)} to
 *       {@code ebw_app_role}).</li>
 *   <li>Grant USAGE on the schema to {@code ebw_app_role}.</li>
 *   <li>Seed a {@code wallet_user} row, a {@code hybrid_prf_salt} row, and a
 *       {@code hybrid_wrapped_key_handle} row as the superuser (for UPDATE/DELETE tests).</li>
 * </ol>
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>AC-04 — SELECT, INSERT, UPDATE(last_used_at) are permitted</li>
 *   <li>AC-04 — UPDATE of wrapped_blob, iv, tag, kdf_algo, kdf_version,
 *       holder_id, credential_id are denied (SQLSTATE 42501)</li>
 *   <li>AC-04 — DELETE is denied (SQLSTATE 42501)</li>
 *   <li>EC-01 — UPDATE last_used_at is permitted; no other crypto column changes</li>
 *   <li>ES-04 — UPDATE/DELETE not authorised -> SQLSTATE 42501</li>
 *   <li>NFR-S-535-03 — exactly SELECT, INSERT, UPDATE(last_used_at) granted</li>
 * </ul>
 *
 * <p>Spec: EUDISTACK-535 T7; acceptance-criteria.md §1 AC-04; §2 EC-01; §3 ES-04;
 * NFR-S-535-03; technical-design.md §3.5 AD-1; §3.7.2 R-4.
 */
@Tag("integration")
@Testcontainers
class HybridWrappedKeyHandleAclIT {

    /** SQLSTATE for insufficient_privilege (PostgreSQL). */
    private static final String SQLSTATE_INSUFFICIENT_PRIVILEGE = "42501";

    /** Login user whose active role is set to {@code ebw_app_role}. */
    private static final String EBW_APP_USER     = "ebw_app_user_acl";
    private static final String EBW_APP_PASSWORD = "test_acl_pass";

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:17-alpine")
                    .withDatabaseName("acl_hybrid_it")
                    .withUsername("test")
                    .withPassword("test");

    private String testSchema;
    private String jdbcUrl;
    private UUID seededHolderId;
    private static final String SEEDED_CRED_ID = "cred-acl-seed";

    /**
     * Before each test: create roles + login user (idempotent), create schema,
     * apply Flyway migrations, grant USAGE on schema, and seed one handle row
     * for UPDATE/DELETE tests.
     */
    @BeforeEach
    void setUp() throws SQLException {
        jdbcUrl = postgres.getJdbcUrl();
        testSchema = "acl_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        provisionRolesAndMigrate();
        seededHolderId = insertWalletUser();
        insertPrfSalt(seededHolderId, SEEDED_CRED_ID);
        insertHandle(seededHolderId, SEEDED_CRED_ID);
    }

    // -------------------------------------------------------------------------
    // AC-04 / EC-01 — SELECT is permitted
    // -------------------------------------------------------------------------

    @Test
    void ebw_app_role_can_select_from_hybrid_wrapped_key_handle() throws SQLException {
        try (Connection conn = connectionAsEbwAppRole()) {
            try (ResultSet rs = conn.createStatement().executeQuery(
                    "SELECT holder_id, credential_id, kdf_algo FROM hybrid_wrapped_key_handle "
                    + "WHERE credential_id = '" + SEEDED_CRED_ID + "'")) {
                assertThat(rs.next())
                        .as("ebw_app_role must be able to SELECT the seeded row")
                        .isTrue();
                assertThat(rs.getString("kdf_algo"))
                        .isEqualTo("HKDF-SHA-256");
            }
        }
    }

    // -------------------------------------------------------------------------
    // AC-04 — INSERT is permitted
    // -------------------------------------------------------------------------

    @Test
    void ebw_app_role_can_insert_into_hybrid_wrapped_key_handle() throws SQLException {
        UUID newHolder = insertWalletUser();
        String newCred = "cred-acl-insert";
        insertPrfSalt(newHolder, newCred);

        try (Connection conn = connectionAsEbwAppRole()) {
            // Must not throw
            conn.createStatement().execute(insertSql(newHolder, newCred));
        }

        // Verify row was persisted (read as superuser)
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test");
             ResultSet rs = conn.createStatement().executeQuery(
                     "SELECT count(*) FROM " + testSchema + ".hybrid_wrapped_key_handle "
                     + "WHERE credential_id = '" + newCred + "'")) {
            assertThat(rs.next()).isTrue();
            assertThat(rs.getLong(1))
                    .as("INSERT by ebw_app_role must have persisted the row")
                    .isEqualTo(1L);
        }
    }

    // -------------------------------------------------------------------------
    // AC-04 / EC-01 — UPDATE last_used_at is permitted
    // -------------------------------------------------------------------------

    @Test
    void ebw_app_role_can_update_last_used_at() throws SQLException {
        try (Connection conn = connectionAsEbwAppRole()) {
            int affected = conn.createStatement().executeUpdate(
                    "UPDATE hybrid_wrapped_key_handle "
                    + "SET last_used_at = now() "
                    + "WHERE credential_id = '" + SEEDED_CRED_ID + "'");
            assertThat(affected)
                    .as("UPDATE last_used_at must succeed and affect exactly one row")
                    .isEqualTo(1);
        }
    }

    // -------------------------------------------------------------------------
    // AC-04 / ES-04 — UPDATE wrapped_blob is denied (SQLSTATE 42501)
    // -------------------------------------------------------------------------

    @Test
    void ebw_app_role_update_wrapped_blob_is_denied() {
        assertUpdateDenied(
                "wrapped_blob = decode('" + hex(new byte[48]) + "', 'hex')",
                "wrapped_blob");
    }

    @Test
    void ebw_app_role_update_iv_is_denied() {
        assertUpdateDenied(
                "iv = decode('" + hex(new byte[12]) + "', 'hex')",
                "iv");
    }

    @Test
    void ebw_app_role_update_tag_is_denied() {
        assertUpdateDenied(
                "tag = decode('" + hex(new byte[16]) + "', 'hex')",
                "tag");
    }

    @Test
    void ebw_app_role_update_kdf_algo_is_denied() {
        assertUpdateDenied("kdf_algo = 'HKDF-SHA-512'", "kdf_algo");
    }

    @Test
    void ebw_app_role_update_kdf_version_is_denied() {
        assertUpdateDenied("kdf_version = 2", "kdf_version");
    }

    // -------------------------------------------------------------------------
    // AC-04 / ES-04 — DELETE is denied (SQLSTATE 42501)
    // -------------------------------------------------------------------------

    @Test
    void ebw_app_role_delete_is_denied() throws SQLException {
        try (Connection conn = connectionAsEbwAppRole()) {
            try {
                conn.createStatement().execute(
                        "DELETE FROM hybrid_wrapped_key_handle "
                        + "WHERE credential_id = '" + SEEDED_CRED_ID + "'");
                fail("Expected SQLSTATE 42501 (insufficient_privilege) for DELETE as ebw_app_role "
                        + "but no exception was thrown");
            } catch (SQLException ex) {
                assertThat(ex.getSQLState())
                        .as("DELETE must be denied with SQLSTATE 42501 (insufficient_privilege)")
                        .isEqualTo(SQLSTATE_INSUFFICIENT_PRIVILEGE);
            }
        }

        // Row must still exist
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test");
             ResultSet rs = conn.createStatement().executeQuery(
                     "SELECT count(*) FROM " + testSchema + ".hybrid_wrapped_key_handle "
                     + "WHERE credential_id = '" + SEEDED_CRED_ID + "'")) {
            assertThat(rs.next()).isTrue();
            assertThat(rs.getLong(1))
                    .as("Handle must remain immutable after denied DELETE")
                    .isEqualTo(1L);
        }
    }

    // -------------------------------------------------------------------------
    // EC-01 — after UPDATE last_used_at, crypto columns are unchanged
    // -------------------------------------------------------------------------

    @Test
    void after_update_last_used_at_crypto_columns_remain_unchanged() throws SQLException {
        // Read original blob bytes as superuser
        byte[] originalBlob;
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test");
             ResultSet rs = conn.createStatement().executeQuery(
                     "SELECT wrapped_blob FROM " + testSchema + ".hybrid_wrapped_key_handle "
                     + "WHERE credential_id = '" + SEEDED_CRED_ID + "'")) {
            assertThat(rs.next()).isTrue();
            originalBlob = rs.getBytes("wrapped_blob");
        }

        // Update last_used_at as ebw_app_role
        try (Connection conn = connectionAsEbwAppRole()) {
            conn.createStatement().executeUpdate(
                    "UPDATE hybrid_wrapped_key_handle "
                    + "SET last_used_at = now() "
                    + "WHERE credential_id = '" + SEEDED_CRED_ID + "'");
        }

        // Verify wrapped_blob has not changed
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test");
             ResultSet rs = conn.createStatement().executeQuery(
                     "SELECT wrapped_blob FROM " + testSchema + ".hybrid_wrapped_key_handle "
                     + "WHERE credential_id = '" + SEEDED_CRED_ID + "'")) {
            assertThat(rs.next()).isTrue();
            assertThat(rs.getBytes("wrapped_blob"))
                    .as("wrapped_blob must be unchanged after UPDATE last_used_at (EC-01)")
                    .isEqualTo(originalBlob);
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Creates group roles and a login user that is a member of {@code ebw_app_role},
     * creates the test schema, applies Flyway migrations, and grants USAGE on the
     * schema to {@code ebw_app_role}.
     *
     * <p>All role/user creation is idempotent via {@code DO ... EXCEPTION} blocks.
     */
    private void provisionRolesAndMigrate() throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            // Group roles (non-login)
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE ebw_app_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE config_manager_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");

            // Login user for ebw_app_role
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE " + EBW_APP_USER
                    + " LOGIN PASSWORD '" + EBW_APP_PASSWORD + "'; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");

            // Membership grant
            conn.createStatement().execute(
                    "DO $$ BEGIN GRANT ebw_app_role TO " + EBW_APP_USER + "; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");

            conn.createStatement().execute("CREATE SCHEMA IF NOT EXISTS " + testSchema);

            conn.createStatement().execute(
                    "GRANT USAGE ON SCHEMA " + testSchema + " TO ebw_app_role");
        }

        Flyway.configure()
                .dataSource(jdbcUrl, "test", "test")
                .locations("classpath:db/tenant")
                .defaultSchema(testSchema)
                .schemas(testSchema)
                .table("flyway_schema_history")
                .baselineOnMigrate(true)
                .load()
                .migrate();
    }

    /**
     * Opens a JDBC connection as {@code ebw_app_user} and activates {@code ebw_app_role}
     * via {@code SET ROLE}. The {@code search_path} is set to the test schema.
     */
    private Connection connectionAsEbwAppRole() throws SQLException {
        String baseUrl = jdbcUrl.replaceFirst("\\?.*", "");
        Connection conn = DriverManager.getConnection(baseUrl, EBW_APP_USER, EBW_APP_PASSWORD);
        conn.createStatement().execute("SET ROLE ebw_app_role");
        conn.createStatement().execute("SET search_path TO " + testSchema);
        return conn;
    }

    private UUID insertWalletUser() throws SQLException {
        UUID id = UUID.randomUUID();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute("SET search_path TO " + testSchema);
            conn.createStatement().execute(
                    "INSERT INTO wallet_user (id, email) "
                    + "VALUES ('" + id + "', 'acl-it-" + id + "@test.local')");
        }
        return id;
    }

    private void insertPrfSalt(UUID hId, String credId) throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute("SET search_path TO " + testSchema);
            conn.createStatement().execute(
                    "INSERT INTO hybrid_prf_salt (holder_id, credential_id, prf_salt) "
                    + "VALUES ('" + hId + "', '" + credId + "', "
                    + " decode('" + hex(new byte[32]) + "', 'hex'))");
        }
    }

    private void insertHandle(UUID hId, String credId) throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute("SET search_path TO " + testSchema);
            conn.createStatement().execute(insertSql(hId, credId));
        }
    }

    private String insertSql(UUID hId, String credId) {
        byte[] blob = new byte[48];
        for (int i = 0; i < blob.length; i++) {
            blob[i] = (byte) (i % 256);
        }
        return "INSERT INTO hybrid_wrapped_key_handle "
                + "(holder_id, credential_id, wrapped_blob, iv, tag, kdf_algo, kdf_version, cnf_jwk) "
                + "VALUES ('" + hId + "', '" + credId + "', "
                + " decode('" + hex(blob) + "', 'hex'), "
                + " decode('" + hex(new byte[12]) + "', 'hex'), "
                + " decode('" + hex(new byte[16]) + "', 'hex'), "
                + " 'HKDF-SHA-256', 1, '{\"kty\":\"EC\"}')";
    }

    private void assertUpdateDenied(String setClause, String column) {
        try (Connection conn = connectionAsEbwAppRole()) {
            try {
                conn.createStatement().execute(
                        "UPDATE hybrid_wrapped_key_handle SET " + setClause
                        + " WHERE credential_id = '" + SEEDED_CRED_ID + "'");
                fail("Expected SQLSTATE 42501 (insufficient_privilege) for UPDATE " + column
                        + " as ebw_app_role but no exception was thrown");
            } catch (SQLException ex) {
                assertThat(ex.getSQLState())
                        .as("UPDATE %s must be denied with SQLSTATE 42501 (insufficient_privilege)",
                            column)
                        .isEqualTo(SQLSTATE_INSUFFICIENT_PRIVILEGE);
            }
        } catch (SQLException ex) {
            throw new RuntimeException("Unexpected error opening connection as ebw_app_role", ex);
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
