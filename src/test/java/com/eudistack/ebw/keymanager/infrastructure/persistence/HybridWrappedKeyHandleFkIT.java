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
 * Verifies the foreign-key constraints on {@code hybrid_wrapped_key_handle}.
 *
 * <p>Covered cases:
 * <ol>
 *   <li>(a) INSERT of a handle whose {@code holder_id} does not exist in
 *       {@code wallet_user} -> rejected by FK (AC-05).</li>
 *   <li>(b) DELETE of a {@code wallet_user} row that is referenced by a handle
 *       -> rejected by FK ON DELETE RESTRICT (AC-05).</li>
 *   <li>(c) INSERT of a handle whose {@code (holder_id, credential_id)} has no
 *       matching row in {@code hybrid_prf_salt} -> rejected by composite FK
 *       (AC-05, ES-02). The {@code hybrid_prf_salt} table is now available as
 *       V3 migration from US-05 (EUDISTACK-537).</li>
 * </ol>
 *
 * <p>Spec: EUDISTACK-535 T8; acceptance-criteria.md §1 AC-05; §3 ES-02;
 * technical-design.md §3.2.1.
 */
@Tag("integration")
@Testcontainers
class HybridWrappedKeyHandleFkIT {

    /** SQLSTATE for foreign_key_violation (PostgreSQL). */
    private static final String SQLSTATE_FOREIGN_KEY_VIOLATION = "23503";

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:17-alpine")
                    .withDatabaseName("fk_it")
                    .withUsername("test")
                    .withPassword("test");

    private String testSchema;
    private String jdbcUrl;

    @BeforeEach
    void setUp() throws SQLException {
        jdbcUrl = postgres.getJdbcUrl();
        testSchema = "fk_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        provisionAndMigrate();
    }

    // -------------------------------------------------------------------------
    // (a) INSERT with non-existent holder_id -> FK violation
    // -------------------------------------------------------------------------

    @Test
    void insert_with_nonexistent_holder_id_is_rejected_by_fk() throws SQLException {
        UUID nonExistentHolder = UUID.randomUUID(); // never inserted into wallet_user
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.setAutoCommit(false);
            conn.createStatement().execute("SET search_path TO " + testSchema);
            try {
                conn.createStatement().execute(insertSql(nonExistentHolder, "cred-fk-no-holder"));
                fail("Expected SQLSTATE " + SQLSTATE_FOREIGN_KEY_VIOLATION
                        + " for holder_id not in wallet_user but no exception was thrown");
            } catch (SQLException ex) {
                assertThat(ex.getSQLState())
                        .as("INSERT with non-existent holder_id must be rejected with "
                            + "SQLSTATE 23503 (foreign_key_violation)")
                        .isEqualTo(SQLSTATE_FOREIGN_KEY_VIOLATION);
            } finally {
                conn.rollback();
            }
        }
        assertNoRow("cred-fk-no-holder");
    }

    // -------------------------------------------------------------------------
    // (b) DELETE of wallet_user referenced by a handle -> ON DELETE RESTRICT
    // -------------------------------------------------------------------------

    @Test
    void delete_wallet_user_referenced_by_handle_is_rejected_by_on_delete_restrict()
            throws SQLException {
        UUID holderId = insertWalletUser();
        String credId = "cred-fk-restrict";
        insertPrfSalt(holderId, credId);

        // Insert a handle referencing holderId
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute("SET search_path TO " + testSchema);
            conn.createStatement().execute(insertSql(holderId, credId));
        }

        // Attempt to delete the wallet_user -> must be rejected
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.setAutoCommit(false);
            conn.createStatement().execute("SET search_path TO " + testSchema);
            try {
                conn.createStatement().execute(
                        "DELETE FROM wallet_user WHERE id = '" + holderId + "'");
                fail("Expected SQLSTATE " + SQLSTATE_FOREIGN_KEY_VIOLATION
                        + " for ON DELETE RESTRICT but no exception was thrown");
            } catch (SQLException ex) {
                assertThat(ex.getSQLState())
                        .as("DELETE of wallet_user with an existing handle must be rejected "
                            + "with SQLSTATE 23503 (foreign_key_violation, ON DELETE RESTRICT)")
                        .isEqualTo(SQLSTATE_FOREIGN_KEY_VIOLATION);
            } finally {
                conn.rollback();
            }
        }

        // Both rows must still exist
        assertRowExists(credId);
        assertWalletUserExists(holderId);
    }

    // -------------------------------------------------------------------------
    // (c) INSERT with no matching (holder_id, credential_id) in hybrid_prf_salt
    //     -> composite FK violation (AC-05, ES-02)
    // -------------------------------------------------------------------------

    @Test
    void insert_with_no_prf_salt_row_is_rejected_by_composite_fk() throws SQLException {
        UUID holderId = insertWalletUser();
        // Deliberately do NOT insert a prf_salt row for this (holderId, credId) pair
        String credId = "cred-fk-no-salt";

        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.setAutoCommit(false);
            conn.createStatement().execute("SET search_path TO " + testSchema);
            try {
                conn.createStatement().execute(insertSql(holderId, credId));
                fail("Expected SQLSTATE " + SQLSTATE_FOREIGN_KEY_VIOLATION
                        + " for composite FK to hybrid_prf_salt but no exception was thrown");
            } catch (SQLException ex) {
                assertThat(ex.getSQLState())
                        .as("INSERT with no matching hybrid_prf_salt row must be rejected with "
                            + "SQLSTATE 23503 (foreign_key_violation) — composite FK (AC-05, ES-02)")
                        .isEqualTo(SQLSTATE_FOREIGN_KEY_VIOLATION);
            } finally {
                conn.rollback();
            }
        }
        assertNoRow(credId);
    }

    // -------------------------------------------------------------------------
    // Positive: valid insert with all FK targets present is accepted
    // -------------------------------------------------------------------------

    @Test
    void insert_with_all_fk_targets_present_is_accepted() throws SQLException {
        UUID holderId = insertWalletUser();
        String credId = "cred-fk-ok";
        insertPrfSalt(holderId, credId);

        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute("SET search_path TO " + testSchema);
            conn.createStatement().execute(insertSql(holderId, credId));
        }
        assertRowExists(credId);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private void provisionAndMigrate() throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE ebw_app_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE config_manager_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute("CREATE SCHEMA IF NOT EXISTS " + testSchema);
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

    private UUID insertWalletUser() throws SQLException {
        UUID id = UUID.randomUUID();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute("SET search_path TO " + testSchema);
            conn.createStatement().execute(
                    "INSERT INTO wallet_user (id, email) "
                    + "VALUES ('" + id + "', 'fk-it-" + id + "@test.local')");
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

    private String insertSql(UUID hId, String credId) {
        byte[] blob = new byte[48];
        return "INSERT INTO hybrid_wrapped_key_handle "
                + "(holder_id, credential_id, wrapped_blob, iv, tag, kdf_algo, kdf_version, cnf_jwk) "
                + "VALUES ('" + hId + "', '" + credId + "', "
                + " decode('" + hex(blob) + "', 'hex'), "
                + " decode('" + hex(new byte[12]) + "', 'hex'), "
                + " decode('" + hex(new byte[16]) + "', 'hex'), "
                + " 'HKDF-SHA-256', 1, '{\"kty\":\"EC\"}')";
    }

    private void assertNoRow(String credId) throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test");
             ResultSet rs = conn.createStatement().executeQuery(
                     "SELECT count(*) FROM " + testSchema + ".hybrid_wrapped_key_handle "
                     + "WHERE credential_id = '" + credId + "'")) {
            assertThat(rs.next()).isTrue();
            assertThat(rs.getLong(1))
                    .as("No partial row must remain (credential_id=%s)", credId)
                    .isZero();
        }
    }

    private void assertRowExists(String credId) throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test");
             ResultSet rs = conn.createStatement().executeQuery(
                     "SELECT count(*) FROM " + testSchema + ".hybrid_wrapped_key_handle "
                     + "WHERE credential_id = '" + credId + "'")) {
            assertThat(rs.next()).isTrue();
            assertThat(rs.getLong(1))
                    .as("Handle row must exist for credential_id=%s", credId)
                    .isEqualTo(1L);
        }
    }

    private void assertWalletUserExists(UUID holderId) throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test");
             ResultSet rs = conn.createStatement().executeQuery(
                     "SELECT count(*) FROM " + testSchema + ".wallet_user "
                     + "WHERE id = '" + holderId + "'")) {
            assertThat(rs.next()).isTrue();
            assertThat(rs.getLong(1))
                    .as("wallet_user row must still exist after rejected DELETE")
                    .isEqualTo(1L);
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
