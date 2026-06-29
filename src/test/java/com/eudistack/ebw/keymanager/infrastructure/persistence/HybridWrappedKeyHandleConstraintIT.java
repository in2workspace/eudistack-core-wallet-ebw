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
 * Verifies the CHECK constraints and NOT NULL invariants on
 * {@code hybrid_wrapped_key_handle} (physical no-custody barriers).
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>AC-03 — CHECK octet_length(wrapped_blob) >= 48 rejects short blobs</li>
 *   <li>AC-03 — CHECK octet_length(iv) = 12 rejects wrong-width IV</li>
 *   <li>ES-01 — wrapped_blob NULL -> NOT NULL violation; blob < 48B -> CHECK violation</li>
 *   <li>ES-03 — duplicate (holder_id, credential_id) -> PK violation; invariant preserved</li>
 * </ul>
 *
 * <p>All rejection cases are atomic: no partial row is persisted after the failure.
 *
 * <p>Note: inserts that expect to succeed must first have a matching row in
 * {@code hybrid_prf_salt} due to the composite FK (V4 migration), so helper
 * {@code insertPrfSalt} is called before each positive-path insert.
 *
 * <p>Spec: EUDISTACK-535 T6; acceptance-criteria.md §1 AC-03; §3 ES-01, ES-03;
 * technical-design.md §3.2.1.
 */
@Tag("integration")
@Testcontainers
class HybridWrappedKeyHandleConstraintIT {

    /** SQLSTATE for check_violation (PostgreSQL). */
    private static final String SQLSTATE_CHECK_VIOLATION = "23514";

    /** SQLSTATE for not_null_violation (PostgreSQL). */
    private static final String SQLSTATE_NOT_NULL_VIOLATION = "23502";

    /** SQLSTATE for unique_violation / PK violation (PostgreSQL). */
    private static final String SQLSTATE_UNIQUE_VIOLATION = "23505";

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:17-alpine")
                    .withDatabaseName("constraint_it")
                    .withUsername("test")
                    .withPassword("test");

    private String testSchema;
    private String jdbcUrl;
    private UUID holderId;

    @BeforeEach
    void setUp() throws SQLException {
        jdbcUrl = postgres.getJdbcUrl();
        testSchema = "con_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        provisionAndMigrate();
        holderId = insertWalletUser();
    }

    // -------------------------------------------------------------------------
    // AC-03 / ES-01 — wrapped_blob < 48 bytes -> CHECK violation
    // -------------------------------------------------------------------------

    @Test
    void insert_with_wrapped_blob_shorter_than_48_bytes_is_rejected_by_check() throws SQLException {
        byte[] shortBlob = new byte[47]; // one byte short of minimum
        String credId = "cred-short-blob";
        // No prf_salt row needed — the CHECK fires before FK evaluation in PG
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.setAutoCommit(false);
            conn.createStatement().execute("SET search_path TO " + testSchema);
            try {
                conn.createStatement().execute(insertSql(
                        holderId, credId,
                        shortBlob, validIv(), validTag()));
                fail("Expected SQLSTATE " + SQLSTATE_CHECK_VIOLATION
                        + " for wrapped_blob < 48 bytes but no exception was thrown");
            } catch (SQLException ex) {
                assertThat(ex.getSQLState())
                        .as("wrapped_blob < 48B must be rejected with SQLSTATE 23514 (check_violation)")
                        .isEqualTo(SQLSTATE_CHECK_VIOLATION);
            } finally {
                conn.rollback();
            }
        }
        assertNoRow(credId);
    }

    // -------------------------------------------------------------------------
    // AC-03 / ES-01 — iv != 12 bytes -> CHECK violation
    // -------------------------------------------------------------------------

    @Test
    void insert_with_iv_length_not_12_bytes_is_rejected_by_check() throws SQLException {
        byte[] wrongIv = new byte[11]; // 11 instead of 12
        String credId = "cred-bad-iv";
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.setAutoCommit(false);
            conn.createStatement().execute("SET search_path TO " + testSchema);
            try {
                conn.createStatement().execute(insertSql(
                        holderId, credId,
                        validBlob(), wrongIv, validTag()));
                fail("Expected SQLSTATE " + SQLSTATE_CHECK_VIOLATION
                        + " for iv != 12 bytes but no exception was thrown");
            } catch (SQLException ex) {
                assertThat(ex.getSQLState())
                        .as("iv != 12 bytes must be rejected with SQLSTATE 23514 (check_violation)")
                        .isEqualTo(SQLSTATE_CHECK_VIOLATION);
            } finally {
                conn.rollback();
            }
        }
        assertNoRow(credId);
    }

    @Test
    void insert_with_iv_length_13_bytes_is_rejected_by_check() throws SQLException {
        byte[] wrongIv = new byte[13]; // 13 instead of 12
        String credId = "cred-long-iv";
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.setAutoCommit(false);
            conn.createStatement().execute("SET search_path TO " + testSchema);
            try {
                conn.createStatement().execute(insertSql(
                        holderId, credId,
                        validBlob(), wrongIv, validTag()));
                fail("Expected SQLSTATE " + SQLSTATE_CHECK_VIOLATION
                        + " for iv = 13 bytes but no exception was thrown");
            } catch (SQLException ex) {
                assertThat(ex.getSQLState())
                        .as("iv = 13 bytes must be rejected with SQLSTATE 23514 (check_violation)")
                        .isEqualTo(SQLSTATE_CHECK_VIOLATION);
            } finally {
                conn.rollback();
            }
        }
        assertNoRow(credId);
    }

    // -------------------------------------------------------------------------
    // ES-01 — wrapped_blob NULL -> NOT NULL violation
    // -------------------------------------------------------------------------

    @Test
    void insert_with_null_wrapped_blob_is_rejected() throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.setAutoCommit(false);
            conn.createStatement().execute("SET search_path TO " + testSchema);
            try {
                conn.createStatement().execute(
                        "INSERT INTO hybrid_wrapped_key_handle "
                        + "(holder_id, credential_id, wrapped_blob, iv, tag, kdf_algo, kdf_version, cnf_jwk) "
                        + "VALUES ('" + holderId + "', 'cred-null-blob', "
                        + " NULL, "
                        + " decode('" + hex(validIv()) + "', 'hex'), "
                        + " decode('" + hex(validTag()) + "', 'hex'), "
                        + " 'HKDF-SHA-256', 1, '{\"kty\":\"EC\"}')");
                fail("Expected NOT NULL violation for wrapped_blob = NULL but no exception was thrown");
            } catch (SQLException ex) {
                assertThat(ex.getSQLState())
                        .as("wrapped_blob = NULL must be rejected with SQLSTATE 23502 (not_null_violation)")
                        .isEqualTo(SQLSTATE_NOT_NULL_VIOLATION);
            } finally {
                conn.rollback();
            }
        }
        assertNoRow("cred-null-blob");
    }

    // -------------------------------------------------------------------------
    // ES-03 — duplicate PK (holder_id, credential_id) -> unique violation
    // -------------------------------------------------------------------------

    @Test
    void second_insert_with_same_pk_is_rejected_preserving_first_row() throws SQLException {
        String credId = "cred-dup-pk";
        // Seed prf_salt for the first (successful) insert
        insertPrfSalt(holderId, credId);

        // First insert succeeds
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute("SET search_path TO " + testSchema);
            conn.createStatement().execute(insertSql(holderId, credId,
                    validBlob(), validIv(), validTag()));
        }

        // Second insert for same (holder_id, credential_id) must fail
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.setAutoCommit(false);
            conn.createStatement().execute("SET search_path TO " + testSchema);
            try {
                conn.createStatement().execute(insertSql(holderId, credId,
                        validBlob(), validIv(), validTag()));
                fail("Expected SQLSTATE " + SQLSTATE_UNIQUE_VIOLATION
                        + " for duplicate PK but no exception was thrown");
            } catch (SQLException ex) {
                assertThat(ex.getSQLState())
                        .as("duplicate (holder_id, credential_id) must be rejected with SQLSTATE 23505")
                        .isEqualTo(SQLSTATE_UNIQUE_VIOLATION);
            } finally {
                conn.rollback();
            }
        }

        // Exactly one row must remain
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test");
             ResultSet rs = conn.createStatement().executeQuery(
                     "SELECT count(*) FROM " + testSchema + ".hybrid_wrapped_key_handle "
                     + "WHERE credential_id = '" + credId + "'")) {
            assertThat(rs.next()).isTrue();
            assertThat(rs.getLong(1))
                    .as("Exactly one row must remain after the rejected duplicate insert")
                    .isEqualTo(1L);
        }
    }

    // -------------------------------------------------------------------------
    // AC-03 — exact minimum boundary (48 bytes) is accepted
    // -------------------------------------------------------------------------

    @Test
    void insert_with_wrapped_blob_exactly_48_bytes_is_accepted() throws SQLException {
        String credId = "cred-min-blob";
        insertPrfSalt(holderId, credId);

        byte[] minBlob = new byte[48];
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute("SET search_path TO " + testSchema);
            // Must not throw
            conn.createStatement().execute(insertSql(
                    holderId, credId, minBlob, validIv(), validTag()));
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
                    + "VALUES ('" + id + "', 'con-it-" + id + "@test.local')");
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

    private String insertSql(UUID hId, String credId, byte[] blob, byte[] iv, byte[] tag) {
        return "INSERT INTO hybrid_wrapped_key_handle "
                + "(holder_id, credential_id, wrapped_blob, iv, tag, kdf_algo, kdf_version, cnf_jwk) "
                + "VALUES ('" + hId + "', '" + credId + "', "
                + " decode('" + hex(blob) + "', 'hex'), "
                + " decode('" + hex(iv) + "', 'hex'), "
                + " decode('" + hex(tag) + "', 'hex'), "
                + " 'HKDF-SHA-256', 1, '{\"kty\":\"EC\"}')";
    }

    private void assertNoRow(String credId) throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test");
             ResultSet rs = conn.createStatement().executeQuery(
                     "SELECT count(*) FROM " + testSchema + ".hybrid_wrapped_key_handle "
                     + "WHERE credential_id = '" + credId + "'")) {
            assertThat(rs.next()).isTrue();
            assertThat(rs.getLong(1))
                    .as("No partial row must remain after a rejected insert (credential_id=%s)", credId)
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
                    .as("Row must exist for credential_id=%s", credId)
                    .isEqualTo(1L);
        }
    }

    private static byte[] validBlob() {
        byte[] b = new byte[48];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) (i % 256);
        }
        return b;
    }

    private static byte[] validIv() {
        return new byte[12];
    }

    private static byte[] validTag() {
        return new byte[16];
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
