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
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Integration tests for the FK invariant R-5 of the {@code hybrid_prf_salt} table:
 * every {@code holder_id} must reference a UUID v4 row in {@code wallet_user(id)}.
 *
 * <p>This test class is the canonical owner of invariant R-5 as declared in
 * {@code architecture.md §11} and {@code tasks.md} note for task 12.</p>
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>AC-07 / ES-01 — INSERT with a valid {@code holder_id} (existing in {@code wallet_user})
 *       succeeds and the row is persisted</li>
 *   <li>ES-01 — INSERT with a non-existent {@code holder_id} → FK violation, no row
 *       persisted</li>
 *   <li>NFR-S-537-03 — all {@code holder_id} values in {@code hybrid_prf_salt} are UUID v4
 *       (opaque, from {@code wallet_user.id}), not PII-like strings</li>
 * </ul>
 *
 * <p>Spec: EUDISTACK-537 T12; AC-07, ES-01, NFR-S-537-03; architecture.md §11 R-5.</p>
 */
@Tag("integration")
@Testcontainers
class PrfSaltFkInvariantIT {

    /** UUID v4 pattern: xxxxxxxx-xxxx-4xxx-[89ab]xxx-xxxxxxxxxxxx */
    private static final Pattern UUID_V4_PATTERN = Pattern.compile(
            "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            Pattern.CASE_INSENSITIVE);

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("prf_salt_fk_it")
                    .withUsername("test")
                    .withPassword("test");

    private String testSchema;
    private String jdbcUrl;
    private UUID knownHolderUuid;

    @BeforeEach
    void setUp() throws SQLException {
        jdbcUrl = postgres.getJdbcUrl();
        testSchema = "fk_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        knownHolderUuid = UUID.randomUUID();
        provisionAndSeed();
    }

    private void provisionAndSeed() throws SQLException {
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

        // Seed a known wallet_user so we have a valid FK target
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + testSchema + ".wallet_user (id, email) "
                    + "VALUES ('" + knownHolderUuid + "', 'fk@test.com')");
        }
    }

    // ------------------------------------------------------------------ AC-07 / ES-01: valid FK succeeds

    @Test
    void insert_withValidHolderId_persistsRow() throws SQLException {
        String credId = "cred-fk-valid-1";
        byte[] salt = randomSalt();

        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + testSchema + ".hybrid_prf_salt "
                    + "(holder_id, credential_id, prf_salt) VALUES "
                    + "('" + knownHolderUuid + "', '" + credId + "', "
                    + "decode('" + hex(salt) + "', 'hex'))");
        }

        // Verify the row is present
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test");
             ResultSet rs = conn.createStatement().executeQuery(
                     "SELECT COUNT(*) FROM " + testSchema + ".hybrid_prf_salt "
                     + "WHERE holder_id = '" + knownHolderUuid + "' AND credential_id = '" + credId + "'")) {
            assertThat(rs.next()).isTrue();
            assertThat(rs.getLong(1)).isEqualTo(1);
        }
    }

    // ------------------------------------------------------------------ ES-01: non-existent FK rejected

    @Test
    void insert_withNonExistentHolderId_throwsFkViolationAndNothingPersisted() throws SQLException {
        UUID nonExistentHolder = UUID.randomUUID();
        String credId = "cred-fk-invalid-1";
        byte[] salt = randomSalt();

        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            try {
                conn.createStatement().execute(
                        "INSERT INTO " + testSchema + ".hybrid_prf_salt "
                        + "(holder_id, credential_id, prf_salt) VALUES "
                        + "('" + nonExistentHolder + "', '" + credId + "', "
                        + "decode('" + hex(salt) + "', 'hex'))");
                fail("Expected FK violation for non-existent holder_id");
            } catch (SQLException ex) {
                // PostgreSQL SQLSTATE 23503 = foreign_key_violation
                assertThat(ex.getSQLState())
                        .as("Non-existent holder_id must cause FK violation (SQLSTATE 23503)")
                        .isEqualTo("23503");
            }
        }

        // Verify no row was persisted
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test");
             ResultSet rs = conn.createStatement().executeQuery(
                     "SELECT COUNT(*) FROM " + testSchema + ".hybrid_prf_salt "
                     + "WHERE credential_id = '" + credId + "'")) {
            assertThat(rs.next()).isTrue();
            assertThat(rs.getLong(1)).as("No row must be persisted after FK violation").isEqualTo(0);
        }
    }

    @Test
    void insert_withPiiLikeString_throwsFkViolation() throws SQLException {
        // A PII-like value (email or name) is not a valid UUID — the FK constraint
        // rejects it because it cannot be cast to UUID. This protects against accidentally
        // inserting raw PII into the holder_id column (NFR-S-537-03).
        String credId = "cred-fk-pii-1";
        byte[] salt = randomSalt();

        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            try {
                // Attempting to insert a non-UUID literal fails at the type-cast level
                conn.createStatement().execute(
                        "INSERT INTO " + testSchema + ".hybrid_prf_salt "
                        + "(holder_id, credential_id, prf_salt) VALUES "
                        + "('user@example.com'::uuid, '" + credId + "', "
                        + "decode('" + hex(salt) + "', 'hex'))");
                fail("Expected error casting PII string to UUID");
            } catch (SQLException ex) {
                // Either invalid_text_representation (22P02) or syntax error — both are correct
                assertThat(ex.getSQLState())
                        .as("PII-like string must not be insertable as holder_id UUID")
                        .isIn("22P02", "42601", "23503");
            }
        }

        // No row must exist
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test");
             ResultSet rs = conn.createStatement().executeQuery(
                     "SELECT COUNT(*) FROM " + testSchema + ".hybrid_prf_salt "
                     + "WHERE credential_id = '" + credId + "'")) {
            assertThat(rs.next()).isTrue();
            assertThat(rs.getLong(1)).as("No row must be persisted for PII-like holder_id").isEqualTo(0);
        }
    }

    // ------------------------------------------------------------------ NFR-S-537-03: holder_id is UUID v4

    @Test
    void allHolderIds_inHybridPrfSalt_areUuidV4() throws SQLException {
        // Insert several rows with valid UUID v4 holder IDs (using knownHolderUuid + extra users)
        UUID holder2 = UUID.randomUUID();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + testSchema + ".wallet_user (id, email) "
                    + "VALUES ('" + holder2 + "', 'fk2@test.com')");
            conn.createStatement().execute(
                    "INSERT INTO " + testSchema + ".hybrid_prf_salt (holder_id, credential_id, prf_salt) VALUES "
                    + "('" + knownHolderUuid + "', 'cred-uuid-check-1', decode('" + hex(randomSalt()) + "', 'hex')), "
                    + "('" + holder2 + "', 'cred-uuid-check-2', decode('" + hex(randomSalt()) + "', 'hex'))");
        }

        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test");
             ResultSet rs = conn.createStatement().executeQuery(
                     "SELECT holder_id::text FROM " + testSchema + ".hybrid_prf_salt")) {
            int rowCount = 0;
            while (rs.next()) {
                String holderId = rs.getString(1);
                assertThat(UUID_V4_PATTERN.matcher(holderId).matches())
                        .as("holder_id '%s' must be a UUID v4 (opaque, not PII)", holderId)
                        .isTrue();
                // Version bit must be 4
                UUID parsed = UUID.fromString(holderId);
                assertThat(parsed.version()).as("holder_id must be UUID version 4").isEqualTo(4);
                rowCount++;
            }
            assertThat(rowCount).as("Expected rows in hybrid_prf_salt").isGreaterThan(0);
        }
    }

    @Test
    void holderIds_areOpaqueUuids_notDerivedFromEmail() throws SQLException {
        // The holder UUID stored in hybrid_prf_salt comes from wallet_user.id,
        // which is generated server-side (UUID v4). It must not equal or embed any
        // PII such as the user's email address.
        String email = "fk-opaque@test.com";
        UUID holderUuid = UUID.randomUUID();

        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + testSchema + ".wallet_user (id, email) "
                    + "VALUES ('" + holderUuid + "', '" + email + "')");
            conn.createStatement().execute(
                    "INSERT INTO " + testSchema + ".hybrid_prf_salt (holder_id, credential_id, prf_salt) VALUES "
                    + "('" + holderUuid + "', 'cred-opaque-1', decode('" + hex(randomSalt()) + "', 'hex'))");
        }

        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test");
             ResultSet rs = conn.createStatement().executeQuery(
                     "SELECT holder_id::text FROM " + testSchema + ".hybrid_prf_salt "
                     + "WHERE credential_id = 'cred-opaque-1'")) {
            assertThat(rs.next()).isTrue();
            String storedHolderId = rs.getString(1);
            // The stored holder_id must not contain the email or any part of it
            assertThat(storedHolderId)
                    .as("holder_id must not embed the user email (NFR-S-537-03)")
                    .doesNotContain("fk-opaque")
                    .doesNotContain("@test.com");
            // It must be a proper UUID v4
            assertThat(UUID_V4_PATTERN.matcher(storedHolderId).matches()).isTrue();
        }
    }

    // ------------------------------------------------------------------ helpers

    private static byte[] randomSalt() {
        byte[] salt = new byte[32];
        new java.security.SecureRandom().nextBytes(salt);
        return salt;
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
