package com.eudistack.ebw.wallet.profile.infrastructure.adapter.r2dbc;

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
import java.sql.Timestamp;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests verifying coherent UPDATE scenarios against
 * {@code tenant_wallet_profile}.
 *
 * <p>Tests run against a shared TestContainers PostgreSQL instance. Each test
 * creates its own UUID-suffix schema to guarantee full state isolation without
 * requiring a fresh container per test.
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>EC-03 — UPDATE from {@code browser} to {@code server + db} commits successfully,
 *       the row reflects the new values, the CHECK validates the new combination, and
 *       {@code updated_at} advances</li>
 * </ul>
 *
 * <p>Incoherent UPDATE scenarios (EC-04) are covered by
 * {@link WalletProfileCheckConstraintIT}.
 *
 * @see WalletProfileCheckConstraintIT for constraint-violation UPDATE tests
 */
@Tag("integration")
@Testcontainers
class WalletProfileUpdateIT {

    private static final String TENANT_SANDBOX = "sandbox";

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("update_test")
                    .withUsername("test")
                    .withPassword("test");

    /** Schema for the current test — UUID-suffix ensures isolation. */
    private String testSchema;
    private String jdbcUrl;

    @BeforeEach
    void setUp() throws SQLException {
        jdbcUrl = postgres.getJdbcUrl();
        testSchema = "twp_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        applyMigrations();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Creates the required DB roles and target schema, then applies all tenant
     * Flyway migrations. Mirrors the helper in {@code WalletProfileMigrationIT}.
     */
    private void applyMigrations() throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "DO $$ BEGIN "
                    + "CREATE ROLE ebw_app_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; "
                    + "END $$");
            conn.createStatement().execute(
                    "DO $$ BEGIN "
                    + "CREATE ROLE config_manager_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; "
                    + "END $$");
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

    // -------------------------------------------------------------------------
    // EC-03 — UPDATE browser → server + db
    // -------------------------------------------------------------------------

    /**
     * EC-03: A coherent UPDATE from {@code (browser, NULL)} to {@code (server, 'db')}
     * commits successfully and the row reflects the new values.
     *
     * <p>Given the table contains {@code ('sandbox', 'browser', NULL)}, when an operator
     * with config_manager_role executes
     * {@code UPDATE … SET wallet_mode='server', key_manager='db', updated_at=now()},
     * then the UPDATE commits, the resulting row is {@code ('sandbox', 'server', 'db')},
     * and the CHECK constraint validates the new combination.
     */
    @Test
    void update_browser_to_server_db_commits_successfully() throws SQLException {
        // Arrange: seed the initial browser profile
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + testSchema + ".tenant_wallet_profile"
                    + " (tenant, wallet_mode, key_manager)"
                    + " VALUES ('" + TENANT_SANDBOX + "', 'browser', NULL)");
        }

        // Act: UPDATE to server + db in a single coherent statement
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            int affected = conn.createStatement().executeUpdate(
                    "UPDATE " + testSchema + ".tenant_wallet_profile"
                    + " SET wallet_mode = 'server',"
                    + "     key_manager = 'db',"
                    + "     updated_at  = now()"
                    + " WHERE tenant = '" + TENANT_SANDBOX + "'");
            assertThat(affected)
                    .as("exactly one row must be updated")
                    .isEqualTo(1);
        }

        // Assert: the row now holds the new values
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            try (ResultSet rs = conn.createStatement().executeQuery(
                    "SELECT wallet_mode, key_manager"
                    + " FROM " + testSchema + ".tenant_wallet_profile"
                    + " WHERE tenant = '" + TENANT_SANDBOX + "'")) {

                assertThat(rs.next())
                        .as("row must still exist after UPDATE")
                        .isTrue();
                assertThat(rs.getString("wallet_mode"))
                        .as("wallet_mode must be 'server' after UPDATE")
                        .isEqualTo("server");
                assertThat(rs.getString("key_manager"))
                        .as("key_manager must be 'db' after UPDATE")
                        .isEqualTo("db");
            }
        }
    }

    /**
     * EC-03 (extended): {@code updated_at} advances to reflect the UPDATE.
     *
     * <p>The UPDATE statement sets {@code updated_at=now()} explicitly. The resulting
     * {@code updated_at} value must be greater than or equal to {@code created_at},
     * confirming the timestamp was refreshed by the operation.
     */
    @Test
    void update_browser_to_server_db_refreshes_updated_at() throws SQLException {
        // Arrange: seed browser profile and capture created_at
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + testSchema + ".tenant_wallet_profile"
                    + " (tenant, wallet_mode, key_manager)"
                    + " VALUES ('" + TENANT_SANDBOX + "', 'browser', NULL)");
        }

        Timestamp createdAt;
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            try (ResultSet rs = conn.createStatement().executeQuery(
                    "SELECT created_at FROM " + testSchema + ".tenant_wallet_profile"
                    + " WHERE tenant = '" + TENANT_SANDBOX + "'")) {
                rs.next();
                createdAt = rs.getTimestamp("created_at");
            }
        }

        // Act: UPDATE — updated_at set to now()
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().executeUpdate(
                    "UPDATE " + testSchema + ".tenant_wallet_profile"
                    + " SET wallet_mode = 'server',"
                    + "     key_manager = 'db',"
                    + "     updated_at  = now()"
                    + " WHERE tenant = '" + TENANT_SANDBOX + "'");
        }

        // Assert: updated_at is not null and is >= created_at
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            try (ResultSet rs = conn.createStatement().executeQuery(
                    "SELECT created_at, updated_at"
                    + " FROM " + testSchema + ".tenant_wallet_profile"
                    + " WHERE tenant = '" + TENANT_SANDBOX + "'")) {

                assertThat(rs.next()).as("row must exist").isTrue();
                Timestamp updatedAt = rs.getTimestamp("updated_at");
                assertThat(updatedAt)
                        .as("updated_at must be non-null after UPDATE")
                        .isNotNull();
                assertThat(updatedAt.getTime())
                        .as("updated_at must be >= created_at after UPDATE")
                        .isGreaterThanOrEqualTo(createdAt.getTime());
            }
        }
    }

    /**
     * EC-03 (completeness): After the UPDATE only one row exists for the tenant.
     *
     * <p>Verifies the UPDATE does not accidentally insert an extra row.
     */
    @Test
    void update_browser_to_server_db_does_not_duplicate_row() throws SQLException {
        // Arrange
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + testSchema + ".tenant_wallet_profile"
                    + " (tenant, wallet_mode, key_manager)"
                    + " VALUES ('" + TENANT_SANDBOX + "', 'browser', NULL)");
        }

        // Act
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().executeUpdate(
                    "UPDATE " + testSchema + ".tenant_wallet_profile"
                    + " SET wallet_mode = 'server',"
                    + "     key_manager = 'db',"
                    + "     updated_at  = now()"
                    + " WHERE tenant = '" + TENANT_SANDBOX + "'");
        }

        // Assert: still exactly one row
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            try (ResultSet rs = conn.createStatement().executeQuery(
                    "SELECT COUNT(*) FROM " + testSchema + ".tenant_wallet_profile"
                    + " WHERE tenant = '" + TENANT_SANDBOX + "'")) {
                rs.next();
                assertThat(rs.getInt(1))
                        .as("exactly one row must remain after UPDATE — no spurious duplicates")
                        .isEqualTo(1);
            }
        }
    }
}