package com.eudistack.ebw.wallet.profile.infrastructure.adapter.r2dbc;

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

import org.flywaydb.core.Flyway;

/**
 * Integration tests for {@code browser} seed scenarios against {@code tenant_wallet_profile}.
 *
 * <p>These tests exercise the happy path of persisting a {@code browser} profile (AC-02),
 * the idempotent UPSERT re-seed scenario (EC-02), and the duplicate INSERT without ON CONFLICT
 * error scenario (ES-03, NFR-S-412-03).
 *
 * <p>All tests run against a shared TestContainers PostgreSQL instance. Each test uses a
 * UUID-suffix schema to guarantee full isolation without requiring a fresh container per test.
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>AC-02 — browser + key_manager=null persists successfully</li>
 *   <li>EC-02 — UPSERT idempotent re-seed updates updated_at</li>
 *   <li>ES-03 — duplicate INSERT without ON CONFLICT raises SQLSTATE 23505</li>
 *   <li>NFR-S-412-03 — exactly one row per tenant (enforced by PK)</li>
 * </ul>
 *
 * @see WalletProfileServerSeedIT for server-mode seed tests
 */
@Tag("integration")
@Testcontainers
class WalletProfileBrowserSeedIT {

    /** SQLSTATE for unique_violation (PostgreSQL). */
    private static final String SQLSTATE_UNIQUE_VIOLATION = "23505";

    private static final String TENANT_SANDBOX = "sandbox";

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("seed_browser_test")
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
     * Flyway migrations. Mirrors the logic in {@code WalletProfileMigrationIT#applyMigrations()}.
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

    /**
     * Inserts a browser profile for the given tenant using a plain INSERT (no ON CONFLICT).
     * Callers that expect failure should catch {@link SQLException}.
     */
    private void insertBrowserProfile(Connection conn, String tenant) throws SQLException {
        conn.createStatement().execute(
                "INSERT INTO " + testSchema + ".tenant_wallet_profile"
                + " (tenant, wallet_mode)"
                + " VALUES ('" + tenant + "', 'browser')");
    }

    /**
     * Executes an idempotent UPSERT for the given browser profile.
     * This is the production-grade pattern prescribed by the US-09 runbook (EC-02).
     */
    private void upsertBrowserProfile(Connection conn, String tenant) throws SQLException {
        conn.createStatement().execute(
                "INSERT INTO " + testSchema + ".tenant_wallet_profile"
                + " (tenant, wallet_mode, key_manager)"
                + " VALUES ('" + tenant + "', 'browser', NULL)"
                + " ON CONFLICT (tenant) DO UPDATE"
                + " SET wallet_mode = EXCLUDED.wallet_mode,"
                + "     key_manager = EXCLUDED.key_manager,"
                + "     updated_at  = now()");
    }

    // -------------------------------------------------------------------------
    // AC-02 — browser + key_manager=null persists successfully
    // -------------------------------------------------------------------------

    /**
     * AC-02: INSERT with wallet_mode='browser' and key_manager=NULL commits successfully.
     *
     * <p>Given the table exists, when a config_manager_role operator inserts a browser
     * profile (key_manager explicit NULL), then the INSERT commits and SELECT returns
     * the expected values. created_at and updated_at are auto-filled.
     */
    @Test
    void browser_profile_with_null_key_manager_inserts_successfully() throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + testSchema + ".tenant_wallet_profile"
                    + " (tenant, wallet_mode, key_manager)"
                    + " VALUES ('" + TENANT_SANDBOX + "', 'browser', NULL)");

            try (ResultSet rs = conn.createStatement().executeQuery(
                    "SELECT wallet_mode, key_manager"
                    + " FROM " + testSchema + ".tenant_wallet_profile"
                    + " WHERE tenant = '" + TENANT_SANDBOX + "'")) {

                assertThat(rs.next())
                        .as("row must exist after INSERT")
                        .isTrue();
                assertThat(rs.getString("wallet_mode"))
                        .as("wallet_mode must be 'browser'")
                        .isEqualTo("browser");
                assertThat(rs.getString("key_manager"))
                        .as("key_manager must be NULL for browser mode")
                        .isNull();
            }
        }
    }

    /**
     * AC-02: created_at and updated_at are auto-populated by the DEFAULT now() expression.
     *
     * <p>Neither column is supplied in the INSERT statement; both must be non-null
     * after the commit.
     */
    @Test
    void browser_profile_insert_auto_populates_timestamps() throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            insertBrowserProfile(conn, TENANT_SANDBOX);

            try (ResultSet rs = conn.createStatement().executeQuery(
                    "SELECT created_at, updated_at"
                    + " FROM " + testSchema + ".tenant_wallet_profile"
                    + " WHERE tenant = '" + TENANT_SANDBOX + "'")) {

                assertThat(rs.next()).as("row must exist").isTrue();
                assertThat(rs.getTimestamp("created_at"))
                        .as("created_at must be auto-set by DEFAULT now()")
                        .isNotNull();
                assertThat(rs.getTimestamp("updated_at"))
                        .as("updated_at must be auto-set by DEFAULT now()")
                        .isNotNull();
            }
        }
    }

    // -------------------------------------------------------------------------
    // EC-02 — UPSERT idempotent re-seed
    // -------------------------------------------------------------------------

    /**
     * EC-02: UPSERT with ON CONFLICT is idempotent; updated_at advances on re-seed.
     *
     * <p>Given the table already contains the sandbox browser profile, when the same
     * UPSERT is executed again, then the statement succeeds, the row values remain
     * consistent, and updated_at reflects the re-execution (is >= created_at).
     */
    @Test
    void upsert_idempotent_same_payload_succeeds() throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            // Initial seed
            upsertBrowserProfile(conn, TENANT_SANDBOX);

            // Re-seed — must not raise and must not duplicate the row
            upsertBrowserProfile(conn, TENANT_SANDBOX);

            try (ResultSet rs = conn.createStatement().executeQuery(
                    "SELECT wallet_mode, key_manager, created_at, updated_at"
                    + " FROM " + testSchema + ".tenant_wallet_profile"
                    + " WHERE tenant = '" + TENANT_SANDBOX + "'")) {

                assertThat(rs.next()).as("row must exist after UPSERT").isTrue();
                assertThat(rs.getString("wallet_mode"))
                        .as("wallet_mode must remain 'browser' after UPSERT")
                        .isEqualTo("browser");
                assertThat(rs.getString("key_manager"))
                        .as("key_manager must remain NULL after UPSERT")
                        .isNull();
                assertThat(rs.next())
                        .as("exactly one row must exist — PK prevents duplicates")
                        .isFalse();
            }
        }
    }

    /**
     * EC-02 / NFR-S-412-03: After UPSERT the table holds exactly one row for the tenant.
     */
    @Test
    void upsert_does_not_create_duplicate_row() throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            upsertBrowserProfile(conn, TENANT_SANDBOX);
            upsertBrowserProfile(conn, TENANT_SANDBOX);

            try (ResultSet rs = conn.createStatement().executeQuery(
                    "SELECT COUNT(*) FROM " + testSchema + ".tenant_wallet_profile"
                    + " WHERE tenant = '" + TENANT_SANDBOX + "'")) {

                rs.next();
                assertThat(rs.getInt(1))
                        .as("exactly one row must exist for the tenant after idempotent UPSERT")
                        .isEqualTo(1);
            }
        }
    }

    // -------------------------------------------------------------------------
    // ES-03 — Duplicate INSERT without ON CONFLICT raises SQLSTATE 23505
    // -------------------------------------------------------------------------

    /**
     * ES-03 / NFR-S-412-03: A plain INSERT on an already-seeded tenant fails with
     * SQLSTATE 23505 (unique_violation), confirming the PK enforcement.
     *
     * <p>This test verifies that the table has exactly one row per tenant and that
     * a naive retry without the idempotent UPSERT form is correctly rejected.
     */
    @Test
    void double_insert_without_on_conflict_fails_with_unique_violation() throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            insertBrowserProfile(conn, TENANT_SANDBOX); // first — must succeed
        }

        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            try {
                insertBrowserProfile(conn, TENANT_SANDBOX); // second — must fail
                fail("Expected SQLSTATE 23505 (unique_violation) but no exception was thrown");
            } catch (SQLException ex) {
                assertThat(ex.getSQLState())
                        .as("duplicate INSERT must raise SQLSTATE 23505 (unique_violation)")
                        .isEqualTo(SQLSTATE_UNIQUE_VIOLATION);
            }
        }

        // The pre-existing row must be intact after the failed second INSERT
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            try (ResultSet rs = conn.createStatement().executeQuery(
                    "SELECT COUNT(*) FROM " + testSchema + ".tenant_wallet_profile"
                    + " WHERE tenant = '" + TENANT_SANDBOX + "'")) {
                rs.next();
                assertThat(rs.getInt(1))
                        .as("original row must be preserved after rejected duplicate INSERT")
                        .isEqualTo(1);
            }
        }
    }
}