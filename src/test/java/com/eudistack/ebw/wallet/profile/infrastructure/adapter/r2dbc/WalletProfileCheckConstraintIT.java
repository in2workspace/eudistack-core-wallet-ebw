package com.eudistack.ebw.wallet.profile.infrastructure.adapter.r2dbc;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
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
 * Integration tests verifying that the CHECK constraint
 * {@code chk_wallet_profile_mode_manager} and the NOT NULL constraint on
 * {@code tenant} are enforced by PostgreSQL at the persistence layer.
 *
 * <p>Tests run against a shared TestContainers PostgreSQL instance. Each test
 * (or parameterized invocation) creates its own UUID-suffix schema to guarantee
 * full state isolation without requiring a fresh container per test.
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>AC-04 — {@code browser} + {@code key_manager} not null → SQLSTATE 23514</li>
 *   <li>AC-05 — {@code server} + {@code key_manager=NULL} → SQLSTATE 23514</li>
 *   <li>AC-05 — {@code server} + {@code key_manager} outside enum → SQLSTATE 23514</li>
 *   <li>EC-04 — UPDATE from coherent row to incoherent state → SQLSTATE 23514</li>
 *   <li>ES-01 — {@code tenant=NULL} → SQLSTATE 23502 (not_null_violation)</li>
 * </ul>
 *
 * @see WalletProfileBrowserSeedIT for browser happy-path tests
 * @see WalletProfileServerSeedIT for server happy-path tests
 * @see WalletProfileUpdateIT for coherent UPDATE scenarios
 */
@Tag("integration")
@Testcontainers
class WalletProfileCheckConstraintIT {

    /** SQLSTATE for check_violation (PostgreSQL). */
    private static final String SQLSTATE_CHECK_VIOLATION = "23514";

    /** SQLSTATE for not_null_violation (PostgreSQL). */
    private static final String SQLSTATE_NOT_NULL_VIOLATION = "23502";

    private static final String TENANT_SANDBOX = "sandbox";

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("check_constraint_test")
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

    /**
     * Inserts a server profile row with the given key_manager value.
     * Used as the pre-existing state for EC-04 and UPDATE tests.
     */
    private void insertServerProfile(Connection conn, String tenant, String keyManager)
            throws SQLException {
        conn.createStatement().execute(
                "INSERT INTO " + testSchema + ".tenant_wallet_profile"
                + " (tenant, wallet_mode, key_manager)"
                + " VALUES ('" + tenant + "', 'server', '" + keyManager + "')");
    }

    /**
     * Returns the row count for a given tenant in the current test schema.
     */
    private int countRows(Connection conn, String tenant) throws SQLException {
        try (ResultSet rs = conn.createStatement().executeQuery(
                "SELECT COUNT(*) FROM " + testSchema + ".tenant_wallet_profile"
                + " WHERE tenant = '" + tenant + "'")) {
            rs.next();
            return rs.getInt(1);
        }
    }

    // -------------------------------------------------------------------------
    // AC-04 — browser + key_manager not null → SQLSTATE 23514
    // -------------------------------------------------------------------------

    /**
     * AC-04: INSERT with {@code wallet_mode='browser'} and a non-null {@code key_manager}
     * is rejected by the CHECK constraint with SQLSTATE 23514.
     *
     * <p>Given the table exists, when an operator inserts {@code ('sandbox', 'browser', 'db')},
     * then PostgreSQL rejects the operation with SQLSTATE 23514 (check_violation) and
     * the row is not persisted.
     */
    @Test
    void browser_with_non_null_key_manager_violates_check_constraint() throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            try {
                conn.createStatement().execute(
                        "INSERT INTO " + testSchema + ".tenant_wallet_profile"
                        + " (tenant, wallet_mode, key_manager)"
                        + " VALUES ('" + TENANT_SANDBOX + "', 'browser', 'db')");
                fail("Expected SQLSTATE 23514 (check_violation) but no exception was thrown");
            } catch (SQLException ex) {
                assertThat(ex.getSQLState())
                        .as("browser + key_manager='db' must violate chk_wallet_profile_mode_manager"
                                + " — expected SQLSTATE 23514")
                        .isEqualTo(SQLSTATE_CHECK_VIOLATION);
            }
        }

        // The row must not have been persisted
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            assertThat(countRows(conn, TENANT_SANDBOX))
                    .as("no row must exist after rejected INSERT (browser + key_manager not null)")
                    .isEqualTo(0);
        }
    }

    /**
     * AC-04 (extended): All four server key_manager values are rejected when paired
     * with {@code wallet_mode='browser'}.
     *
     * @param keyManager one of {@code db}, {@code hybrid}, {@code hsm}, {@code qtsp}
     */
    @ParameterizedTest(name = "browser_with_key_manager_{0}_violates_check_constraint")
    @ValueSource(strings = {"db", "hybrid", "hsm", "qtsp"})
    void browser_with_any_key_manager_value_violates_check_constraint(String keyManager)
            throws SQLException {
        String tenant = "browser_km_" + keyManager;

        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            try {
                conn.createStatement().execute(
                        "INSERT INTO " + testSchema + ".tenant_wallet_profile"
                        + " (tenant, wallet_mode, key_manager)"
                        + " VALUES ('" + tenant + "', 'browser', '" + keyManager + "')");
                fail("Expected SQLSTATE 23514 but no exception was thrown for key_manager="
                        + keyManager);
            } catch (SQLException ex) {
                assertThat(ex.getSQLState())
                        .as("browser + key_manager='" + keyManager
                                + "' must violate CHECK — expected SQLSTATE 23514")
                        .isEqualTo(SQLSTATE_CHECK_VIOLATION);
            }
        }

        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            assertThat(countRows(conn, tenant))
                    .as("no row must be persisted after CHECK violation (browser + key_manager="
                            + keyManager + ")")
                    .isEqualTo(0);
        }
    }

    // -------------------------------------------------------------------------
    // AC-05 — server + key_manager=NULL → SQLSTATE 23514
    // -------------------------------------------------------------------------

    /**
     * AC-05: INSERT with {@code wallet_mode='server'} and {@code key_manager=NULL}
     * is rejected by the CHECK constraint with SQLSTATE 23514.
     *
     * <p>The CHECK requires server mode to have a non-null key_manager from the
     * allowed set; NULL violates this invariant.
     */
    @Test
    void server_with_null_key_manager_violates_check_constraint() throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            try {
                conn.createStatement().execute(
                        "INSERT INTO " + testSchema + ".tenant_wallet_profile"
                        + " (tenant, wallet_mode, key_manager)"
                        + " VALUES ('" + TENANT_SANDBOX + "', 'server', NULL)");
                fail("Expected SQLSTATE 23514 (check_violation) but no exception was thrown");
            } catch (SQLException ex) {
                assertThat(ex.getSQLState())
                        .as("server + key_manager=NULL must violate chk_wallet_profile_mode_manager"
                                + " — expected SQLSTATE 23514")
                        .isEqualTo(SQLSTATE_CHECK_VIOLATION);
            }
        }

        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            assertThat(countRows(conn, TENANT_SANDBOX))
                    .as("no row must exist after rejected INSERT (server + key_manager=NULL)")
                    .isEqualTo(0);
        }
    }

    /**
     * AC-05 (extended): INSERT with {@code wallet_mode='server'} and a
     * {@code key_manager} value outside the allowed enum is rejected with SQLSTATE 23514.
     *
     * <p>The CHECK constraint explicitly enumerates the allowed values
     * {@code ('db', 'hybrid', 'hsm', 'qtsp')}; any other value must be rejected.
     *
     * @param keyManager a value not in the allowed set
     */
    @ParameterizedTest(name = "server_with_invalid_key_manager_{0}_violates_check_constraint")
    @ValueSource(strings = {"not_in_enum", "cloud", "QTSP", "  ", ""})
    void server_with_key_manager_outside_enum_violates_check_constraint(String keyManager)
            throws SQLException {
        String tenant = "server_inv_" + UUID.randomUUID().toString().replace("-", "").substring(0, 6);

        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            try {
                conn.createStatement().execute(
                        "INSERT INTO " + testSchema + ".tenant_wallet_profile"
                        + " (tenant, wallet_mode, key_manager)"
                        + " VALUES ('" + tenant + "', 'server', '" + keyManager + "')");
                fail("Expected SQLSTATE 23514 but no exception was thrown for key_manager='"
                        + keyManager + "'");
            } catch (SQLException ex) {
                assertThat(ex.getSQLState())
                        .as("server + key_manager='" + keyManager
                                + "' (outside enum) must violate CHECK — expected SQLSTATE 23514")
                        .isEqualTo(SQLSTATE_CHECK_VIOLATION);
            }
        }

        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            assertThat(countRows(conn, tenant))
                    .as("no row must be persisted after CHECK violation (server + key_manager='"
                            + keyManager + "')")
                    .isEqualTo(0);
        }
    }

    // -------------------------------------------------------------------------
    // EC-04 — UPDATE incoherent: server + db → browser without nullifying key_manager
    // -------------------------------------------------------------------------

    /**
     * EC-04: UPDATE that changes only {@code wallet_mode} from {@code 'server'} to
     * {@code 'browser'} without also nullifying {@code key_manager} is rejected by
     * the CHECK constraint with SQLSTATE 23514.
     *
     * <p>Given the table contains {@code ('sandbox', 'server', 'db')}, when an operator
     * executes {@code UPDATE … SET wallet_mode='browser'} (leaving {@code key_manager='db'}),
     * then PostgreSQL rejects the UPDATE and the row reverts to its pre-update state.
     */
    @Test
    void update_violates_check_when_wallet_mode_changed_without_nullifying_key_manager()
            throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            insertServerProfile(conn, TENANT_SANDBOX, "db");
        }

        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            try {
                conn.createStatement().execute(
                        "UPDATE " + testSchema + ".tenant_wallet_profile"
                        + " SET wallet_mode = 'browser'"
                        + " WHERE tenant = '" + TENANT_SANDBOX + "'");
                fail("Expected SQLSTATE 23514 (check_violation) but no exception was thrown");
            } catch (SQLException ex) {
                assertThat(ex.getSQLState())
                        .as("UPDATE setting wallet_mode='browser' without nullifying key_manager"
                                + " must violate CHECK — expected SQLSTATE 23514")
                        .isEqualTo(SQLSTATE_CHECK_VIOLATION);
            }
        }

        // The row must have been preserved in its original pre-update state
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            try (ResultSet rs = conn.createStatement().executeQuery(
                    "SELECT wallet_mode, key_manager"
                    + " FROM " + testSchema + ".tenant_wallet_profile"
                    + " WHERE tenant = '" + TENANT_SANDBOX + "'")) {

                assertThat(rs.next())
                        .as("original row must still exist after rejected UPDATE")
                        .isTrue();
                assertThat(rs.getString("wallet_mode"))
                        .as("wallet_mode must remain 'server' after rejected UPDATE")
                        .isEqualTo("server");
                assertThat(rs.getString("key_manager"))
                        .as("key_manager must remain 'db' after rejected UPDATE")
                        .isEqualTo("db");
            }
        }
    }

    // -------------------------------------------------------------------------
    // ES-01 — tenant=NULL → SQLSTATE 23502 (not_null_violation)
    // -------------------------------------------------------------------------

    /**
     * ES-01: INSERT with {@code tenant=NULL} is rejected by the NOT NULL constraint
     * on the primary key column with SQLSTATE 23502 (not_null_violation).
     *
     * <p>The {@code tenant} column is the primary key; PostgreSQL forbids NULL PKs
     * regardless of the CHECK constraint.
     */
    @Test
    void insert_null_tenant_rejected_with_not_null_violation() throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            try {
                conn.createStatement().execute(
                        "INSERT INTO " + testSchema + ".tenant_wallet_profile"
                        + " (tenant, wallet_mode)"
                        + " VALUES (NULL, 'browser')");
                fail("Expected SQLSTATE 23502 (not_null_violation) but no exception was thrown");
            } catch (SQLException ex) {
                assertThat(ex.getSQLState())
                        .as("tenant=NULL must violate NOT NULL constraint"
                                + " — expected SQLSTATE 23502")
                        .isEqualTo(SQLSTATE_NOT_NULL_VIOLATION);
            }
        }
    }
}