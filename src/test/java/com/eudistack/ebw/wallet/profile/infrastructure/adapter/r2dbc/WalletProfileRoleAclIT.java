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
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Integration tests verifying the ACL matrix on {@code tenant_wallet_profile}
 * as defined in architecture.md AD-2 and enforced by {@code V3__Wallet_profile.sql}.
 *
 * <p>Tests use a shared TestContainers PostgreSQL instance. The setup creates
 * the group roles ({@code ebw_app_role}, {@code config_manager_role}) and two
 * matching login users ({@code ebw_app_user}, {@code config_manager_user}) whose
 * active role is set to the corresponding group role via {@code SET ROLE} after
 * each connection. This mirrors production: the EBW service connects as a login
 * user that is a member of {@code ebw_app_role}.
 *
 * <p>Each test creates its own UUID-suffix schema so state does not leak across
 * test methods even though the container is shared across the class.
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>AC-06 — {@code ebw_app_role} has SELECT; INSERT/UPDATE/DELETE are denied
 *       (SQLSTATE 42501)</li>
 *   <li>AC-06 — {@code config_manager_role} has SELECT/INSERT/UPDATE; DELETE is denied</li>
 *   <li>AC-06 — no role has DELETE</li>
 *   <li>EC-05 — SELECT from a connection acting as {@code ebw_app_role} completes
 *       successfully and returns the seeded row</li>
 *   <li>NFR-S-412-02 — all three ACL scenarios are green in CI</li>
 * </ul>
 *
 * @see WalletProfileMigrationIT for Flyway migration structure tests
 * @see WalletProfileCheckConstraintIT for CHECK constraint tests
 */
@Tag("integration")
@Testcontainers
class WalletProfileRoleAclIT {

    /** SQLSTATE for insufficient_privilege (PostgreSQL). */
    private static final String SQLSTATE_INSUFFICIENT_PRIVILEGE = "42501";

    private static final String TENANT_SANDBOX = "sandbox";

    /** Login username whose active role is set to {@code ebw_app_role}. */
    private static final String EBW_APP_USER = "ebw_app_user";

    /** Login username whose active role is set to {@code config_manager_role}. */
    private static final String CONFIG_MANAGER_USER = "config_manager_user";

    private static final String USER_PASSWORD = "testpass";

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("acl_test")
                    .withUsername("test")
                    .withPassword("test");

    /** Schema for the current test — UUID-suffix ensures isolation. */
    private String testSchema;
    private String jdbcUrl;

    @BeforeEach
    void setUp() throws SQLException {
        jdbcUrl = postgres.getJdbcUrl();
        testSchema = "twp_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        provisionRolesAndMigrate();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Creates the group roles ({@code ebw_app_role}, {@code config_manager_role}),
     * the login users that are members of each group role, the test schema, and
     * applies all tenant Flyway migrations (including the GRANTs in V3).
     *
     * <p>Role and user creation are wrapped in {@code DO ... EXCEPTION} blocks so
     * this method is safely re-entrant when the container is reused across tests
     * (the roles are created at DB level, not schema level, so they survive across
     * schema-isolated test methods).
     *
     * <p>Granting USAGE on the schema to both roles allows the login users to
     * resolve objects within the schema after {@code SET ROLE}.
     */
    private void provisionRolesAndMigrate() throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            // Group roles (non-login)
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

            // Login users that are members of the corresponding group role
            conn.createStatement().execute(
                    "DO $$ BEGIN "
                    + "CREATE ROLE " + EBW_APP_USER
                    + " LOGIN PASSWORD '" + USER_PASSWORD + "'; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; "
                    + "END $$");
            conn.createStatement().execute(
                    "DO $$ BEGIN "
                    + "CREATE ROLE " + CONFIG_MANAGER_USER
                    + " LOGIN PASSWORD '" + USER_PASSWORD + "'; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; "
                    + "END $$");

            // Membership: login user → group role
            conn.createStatement().execute(
                    "DO $$ BEGIN "
                    + "GRANT ebw_app_role TO " + EBW_APP_USER + "; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; "
                    + "END $$");
            conn.createStatement().execute(
                    "DO $$ BEGIN "
                    + "GRANT config_manager_role TO " + CONFIG_MANAGER_USER + "; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; "
                    + "END $$");

            // Schema
            conn.createStatement().execute("CREATE SCHEMA IF NOT EXISTS " + testSchema);

            // Allow login users to look up objects in the schema (required after SET ROLE)
            conn.createStatement().execute(
                    "GRANT USAGE ON SCHEMA " + testSchema + " TO ebw_app_role");
            conn.createStatement().execute(
                    "GRANT USAGE ON SCHEMA " + testSchema + " TO config_manager_role");
        }

        // Apply tenant Flyway migrations (V3 GRANTs ebw_app_role SELECT and
        // config_manager_role SELECT/INSERT/UPDATE inside the schema)
        Flyway.configure()
                .dataSource(jdbcUrl, "test", "test")
                .locations("classpath:db/tenant")
                .defaultSchema(testSchema)
                .schemas(testSchema)
                .table("flyway_schema_history")
                .baselineOnMigrate(true)
                .load()
                .migrate();

        // Seed a row so SELECT tests can verify actual data retrieval
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + testSchema + ".tenant_wallet_profile"
                    + " (tenant, wallet_mode, key_manager)"
                    + " VALUES ('" + TENANT_SANDBOX + "', 'browser', NULL)");
        }
    }

    /**
     * Opens a JDBC connection as the given login user and immediately sets the
     * active role to the corresponding group role.
     *
     * <p>This mirrors the production setup where the EBW runtime connects as a
     * service account ({@code ebw_app_user}) and the effective privileges come
     * from the group role ({@code ebw_app_role}).
     *
     * @param loginUser  the login user to authenticate as
     * @param groupRole  the group role to activate via {@code SET ROLE}
     * @return an open connection with the active role set
     */
    private Connection connectionAs(String loginUser, String groupRole) throws SQLException {
        // Extract the base host/port/db from the JDBC URL to build a URL for the login user
        String baseUrl = jdbcUrl.replaceFirst("\\?.*", ""); // strip any existing query params
        Connection conn = DriverManager.getConnection(baseUrl, loginUser, USER_PASSWORD);
        conn.createStatement().execute("SET ROLE " + groupRole);
        conn.createStatement().execute("SET search_path TO " + testSchema);
        return conn;
    }

    // -------------------------------------------------------------------------
    // EC-05 — ebw_app_role can SELECT
    // -------------------------------------------------------------------------

    /**
     * EC-05: A connection acting as {@code ebw_app_role} can execute SELECT on
     * {@code tenant_wallet_profile} and retrieves the seeded row correctly.
     *
     * <p>Given the migration has been applied and a browser profile is seeded,
     * when the EBW application (acting as {@code ebw_app_role}) calls SELECT,
     * then the query completes without error and returns the expected row.
     */
    @Test
    void ebw_app_role_can_select_from_tenant_wallet_profile() throws SQLException {
        try (Connection conn = connectionAs(EBW_APP_USER, "ebw_app_role")) {
            try (ResultSet rs = conn.createStatement().executeQuery(
                    "SELECT wallet_mode, key_manager"
                    + " FROM tenant_wallet_profile"
                    + " WHERE tenant = '" + TENANT_SANDBOX + "'")) {

                assertThat(rs.next())
                        .as("ebw_app_role must be able to SELECT — seeded row must be visible")
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

    // -------------------------------------------------------------------------
    // AC-06 — ebw_app_role INSERT denied (SQLSTATE 42501)
    // -------------------------------------------------------------------------

    /**
     * AC-06: A connection acting as {@code ebw_app_role} is denied INSERT on
     * {@code tenant_wallet_profile} with SQLSTATE 42501 (insufficient_privilege).
     *
     * <p>The EBW runtime must only read the profile; write access would violate
     * the operator-only mutation contract (architecture.md AD-2).
     */
    @Test
    void ebw_app_role_insert_denied_with_insufficient_privilege() throws SQLException {
        try (Connection conn = connectionAs(EBW_APP_USER, "ebw_app_role")) {
            try {
                conn.createStatement().execute(
                        "INSERT INTO tenant_wallet_profile"
                        + " (tenant, wallet_mode, key_manager)"
                        + " VALUES ('ebw_should_not_write', 'browser', NULL)");
                fail("Expected SQLSTATE 42501 (insufficient_privilege) for INSERT as ebw_app_role"
                        + " but no exception was thrown");
            } catch (SQLException ex) {
                assertThat(ex.getSQLState())
                        .as("INSERT as ebw_app_role must be denied with SQLSTATE 42501"
                                + " (insufficient_privilege / permission denied)")
                        .isEqualTo(SQLSTATE_INSUFFICIENT_PRIVILEGE);
            }
        }
    }

    /**
     * AC-06: A connection acting as {@code ebw_app_role} is denied UPDATE on
     * {@code tenant_wallet_profile} with SQLSTATE 42501 (insufficient_privilege).
     */
    @Test
    void ebw_app_role_update_denied_with_insufficient_privilege() throws SQLException {
        try (Connection conn = connectionAs(EBW_APP_USER, "ebw_app_role")) {
            try {
                conn.createStatement().execute(
                        "UPDATE tenant_wallet_profile"
                        + " SET wallet_mode = 'server', key_manager = 'db'"
                        + " WHERE tenant = '" + TENANT_SANDBOX + "'");
                fail("Expected SQLSTATE 42501 (insufficient_privilege) for UPDATE as ebw_app_role"
                        + " but no exception was thrown");
            } catch (SQLException ex) {
                assertThat(ex.getSQLState())
                        .as("UPDATE as ebw_app_role must be denied with SQLSTATE 42501"
                                + " (insufficient_privilege / permission denied)")
                        .isEqualTo(SQLSTATE_INSUFFICIENT_PRIVILEGE);
            }
        }
    }

    /**
     * AC-06: No role has DELETE on {@code tenant_wallet_profile}.
     *
     * <p>A tenant that is deactivated is flagged — never deleted
     * (architecture.md AD-2 Consequences). {@code ebw_app_role} must not have
     * DELETE; verifying that the EBW runtime role cannot accidentally delete rows.
     */
    @Test
    void ebw_app_role_delete_denied_with_insufficient_privilege() throws SQLException {
        try (Connection conn = connectionAs(EBW_APP_USER, "ebw_app_role")) {
            try {
                conn.createStatement().execute(
                        "DELETE FROM tenant_wallet_profile"
                        + " WHERE tenant = '" + TENANT_SANDBOX + "'");
                fail("Expected SQLSTATE 42501 (insufficient_privilege) for DELETE as ebw_app_role"
                        + " but no exception was thrown");
            } catch (SQLException ex) {
                assertThat(ex.getSQLState())
                        .as("DELETE as ebw_app_role must be denied with SQLSTATE 42501"
                                + " — no role has DELETE (architecture.md AD-2 Consequences)")
                        .isEqualTo(SQLSTATE_INSUFFICIENT_PRIVILEGE);
            }
        }
    }

    // -------------------------------------------------------------------------
    // AC-06 — config_manager_role has SELECT/INSERT/UPDATE; DELETE denied
    // -------------------------------------------------------------------------

    /**
     * AC-06: A connection acting as {@code config_manager_role} can SELECT from
     * {@code tenant_wallet_profile}.
     */
    @Test
    void config_manager_role_can_select_from_tenant_wallet_profile() throws SQLException {
        try (Connection conn = connectionAs(CONFIG_MANAGER_USER, "config_manager_role")) {
            try (ResultSet rs = conn.createStatement().executeQuery(
                    "SELECT wallet_mode FROM tenant_wallet_profile"
                    + " WHERE tenant = '" + TENANT_SANDBOX + "'")) {

                assertThat(rs.next())
                        .as("config_manager_role must be able to SELECT — seeded row must be visible")
                        .isTrue();
                assertThat(rs.getString("wallet_mode"))
                        .as("wallet_mode must be 'browser'")
                        .isEqualTo("browser");
            }
        }
    }

    /**
     * AC-06: A connection acting as {@code config_manager_role} can INSERT into
     * {@code tenant_wallet_profile} (the configuration manager is the operator
     * responsible for provisioning tenant profiles).
     */
    @Test
    void config_manager_role_can_insert_into_tenant_wallet_profile() throws SQLException {
        String newTenant = "dome_" + UUID.randomUUID().toString().replace("-", "").substring(0, 6);

        try (Connection conn = connectionAs(CONFIG_MANAGER_USER, "config_manager_role")) {
            // Must not throw
            conn.createStatement().execute(
                    "INSERT INTO tenant_wallet_profile"
                    + " (tenant, wallet_mode, key_manager)"
                    + " VALUES ('" + newTenant + "', 'server', 'db')");
        }

        // Verify the row exists (using superuser connection to avoid role assumptions)
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            try (ResultSet rs = conn.createStatement().executeQuery(
                    "SELECT wallet_mode, key_manager"
                    + " FROM " + testSchema + ".tenant_wallet_profile"
                    + " WHERE tenant = '" + newTenant + "'")) {

                assertThat(rs.next())
                        .as("row inserted by config_manager_role must be visible")
                        .isTrue();
                assertThat(rs.getString("wallet_mode"))
                        .as("wallet_mode must be 'server'")
                        .isEqualTo("server");
                assertThat(rs.getString("key_manager"))
                        .as("key_manager must be 'db'")
                        .isEqualTo("db");
            }
        }
    }

    /**
     * AC-06: A connection acting as {@code config_manager_role} can UPDATE
     * {@code tenant_wallet_profile}.
     */
    @Test
    void config_manager_role_can_update_tenant_wallet_profile() throws SQLException {
        try (Connection conn = connectionAs(CONFIG_MANAGER_USER, "config_manager_role")) {
            int affected = conn.createStatement().executeUpdate(
                    "UPDATE tenant_wallet_profile"
                    + " SET wallet_mode = 'server',"
                    + "     key_manager = 'db',"
                    + "     updated_at  = now()"
                    + " WHERE tenant = '" + TENANT_SANDBOX + "'");

            assertThat(affected)
                    .as("exactly one row must be updated by config_manager_role")
                    .isEqualTo(1);
        }

        // Verify the updated values using a superuser connection
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            try (ResultSet rs = conn.createStatement().executeQuery(
                    "SELECT wallet_mode, key_manager"
                    + " FROM " + testSchema + ".tenant_wallet_profile"
                    + " WHERE tenant = '" + TENANT_SANDBOX + "'")) {

                assertThat(rs.next()).as("row must still exist after UPDATE").isTrue();
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
     * AC-06: A connection acting as {@code config_manager_role} is denied DELETE on
     * {@code tenant_wallet_profile} with SQLSTATE 42501 (insufficient_privilege).
     *
     * <p>DELETE is intentionally omitted from all GRANTs: deactivated tenants are
     * flagged, never deleted (architecture.md AD-2 Consequences).
     */
    @Test
    void config_manager_role_delete_denied_with_insufficient_privilege() throws SQLException {
        try (Connection conn = connectionAs(CONFIG_MANAGER_USER, "config_manager_role")) {
            try {
                conn.createStatement().execute(
                        "DELETE FROM tenant_wallet_profile"
                        + " WHERE tenant = '" + TENANT_SANDBOX + "'");
                fail("Expected SQLSTATE 42501 (insufficient_privilege) for DELETE as"
                        + " config_manager_role but no exception was thrown");
            } catch (SQLException ex) {
                assertThat(ex.getSQLState())
                        .as("DELETE as config_manager_role must be denied with SQLSTATE 42501"
                                + " — DELETE is intentionally omitted from all GRANTs"
                                + " (architecture.md AD-2 Consequences)")
                        .isEqualTo(SQLSTATE_INSUFFICIENT_PRIVILEGE);
            }
        }
    }
}
