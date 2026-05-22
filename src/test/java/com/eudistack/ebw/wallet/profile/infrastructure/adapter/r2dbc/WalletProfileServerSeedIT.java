package com.eudistack.ebw.wallet.profile.infrastructure.adapter.r2dbc;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
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

/**
 * Integration tests for {@code server} seed scenarios against {@code tenant_wallet_profile}.
 *
 * <p>Parameterized over all valid {@code key_manager} values — {@code db}, {@code hybrid},
 * {@code hsm}, {@code qtsp} — as required by AC-03.
 *
 * <p>Each parameterized invocation runs in an isolated UUID-suffix schema to prevent
 * any state leakage. The same shared TestContainers PostgreSQL instance is used for all
 * tests in the class to keep suite startup cost low.
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>AC-03 — server + key_manager ∈ {db, hybrid, hsm, qtsp} persists successfully for each value</li>
 * </ul>
 *
 * @see WalletProfileBrowserSeedIT for browser-mode seed tests
 */
@Tag("integration")
@Testcontainers
class WalletProfileServerSeedIT {

    private static final String TENANT_PREFIX = "tenant_server_";

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("seed_server_test")
                    .withUsername("test")
                    .withPassword("test");

    private String jdbcUrl;

    @BeforeEach
    void setUp() {
        jdbcUrl = postgres.getJdbcUrl();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Creates the required DB roles (idempotent via DO-block), creates the target schema,
     * and applies all tenant Flyway migrations. Each call uses a caller-provided schema name,
     * so parameterized tests can each have their own fully isolated schema.
     */
    private void applyMigrations(String schema) throws SQLException {
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
            conn.createStatement().execute("CREATE SCHEMA IF NOT EXISTS " + schema);
        }
        Flyway.configure()
                .dataSource(jdbcUrl, "test", "test")
                .locations("classpath:db/tenant")
                .defaultSchema(schema)
                .schemas(schema)
                .table("flyway_schema_history")
                .baselineOnMigrate(true)
                .load()
                .migrate();
    }

    /**
     * Builds a unique schema name for each parameterized invocation, ensuring isolation
     * when the same container is shared across runs.
     *
     * @param keyManager the key_manager value under test — used as a human-readable suffix
     */
    private String schemaFor(String keyManager) {
        return "twp_" + keyManager + "_" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    }

    // -------------------------------------------------------------------------
    // AC-03 — server + key_manager ∈ {db, hybrid, hsm, qtsp}
    // -------------------------------------------------------------------------

    /**
     * AC-03: INSERT with wallet_mode='server' and each valid key_manager value commits
     * successfully, and SELECT returns the exact seeded pair without transformation.
     *
     * <p>The test is parameterized over all four valid key_manager values defined by
     * the CHECK constraint {@code chk_wallet_profile_mode_manager}. Each invocation
     * runs in an isolated schema (UUID-suffix) to avoid PK conflicts.
     *
     * @param keyManager one of {@code db}, {@code hybrid}, {@code hsm}, {@code qtsp}
     */
    @ParameterizedTest(name = "server_profile_with_key_manager_{0}_inserts_successfully")
    @ValueSource(strings = {"db", "hybrid", "hsm", "qtsp"})
    void server_profile_with_valid_key_manager_inserts_successfully(String keyManager)
            throws SQLException {
        String schema = schemaFor(keyManager);
        applyMigrations(schema);

        String tenant = TENANT_PREFIX + keyManager;

        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + schema + ".tenant_wallet_profile"
                    + " (tenant, wallet_mode, key_manager)"
                    + " VALUES ('" + tenant + "', 'server', '" + keyManager + "')");

            try (ResultSet rs = conn.createStatement().executeQuery(
                    "SELECT wallet_mode, key_manager"
                    + " FROM " + schema + ".tenant_wallet_profile"
                    + " WHERE tenant = '" + tenant + "'")) {

                assertThat(rs.next())
                        .as("row must exist after INSERT for key_manager=" + keyManager)
                        .isTrue();
                assertThat(rs.getString("wallet_mode"))
                        .as("wallet_mode must be 'server' for key_manager=" + keyManager)
                        .isEqualTo("server");
                assertThat(rs.getString("key_manager"))
                        .as("key_manager must be '" + keyManager + "' without transformation")
                        .isEqualTo(keyManager);
            }
        }
    }

    /**
     * AC-03 (extended): created_at and updated_at are auto-populated by DEFAULT now()
     * for every server-mode key_manager value.
     *
     * @param keyManager one of {@code db}, {@code hybrid}, {@code hsm}, {@code qtsp}
     */
    @ParameterizedTest(name = "server_profile_with_key_manager_{0}_auto_populates_timestamps")
    @ValueSource(strings = {"db", "hybrid", "hsm", "qtsp"})
    void server_profile_insert_auto_populates_timestamps(String keyManager)
            throws SQLException {
        String schema = schemaFor(keyManager);
        applyMigrations(schema);

        String tenant = TENANT_PREFIX + keyManager + "_ts";

        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + schema + ".tenant_wallet_profile"
                    + " (tenant, wallet_mode, key_manager)"
                    + " VALUES ('" + tenant + "', 'server', '" + keyManager + "')");

            try (ResultSet rs = conn.createStatement().executeQuery(
                    "SELECT created_at, updated_at"
                    + " FROM " + schema + ".tenant_wallet_profile"
                    + " WHERE tenant = '" + tenant + "'")) {

                assertThat(rs.next()).as("row must exist").isTrue();
                assertThat(rs.getTimestamp("created_at"))
                        .as("created_at must be auto-set by DEFAULT now() for key_manager=" + keyManager)
                        .isNotNull();
                assertThat(rs.getTimestamp("updated_at"))
                        .as("updated_at must be auto-set by DEFAULT now() for key_manager=" + keyManager)
                        .isNotNull();
            }
        }
    }
}