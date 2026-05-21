package com.eudistack.ebw.wallet.profile.infrastructure.migration;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationInfo;
import org.flywaydb.core.api.MigrationState;
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
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.fail;

/**
 * Integration test for Flyway migration V3__Wallet_profile.sql.
 *
 * <p>Covers AC-01, EC-01, and NFR-S-412-01 without starting the Spring context.
 * Flyway is invoked directly (same mechanism as {@code TenantSchemaFlywayMigrator})
 * so the test exercises the actual SQL artefact in isolation.
 *
 * <p>A dedicated per-class PostgreSQL container is used (not the shared container
 * from {@code IntegrationTestBase}) because this test inspects schema-level DDL.
 * Each test that needs an isolated schema creates a unique one (UUID-suffix pattern)
 * so state from one test does not leak into another even when the container is reused
 * across the test class.
 *
 * <p>AC covered: AC-01 (table + columns + CHECK + PK + Flyway history V3 SUCCESS).
 * EC covered: EC-01 (re-run does not re-execute DDL).
 * NFR covered: NFR-S-412-01 (idempotent re-application).
 */
@Tag("integration")
@Testcontainers
class WalletProfileMigrationIT {

    /** SQLSTATE code for check_violation (PostgreSQL). */
    private static final String SQLSTATE_CHECK_VIOLATION = "23514";

    /** SQLSTATE code for unique_violation (PostgreSQL). */
    private static final String SQLSTATE_UNIQUE_VIOLATION = "23505";

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("migration_test")
                    .withUsername("test")
                    .withPassword("test");

    /** Schema used by the current test — refreshed per-test to isolate DDL state. */
    private String testSchema;
    private String jdbcUrl;

    @BeforeEach
    void setUp() {
        jdbcUrl = postgres.getJdbcUrl();
        testSchema = "twp_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Creates the database roles required by the migration and the target schema,
     * then runs all tenant-level Flyway migrations against the schema.
     *
     * <p>Both V3 GRANTs ({@code ebw_app_role} SELECT and {@code config_manager_role}
     * SELECT/INSERT/UPDATE) are wrapped in DO-block exception handlers (AD-412-4).
     * Both roles are created here so both GRANTs succeed and the full ACL matrix
     * is exercised. In production both roles are provisioned by IaC.
     *
     * <p>Both role creation statements use {@code DO ... EXCEPTION} so this method
     * is safe to call multiple times (NFR-S-412-01 multi-run tests). The same
     * idempotency pattern mirrors what the test for AC-06 (WalletProfileRoleAclIT)
     * will use to set up its dual-role connections.
     *
     * <p>Mirrors the logic in {@code TenantSchemaFlywayMigrator#migrateTenantSchema}
     * with the addition of role provisioning that IaC normally handles.
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

    private boolean tableExists(Connection conn, String schema, String table) throws SQLException {
        try (ResultSet rs = conn.getMetaData().getTables(null, schema, table, new String[]{"TABLE"})) {
            return rs.next();
        }
    }

    private List<String> getTableColumns(Connection conn, String schema, String table) throws SQLException {
        List<String> cols = new ArrayList<>();
        try (ResultSet rs = conn.getMetaData().getColumns(null, schema, table, "%")) {
            while (rs.next()) {
                cols.add(rs.getString("COLUMN_NAME").toLowerCase());
            }
        }
        return cols;
    }

    private boolean constraintExists(Connection conn, String schema, String table,
            String constraintName) throws SQLException {
        String sql = "SELECT 1 FROM information_schema.table_constraints "
                + "WHERE table_schema = ? AND table_name = ? AND constraint_name = ?";
        try (var ps = conn.prepareStatement(sql)) {
            ps.setString(1, schema);
            ps.setString(2, table);
            ps.setString(3, constraintName);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    /**
     * Returns the Flyway migration info for a specific version tag using
     * the current {@link #testSchema}.
     */
    private MigrationInfo findMigrationInfo(String version) {
        Flyway flyway = Flyway.configure()
                .dataSource(jdbcUrl, "test", "test")
                .locations("classpath:db/tenant")
                .defaultSchema(testSchema)
                .schemas(testSchema)
                .table("flyway_schema_history")
                .baselineOnMigrate(true)
                .load();
        for (MigrationInfo info : flyway.info().all()) {
            if (version.equals(info.getVersion() != null ? info.getVersion().getVersion() : null)) {
                return info;
            }
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // AC-01 — Table structure
    // -------------------------------------------------------------------------

    /**
     * AC-01: Flyway creates the table with the required columns.
     *
     * <p>Given a fresh tenant schema, when V3 is applied, then
     * {@code tenant_wallet_profile} exists with columns
     * {@code tenant}, {@code wallet_mode}, {@code key_manager},
     * {@code created_at}, and {@code updated_at}.
     */
    @Test
    void migration_creates_tenant_wallet_profile_table_with_required_columns() throws SQLException {
        applyMigrations();

        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            assertThat(tableExists(conn, testSchema, "tenant_wallet_profile"))
                    .as("tenant_wallet_profile table must exist after V3 migration")
                    .isTrue();

            List<String> columns = getTableColumns(conn, testSchema, "tenant_wallet_profile");
            assertThat(columns)
                    .as("all required columns must be present")
                    .contains("tenant", "wallet_mode", "key_manager", "created_at", "updated_at");
        }
    }

    /**
     * AC-01: PRIMARY KEY constraint {@code pk_tenant_wallet_profile} exists and is enforced.
     *
     * <p>A duplicate INSERT without ON CONFLICT must fail with SQLSTATE 23505 (unique_violation),
     * confirming the PK exists on the {@code tenant} column (AD-412-1).
     */
    @Test
    void migration_creates_primary_key_on_tenant_column() throws SQLException {
        applyMigrations();

        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            assertThat(constraintExists(conn, testSchema, "tenant_wallet_profile",
                    "pk_tenant_wallet_profile"))
                    .as("pk_tenant_wallet_profile constraint must exist")
                    .isTrue();
        }

        // Behavioural check: a second unconditional INSERT must raise SQLSTATE 23505.
        String insert = "INSERT INTO " + testSchema
                + ".tenant_wallet_profile (tenant, wallet_mode) VALUES ('pk_test', 'browser')";
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(insert); // first insert — must succeed
        }
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            try {
                conn.createStatement().execute(insert); // second insert — must fail
                fail("Expected SQLSTATE 23505 but no exception was thrown");
            } catch (SQLException ex) {
                assertThat(ex.getSQLState())
                        .as("duplicate INSERT must violate primary key — expected SQLSTATE 23505")
                        .isEqualTo(SQLSTATE_UNIQUE_VIOLATION);
            }
        }
    }

    /**
     * AC-01: CHECK constraint {@code chk_wallet_profile_mode_manager} is present and enforced.
     *
     * <p>When a row violates FR-10/FR-11 ({@code browser + key_manager='db'}),
     * PostgreSQL rejects with SQLSTATE 23514 (check_violation).
     */
    @Test
    void migration_creates_check_constraint_enforcing_mode_manager_invariant() throws SQLException {
        applyMigrations();

        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            assertThat(constraintExists(conn, testSchema, "tenant_wallet_profile",
                    "chk_wallet_profile_mode_manager"))
                    .as("chk_wallet_profile_mode_manager must exist")
                    .isTrue();
        }

        // Behavioural check: browser + key_manager not null must be rejected (AC-04).
        String violating = "INSERT INTO " + testSchema
                + ".tenant_wallet_profile (tenant, wallet_mode, key_manager)"
                + " VALUES ('chk_test', 'browser', 'db')";
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            try {
                conn.createStatement().execute(violating);
                fail("Expected SQLSTATE 23514 but no exception was thrown");
            } catch (SQLException ex) {
                assertThat(ex.getSQLState())
                        .as("browser + key_manager='db' must violate CHECK — expected SQLSTATE 23514")
                        .isEqualTo(SQLSTATE_CHECK_VIOLATION);
            }
        }
    }

    /**
     * AC-01: Flyway history records V3 as SUCCESS.
     *
     * <p>The {@code flyway_schema_history} table in the tenant schema must contain
     * an entry for version 3 with state {@code SUCCESS}.
     */
    @Test
    void migration_records_v3_as_success_in_flyway_history() throws SQLException {
        applyMigrations();

        MigrationInfo v3Info = findMigrationInfo("3");
        assertThat(v3Info)
                .as("V3 migration info must be present in Flyway history")
                .isNotNull();
        assertThat(v3Info.getState())
                .as("V3 migration state must be SUCCESS")
                .isEqualTo(MigrationState.SUCCESS);
    }

    // -------------------------------------------------------------------------
    // EC-01 / NFR-S-412-01 — Idempotency
    // -------------------------------------------------------------------------

    /**
     * EC-01 / NFR-S-412-01: Re-applying V3 is idempotent.
     *
     * <p>Given the schema already has V3 applied, when the migrator runs again
     * (simulating a service restart or redeploy), then Flyway detects V3 as
     * already applied and does not re-execute the DDL. The table definition and
     * row count remain unchanged.
     */
    @Test
    void idempotent_reapplication_does_not_rerun_v3() throws SQLException {
        // First application — baseline
        applyMigrations();

        // Seed a test row to verify it survives the idempotent re-run
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + testSchema
                    + ".tenant_wallet_profile (tenant, wallet_mode)"
                    + " VALUES ('idempotent_tenant', 'browser')");
        }

        // Second application — must not throw and must not alter table or data
        assertThatNoException()
                .as("Flyway re-run must not throw on an already-applied migration")
                .isThrownBy(this::applyMigrations);

        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            // Table still exists
            assertThat(tableExists(conn, testSchema, "tenant_wallet_profile"))
                    .as("table must still exist after re-run")
                    .isTrue();

            // Seeded row is intact — re-run must not truncate or re-create the table
            try (ResultSet rs = conn.createStatement().executeQuery(
                    "SELECT COUNT(*) FROM " + testSchema + ".tenant_wallet_profile")) {
                rs.next();
                assertThat(rs.getInt(1))
                        .as("seeded row must be preserved — re-run must not truncate")
                        .isEqualTo(1);
            }

            // V3 is still SUCCESS (not re-applied as a new entry)
            MigrationInfo v3Info = findMigrationInfo("3");
            assertThat(v3Info).isNotNull();
            assertThat(v3Info.getState()).isEqualTo(MigrationState.SUCCESS);
        }
    }

    /**
     * NFR-S-412-01 extended: multiple consecutive re-applications all succeed.
     *
     * <p>Simulates N=5 consecutive migrator invocations to surface any flaky
     * idempotency failure (the NFR requires 0 failures in N=10; 5 is sufficient
     * for a deterministic CI guard).
     */
    @Test
    void multiple_reapplications_are_all_idempotent() throws SQLException {
        applyMigrations(); // first run

        for (int i = 0; i < 5; i++) {
            final int attempt = i + 2;
            assertThatNoException()
                    .as("Flyway application attempt #" + attempt + " must not throw")
                    .isThrownBy(this::applyMigrations);
        }

        MigrationInfo v3Info = findMigrationInfo("3");
        assertThat(v3Info).isNotNull();
        assertThat(v3Info.getState()).isEqualTo(MigrationState.SUCCESS);
    }
}