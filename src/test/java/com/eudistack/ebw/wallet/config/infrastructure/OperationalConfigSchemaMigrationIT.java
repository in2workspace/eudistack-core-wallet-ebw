package com.eudistack.ebw.wallet.config.infrastructure;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Migration / schema integration test for {@code db/tenant/V4__Wallet_operational_config.sql}
 * (T-6 — EUDISTACK-414, AC-1, AC-3).
 *
 * <p>No Spring context. Pure JDBC + programmatic Flyway. One isolated schema per test method
 * prevents cross-test pollution. Flyway is configured with
 * {@code locations("classpath:db/tenant")} which targets the per-tenant migration set
 * ({@code V1__EBW_schema.sql} through {@code V4__Wallet_operational_config.sql}).
 *
 * <p>What is asserted:
 * <ul>
 *   <li>V4 migrates cleanly on an empty tenant schema; Flyway version history shows {@code "4"}
 *       as the latest successful migration.</li>
 *   <li>CHECK {@code chk_woc_key_manager}: invalid {@code key_manager} value is rejected.</li>
 *   <li>CHECK {@code chk_woc_activation_status}: invalid {@code activation_status} value is
 *       rejected.</li>
 *   <li>Cross-field CHECK {@code chk_woc_active_requires_probe}: {@code activation_status='active'}
 *       with {@code connectivity_verified_at NULL} is rejected.</li>
 *   <li>Cross-field CHECK {@code chk_woc_active_requires_probe}: {@code activation_status='pending-spi'}
 *       with {@code connectivity_verified_at NOT NULL} is rejected (the CHECK is bi-directional).</li>
 *   <li>CHECK {@code chk_woc_db_tde_algorithm}: non-{@code AES-256-GCM} algorithm value is
 *       rejected.</li>
 *   <li>CHECK {@code chk_woc_db_tde_wrapped_dek_not_empty}: empty {@code bytea} is rejected.</li>
 *   <li>Partial unique index {@code uidx_woc_active_key_manager}: two {@code is_active=true} rows
 *       for the same {@code key_manager} → unique violation.</li>
 *   <li>{@code ON DELETE CASCADE}: deleting the root row removes the sub-table row.</li>
 *   <li>Idempotency: running Flyway {@code migrate()} twice does not fail.</li>
 *   <li>Tenant-scope: the V4 tables must NOT appear in the {@code public} schema.</li>
 *   <li>Absence of sibling sub-tables: {@code wallet_operational_config_hsm},
 *       {@code _qtsp}, {@code _hybrid} must NOT exist in the tenant schema after V4.</li>
 * </ul>
 *
 * <p>Tagged {@code integration} → runs under {@code ./gradlew integrationTest} (Docker required).
 */
@Testcontainers
@Tag("integration")
class OperationalConfigSchemaMigrationIT {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:17-alpine")
            .withDatabaseName("wallet_ebw_test")
            .withUsername("ebw_test")
            .withPassword("ebw_test");

    // ------------------------------------------------------------------
    // Schema helpers
    // ------------------------------------------------------------------

    /**
     * Returns a new JDBC {@code Connection} to the shared container database.
     * Each caller is responsible for closing it (use try-with-resources).
     */
    private static Connection openConnection() throws SQLException {
        return DriverManager.getConnection(
                POSTGRES.getJdbcUrl(),
                POSTGRES.getUsername(),
                POSTGRES.getPassword());
    }

    /**
     * Creates the given schema if absent, then applies Flyway migrations from
     * {@code classpath:db/tenant} (the per-tenant migration set) scoped to that schema.
     *
     * <p>Each test method uses a distinct schema name so test executions are fully isolated
     * from one another regardless of JUnit execution order.
     */
    private static void runMigrationOnSchema(String schemaName) throws SQLException {
        try (Connection conn = openConnection();
             Statement st = conn.createStatement()) {
            st.execute("CREATE SCHEMA IF NOT EXISTS \"" + schemaName + "\"");
        }
        Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .schemas(schemaName)
                .locations("classpath:db/tenant")
                .load()
                .migrate();
    }

    /**
     * Returns a schema name that is safe for PG identifiers (max 63 chars).
     * Prefixes with {@code tit_} (short for "test isolation tenant") then appends the
     * method name, lower-cased and stripped of non-alphanumeric characters.
     */
    private static String schema(String methodName) {
        String raw = "tit_" + methodName.toLowerCase().replaceAll("[^a-z0-9]", "_");
        return raw.length() > 63 ? raw.substring(0, 63) : raw;
    }

    // ------------------------------------------------------------------
    // TC-1 — V4 applies cleanly; version history shows "4" as latest.
    // ------------------------------------------------------------------

    @Test
    void v4AppliesCleanly_onEmptyTenantSchema() throws SQLException {
        String schemaName = schema("v4_applies_cleanly");
        runMigrationOnSchema(schemaName);

        try (Connection conn = openConnection();
             Statement st = conn.createStatement()) {

            // Latest successful migration version must be "4".
            ResultSet rs = st.executeQuery(
                    "SELECT version FROM \"" + schemaName + "\".flyway_schema_history "
                            + "WHERE success = true ORDER BY installed_rank DESC LIMIT 1");
            assertThat(rs.next()).isTrue();
            assertThat(rs.getString("version")).isEqualTo("4");

            // Root table must exist.
            assertTableExists(conn, schemaName, "wallet_operational_config");

            // Sub-table must exist.
            assertTableExists(conn, schemaName, "wallet_operational_config_db_tde");
        }
    }

    // ------------------------------------------------------------------
    // TC-2 — chk_woc_key_manager: invalid key_manager value is rejected.
    // ------------------------------------------------------------------

    @Test
    void keyManagerCheck_rejectsInvalidValue() throws SQLException {
        String schemaName = schema("key_manager_check");
        runMigrationOnSchema(schemaName);

        try (Connection conn = openConnection()) {
            assertThatThrownBy(() -> {
                try (Statement st = conn.createStatement()) {
                    st.execute(
                            "INSERT INTO \"" + schemaName + "\".wallet_operational_config "
                                    + "(key_manager, activation_status, updated_by) "
                                    + "VALUES ('invalid', 'pending-spi', 'test')");
                }
            }).isInstanceOf(SQLException.class)
              .hasMessageContaining("chk_woc_key_manager");
        }
    }

    // ------------------------------------------------------------------
    // TC-3 — chk_woc_activation_status: unknown status value is rejected.
    // ------------------------------------------------------------------

    @Test
    void activationStatusCheck_rejectsInvalidValue() throws SQLException {
        String schemaName = schema("activation_status_check");
        runMigrationOnSchema(schemaName);

        try (Connection conn = openConnection()) {
            assertThatThrownBy(() -> {
                try (Statement st = conn.createStatement()) {
                    st.execute(
                            "INSERT INTO \"" + schemaName + "\".wallet_operational_config "
                                    + "(key_manager, activation_status, updated_by) "
                                    + "VALUES ('db-tde', 'unknown', 'test')");
                }
            }).isInstanceOf(SQLException.class)
              .hasMessageContaining("chk_woc_activation_status");
        }
    }

    // ------------------------------------------------------------------
    // TC-4 — cross-field CHECK: active + NULL connectivity_verified_at is rejected.
    // ------------------------------------------------------------------

    @Test
    void crossFieldCheck_activeWithoutConnectivityAt_isRejected() throws SQLException {
        String schemaName = schema("cross_field_active_null");
        runMigrationOnSchema(schemaName);

        try (Connection conn = openConnection()) {
            assertThatThrownBy(() -> {
                try (Statement st = conn.createStatement()) {
                    // activation_status='active' but connectivity_verified_at is NULL (default).
                    st.execute(
                            "INSERT INTO \"" + schemaName + "\".wallet_operational_config "
                                    + "(key_manager, activation_status, connectivity_verified_at, updated_by) "
                                    + "VALUES ('db-tde', 'active', NULL, 'test')");
                }
            }).isInstanceOf(SQLException.class)
              .hasMessageContaining("chk_woc_active_requires_probe");
        }
    }

    // ------------------------------------------------------------------
    // TC-5 — cross-field CHECK: pending-spi + non-NULL connectivity_verified_at is rejected.
    //
    // The V4 CHECK is bi-directional:
    //   (active AND NOT NULL) OR (pending-spi AND NULL)
    // A row with pending-spi + non-NULL connectivity_verified_at satisfies neither branch.
    // ------------------------------------------------------------------

    @Test
    void crossFieldCheck_pendingSpiWithConnectivityAt_isRejected() throws SQLException {
        String schemaName = schema("cross_field_pending_non_null");
        runMigrationOnSchema(schemaName);

        try (Connection conn = openConnection()) {
            assertThatThrownBy(() -> {
                try (Statement st = conn.createStatement()) {
                    // pending-spi is the default activation_status, but connectivity_verified_at NOT NULL.
                    st.execute(
                            "INSERT INTO \"" + schemaName + "\".wallet_operational_config "
                                    + "(key_manager, activation_status, connectivity_verified_at, updated_by) "
                                    + "VALUES ('db-tde', 'pending-spi', now(), 'test')");
                }
            }).isInstanceOf(SQLException.class)
              .hasMessageContaining("chk_woc_active_requires_probe");
        }
    }

    // ------------------------------------------------------------------
    // TC-6 — chk_woc_db_tde_algorithm: non-AES-256-GCM algorithm is rejected.
    // ------------------------------------------------------------------

    @Test
    void algorithmCheck_rejectsInvalidValue() throws SQLException {
        String schemaName = schema("algorithm_check");
        runMigrationOnSchema(schemaName);

        try (Connection conn = openConnection();
             Statement st = conn.createStatement()) {

            // Insert a valid root row first.
            st.execute(
                    "INSERT INTO \"" + schemaName + "\".wallet_operational_config "
                            + "(id, key_manager, activation_status, connectivity_verified_at, updated_by) "
                            + "VALUES ('a0000000-0000-0000-0000-000000000001', 'db-tde', 'active', now(), 'test')");

            assertThatThrownBy(() -> {
                try (Statement st2 = conn.createStatement()) {
                    st2.execute(
                            "INSERT INTO \"" + schemaName + "\".wallet_operational_config_db_tde "
                                    + "(config_id, column_encryption_key_arn, wrapped_dek, algorithm) "
                                    + "VALUES ('a0000000-0000-0000-0000-000000000001', "
                                    + "'arn:aws:kms:eu-west-1:123456789012:key/test', "
                                    + "'\\xDEADBEEF'::bytea, 'RSA')");
                }
            }).isInstanceOf(SQLException.class)
              .hasMessageContaining("chk_woc_db_tde_algorithm");
        }
    }

    // ------------------------------------------------------------------
    // TC-7 — chk_woc_db_tde_wrapped_dek_not_empty: empty bytea is rejected.
    // ------------------------------------------------------------------

    @Test
    void wrappedDekCheck_rejectsEmptyBytea() throws SQLException {
        String schemaName = schema("wrapped_dek_empty");
        runMigrationOnSchema(schemaName);

        try (Connection conn = openConnection();
             Statement st = conn.createStatement()) {

            // Insert a valid root row first.
            st.execute(
                    "INSERT INTO \"" + schemaName + "\".wallet_operational_config "
                            + "(id, key_manager, activation_status, connectivity_verified_at, updated_by) "
                            + "VALUES ('b0000000-0000-0000-0000-000000000001', 'db-tde', 'active', now(), 'test')");

            assertThatThrownBy(() -> {
                try (Statement st2 = conn.createStatement()) {
                    st2.execute(
                            "INSERT INTO \"" + schemaName + "\".wallet_operational_config_db_tde "
                                    + "(config_id, column_encryption_key_arn, wrapped_dek, algorithm) "
                                    + "VALUES ('b0000000-0000-0000-0000-000000000001', "
                                    + "'arn:aws:kms:eu-west-1:123456789012:key/test', "
                                    + "''::bytea, 'AES-256-GCM')");
                }
            }).isInstanceOf(SQLException.class)
              .hasMessageContaining("chk_woc_db_tde_wrapped_dek_not_empty");
        }
    }

    // ------------------------------------------------------------------
    // TC-8 — partial unique index uidx_woc_active_key_manager:
    //        second is_active=true row for the same key_manager is rejected.
    // ------------------------------------------------------------------

    @Test
    void partialUniqueIndex_rejectsSecondActiveRow_sameKeyManager() throws SQLException {
        String schemaName = schema("partial_unique_active");
        runMigrationOnSchema(schemaName);

        try (Connection conn = openConnection();
             Statement st = conn.createStatement()) {

            // First active row — must succeed.
            st.execute(
                    "INSERT INTO \"" + schemaName + "\".wallet_operational_config "
                            + "(id, key_manager, is_active, activation_status, connectivity_verified_at, updated_by) "
                            + "VALUES ('c0000000-0000-0000-0000-000000000001', 'db-tde', true, 'active', now(), 'test')");

            // Second active row with the same key_manager — must fail on the partial unique index.
            assertThatThrownBy(() -> {
                try (Statement st2 = conn.createStatement()) {
                    st2.execute(
                            "INSERT INTO \"" + schemaName + "\".wallet_operational_config "
                                    + "(id, key_manager, is_active, activation_status, connectivity_verified_at, updated_by) "
                                    + "VALUES ('c0000000-0000-0000-0000-000000000002', 'db-tde', true, 'active', now(), 'test')");
                }
            }).isInstanceOf(SQLException.class)
              .hasMessageContaining("uidx_woc_active_key_manager");
        }
    }

    // ------------------------------------------------------------------
    // TC-9 — ON DELETE CASCADE: deleting the root row removes the sub-table row.
    // ------------------------------------------------------------------

    @Test
    void fkOnDeleteCascade_removesSubTableRow() throws SQLException {
        String schemaName = schema("fk_on_delete_cascade");
        runMigrationOnSchema(schemaName);

        try (Connection conn = openConnection();
             Statement st = conn.createStatement()) {

            // Insert root row.
            st.execute(
                    "INSERT INTO \"" + schemaName + "\".wallet_operational_config "
                            + "(id, key_manager, activation_status, connectivity_verified_at, updated_by) "
                            + "VALUES ('d0000000-0000-0000-0000-000000000001', 'db-tde', 'active', now(), 'test')");

            // Insert sub-table row.
            st.execute(
                    "INSERT INTO \"" + schemaName + "\".wallet_operational_config_db_tde "
                            + "(config_id, column_encryption_key_arn, wrapped_dek, algorithm) "
                            + "VALUES ('d0000000-0000-0000-0000-000000000001', "
                            + "'arn:aws:kms:eu-west-1:123456789012:key/test', "
                            + "'\\xDEADBEEF'::bytea, 'AES-256-GCM')");

            // Sub-table row must be present before delete.
            ResultSet before = st.executeQuery(
                    "SELECT count(*) FROM \"" + schemaName + "\".wallet_operational_config_db_tde "
                            + "WHERE config_id = 'd0000000-0000-0000-0000-000000000001'");
            before.next();
            assertThat(before.getLong(1)).isEqualTo(1L);

            // Delete root row.
            st.execute(
                    "DELETE FROM \"" + schemaName + "\".wallet_operational_config "
                            + "WHERE id = 'd0000000-0000-0000-0000-000000000001'");

            // Sub-table row must be gone (CASCADE).
            ResultSet after = st.executeQuery(
                    "SELECT count(*) FROM \"" + schemaName + "\".wallet_operational_config_db_tde "
                            + "WHERE config_id = 'd0000000-0000-0000-0000-000000000001'");
            after.next();
            assertThat(after.getLong(1)).isZero();
        }
    }

    // ------------------------------------------------------------------
    // TC-10 — Idempotency: running Flyway migrate twice does not fail.
    // ------------------------------------------------------------------

    @Test
    void idempotency_reRunningMigration_doesNotFail() throws SQLException {
        String schemaName = schema("idempotency_rerun");
        runMigrationOnSchema(schemaName);

        // Second migrate() call on the same schema must be a no-op (already at V4).
        Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .schemas(schemaName)
                .locations("classpath:db/tenant")
                .load()
                .migrate();

        // Tables still present after the second run.
        try (Connection conn = openConnection()) {
            assertTableExists(conn, schemaName, "wallet_operational_config");
            assertTableExists(conn, schemaName, "wallet_operational_config_db_tde");
        }
    }

    // ------------------------------------------------------------------
    // TC-11 — Tenant-scope: V4 tables must NOT appear in the public schema.
    // ------------------------------------------------------------------

    @Test
    void tablesExistOnlyInTenantSchema_notInPublic() throws SQLException {
        String schemaName = schema("tenant_scope_not_public");
        runMigrationOnSchema(schemaName);

        try (Connection conn = openConnection();
             Statement st = conn.createStatement()) {

            ResultSet rs = st.executeQuery(
                    "SELECT count(*) FROM information_schema.tables "
                            + "WHERE table_schema = 'public' "
                            + "AND table_name LIKE 'wallet_operational_config%'");
            rs.next();
            assertThat(rs.getLong(1)).isZero();
        }
    }

    // ------------------------------------------------------------------
    // TC-12 — Absence of sibling sub-tables (HSM, QTSP, Hybrid are US-05/06/07).
    // ------------------------------------------------------------------

    @Test
    void subTablesForOtherKeyManagers_doNotExist() throws SQLException {
        String schemaName = schema("sibling_subtables_absent");
        runMigrationOnSchema(schemaName);

        try (Connection conn = openConnection()) {
            assertTableAbsent(conn, schemaName, "wallet_operational_config_hsm");
            assertTableAbsent(conn, schemaName, "wallet_operational_config_qtsp");
            assertTableAbsent(conn, schemaName, "wallet_operational_config_hybrid");
        }
    }

    // ------------------------------------------------------------------
    // Private assertion helpers
    // ------------------------------------------------------------------

    private static void assertTableExists(Connection conn, String schema, String table) throws SQLException {
        try (Statement st = conn.createStatement()) {
            ResultSet rs = st.executeQuery(
                    "SELECT count(*) FROM information_schema.tables "
                            + "WHERE table_schema = '" + schema + "' "
                            + "AND table_name = '" + table + "'");
            rs.next();
            assertThat(rs.getLong(1))
                    .as("Table %s.%s must exist", schema, table)
                    .isEqualTo(1L);
        }
    }

    private static void assertTableAbsent(Connection conn, String schema, String table) throws SQLException {
        try (Statement st = conn.createStatement()) {
            ResultSet rs = st.executeQuery(
                    "SELECT count(*) FROM information_schema.tables "
                            + "WHERE table_schema = '" + schema + "' "
                            + "AND table_name = '" + table + "'");
            rs.next();
            assertThat(rs.getLong(1))
                    .as("Table %s.%s must NOT exist", schema, table)
                    .isZero();
        }
    }
}
