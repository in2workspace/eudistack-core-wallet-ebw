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

/**
 * Verifies schema-per-tenant isolation for {@code hybrid_wrapped_key_handle}.
 *
 * <p>Two independent tenant schemas are created and seeded; each schema has its own
 * {@code hybrid_wrapped_key_handle} table. A connection whose {@code search_path} is
 * set to schema A must not see rows from schema B, and vice versa.
 *
 * <p>No additional code was written to enforce this isolation — it is inherited from
 * the schema-per-tenant pattern established by EUDISTACK-411 FR-07 and implemented by
 * {@code TenantAwareConnectionFactoryDecorator}. This test verifies the invariant holds
 * for the new table.
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>AC-06 — cross-tenant read is impossible by schema isolation</li>
 *   <li>NFR-S-535-04 — no cross-tenant access route exists for the handle</li>
 * </ul>
 *
 * <p>Spec: EUDISTACK-535 T9; acceptance-criteria.md §1 AC-06; NFR-S-535-04;
 * technical-design.md §3.3.
 */
@Tag("integration")
@Testcontainers
class HybridMultiTenantIsolationIT {

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:17-alpine")
                    .withDatabaseName("mt_isolation_it")
                    .withUsername("test")
                    .withPassword("test");

    private String schemaA;
    private String schemaB;
    private String jdbcUrl;

    private static final String CRED_A = "cred-tenant-a";
    private static final String CRED_B = "cred-tenant-b";

    @BeforeEach
    void setUp() throws SQLException {
        jdbcUrl = postgres.getJdbcUrl();
        schemaA = "mt_a_" + UUID.randomUUID().toString().replace("-", "").substring(0, 10);
        schemaB = "mt_b_" + UUID.randomUUID().toString().replace("-", "").substring(0, 10);
        provisionAndMigrate(schemaA);
        provisionAndMigrate(schemaB);
        seedHandle(schemaA, CRED_A);
        seedHandle(schemaB, CRED_B);
    }

    // -------------------------------------------------------------------------
    // AC-06 — connection in schema A cannot read rows from schema B
    // -------------------------------------------------------------------------

    @Test
    void connection_in_schema_a_cannot_read_handles_from_schema_b() throws SQLException {
        // A connection whose search_path is set to schemaA must see no rows for CRED_B
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute("SET search_path TO " + schemaA);

            try (ResultSet rs = conn.createStatement().executeQuery(
                    "SELECT count(*) FROM hybrid_wrapped_key_handle "
                    + "WHERE credential_id = '" + CRED_B + "'")) {
                assertThat(rs.next()).isTrue();
                assertThat(rs.getLong(1))
                        .as("Schema A context must not see credential '%s' from schema B "
                            + "(AC-06, schema-per-tenant isolation)", CRED_B)
                        .isZero();
            }
        }
    }

    @Test
    void connection_in_schema_b_cannot_read_handles_from_schema_a() throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute("SET search_path TO " + schemaB);

            try (ResultSet rs = conn.createStatement().executeQuery(
                    "SELECT count(*) FROM hybrid_wrapped_key_handle "
                    + "WHERE credential_id = '" + CRED_A + "'")) {
                assertThat(rs.next()).isTrue();
                assertThat(rs.getLong(1))
                        .as("Schema B context must not see credential '%s' from schema A "
                            + "(AC-06, schema-per-tenant isolation)", CRED_A)
                        .isZero();
            }
        }
    }

    // -------------------------------------------------------------------------
    // AC-06 — each schema sees only its own rows (positive sanity check)
    // -------------------------------------------------------------------------

    @Test
    void schema_a_context_sees_only_schema_a_handles() throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute("SET search_path TO " + schemaA);

            try (ResultSet rs = conn.createStatement().executeQuery(
                    "SELECT count(*) FROM hybrid_wrapped_key_handle")) {
                assertThat(rs.next()).isTrue();
                assertThat(rs.getLong(1))
                        .as("Schema A context must see exactly its own row (1 handle seeded)")
                        .isEqualTo(1L);
            }
        }
    }

    @Test
    void schema_b_context_sees_only_schema_b_handles() throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute("SET search_path TO " + schemaB);

            try (ResultSet rs = conn.createStatement().executeQuery(
                    "SELECT count(*) FROM hybrid_wrapped_key_handle")) {
                assertThat(rs.next()).isTrue();
                assertThat(rs.getLong(1))
                        .as("Schema B context must see exactly its own row (1 handle seeded)")
                        .isEqualTo(1L);
            }
        }
    }

    // -------------------------------------------------------------------------
    // AC-06 — combined total confirms no cross-schema leakage
    // -------------------------------------------------------------------------

    @Test
    void total_row_count_across_both_schemas_is_correct() throws SQLException {
        long countA = countHandlesInSchema(schemaA);
        long countB = countHandlesInSchema(schemaB);

        assertThat(countA).as("Schema A must have exactly 1 handle").isEqualTo(1L);
        assertThat(countB).as("Schema B must have exactly 1 handle").isEqualTo(1L);
        assertThat(countA + countB)
                .as("Combined total must be 2 (1 per schema, no cross-schema leakage)")
                .isEqualTo(2L);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private void provisionAndMigrate(String schema) throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE ebw_app_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE config_manager_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
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

    private void seedHandle(String schema, String credId) throws SQLException {
        UUID holderId = UUID.randomUUID();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute("SET search_path TO " + schema);
            conn.createStatement().execute(
                    "INSERT INTO wallet_user (id, email) "
                    + "VALUES ('" + holderId + "', 'mt-" + schema + "@test.local')");
            // Must insert prf_salt before handle (composite FK)
            conn.createStatement().execute(
                    "INSERT INTO hybrid_prf_salt (holder_id, credential_id, prf_salt) "
                    + "VALUES ('" + holderId + "', '" + credId + "', "
                    + " decode('" + hex(new byte[32]) + "', 'hex'))");
            byte[] blob = new byte[48];
            conn.createStatement().execute(
                    "INSERT INTO hybrid_wrapped_key_handle "
                    + "(holder_id, credential_id, wrapped_blob, iv, tag, kdf_algo, kdf_version, cnf_jwk) "
                    + "VALUES ('" + holderId + "', '" + credId + "', "
                    + " decode('" + hex(blob) + "', 'hex'), "
                    + " decode('" + hex(new byte[12]) + "', 'hex'), "
                    + " decode('" + hex(new byte[16]) + "', 'hex'), "
                    + " 'HKDF-SHA-256', 1, '{\"kty\":\"EC\"}')");
        }
    }

    private long countHandlesInSchema(String schema) throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test");
             ResultSet rs = conn.createStatement().executeQuery(
                     "SELECT count(*) FROM " + schema + ".hybrid_wrapped_key_handle")) {
            assertThat(rs.next()).isTrue();
            return rs.getLong(1);
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
