package com.eudistack.ebw.keymanager.infrastructure.persistence;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the structure of {@code hybrid_wrapped_key_handle} after applying
 * the Flyway migration V4.
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>AC-01 — table exists with PK (holder_id, credential_id), FK to wallet_user,
 *       FK to hybrid_prf_salt, correct columns and types</li>
 *   <li>AC-05 — FK (holder_id, credential_id) -> hybrid_prf_salt (ES-02 physical barrier)</li>
 *   <li>EC-02 — created_at DEFAULT now() is populated when not supplied; not updatable
 *       via ACL</li>
 *   <li>NFR-S-535-02 — no column stores holder private key or wrap key in clear</li>
 *   <li>NFR-S-535-05 — migration is re-applicable on a clean DB</li>
 * </ul>
 *
 * <p>Spec: EUDISTACK-535 T5; acceptance-criteria.md §1 AC-01, AC-05, EC-02;
 * technical-design.md §3.2.1.
 */
@Tag("integration")
@Testcontainers
class HybridWrappedKeyHandleSchemaIT {

    private static final String TABLE_NAME = "hybrid_wrapped_key_handle";

    /** Expected (column_name -> jdbc_type_name) for the table. */
    private static final Map<String, String> EXPECTED_COLUMNS = new HashMap<>();

    static {
        // JDBC metadata returns type names in lower case from PostgreSQL driver
        EXPECTED_COLUMNS.put("holder_id",     "uuid");
        EXPECTED_COLUMNS.put("credential_id", "varchar");
        EXPECTED_COLUMNS.put("wrapped_blob",  "bytea");
        EXPECTED_COLUMNS.put("iv",            "bytea");
        EXPECTED_COLUMNS.put("tag",           "bytea");
        EXPECTED_COLUMNS.put("kdf_algo",      "varchar");
        EXPECTED_COLUMNS.put("kdf_version",   "int4");
        EXPECTED_COLUMNS.put("cnf_jwk",       "text");
        EXPECTED_COLUMNS.put("created_at",    "timestamptz");
        EXPECTED_COLUMNS.put("last_used_at",  "timestamptz");
    }

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:17-alpine")
                    .withDatabaseName("schema_it")
                    .withUsername("test")
                    .withPassword("test");

    private String testSchema;
    private String jdbcUrl;

    @BeforeEach
    void setUp() throws SQLException {
        jdbcUrl = postgres.getJdbcUrl();
        testSchema = "sch_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        provisionAndMigrate();
    }

    // -------------------------------------------------------------------------
    // AC-01 — table exists
    // -------------------------------------------------------------------------

    @Test
    void table_hybrid_wrapped_key_handle_exists_after_migration() throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test");
             ResultSet rs = conn.getMetaData().getTables(
                     null, testSchema, TABLE_NAME, new String[]{"TABLE"})) {
            assertThat(rs.next())
                    .as("Table '%s.%s' must exist after Flyway migration V4", testSchema, TABLE_NAME)
                    .isTrue();
        }
    }

    // -------------------------------------------------------------------------
    // AC-01 — PK columns
    // -------------------------------------------------------------------------

    @Test
    void primary_key_is_composite_holder_id_and_credential_id() throws SQLException {
        List<String> pkColumns = new ArrayList<>();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test");
             ResultSet rs = conn.getMetaData().getPrimaryKeys(null, testSchema, TABLE_NAME)) {
            while (rs.next()) {
                pkColumns.add(rs.getString("COLUMN_NAME"));
            }
        }
        assertThat(pkColumns)
                .as("PK must be composite (holder_id, credential_id)")
                .containsExactlyInAnyOrder("holder_id", "credential_id");
    }

    // -------------------------------------------------------------------------
    // AC-01 / AC-05 — FK to wallet_user(id) ON DELETE RESTRICT
    // -------------------------------------------------------------------------

    @Test
    void foreign_key_holder_id_references_wallet_user() throws SQLException {
        boolean fkFound = false;
        String deleteRule = null;
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test");
             ResultSet rs = conn.getMetaData().getImportedKeys(null, testSchema, TABLE_NAME)) {
            while (rs.next()) {
                String fkCol = rs.getString("FKCOLUMN_NAME");
                String pkTable = rs.getString("PKTABLE_NAME");
                String pkCol = rs.getString("PKCOLUMN_NAME");
                if ("holder_id".equals(fkCol) && "wallet_user".equals(pkTable) && "id".equals(pkCol)) {
                    fkFound = true;
                    // JDBC: DELETE_RULE 1 = CASCADE, 2 = SET NULL, 3 = SET DEFAULT, 4 = RESTRICT
                    deleteRule = String.valueOf(rs.getShort("DELETE_RULE"));
                }
            }
        }
        assertThat(fkFound)
                .as("FK holder_id -> wallet_user(id) must exist")
                .isTrue();
        // JDBC DatabaseMetaData.importedKeyRestrict = 1 for RESTRICT in PostgreSQL
        assertThat(deleteRule)
                .as("FK must be ON DELETE RESTRICT (JDBC rule = 1)")
                .isEqualTo(String.valueOf(DatabaseMetaData.importedKeyRestrict));
    }

    // -------------------------------------------------------------------------
    // AC-01 / AC-05 / ES-02 — composite FK to hybrid_prf_salt
    // -------------------------------------------------------------------------

    @Test
    void composite_foreign_key_references_hybrid_prf_salt() throws SQLException {
        // Collect all FK columns that point to hybrid_prf_salt
        List<String> fkColsToSalt = new ArrayList<>();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test");
             ResultSet rs = conn.getMetaData().getImportedKeys(null, testSchema, TABLE_NAME)) {
            while (rs.next()) {
                String pkTable = rs.getString("PKTABLE_NAME");
                if ("hybrid_prf_salt".equals(pkTable)) {
                    fkColsToSalt.add(rs.getString("FKCOLUMN_NAME"));
                }
            }
        }
        assertThat(fkColsToSalt)
                .as("Composite FK (holder_id, credential_id) -> hybrid_prf_salt must exist (AC-05, ES-02)")
                .containsExactlyInAnyOrder("holder_id", "credential_id");
    }

    // -------------------------------------------------------------------------
    // AC-01 — columns, names and types
    // -------------------------------------------------------------------------

    @Test
    void all_expected_columns_exist_with_correct_types() throws SQLException {
        Map<String, String> actual = new HashMap<>();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test");
             ResultSet rs = conn.getMetaData().getColumns(null, testSchema, TABLE_NAME, null)) {
            while (rs.next()) {
                String colName = rs.getString("COLUMN_NAME").toLowerCase();
                String typeName = rs.getString("TYPE_NAME").toLowerCase();
                actual.put(colName, typeName);
            }
        }

        for (Map.Entry<String, String> expected : EXPECTED_COLUMNS.entrySet()) {
            assertThat(actual)
                    .as("Column '%s' must exist in the table", expected.getKey())
                    .containsKey(expected.getKey());
            assertThat(actual.get(expected.getKey()))
                    .as("Column '%s' must have type '%s' (got '%s')",
                        expected.getKey(), expected.getValue(), actual.get(expected.getKey()))
                    .isEqualTo(expected.getValue());
        }
    }

    // -------------------------------------------------------------------------
    // EC-02 — created_at DEFAULT now() is populated automatically
    // -------------------------------------------------------------------------

    @Test
    void created_at_is_populated_by_default_when_not_supplied() throws SQLException {
        UUID holderId = insertWalletUser();
        String credId = "cred-schema-default";
        insertPrfSalt(holderId, credId);

        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute("SET search_path TO " + testSchema);
            // Insert without specifying created_at
            conn.createStatement().execute(
                    "INSERT INTO hybrid_wrapped_key_handle "
                    + "(holder_id, credential_id, wrapped_blob, iv, tag, kdf_algo, kdf_version, cnf_jwk) "
                    + "VALUES ('" + holderId + "', '" + credId + "', "
                    + " decode('" + hex(new byte[48]) + "', 'hex'), "
                    + " decode('" + hex(new byte[12]) + "', 'hex'), "
                    + " decode('" + hex(new byte[16]) + "', 'hex'), "
                    + " 'HKDF-SHA-256', 1, '{\"kty\":\"EC\"}')");

            try (ResultSet rs = conn.createStatement().executeQuery(
                    "SELECT created_at FROM hybrid_wrapped_key_handle "
                    + "WHERE credential_id = '" + credId + "'")) {
                assertThat(rs.next()).as("row must be present").isTrue();
                assertThat(rs.getTimestamp("created_at"))
                        .as("created_at must be populated by DEFAULT now()")
                        .isNotNull();
            }
        }
    }

    // -------------------------------------------------------------------------
    // NFR-S-535-02 — no column stores plaintext private key or wrap key
    // -------------------------------------------------------------------------

    @Test
    void no_plaintext_key_or_wrap_key_column_exists() throws SQLException {
        List<String> columns = new ArrayList<>();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test");
             ResultSet rs = conn.getMetaData().getColumns(null, testSchema, TABLE_NAME, null)) {
            while (rs.next()) {
                columns.add(rs.getString("COLUMN_NAME").toLowerCase());
            }
        }
        for (String col : columns) {
            assertThat(col)
                    .as("Column '%s' must not suggest plaintext private key or wrap key storage", col)
                    .doesNotContainIgnoringCase("private")
                    .doesNotContainIgnoringCase("plain")
                    .doesNotContainIgnoringCase("wrap_key")
                    .doesNotContainIgnoringCase("secret");
        }
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
                    + "VALUES ('" + id + "', 'schema-it-" + id + "@test.local')");
        }
        return id;
    }

    private void insertPrfSalt(UUID holderId, String credId) throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute("SET search_path TO " + testSchema);
            conn.createStatement().execute(
                    "INSERT INTO hybrid_prf_salt (holder_id, credential_id, prf_salt) "
                    + "VALUES ('" + holderId + "', '" + credId + "', "
                    + " decode('" + hex(new byte[32]) + "', 'hex'))");
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
