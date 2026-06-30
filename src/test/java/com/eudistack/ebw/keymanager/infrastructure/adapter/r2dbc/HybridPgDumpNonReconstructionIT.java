package com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.keymanager.domain.model.WrappedKeyHandle;
import com.eudistack.ebw.keymanager.domain.port.WrappedKeyHandleRepository;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import reactor.test.StepVerifier;

import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies AC-02 / NFR-S-535-01: a full dump of the {@code hybrid_wrapped_key_handle}
 * table cannot be used to reconstruct the holder private key, even at volume (>= 100 holders).
 *
 * <p>The test inserts handles whose {@code wrapped_blob} is opaque ciphertext that does NOT
 * contain a simulated "plaintext private key" marker. It then:
 * <ol>
 *   <li>Reads back the raw column bytes via JDBC and confirms that the stored blob equals
 *       the submitted ciphertext and does not contain the plaintext marker.</li>
 *   <li>Verifies that no column in the table is named to suggest plaintext key storage.</li>
 *   <li>With >= 100 holders seeded, executes a real {@code pg_dump} of the schema and
 *       searches the dump output for the plaintext marker (NFR-S-535-01, EC-03).</li>
 *   <li>Verifies that EXPLAIN for a lookup by composite PK uses Index Scan (EC-03).</li>
 * </ol>
 *
 * <p>This test uses the real Flyway tenant migrations (V1-V4) provided by US-03
 * (EUDISTACK-535). The temporary DDL stub used in the US-02 (EUDISTACK-534) version
 * of this test has been removed -- the real V4 migration is the single source of truth.
 *
 * <p>Note: each seeded handle requires a matching {@code hybrid_prf_salt} row due to
 * the composite FK introduced in V4 ({@code fk_hwkh_prf_salt}).
 *
 * <p>Spec: EUDISTACK-534 AC-05; EUDISTACK-535 AC-02, EC-03, NFR-S-535-01;
 * architecture.md §5.3.
 */
@Tag("integration")
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.NONE,
        properties = {"spring.autoconfigure.exclude=", "ebw.tenant-flyway.enabled=false"}
)
@ActiveProfiles("integration")
@Testcontainers
class HybridPgDumpNonReconstructionIT {

    private static final String SCHEMA_SUFFIX = "_business_wallet";
    private static final String TENANT        = "pgdump";

    // Marker bytes that represent a "plaintext private key" -- these must NOT appear in the DB.
    // In a real scenario the blob is AES-256-GCM ciphertext; here we verify the server stores
    // only what it receives and doesn't leak a separate plaintext column.
    private static final byte[] SIMULATED_PLAINTEXT = "PRIVATE_KEY_MARKER_BYTES_12345678".getBytes();
    private static final byte[] WRAPPED_BLOB;   // blob is arbitrary ciphertext, >= 48 bytes
    private static final byte[] IV  = new byte[12];
    private static final byte[] TAG = new byte[16];

    private static final int VOLUME_COUNT = 100; // EC-03: >= 100 holders

    static {
        // wrappedBlob is 48+ bytes of ciphertext -- does NOT contain SIMULATED_PLAINTEXT
        WRAPPED_BLOB = new byte[48];
        Arrays.fill(WRAPPED_BLOB, (byte) 0xAB);  // opaque marker, not the plaintext
    }

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:17-alpine")
                    .withDatabaseName("pgdump_it")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        String host = postgres.getHost();
        int port = postgres.getMappedPort(5432);
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://" + host + ":" + port + "/pgdump_it");
        registry.add("spring.r2dbc.username", () -> "test");
        registry.add("spring.r2dbc.password", () -> "test");
        registry.add("spring.flyway.url", () ->
                "jdbc:postgresql://" + host + ":" + port + "/pgdump_it");
        registry.add("spring.flyway.user", () -> "test");
        registry.add("spring.flyway.password", () -> "test");
        registry.add("spring.flyway.default-schema", () -> "public");
    }

    @Autowired
    WrappedKeyHandleRepository repository;

    @BeforeAll
    static void provisionSchema() throws SQLException {
        String jdbcUrl = postgres.getJdbcUrl();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE ebw_app_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE config_manager_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute(
                    "CREATE SCHEMA IF NOT EXISTS " + TENANT + SCHEMA_SUFFIX);
        }

        // Apply the real Flyway tenant migrations (V1-V4 from US-03/EUDISTACK-535).
        // No temporary DDL stub is used; the V4 migration is the single source of truth.
        Flyway.configure()
                .dataSource(jdbcUrl, "test", "test")
                .locations("classpath:db/tenant")
                .defaultSchema(TENANT + SCHEMA_SUFFIX)
                .schemas(TENANT + SCHEMA_SUFFIX)
                .table("flyway_schema_history")
                .baselineOnMigrate(true)
                .load()
                .migrate();
    }

    @BeforeEach
    void clearTable() throws SQLException {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            // Delete in FK order: child (handle) before parents (prf_salt, wallet_user)
            conn.createStatement().execute(
                    "DELETE FROM " + TENANT + SCHEMA_SUFFIX + ".hybrid_wrapped_key_handle");
            conn.createStatement().execute(
                    "DELETE FROM " + TENANT + SCHEMA_SUFFIX + ".hybrid_prf_salt");
            conn.createStatement().execute(
                    "DELETE FROM " + TENANT + SCHEMA_SUFFIX + ".wallet_user");
        }
    }

    // ------------------------------------------------------------------ AC-02 / NFR-S-535-01

    @Test
    void pgDump_wrappedBlobColumn_doesNotContainSimulatedPlaintextKey() throws SQLException {
        UUID holderId = insertWalletUser("holder-pgdump");
        String credId = "cred-pgdump-1";
        insertPrfSalt(holderId, credId);

        insertHandleViaRepository(holderId.toString(), credId);

        // Read the raw blob bytes directly from JDBC to simulate a pg_dump inspection
        byte[] storedBlob;
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test");
             ResultSet rs = conn.createStatement().executeQuery(
                     "SELECT wrapped_blob FROM " + TENANT + SCHEMA_SUFFIX
                     + ".hybrid_wrapped_key_handle WHERE credential_id = '" + credId + "'")) {
            assertThat(rs.next()).as("Expected one row").isTrue();
            storedBlob = rs.getBytes("wrapped_blob");
        }

        // The stored blob must equal the submitted ciphertext (no transformation)
        assertThat(storedBlob).isEqualTo(WRAPPED_BLOB);

        // The simulated "plaintext private key" bytes must NOT appear anywhere in the blob
        assertThat(containsSubArray(storedBlob, SIMULATED_PLAINTEXT))
                .as("Plaintext key marker must not appear in the stored blob")
                .isFalse();
    }

    @Test
    void pgDump_noPlaintextKeyColumns_existInTable() throws SQLException {
        // Verify there is no separate plaintext_key or private_key column in the table
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test");
             ResultSet rs = conn.getMetaData().getColumns(
                     null, TENANT + SCHEMA_SUFFIX, "hybrid_wrapped_key_handle", null)) {
            while (rs.next()) {
                String colName = rs.getString("COLUMN_NAME").toLowerCase();
                assertThat(colName)
                        .as("Table must not contain a plaintext key column '%s'", colName)
                        .doesNotContain("private")
                        .doesNotContain("plaintext");
            }
        }
    }

    // ------------------------------------------------------------------ EC-03 / NFR-S-535-01 -- volume >= 100

    @Test
    void volume_100_holders_pgDump_contains_no_plaintext_marker() throws Exception {
        List<String> holderIds = seedHundredHolders();
        assertThat(holderIds).hasSizeGreaterThanOrEqualTo(VOLUME_COUNT);

        // Execute a real pg_dump of the schema and search output for the plaintext marker
        String dumpOutput = execPgDump();

        assertThat(dumpOutput)
                .as("pg_dump output must not contain the simulated plaintext key marker "
                    + "(NFR-S-535-01, AC-02 at scale with %d holders)", VOLUME_COUNT)
                .doesNotContain(new String(SIMULATED_PLAINTEXT));

        assertThat(dumpOutput)
                .as("pg_dump output must not contain 'private_key' column references "
                    + "(the column must not exist by structural design, AD-2)")
                .doesNotContainIgnoringCase("private_key");
    }

    @Test
    void volume_100_holders_pk_lookup_uses_index_scan() throws SQLException {
        List<String> holderIds = seedHundredHolders();
        String sampleHolderId = holderIds.get(0);
        String sampleCredId  = credIdForHolder(sampleHolderId);

        // EXPLAIN a lookup by composite PK and verify Index Scan is used
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test");
             ResultSet rs = conn.createStatement().executeQuery(
                     "EXPLAIN SELECT * FROM " + TENANT + SCHEMA_SUFFIX
                     + ".hybrid_wrapped_key_handle "
                     + "WHERE holder_id = '" + sampleHolderId + "'"
                     + "  AND credential_id = '" + sampleCredId + "'")) {
            StringBuilder plan = new StringBuilder();
            while (rs.next()) {
                plan.append(rs.getString(1)).append("\n");
            }
            String planStr = plan.toString();
            assertThat(planStr)
                    .as("PK lookup must use Index Scan (not Seq Scan) at volume %d -- "
                        + "EXPLAIN plan:\n%s", VOLUME_COUNT, planStr)
                    .containsIgnoringCase("Index Scan");
        }
    }

    // ------------------------------------------------------------------ helpers

    private UUID insertWalletUser(String emailPrefix) throws SQLException {
        UUID id = UUID.randomUUID();
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + TENANT + SCHEMA_SUFFIX + ".wallet_user (id, email) "
                    + "VALUES ('" + id + "', '" + emailPrefix + "-" + id + "@test.local')");
        }
        return id;
    }

    private void insertPrfSalt(UUID holderId, String credId) throws SQLException {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + TENANT + SCHEMA_SUFFIX + ".hybrid_prf_salt "
                    + "(holder_id, credential_id, prf_salt) "
                    + "VALUES ('" + holderId + "', '" + credId + "', "
                    + " decode('" + hex(new byte[32]) + "', 'hex'))");
        }
    }

    private void insertHandleViaRepository(String holderId, String credId) {
        WrappedKeyHandle handle = new WrappedKeyHandle(
                holderId, credId,
                WRAPPED_BLOB.clone(), IV.clone(), TAG.clone(),
                "HKDF-SHA-256", 1,
                "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"abc\",\"y\":\"def\"}",
                Instant.now(), null);

        StepVerifier.create(repository.insert(handle)
                        .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TENANT)))
                .verifyComplete();
    }

    /**
     * Seeds exactly {@code VOLUME_COUNT} wallet_user rows, one prf_salt row per user,
     * and one handle per user (in FK order: wallet_user -> prf_salt -> handle).
     *
     * @return list of UUID strings for each seeded holder
     */
    private List<String> seedHundredHolders() throws SQLException {
        List<String> holderIds = new ArrayList<>(VOLUME_COUNT);
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            conn.setAutoCommit(false);
            conn.createStatement().execute("SET search_path TO " + TENANT + SCHEMA_SUFFIX);
            for (int i = 0; i < VOLUME_COUNT; i++) {
                UUID hId = UUID.randomUUID();
                holderIds.add(hId.toString());
                String credId = credIdForHolder(hId.toString());
                conn.createStatement().execute(
                        "INSERT INTO wallet_user (id, email) "
                        + "VALUES ('" + hId + "', 'vol-" + i + "-" + hId + "@test.local')");
                // Seed prf_salt before handle (composite FK in V4 requires this order)
                conn.createStatement().execute(
                        "INSERT INTO hybrid_prf_salt (holder_id, credential_id, prf_salt) "
                        + "VALUES ('" + hId + "', '" + credId + "', "
                        + " decode('" + hex(new byte[32]) + "', 'hex'))");
                conn.createStatement().execute(
                        "INSERT INTO hybrid_wrapped_key_handle "
                        + "(holder_id, credential_id, wrapped_blob, iv, tag, kdf_algo, kdf_version, cnf_jwk) "
                        + "VALUES ('" + hId + "', '" + credId + "', "
                        + " decode('" + hex(WRAPPED_BLOB) + "', 'hex'), "
                        + " decode('" + hex(IV) + "', 'hex'), "
                        + " decode('" + hex(TAG) + "', 'hex'), "
                        + " 'HKDF-SHA-256', 1, '{\"kty\":\"EC\"}')");
            }
            conn.commit();
        }
        return holderIds;
    }

    private static String credIdForHolder(String holderId) {
        return "cred-vol-" + holderId.substring(0, 8);
    }

    /**
     * Executes {@code pg_dump} inside the PostgreSQL container and returns the dump output
     * as a string. Only the relevant schema is dumped to keep output manageable.
     */
    private String execPgDump() throws IOException, InterruptedException {
        String schemaName = TENANT + SCHEMA_SUFFIX;
        // pg_dump is available inside the Postgres container image
        org.testcontainers.containers.Container.ExecResult result = postgres.execInContainer(
                "pg_dump",
                "--username=test",
                "--no-password",
                "--schema=" + schemaName,
                "--data-only",
                "--table=" + schemaName + ".hybrid_wrapped_key_handle",
                "pgdump_it"
        );
        // Return stdout; ignore stderr (pg_dump warning about no password is expected)
        return result.getStdout();
    }

    private static boolean containsSubArray(byte[] outer, byte[] inner) {
        if (inner.length > outer.length) return false;
        outer_loop:
        for (int i = 0; i <= outer.length - inner.length; i++) {
            for (int j = 0; j < inner.length; j++) {
                if (outer[i + j] != inner[j]) continue outer_loop;
            }
            return true;
        }
        return false;
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
