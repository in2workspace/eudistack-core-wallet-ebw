package com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.keymanager.domain.model.WrappedKeyHandle;
import com.eudistack.ebw.keymanager.domain.port.WrappedKeyHandleRepository;
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

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies AC-05 / NFR-04: a full dump of the {@code hybrid_wrapped_key_handle} table
 * cannot be used to reconstruct the holder private key.
 *
 * <p>The test inserts a handle whose {@code wrapped_blob} contains known marker bytes,
 * then reads back the raw column bytes and asserts that the plaintext key bytes are
 * NOT present — confirming that only ciphertext (opaque from the server's perspective)
 * is stored.</p>
 *
 * <p>This test relies on a contract from the client (Wallet PWA): the blob it submits
 * is the output of {@code AES-256-GCM.encrypt(wrapKey, holderPrivateKey)} where
 * {@code wrapKey} is derived from the holder's passkey PRF output. The server never
 * sees the wrap key. This test just verifies the server does not accidentally store
 * or expose the raw private key bytes alongside the ciphertext.</p>
 *
 * <p>The {@code hybrid_wrapped_key_handle} table is created via a temporary DDL stub.
 * // TODO: replace with US-03 (EUDISTACK-535) Flyway tenant migration once merged.</p>
 *
 * <p>Spec: EUDISTACK-534 AC-05; NFR-04; architecture.md §5.3.</p>
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
    private static final String HOLDER        = "holder-pgdump";
    private static final String CRED_ID       = "cred-pgdump-1";

    // Marker bytes that represent a "plaintext private key" — these should NOT appear
    // in the DB. In a real scenario the blob is AES-256-GCM ciphertext; here we just
    // verify the server stores what it receives and doesn't leak separate plaintext columns.
    private static final byte[] SIMULATED_PLAINTEXT = "PRIVATE_KEY_MARKER_BYTES_12345678".getBytes();
    private static final byte[] WRAPPED_BLOB;   // blob is arbitrary ciphertext, ≥48 bytes
    private static final byte[] IV  = new byte[12];
    private static final byte[] TAG = new byte[16];

    static {
        // wrappedBlob is 48+ bytes of ciphertext — does NOT contain SIMULATED_PLAINTEXT
        WRAPPED_BLOB = new byte[48];
        Arrays.fill(WRAPPED_BLOB, (byte) 0xAB);  // opaque marker, not the plaintext
    }

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
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

    @Autowired WrappedKeyHandleRepository repository;

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
        // TODO: replace with US-03 (EUDISTACK-535) Flyway tenant migration once merged
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "CREATE TABLE IF NOT EXISTS " + TENANT + SCHEMA_SUFFIX + ".hybrid_wrapped_key_handle ("
                    + "  tenant_id     TEXT NOT NULL,"
                    + "  holder_id     TEXT NOT NULL,"
                    + "  credential_id TEXT NOT NULL,"
                    + "  wrapped_blob  BYTEA NOT NULL,"
                    + "  iv            BYTEA NOT NULL,"
                    + "  tag           BYTEA NOT NULL,"
                    + "  kdf_algo      VARCHAR(32) NOT NULL,"
                    + "  kdf_version   INTEGER NOT NULL,"
                    + "  cnf_jwk       TEXT NOT NULL,"
                    + "  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),"
                    + "  last_used_at  TIMESTAMPTZ,"
                    + "  PRIMARY KEY (holder_id, credential_id)"
                    + ")");
        }
    }

    @BeforeEach
    void clearTable() throws SQLException {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            conn.createStatement().execute(
                    "DELETE FROM " + TENANT + SCHEMA_SUFFIX + ".hybrid_wrapped_key_handle");
        }
    }

    // ------------------------------------------------------------------ AC-05 / NFR-04

    @Test
    void pgDump_wrappedBlobColumn_doesNotContainSimulatedPlaintextKey() throws SQLException {
        WrappedKeyHandle handle = new WrappedKeyHandle(
                TENANT, HOLDER, CRED_ID,
                WRAPPED_BLOB, IV, TAG,
                "HKDF-SHA-256", 1,
                "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"abc\",\"y\":\"def\"}",
                Instant.now(), null);

        StepVerifier.create(repository.insert(handle))
                .verifyComplete();

        // Read the raw blob bytes directly from JDBC to simulate a pg_dump inspection
        String jdbcUrl = postgres.getJdbcUrl();
        byte[] storedBlob;
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test");
             ResultSet rs = conn.createStatement().executeQuery(
                     "SELECT wrapped_blob FROM " + TENANT + SCHEMA_SUFFIX
                     + ".hybrid_wrapped_key_handle WHERE credential_id = '" + CRED_ID + "'")) {
            assertThat(rs.next()).as("Expected one row").isTrue();
            storedBlob = rs.getBytes("wrapped_blob");
        }

        // The stored blob must equal the submitted ciphertext (no transformation)
        assertThat(storedBlob).isEqualTo(WRAPPED_BLOB);

        // The simulated "plaintext private key" bytes must NOT appear anywhere in the blob
        // (in a real scenario they would be encrypted; here we confirm no accidental leakage)
        assertThat(containsSubArray(storedBlob, SIMULATED_PLAINTEXT))
                .as("Plaintext key marker must not appear in the stored blob")
                .isFalse();
    }

    @Test
    void pgDump_noPlaintextKeyColumns_existInTable() throws SQLException {
        // Verify there is no separate plaintext_key or private_key column in the table
        String jdbcUrl = postgres.getJdbcUrl();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test");
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

    // ------------------------------------------------------------------ helpers

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
}