package com.eudistack.ebw.keymanager.infrastructure.adapter.http;

import com.eudistack.ebw.domain.spi.TokenSigner;
import com.eudistack.ebw.keymanager.application.PrfSaltUseCase;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import reactor.core.publisher.Mono;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Integration tests for the {@code POST /api/v1/keys/hybrid/onboarding/commit} endpoint.
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>AC-04 / AC-06 — new handle persisted with holderId from DPoP session → 201</li>
 *   <li>AC-07 — identical re-submit → 200 ACK (idempotent)</li>
 *   <li>ES-03 — different blob for same (holderId, credentialId) → 409</li>
 *   <li>ES-01 — missing required field → 400</li>
 *   <li>ES-02 — non-hybrid tenant → 403 opaque</li>
 * </ul>
 *
 * <p>The {@code hybrid_wrapped_key_handle} table is created via a temporary DDL stub.
 * // TODO: replace with US-03 (EUDISTACK-535) Flyway tenant migration once merged.</p>
 *
 * <p>Spec: EUDISTACK-534 AC-04, AC-06, AC-07, ES-01, ES-02, ES-03.</p>
 */
@Tag("integration")
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"spring.autoconfigure.exclude=", "ebw.tenant-flyway.enabled=false"}
)
@AutoConfigureWebTestClient
@ActiveProfiles("integration")
@Testcontainers
class EnrollHolderCommitIT {

    private static final String SCHEMA_SUFFIX   = "_business_wallet";
    private static final String HYBRID_TENANT   = "hcommit";
    private static final String DB_TENANT       = "hcommitdb";
    private static final UUID   HOLDER_UUID     = UUID.fromString("aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb");
    private static final String BEARER          = "hybrid-commit-bearer";
    private static final String COMMIT_URL      = "/api/v1/keys/hybrid/onboarding/commit";

    // Minimal valid commit payload fixtures
    private static final String BLOB_B64 =
            Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[48]);
    private static final String IV_B64 =
            Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[12]);
    private static final String TAG_B64 =
            Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[16]);
    private static final String CNF_JWK =
            "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"abc\",\"y\":\"def\"}";

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("enroll_commit_it")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        String host = postgres.getHost();
        int port = postgres.getMappedPort(5432);
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://" + host + ":" + port + "/enroll_commit_it");
        registry.add("spring.r2dbc.username", () -> "test");
        registry.add("spring.r2dbc.password", () -> "test");
        registry.add("spring.flyway.url", () ->
                "jdbc:postgresql://" + host + ":" + port + "/enroll_commit_it");
        registry.add("spring.flyway.user", () -> "test");
        registry.add("spring.flyway.password", () -> "test");
        registry.add("spring.flyway.default-schema", () -> "public");
    }

    @MockitoBean TokenSigner tokenSigner;
    @MockitoBean PrfSaltUseCase prfSaltUseCase;

    @Autowired WebTestClient webClient;

    @BeforeAll
    static void provisionSchemas() throws SQLException {
        String jdbcUrl = postgres.getJdbcUrl();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE ebw_app_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE config_manager_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute(
                    "CREATE SCHEMA IF NOT EXISTS " + HYBRID_TENANT + SCHEMA_SUFFIX);
            conn.createStatement().execute(
                    "CREATE SCHEMA IF NOT EXISTS " + DB_TENANT + SCHEMA_SUFFIX);
        }
        runTenantMigrations(jdbcUrl, HYBRID_TENANT + SCHEMA_SUFFIX);
        runTenantMigrations(jdbcUrl, DB_TENANT + SCHEMA_SUFFIX);
        createHandleTable(jdbcUrl, HYBRID_TENANT + SCHEMA_SUFFIX);
        createHandleTable(jdbcUrl, DB_TENANT + SCHEMA_SUFFIX);
    }

    private static void runTenantMigrations(String jdbcUrl, String schema) {
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

    // TODO: replace with US-03 (EUDISTACK-535) Flyway tenant migration once merged
    private static void createHandleTable(String jdbcUrl, String schema) throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "CREATE TABLE IF NOT EXISTS " + schema + ".hybrid_wrapped_key_handle ("
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
    void setUp() throws SQLException {
        seedWalletProfile(HYBRID_TENANT, "server", "hybrid");
        seedWalletProfile(DB_TENANT, "server", "db");
        when(tokenSigner.verify(BEARER)).thenReturn(
                Map.of("sub", HOLDER_UUID.toString(), "email", "test@test.com"));
        clearHandleTable(HYBRID_TENANT + SCHEMA_SUFFIX);
    }

    private void seedWalletProfile(String tenant, String mode, String km) throws SQLException {
        String schema = tenant + SCHEMA_SUFFIX;
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            conn.createStatement().execute(
                    "DELETE FROM " + schema + ".tenant_wallet_profile WHERE tenant = '" + tenant + "'");
            conn.createStatement().execute(
                    "INSERT INTO " + schema + ".tenant_wallet_profile (tenant, wallet_mode, key_manager) "
                    + "VALUES ('" + tenant + "', '" + mode + "', '" + km + "') "
                    + "ON CONFLICT (tenant) DO NOTHING");
        }
    }

    private void clearHandleTable(String schema) throws SQLException {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            conn.createStatement().execute(
                    "DELETE FROM " + schema + ".hybrid_wrapped_key_handle");
        }
    }

    // ------------------------------------------------------------------ AC-04/AC-06

    @Test
    void commit_hybridTenant_newHandle_returns201WithCredentialId() {
        webClient.post().uri(COMMIT_URL)
                .header("Host", HYBRID_TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(validBody("cred-new-1"))
                .exchange()
                .expectStatus().isCreated()
                .expectBody()
                .jsonPath("$.credential_id").isEqualTo("cred-new-1");
    }

    // ------------------------------------------------------------------ AC-07

    @Test
    void commit_identicalReplay_returns200WithoutDuplicate() {
        String credId = "cred-replay-1";
        // First commit
        webClient.post().uri(COMMIT_URL)
                .header("Host", HYBRID_TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(validBody(credId))
                .exchange()
                .expectStatus().isCreated();

        // Identical replay
        webClient.post().uri(COMMIT_URL)
                .header("Host", HYBRID_TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(validBody(credId))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.credential_id").isEqualTo(credId);
    }

    // ------------------------------------------------------------------ ES-03

    @Test
    void commit_differentBlob_returns409WithIdempotencyReplay() {
        String credId = "cred-conflict-1";
        webClient.post().uri(COMMIT_URL)
                .header("Host", HYBRID_TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(validBody(credId))
                .exchange()
                .expectStatus().isCreated();

        // Different blob
        byte[] differentBlob = new byte[48];
        differentBlob[0] = 0x42;
        String differentBlobB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(differentBlob);
        webClient.post().uri(COMMIT_URL)
                .header("Host", HYBRID_TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(bodyWith(credId, differentBlobB64, IV_B64, TAG_B64))
                .exchange()
                .expectStatus().isEqualTo(409)
                .expectBody()
                .jsonPath("$.error").isEqualTo("idempotency_replay");
    }

    // ------------------------------------------------------------------ ES-01

    @Test
    void commit_missingRequiredField_returns400() {
        webClient.post().uri(COMMIT_URL)
                .header("Host", HYBRID_TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"credential_id\":\"cred-1\"}")  // missing all crypto fields
                .exchange()
                .expectStatus().isBadRequest();
    }

    // ------------------------------------------------------------------ ES-02

    @Test
    void commit_dbTenant_returns403Opaque() {
        webClient.post().uri(COMMIT_URL)
                .header("Host", DB_TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(validBody("cred-db-1"))
                .exchange()
                .expectStatus().isForbidden()
                .expectBody().isEmpty();
    }

    // ------------------------------------------------------------------ helpers

    private Map<String, Object> validBody(String credId) {
        return bodyWith(credId, BLOB_B64, IV_B64, TAG_B64);
    }

    private Map<String, Object> bodyWith(String credId, String blob, String iv, String tag) {
        return Map.of(
                "credential_id", credId,
                "wrapped_blob",  blob,
                "iv",            iv,
                "tag",           tag,
                "kdf_algo",      "HKDF-SHA-256",
                "kdf_version",   1,
                "cnf_jwk",       CNF_JWK
        );
    }
}