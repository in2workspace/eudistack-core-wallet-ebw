package com.eudistack.ebw.keymanager.infrastructure.adapter.http;

import com.eudistack.ebw.domain.spi.TokenSigner;
import com.eudistack.ebw.keymanager.domain.exception.UnsupportedJwsAlgorithmException;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyId;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyResult;
import com.eudistack.ebw.keymanager.domain.model.JwkPublic;
import com.eudistack.ebw.keymanager.domain.model.JwsProof;
import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;
import com.eudistack.ebw.keymanager.domain.port.KeyManagerPort;
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
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeoutException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Integration tests for {@link KeyManagerController} using the full Spring Boot context.
 *
 * <p>The {@link KeyManagerPort} is replaced with a Mockito mock so each test controls
 * the outcome without touching the database. The {@link TokenSigner} is also mocked so JWT
 * auth can be bypassed without a running key pair file.
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>AC-01 — new key: 201 with key_id, public_jwk, jws_proof, no warning field</li>
 *   <li>AC-01 / EC-01 — existing key: 201 + {@code warning="existing_key_algorithm_used"}</li>
 *   <li>AC-02 — unsupported credential format → 400</li>
 *   <li>AC-03 — no intersecting algorithm → 422</li>
 *   <li>ES-01 — invalid request body → 400, no field-name disclosure</li>
 *   <li>ES-02 — browser-mode tenant → 403 with no body (anti-probing)</li>
 *   <li>ES-04 — key generation timeout → 503</li>
 *   <li>No Authorization header → 401</li>
 * </ul>
 */
@Tag("integration")
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"spring.autoconfigure.exclude=", "ebw.tenant-flyway.enabled=false"}
)
@AutoConfigureWebTestClient
@ActiveProfiles("integration")
@Testcontainers
class KeyManagerControllerIT {

    private static final String SCHEMA_SUFFIX = "_business_wallet";
    private static final String SERVER_DB_TENANT = "kmctrlit";
    private static final String BROWSER_TENANT = "kmbrowserit";
    private static final UUID HOLDER_ID = UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    private static final String BEARER = "test-bearer-token";

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("keymanager_ctrl_it")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        String host = postgres.getHost();
        int port = postgres.getMappedPort(5432);
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://" + host + ":" + port + "/keymanager_ctrl_it");
        registry.add("spring.r2dbc.username", () -> "test");
        registry.add("spring.r2dbc.password", () -> "test");
        registry.add("spring.flyway.url", () ->
                "jdbc:postgresql://" + host + ":" + port + "/keymanager_ctrl_it");
        registry.add("spring.flyway.user", () -> "test");
        registry.add("spring.flyway.password", () -> "test");
        registry.add("spring.flyway.default-schema", () -> "public");
    }

    @MockitoBean
    TokenSigner tokenSigner;

    @MockitoBean
    KeyManagerPort keyManagerPort;

    @Autowired
    WebTestClient webClient;

    // -------------------------------------------------------------------------
    // One-time schema provisioning (idempotent via IF NOT EXISTS + ON CONFLICT)
    // -------------------------------------------------------------------------

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
                    "CREATE SCHEMA IF NOT EXISTS " + SERVER_DB_TENANT + SCHEMA_SUFFIX);
            conn.createStatement().execute(
                    "CREATE SCHEMA IF NOT EXISTS " + BROWSER_TENANT + SCHEMA_SUFFIX);
        }
        runTenantMigrations(jdbcUrl, SERVER_DB_TENANT + SCHEMA_SUFFIX);
        runTenantMigrations(jdbcUrl, BROWSER_TENANT + SCHEMA_SUFFIX);
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

    @BeforeEach
    void setUp() throws SQLException {
        seedWalletProfile(SERVER_DB_TENANT, "server", "db");
        seedWalletProfile(BROWSER_TENANT, "browser", null);
        when(tokenSigner.verify(BEARER)).thenReturn(
                Map.of("sub", HOLDER_ID.toString(), "email", "test@test.com"));
    }

    private void seedWalletProfile(String tenant, String walletMode, String keyManager)
            throws SQLException {
        String schema = tenant + SCHEMA_SUFFIX;
        String kmValue = (keyManager == null) ? "NULL" : ("'" + keyManager + "'");
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            conn.createStatement().execute(
                    "DELETE FROM " + schema + ".tenant_wallet_profile WHERE tenant = '" + tenant + "'");
            conn.createStatement().execute(
                    "INSERT INTO " + schema + ".tenant_wallet_profile (tenant, wallet_mode, key_manager) "
                    + "VALUES ('" + tenant + "', '" + walletMode + "', " + kmValue + ") "
                    + "ON CONFLICT (tenant) DO NOTHING");
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static Map<String, Object> validBody(String credentialId) {
        return Map.of(
                "credential_id", credentialId,
                "format", "dc+sd-jwt",
                "supported_algs", new String[]{"ES256"},
                "issuer_identifier", "https://issuer.example.com"
        );
    }

    private static HolderKeyResult fakeResult(boolean created) {
        return new HolderKeyResult(
                HolderKeyId.generate(),
                new JwkPublic(Map.of("kty", "EC", "crv", "P-256", "x", "abc", "y", "def")),
                new JwsProof("aaa.bbb.ccc", KeyAlgorithm.ES256),
                created
        );
    }

    private WebTestClient.ResponseSpec postWithAuth(String tenant, Object body) {
        return webClient.post()
                .uri("/api/v1/keys/generate")
                .header("Host", tenant + ".eudistack.net")
                .header("Authorization", "Bearer " + BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .exchange();
    }

    // -------------------------------------------------------------------------
    // AC-01 — new key: 201 with all fields, no warning
    // -------------------------------------------------------------------------

    @Test
    void generate_newKey_returns201WithAllFieldsAndNoWarning() {
        when(keyManagerPort.generateHolderKey(any())).thenReturn(Mono.just(fakeResult(true)));

        postWithAuth(SERVER_DB_TENANT, validBody("cred-new"))
                .expectStatus().isCreated()
                .expectBody()
                .jsonPath("$.key_id").isNotEmpty()
                .jsonPath("$.public_jwk").isNotEmpty()
                .jsonPath("$.jws_proof").isEqualTo("aaa.bbb.ccc")
                .jsonPath("$.warning").doesNotExist();
    }

    // -------------------------------------------------------------------------
    // AC-01 / EC-01 / ES-03 — existing key: 201 + warning
    // -------------------------------------------------------------------------

    @Test
    void generate_existingKey_returns201WithWarning() {
        when(keyManagerPort.generateHolderKey(any())).thenReturn(Mono.just(fakeResult(false)));

        postWithAuth(SERVER_DB_TENANT, validBody("cred-existing"))
                .expectStatus().isCreated()
                .expectBody()
                .jsonPath("$.key_id").isNotEmpty()
                .jsonPath("$.warning").isEqualTo("existing_key_algorithm_used");
    }

    // -------------------------------------------------------------------------
    // AC-02 — unsupported credential format → 400
    // -------------------------------------------------------------------------

    @Test
    void generate_unsupportedFormat_returns400() {
        Map<String, Object> body = Map.of(
                "credential_id", "cred-1",
                "format", "ldp_vc",
                "supported_algs", new String[]{"ES256"},
                "issuer_identifier", "https://issuer.example.com"
        );

        postWithAuth(SERVER_DB_TENANT, body)
                .expectStatus().isBadRequest();
    }

    // -------------------------------------------------------------------------
    // AC-03 — no intersecting algorithm → 422
    // -------------------------------------------------------------------------

    @Test
    void generate_noIntersectingAlgorithm_returns422() {
        when(keyManagerPort.generateHolderKey(any())).thenReturn(
                Mono.error(new UnsupportedJwsAlgorithmException(
                        java.util.List.of("RS256"), java.util.List.of("ES256", "ES384", "EdDSA"))));

        postWithAuth(SERVER_DB_TENANT, validBody("cred-alg"))
                .expectStatus().isEqualTo(422);
    }

    // -------------------------------------------------------------------------
    // ES-01 — validation matrix: invalid body → 400, no field-name disclosure
    // -------------------------------------------------------------------------

    @Test
    void generate_blankCredentialId_returns400() {
        Map<String, Object> body = Map.of(
                "credential_id", "",
                "format", "dc+sd-jwt",
                "supported_algs", new String[]{"ES256"},
                "issuer_identifier", "https://issuer.example.com"
        );
        postWithAuth(SERVER_DB_TENANT, body)
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.detail").doesNotExist();
    }

    @Test
    void generate_emptySupportedAlgs_returns400() {
        Map<String, Object> body = Map.of(
                "credential_id", "cred-1",
                "format", "dc+sd-jwt",
                "supported_algs", new String[]{},
                "issuer_identifier", "https://issuer.example.com"
        );
        postWithAuth(SERVER_DB_TENANT, body)
                .expectStatus().isBadRequest();
    }

    @Test
    void generate_invalidIssuerUrl_returns400() {
        Map<String, Object> body = Map.of(
                "credential_id", "cred-1",
                "format", "dc+sd-jwt",
                "supported_algs", new String[]{"ES256"},
                "issuer_identifier", "not-a-url"
        );
        postWithAuth(SERVER_DB_TENANT, body)
                .expectStatus().isBadRequest();
    }

    @Test
    void generate_missingRequiredField_returns400() {
        // No credential_id
        Map<String, Object> body = Map.of(
                "format", "dc+sd-jwt",
                "supported_algs", new String[]{"ES256"},
                "issuer_identifier", "https://issuer.example.com"
        );
        postWithAuth(SERVER_DB_TENANT, body)
                .expectStatus().isBadRequest();
    }

    // -------------------------------------------------------------------------
    // ES-02 — browser-mode tenant → 403 with no body (anti-probing)
    // -------------------------------------------------------------------------

    @Test
    void generate_browserTenant_returns403WithNoBody() {
        when(keyManagerPort.generateHolderKey(any())).thenReturn(Mono.just(fakeResult(true)));

        postWithAuth(BROWSER_TENANT, validBody("cred-browser"))
                .expectStatus().isForbidden()
                .expectBody().isEmpty();
    }

    // -------------------------------------------------------------------------
    // ES-04 — key generation timeout → 503
    // -------------------------------------------------------------------------

    @Test
    void generate_timeout_returns503() {
        when(keyManagerPort.generateHolderKey(any())).thenReturn(
                Mono.error(new TimeoutException("key generation timed out")));

        postWithAuth(SERVER_DB_TENANT, validBody("cred-timeout"))
                .expectStatus().isEqualTo(503);
    }

    // -------------------------------------------------------------------------
    // No Authorization header → 401
    // -------------------------------------------------------------------------

    @Test
    void generate_noAuthorizationHeader_returns401() {
        webClient.post()
                .uri("/api/v1/keys/generate")
                .header("Host", SERVER_DB_TENANT + ".eudistack.net")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(validBody("cred-noauth"))
                .exchange()
                .expectStatus().isUnauthorized();
    }
}