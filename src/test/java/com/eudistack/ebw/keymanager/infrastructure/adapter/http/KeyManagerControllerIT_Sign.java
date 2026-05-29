package com.eudistack.ebw.keymanager.infrastructure.adapter.http;

import com.eudistack.ebw.domain.spi.TokenSigner;
import com.eudistack.ebw.keymanager.domain.exception.KeyAccessDeniedException;
import com.eudistack.ebw.keymanager.domain.exception.SigningTypeFormatMismatchException;
import com.eudistack.ebw.keymanager.domain.exception.TenantWalletProfileUnsupportedException;
import com.eudistack.ebw.keymanager.domain.exception.UnsupportedSigningTypeException;
import com.eudistack.ebw.keymanager.domain.model.CredentialFormat;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyId;
import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;
import com.eudistack.ebw.keymanager.domain.model.SignHolderKeyResult;
import com.eudistack.ebw.keymanager.domain.model.SigningType;
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
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeoutException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * HTTP integration tests for {@code POST /api/v1/keys/{keyId}/sign}.
 *
 * <p>Covers: AC-01 (KB_JWT happy path), AC-02 (VP_ENVELOPE happy path), AC-03 (unsupported type),
 * AC-04 (format mismatch), AC-06 (opaque 401), ES-01 (invalid body), ES-02 (key not found),
 * ES-03 (tenant profile unsupported), ES-05 (timeout), and no-auth 401.</p>
 */
@Tag("integration")
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"spring.autoconfigure.exclude=", "ebw.tenant-flyway.enabled=false"}
)
@AutoConfigureWebTestClient
@ActiveProfiles("integration")
@Testcontainers
class KeyManagerControllerIT_Sign {

    private static final String SCHEMA_SUFFIX = "_business_wallet";
    private static final String SERVER_DB_TENANT = "signctrltest";
    private static final String BROWSER_TENANT = "signbrowsertest";
    private static final UUID HOLDER_ID = UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-111111111111");
    private static final String BEARER = "test-bearer-token";
    private static final String KEY_ID = UUID.randomUUID().toString();
    private static final String SIGNING_INPUT = Base64.getUrlEncoder().withoutPadding()
            .encodeToString("test payload".getBytes());

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("sign_ctrl_it")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        String host = postgres.getHost();
        int port = postgres.getMappedPort(5432);
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://" + host + ":" + port + "/sign_ctrl_it");
        registry.add("spring.r2dbc.username", () -> "test");
        registry.add("spring.r2dbc.password", () -> "test");
        registry.add("spring.flyway.url", () ->
                "jdbc:postgresql://" + host + ":" + port + "/sign_ctrl_it");
        registry.add("spring.flyway.user", () -> "test");
        registry.add("spring.flyway.password", () -> "test");
        registry.add("spring.flyway.default-schema", () -> "public");
        registry.add("ebw.encryption.key", () -> "01LvWiH/24uNc/Um3GF8n3sFUwtfv8xBmFST4bc56oc=");
    }

    @MockitoBean
    TokenSigner tokenSigner;

    @MockitoBean
    KeyManagerPort keyManagerPort;

    @Autowired
    WebTestClient webClient;

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

    private WebTestClient.ResponseSpec postSign(String tenant, String keyId, Object body) {
        return webClient.post()
                .uri("/api/v1/keys/" + keyId + "/sign")
                .header("Host", tenant + ".eudistack.net")
                .header("Authorization", "Bearer " + BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .exchange();
    }

    private static Map<String, Object> validBody(String signingType) {
        return Map.of(
                "signing_type", signingType,
                "purpose", "PRESENTATION",
                "signing_input", SIGNING_INPUT
        );
    }

    private static SignHolderKeyResult fakeResult() {
        return new SignHolderKeyResult("h.p.s", KeyAlgorithm.ES256, "jkt-abc");
    }

    // --- AC-01: KB_JWT happy path → 200 with jws, algorithm, jkt ---

    @Test
    void sign_kbJwt_happyPath_returns200() {
        when(keyManagerPort.signWithHolderKey(any())).thenReturn(Mono.just(fakeResult()));

        postSign(SERVER_DB_TENANT, KEY_ID, validBody("KB_JWT"))
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.jws").isEqualTo("h.p.s")
                .jsonPath("$.algorithm").isEqualTo("ES256")
                .jsonPath("$.jkt").isEqualTo("jkt-abc");
    }

    // --- AC-02: VP_ENVELOPE happy path → 200 ---

    @Test
    void sign_vpEnvelope_happyPath_returns200() {
        when(keyManagerPort.signWithHolderKey(any())).thenReturn(Mono.just(fakeResult()));

        postSign(SERVER_DB_TENANT, KEY_ID, validBody("VP_ENVELOPE"))
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.jws").isNotEmpty();
    }

    // --- AC-03: unsupported signing type → 400 ---

    @Test
    void sign_unsupportedSigningType_returns400() {
        when(keyManagerPort.signWithHolderKey(any())).thenReturn(
                Mono.error(new UnsupportedSigningTypeException(SigningType.KB_JWT)));

        postSign(SERVER_DB_TENANT, KEY_ID, validBody("KB_JWT"))
                .expectStatus().isBadRequest();
    }

    // --- AC-04: format mismatch → 400 ---

    @Test
    void sign_formatMismatch_returns400() {
        when(keyManagerPort.signWithHolderKey(any())).thenReturn(
                Mono.error(new SigningTypeFormatMismatchException(SigningType.KB_JWT, CredentialFormat.VC_JWT)));

        postSign(SERVER_DB_TENANT, KEY_ID, validBody("KB_JWT"))
                .expectStatus().isBadRequest();
    }

    // --- AC-06: key not found → opaque 401 with {"error": "KeyAccessDenied"} ---

    @Test
    void sign_keyNotFound_returns401Opaque() {
        when(keyManagerPort.signWithHolderKey(any())).thenReturn(
                Mono.error(new KeyAccessDeniedException("KEY_NOT_FOUND")));

        postSign(SERVER_DB_TENANT, KEY_ID, validBody("KB_JWT"))
                .expectStatus().isUnauthorized()
                .expectBody()
                .jsonPath("$.error").isEqualTo("KeyAccessDenied");
    }

    // --- ES-01: invalid request body → 400 ---

    @Test
    void sign_missingSigningInput_returns400() {
        Map<String, Object> body = Map.of(
                "signing_type", "KB_JWT",
                "purpose", "PRESENTATION"
                // missing signing_input
        );
        postSign(SERVER_DB_TENANT, KEY_ID, body)
                .expectStatus().isBadRequest();
    }

    // --- ES-03: browser tenant → 403 ---

    @Test
    void sign_browserTenant_returns403() {
        when(keyManagerPort.signWithHolderKey(any())).thenReturn(
                Mono.error(new TenantWalletProfileUnsupportedException("browser")));

        postSign(BROWSER_TENANT, KEY_ID, validBody("KB_JWT"))
                .expectStatus().isForbidden();
    }

    // --- ES-05: timeout → 503 ---

    @Test
    void sign_timeout_returns503() {
        when(keyManagerPort.signWithHolderKey(any())).thenReturn(
                Mono.error(new TimeoutException("signing timed out")));

        postSign(SERVER_DB_TENANT, KEY_ID, validBody("KB_JWT"))
                .expectStatus().isEqualTo(503);
    }

    // --- No Authorization → 401 ---

    @Test
    void sign_noAuth_returns401() {
        webClient.post()
                .uri("/api/v1/keys/" + KEY_ID + "/sign")
                .header("Host", SERVER_DB_TENANT + ".eudistack.net")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(validBody("KB_JWT"))
                .exchange()
                .expectStatus().isUnauthorized();
    }
}
