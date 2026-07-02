package com.eudistack.ebw.keymanager.infrastructure.adapter.http;

import com.eudistack.ebw.domain.spi.TokenSigner;
import com.eudistack.ebw.keymanager.application.PrfSaltUseCase;
import com.eudistack.ebw.keymanager.domain.exception.HolderIsolationViolationException;
import com.eudistack.ebw.keymanager.domain.exception.PrfSaltNotFoundException;
import com.eudistack.ebw.keymanager.domain.model.WrappedKeyHandle;
import com.eudistack.ebw.keymanager.domain.port.WrappedKeyHandleRepository;
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
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Integration tests for {@code POST /api/v1/keys/hybrid/sign/prepare}.
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>AC-01 — 200 OK with all required fields ({@code prf_salt}, {@code wrapped_blob},
 *       {@code iv}, {@code tag}, {@code kdf_params}, {@code signing_input},
 *       {@code correlation_id}).</li>
 *   <li>ES-02 — non-hybrid tenant → 403 opaque.</li>
 *   <li>ES-01 — missing required field → 400.</li>
 *   <li>AC-08 — holder isolation violation → 403.</li>
 *   <li>NFR-S-536-03 — error responses MUST NOT contain {@code prf_salt}, {@code wrapped_blob}.</li>
 * </ul>
 *
 * <p>{@link PrfSaltUseCase} and {@link WrappedKeyHandleRepository} are mocked to focus on
 * the HTTP contract and use-case orchestration rather than DB persistence.</p>
 *
 * <p>Spec: EUDISTACK-536 AC-01, AC-03, AC-08, ES-01, ES-02, ES-04, NFR-S-536-03;
 * architecture.md §6.2.</p>
 */
@Tag("integration")
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"spring.autoconfigure.exclude=", "ebw.tenant-flyway.enabled=false"}
)
@AutoConfigureWebTestClient
@ActiveProfiles("integration")
@Testcontainers
class PrepareSignIT {

    private static final String SCHEMA_SUFFIX = "_business_wallet";
    private static final String HYBRID_TENANT = "hprep";
    private static final String DB_TENANT     = "hprepdb";
    private static final UUID   HOLDER_UUID   = UUID.fromString("11111111-aaaa-bbbb-cccc-dddddddddddd");
    private static final String BEARER        = "hybrid-prepare-bearer";
    private static final String PREPARE_URL   = "/api/v1/keys/hybrid/sign/prepare";
    private static final String CRED_ID       = "cred-prepare-1";

    private static final byte[] PRF_SALT   = new byte[32];
    private static final byte[] BLOB_BYTES = new byte[48];
    private static final byte[] IV_BYTES   = new byte[12];
    private static final byte[] TAG_BYTES  = new byte[16];
    private static final String CNF_JWK    =
            "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"test-x\",\"y\":\"test-y\"}";

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("prepare_sign_it")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        String host = postgres.getHost();
        int port = postgres.getMappedPort(5432);
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://" + host + ":" + port + "/prepare_sign_it");
        registry.add("spring.r2dbc.username", () -> "test");
        registry.add("spring.r2dbc.password", () -> "test");
        registry.add("spring.flyway.url", () ->
                "jdbc:postgresql://" + host + ":" + port + "/prepare_sign_it");
        registry.add("spring.flyway.user", () -> "test");
        registry.add("spring.flyway.password", () -> "test");
        registry.add("spring.flyway.default-schema", () -> "public");
    }

    @MockitoBean TokenSigner tokenSigner;
    @MockitoBean PrfSaltUseCase prfSaltUseCase;
    @MockitoBean WrappedKeyHandleRepository wrappedKeyHandleRepository;

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
        seedWalletProfile(HYBRID_TENANT, "server", "hybrid");
        seedWalletProfile(DB_TENANT, "server", "db");
        when(tokenSigner.verify(BEARER)).thenReturn(
                Map.of("sub", HOLDER_UUID.toString(), "email", "test@test.com"));
        when(prfSaltUseCase.getForHolder(any(), any(), any())).thenReturn(Mono.just(PRF_SALT));
        when(wrappedKeyHandleRepository.findBy(any(), any()))
                .thenReturn(Mono.just(Optional.of(validHandle())));
    }

    // ------------------------------------------------------------------ AC-01

    @Test
    void prepare_hybridTenant_returns200WithAllRequiredFields() {
        webClient.post().uri(PREPARE_URL)
                .header("Host", HYBRID_TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("credential_id", CRED_ID, "vp_challenge", "nonce-abc", "format", "vc+sd-jwt"))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.prf_salt").isNotEmpty()
                .jsonPath("$.wrapped_blob").isNotEmpty()
                .jsonPath("$.iv").isNotEmpty()
                .jsonPath("$.tag").isNotEmpty()
                .jsonPath("$.kdf_params").isNotEmpty()
                .jsonPath("$.signing_input").isNotEmpty()
                .jsonPath("$.correlation_id").isNotEmpty();
    }

    @Test
    void prepare_hybridTenant_signingInputHasHeaderDotPayloadFormat() {
        webClient.post().uri(PREPARE_URL)
                .header("Host", HYBRID_TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("credential_id", CRED_ID, "vp_challenge", "nonce-xyz", "format", "vc+sd-jwt"))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.signing_input").value((String s) -> {
                    String[] parts = s.split("\\.");
                    assertThat(parts).as("signing_input must be headerB64.payloadB64").hasSize(2);
                    assertThat(parts[0]).isNotBlank();
                    assertThat(parts[1]).isNotBlank();
                });
    }

    @Test
    void prepare_hybridTenant_correlationIdIsUuidFormat() {
        webClient.post().uri(PREPARE_URL)
                .header("Host", HYBRID_TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("credential_id", CRED_ID, "vp_challenge", "nonce-corr", "format", "vc+sd-jwt"))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.correlation_id").value((String s) ->
                        assertThat(s).as("correlation_id must be UUID format")
                                .matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"));
    }

    // ------------------------------------------------------------------ ES-02

    @Test
    void prepare_dbTenant_returns403Opaque() {
        webClient.post().uri(PREPARE_URL)
                .header("Host", DB_TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("credential_id", CRED_ID, "vp_challenge", "nonce", "format", "vc+sd-jwt"))
                .exchange()
                .expectStatus().isForbidden()
                .expectBody().isEmpty();
    }

    // ------------------------------------------------------------------ ES-01

    @Test
    void prepare_missingVpChallenge_returns400() {
        webClient.post().uri(PREPARE_URL)
                .header("Host", HYBRID_TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("credential_id", CRED_ID, "format", "vc+sd-jwt"))
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    void prepare_missingCredentialId_returns400() {
        webClient.post().uri(PREPARE_URL)
                .header("Host", HYBRID_TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("vp_challenge", "nonce", "format", "vc+sd-jwt"))
                .exchange()
                .expectStatus().isBadRequest();
    }

    // ------------------------------------------------------------------ AC-08 / ES-04

    @Test
    void prepare_holderIsolationViolation_returns403() {
        when(prfSaltUseCase.getForHolder(any(), any(), any()))
                .thenReturn(Mono.error(new HolderIsolationViolationException(CRED_ID)));

        webClient.post().uri(PREPARE_URL)
                .header("Host", HYBRID_TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("credential_id", CRED_ID, "vp_challenge", "nonce", "format", "vc+sd-jwt"))
                .exchange()
                .expectStatus().isForbidden();
    }

    // ------------------------------------------------------------------ wrap_handle_not_found

    @Test
    void prepare_credentialNotFound_returns404() {
        when(prfSaltUseCase.getForHolder(any(), any(), any()))
                .thenReturn(Mono.error(new PrfSaltNotFoundException(CRED_ID)));

        webClient.post().uri(PREPARE_URL)
                .header("Host", HYBRID_TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("credential_id", CRED_ID, "vp_challenge", "nonce", "format", "vc+sd-jwt"))
                .exchange()
                .expectStatus().isNotFound()
                .expectBody()
                .jsonPath("$.error").isEqualTo("wrap_handle_not_found");
    }

    // ------------------------------------------------------------------ NFR-S-536-03

    @Test
    void prepare_errorResponse_doesNotLeakCryptoMaterial() {
        when(prfSaltUseCase.getForHolder(any(), any(), any()))
                .thenReturn(Mono.error(new PrfSaltNotFoundException(CRED_ID)));

        webClient.post().uri(PREPARE_URL)
                .header("Host", HYBRID_TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("credential_id", CRED_ID, "vp_challenge", "nonce", "format", "vc+sd-jwt"))
                .exchange()
                .expectStatus().isNotFound()
                .expectBody(String.class)
                .value(body -> {
                    assertThat(body).as("NFR-S-536-03: error body must not contain prf_salt")
                            .doesNotContain("prf_salt");
                    assertThat(body).as("NFR-S-536-03: error body must not contain wrapped_blob")
                            .doesNotContain("wrapped_blob");
                });
    }

    // ------------------------------------------------------------------ helpers

    private WrappedKeyHandle validHandle() {
        return new WrappedKeyHandle(
                HOLDER_UUID.toString(), CRED_ID, BLOB_BYTES, IV_BYTES, TAG_BYTES,
                "HKDF-SHA-256", 1, CNF_JWK, Instant.now(), null);
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
}
