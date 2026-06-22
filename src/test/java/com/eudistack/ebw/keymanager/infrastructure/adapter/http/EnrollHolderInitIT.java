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
import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Integration tests for the {@code POST /api/v1/keys/hybrid/onboarding/init} endpoint.
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>AC-01 (partial) — 200 OK with {@code prf_salt}, {@code kdf_params}, and
 *       {@code signing_pubkey_envelope_format} for a hybrid tenant.</li>
 *   <li>ES-02 — non-hybrid tenant → 403 opaque.</li>
 *   <li>ES-01 — missing required field → 400.</li>
 * </ul>
 *
 * <p>PRF salt generation logic lives in US-05 (EUDISTACK-537) — {@link PrfSaltUseCase}
 * is mocked here.</p>
 *
 * <p>Spec: EUDISTACK-534 AC-01, ES-01, ES-02; architecture.md §6.1 steps 3–5.</p>
 */
@Tag("integration")
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"spring.autoconfigure.exclude=", "ebw.tenant-flyway.enabled=false"}
)
@AutoConfigureWebTestClient
@ActiveProfiles("integration")
@Testcontainers
class EnrollHolderInitIT {

    private static final String SCHEMA_SUFFIX = "_business_wallet";
    private static final String HYBRID_TENANT = "hinit";
    private static final String DB_TENANT     = "hinitdb";
    private static final UUID   HOLDER_UUID   = UUID.fromString("cccccccc-1111-2222-3333-dddddddddddd");
    private static final String BEARER        = "hybrid-init-bearer";
    private static final String INIT_URL      = "/api/v1/keys/hybrid/onboarding/init";

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("enroll_init_it")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        String host = postgres.getHost();
        int port = postgres.getMappedPort(5432);
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://" + host + ":" + port + "/enroll_init_it");
        registry.add("spring.r2dbc.username", () -> "test");
        registry.add("spring.r2dbc.password", () -> "test");
        registry.add("spring.flyway.url", () ->
                "jdbc:postgresql://" + host + ":" + port + "/enroll_init_it");
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

    // ------------------------------------------------------------------ AC-01

    @Test
    void init_hybridTenant_returns200WithPrfSaltAndKdfParams() {
        byte[] salt = new byte[32];
        salt[0] = 0x01;
        when(prfSaltUseCase.getOrCreatePrfSalt(any(), any(), any())).thenReturn(Mono.just(salt));

        webClient.post().uri(INIT_URL)
                .header("Host", HYBRID_TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("credential_id", "cred-init-1", "format", "vc+sd-jwt"))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.prf_salt").isNotEmpty()
                .jsonPath("$.kdf_params").isNotEmpty()
                .jsonPath("$.signing_pubkey_envelope_format").isEqualTo("SD-JWT");
    }

    @Test
    void init_hybridTenant_prfSaltIsBase64url() {
        byte[] salt = new byte[32];
        when(prfSaltUseCase.getOrCreatePrfSalt(any(), any(), any())).thenReturn(Mono.just(salt));

        webClient.post().uri(INIT_URL)
                .header("Host", HYBRID_TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("credential_id", "cred-init-2", "format", "vc+sd-jwt"))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                // Base64url without padding — no '=' characters
                .jsonPath("$.prf_salt").value((String s) -> {
                    assert !s.contains("=") : "prf_salt must not contain base64 padding";
                    assert !s.contains("+") : "prf_salt must use base64url (no '+')";
                    assert !s.contains("/") : "prf_salt must use base64url (no '/')";
                });
    }

    // ------------------------------------------------------------------ ES-02

    @Test
    void init_dbTenant_returns403Opaque() {
        webClient.post().uri(INIT_URL)
                .header("Host", DB_TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("credential_id", "cred-db-1", "format", "vc+sd-jwt"))
                .exchange()
                .expectStatus().isForbidden()
                .expectBody().isEmpty();
    }

    // ------------------------------------------------------------------ ES-01

    @Test
    void init_missingCredentialId_returns400() {
        webClient.post().uri(INIT_URL)
                .header("Host", HYBRID_TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("format", "vc+sd-jwt"))
                .exchange()
                .expectStatus().isBadRequest();
    }
}