package com.eudistack.ebw.keymanager.infrastructure.adapter.http;

import com.eudistack.ebw.domain.spi.TokenSigner;
import com.eudistack.ebw.keymanager.application.PrfSaltService;
import com.eudistack.ebw.keymanager.domain.exception.HolderIsolationViolationException;
import com.eudistack.ebw.keymanager.domain.exception.PrfSaltNotFoundException;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * HTTP-layer isolation test for PRF salt holder-isolation exception mapping.
 *
 * <p>Exercises the {@link HybridKeyManagerExceptionHandler} mappings for
 * {@link HolderIsolationViolationException} → 403 and
 * {@link PrfSaltNotFoundException} → 404 via the real
 * {@code POST /api/v1/keys/hybrid/onboarding/init} endpoint. {@link PrfSaltService}
 * is mocked so no US-04 endpoints are required.</p>
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>AC-04 / ES-04 — cross-holder → 403 {@code error=holder_isolation_violation},
 *       body must not contain {@code prf_salt} or {@code holder_id} (NFR-S-537-01, NFR-S-537-02)</li>
 *   <li>ES-02 — credential absent → 404 {@code error=wrap_handle_not_found},
 *       body must not contain {@code prf_salt}</li>
 * </ul>
 *
 * <p>Spec: EUDISTACK-537 AC-04, AC-06, ES-02, ES-04, NFR-S-537-01, NFR-S-537-02.</p>
 */
@Tag("integration")
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"spring.autoconfigure.exclude=", "ebw.tenant-flyway.enabled=false"}
)
@AutoConfigureWebTestClient
@ActiveProfiles("integration")
@Testcontainers
class PrfSaltIsolationIT {

    private static final String SCHEMA_SUFFIX = "_business_wallet";
    private static final String TENANT        = "prfisolation";
    private static final UUID   HOLDER_UUID   = UUID.fromString("aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb");
    private static final String BEARER        = "prf-isolation-bearer";
    private static final String INIT_URL      = "/api/v1/keys/hybrid/onboarding/init";

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("prf_isolation_it")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        String host = postgres.getHost();
        int port = postgres.getMappedPort(5432);
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://" + host + ":" + port + "/prf_isolation_it");
        registry.add("spring.r2dbc.username", () -> "test");
        registry.add("spring.r2dbc.password", () -> "test");
        registry.add("spring.flyway.url", () ->
                "jdbc:postgresql://" + host + ":" + port + "/prf_isolation_it");
        registry.add("spring.flyway.user", () -> "test");
        registry.add("spring.flyway.password", () -> "test");
        registry.add("spring.flyway.default-schema", () -> "public");
    }

    @MockitoBean TokenSigner tokenSigner;
    @MockitoBean PrfSaltService prfSaltService;

    @Autowired WebTestClient webClient;

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
    void setUp() throws SQLException {
        seedWalletProfile();
        when(tokenSigner.verify(BEARER)).thenReturn(
                Map.of("sub", HOLDER_UUID.toString(), "email", "test@test.com"));
    }

    private void seedWalletProfile() throws SQLException {
        String schema = TENANT + SCHEMA_SUFFIX;
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + schema + ".tenant_wallet_profile (tenant, wallet_mode, key_manager) "
                    + "VALUES ('" + TENANT + "', 'server', 'hybrid') "
                    + "ON CONFLICT (tenant) DO NOTHING");
        }
    }

    // ------------------------------------------------------------------ AC-04 / ES-04: cross-holder → 403

    @Test
    void getOrCreatePrfSalt_holderIsolationViolation_returns403_withHolderIsolationError() {
        when(prfSaltService.getOrCreatePrfSalt(any(), any(), any()))
                .thenReturn(Mono.error(new HolderIsolationViolationException("cred-cross-1")));

        webClient.post().uri(INIT_URL)
                .header("Host", TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("credential_id", "cred-cross-1", "format", "vc+sd-jwt"))
                .exchange()
                .expectStatus().isForbidden()
                .expectBody()
                .jsonPath("$.error").isEqualTo("holder_isolation_violation");
    }

    @Test
    void getOrCreatePrfSalt_holderIsolationViolation_403body_doesNotContainPrfSaltOrHolderId() {
        when(prfSaltService.getOrCreatePrfSalt(any(), any(), any()))
                .thenReturn(Mono.error(new HolderIsolationViolationException("cred-cross-2")));

        webClient.post().uri(INIT_URL)
                .header("Host", TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("credential_id", "cred-cross-2", "format", "vc+sd-jwt"))
                .exchange()
                .expectStatus().isForbidden()
                .expectBody(String.class).value(body -> {
                    assertThat(body)
                            .as("403 body must not contain prf_salt (NFR-S-537-01)")
                            .doesNotContainIgnoringCase("prf_salt");
                    assertThat(body)
                            .as("403 body must not contain holder_id (NFR-S-537-02)")
                            .doesNotContain(HOLDER_UUID.toString());
                });
    }

    // ------------------------------------------------------------------ ES-02: absent → 404

    @Test
    void getOrCreatePrfSalt_saltNotFound_returns404_withWrapHandleNotFound() {
        when(prfSaltService.getOrCreatePrfSalt(any(), any(), any()))
                .thenReturn(Mono.error(new PrfSaltNotFoundException("cred-absent-1")));

        webClient.post().uri(INIT_URL)
                .header("Host", TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("credential_id", "cred-absent-1", "format", "vc+sd-jwt"))
                .exchange()
                .expectStatus().isNotFound()
                .expectBody()
                .jsonPath("$.error").isEqualTo("wrap_handle_not_found")
                .jsonPath("$").value(body -> assertThat(body.toString())
                        .as("404 body must not contain prf_salt (AC-06)")
                        .doesNotContainIgnoringCase("prf_salt"));
    }
}
