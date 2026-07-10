package com.eudistack.ebw.keymanager.infrastructure.adapter.http;

import com.eudistack.ebw.domain.spi.TokenSigner;
import com.eudistack.ebw.keymanager.application.PrfSaltUseCase;
import com.eudistack.ebw.keymanager.domain.exception.PrfSaltNotFoundException;
import com.eudistack.ebw.keymanager.domain.model.WrappedKeyHandle;
import com.eudistack.ebw.keymanager.domain.port.WrappedKeyHandleRepository;
import com.eudistack.ebw.keymanager.infrastructure.observability.HybridSignTelemetry;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.sdk.testing.exporter.InMemorySpanExporter;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.data.SpanData;
import io.opentelemetry.sdk.trace.export.SimpleSpanProcessor;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
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
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Integration test verifying that OTEL spans for the hybrid signing handshake carry
 * the {@code correlation_id} attribute on both success and error paths.
 *
 * <p>Specifically validates the B2 fix: {@code recordPrepareError} now receives the
 * server-generated {@code correlationId} from the adapter (previously {@code null}),
 * so error-path spans are tagged with the session id.</p>
 *
 * <p>Uses {@link InMemorySpanExporter} to capture OTEL spans in-process.
 * Mirrors the pattern from {@code WalletProfileQueryObservabilityIT}.</p>
 *
 * <p>Spec: EUDISTACK-536 AC-06, NFR-S-536-04; architecture.md §8.2.</p>
 */
@Tag("integration")
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"spring.autoconfigure.exclude=", "ebw.tenant-flyway.enabled=false"}
)
@AutoConfigureWebTestClient
@ActiveProfiles("integration")
@Testcontainers
@Import(HybridSignTracingIT.TracingTestConfig.class)
class HybridSignTracingIT {

    private static final String SCHEMA_SUFFIX  = "_business_wallet";
    private static final String HYBRID_TENANT  = "htracing";
    private static final UUID   HOLDER_UUID    = UUID.fromString("22222222-aaaa-bbbb-cccc-dddddddddddd");
    private static final String BEARER         = "hybrid-tracing-bearer";
    private static final String PREPARE_URL    = "/api/v1/keys/hybrid/sign/prepare";
    private static final String CRED_ID        = "cred-tracing-1";

    private static final byte[] PRF_SALT   = new byte[32];
    private static final byte[] BLOB_BYTES = new byte[48];
    private static final byte[] IV_BYTES   = new byte[12];
    private static final byte[] TAG_BYTES  = new byte[16];
    private static final String CNF_JWK    =
            "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"trace-x\",\"y\":\"trace-y\"}";
    private static final Map<String, Object> PAYLOAD =
            Map.of("nonce", "nonce-trace", "iat", 1_700_000_000, "aud", "https://verifier.example", "sd_hash", "test-sd-hash");

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("hybrid_tracing_it")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        String host = postgres.getHost();
        int port = postgres.getMappedPort(5432);
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://" + host + ":" + port + "/hybrid_tracing_it");
        registry.add("spring.r2dbc.username", () -> "test");
        registry.add("spring.r2dbc.password", () -> "test");
        registry.add("spring.flyway.url", () ->
                "jdbc:postgresql://" + host + ":" + port + "/hybrid_tracing_it");
        registry.add("spring.flyway.user", () -> "test");
        registry.add("spring.flyway.password", () -> "test");
        registry.add("spring.flyway.default-schema", () -> "public");
        registry.add("management.otlp.tracing.endpoint", () -> "http://localhost:14250");
    }

    @MockitoBean TokenSigner tokenSigner;
    @MockitoBean PrfSaltUseCase prfSaltUseCase;
    @MockitoBean WrappedKeyHandleRepository wrappedKeyHandleRepository;

    @Autowired WebTestClient webClient;
    @Autowired InMemorySpanExporter spanExporter;

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
        }
        Flyway.configure()
                .dataSource(jdbcUrl, "test", "test")
                .locations("classpath:db/tenant")
                .defaultSchema(HYBRID_TENANT + SCHEMA_SUFFIX)
                .schemas(HYBRID_TENANT + SCHEMA_SUFFIX)
                .table("flyway_schema_history")
                .baselineOnMigrate(true)
                .load()
                .migrate();
    }

    @BeforeEach
    void setUp() throws SQLException {
        seedWalletProfile(HYBRID_TENANT, "server", "hybrid");
        when(tokenSigner.verify(BEARER)).thenReturn(
                Map.of("sub", HOLDER_UUID.toString(), "email", "test@test.com"));
        when(wrappedKeyHandleRepository.findBy(any(), any()))
                .thenReturn(Mono.just(Optional.of(validHandle())));
        spanExporter.reset();
    }

    @AfterEach
    void tearDown() {
        spanExporter.reset();
    }

    // -------------------------------------------------------------------------
    // Test Configuration — InMemorySpanExporter
    // -------------------------------------------------------------------------

    @TestConfiguration
    static class TracingTestConfig {

        @Bean
        InMemorySpanExporter inMemorySpanExporter() {
            return InMemorySpanExporter.create();
        }

        @Bean
        SdkTracerProvider sdkTracerProvider(InMemorySpanExporter exporter) {
            return SdkTracerProvider.builder()
                    .addSpanProcessor(SimpleSpanProcessor.create(exporter))
                    .build();
        }
    }

    // -------------------------------------------------------------------------
    // B2: prepare success path — span carries correlation_id
    // -------------------------------------------------------------------------

    @Test
    void prepare_success_emitsSpanWithCorrelationId() {
        when(prfSaltUseCase.getForHolder(any(), any(), any())).thenReturn(Mono.just(PRF_SALT));

        String correlationId = webClient.post().uri(PREPARE_URL)
                .header("Host", HYBRID_TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("credential_id", CRED_ID, "payload", PAYLOAD, "format", "vc+sd-jwt"))
                .exchange()
                .expectStatus().isOk()
                .expectBody(Map.class)
                .returnResult().getResponseBody()
                .get("correlation_id").toString();

        List<SpanData> spans = spanExporter.getFinishedSpanItems().stream()
                .filter(s -> HybridSignTelemetry.SPAN_PREPARE.equals(s.getName()))
                .toList();
        assertThat(spans).as("span '%s' must be emitted on prepare success", HybridSignTelemetry.SPAN_PREPARE)
                .isNotEmpty();
        String spanCorrelationId = spans.get(0).getAttributes().get(AttributeKey.stringKey("correlation_id"));
        assertThat(spanCorrelationId)
                .as("prepare-success span must carry correlation_id attribute")
                .isEqualTo(correlationId);
    }

    // -------------------------------------------------------------------------
    // B2: prepare error path — span carries correlation_id (the gap this fix closes)
    // -------------------------------------------------------------------------

    @Test
    void prepare_error_emitsSpanWithCorrelationId() {
        when(prfSaltUseCase.getForHolder(any(), any(), any()))
                .thenReturn(Mono.error(new PrfSaltNotFoundException(CRED_ID)));

        webClient.post().uri(PREPARE_URL)
                .header("Host", HYBRID_TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("credential_id", CRED_ID, "payload", PAYLOAD, "format", "vc+sd-jwt"))
                .exchange()
                .expectStatus().isNotFound();

        List<SpanData> spans = spanExporter.getFinishedSpanItems().stream()
                .filter(s -> HybridSignTelemetry.SPAN_PREPARE.equals(s.getName()))
                .toList();
        assertThat(spans).as("span '%s' must be emitted on prepare error", HybridSignTelemetry.SPAN_PREPARE)
                .isNotEmpty();
        String spanCorrelationId = spans.get(0).getAttributes().get(AttributeKey.stringKey("correlation_id"));
        assertThat(spanCorrelationId)
                .as("prepare-error span must carry correlation_id attribute (B2 fix)")
                .matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

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
