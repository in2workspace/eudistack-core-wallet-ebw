package com.eudistack.ebw.wallet.profile.infrastructure.web;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.eudistack.ebw.wallet.profile.infrastructure.observability.WalletProfileQueryTelemetry;
import io.micrometer.core.instrument.MeterRegistry;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.sdk.testing.exporter.InMemorySpanExporter;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.data.SpanData;
import io.opentelemetry.sdk.trace.export.SimpleSpanProcessor;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test verifying telemetry emission for the wallet profile query endpoint.
 *
 * <p>Uses {@link InMemorySpanExporter} to capture OTEL spans and Logback
 * {@link ListAppender} to capture structured log events.
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>AC-07 — each request emits a span {@code wallet_profile.read} with correct attributes
 *   <li>NFR-S-413-02 — 100% span + log coverage (success and not-found paths both emit)
 * </ul>
 */
@Tag("integration")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@ActiveProfiles("integration")
@Testcontainers
@Import(WalletProfileQueryObservabilityIT.ObservabilityTestConfig.class)
class WalletProfileQueryObservabilityIT {

    private static final String SCHEMA_SUFFIX = "_business_wallet";
    private static final String BROWSER_TENANT = "observabilitybrowser";
    private static final String BROWSER_SCHEMA = BROWSER_TENANT + SCHEMA_SUFFIX;

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("ebw_observability_it")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        String host = postgres.getHost();
        int port = postgres.getMappedPort(5432);
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://" + host + ":" + port + "/ebw_observability_it");
        registry.add("spring.r2dbc.username", () -> "test");
        registry.add("spring.r2dbc.password", () -> "test");
        registry.add("spring.flyway.url", () ->
                "jdbc:postgresql://" + host + ":" + port + "/ebw_observability_it");
        registry.add("spring.flyway.user", () -> "test");
        registry.add("spring.flyway.password", () -> "test");
        registry.add("spring.flyway.default-schema", () -> "public");
        registry.add("ebw.encryption.key", () -> "01LvWiH/24uNc/Um3GF8n3sFUwtfv8xBmFST4bc56oc=");
        // Disable OTLP export to avoid network calls in tests
        registry.add("management.otlp.tracing.endpoint", () -> "http://localhost:14250");
    }

    @Autowired
    private WebTestClient webClient;

    @Autowired
    private InMemorySpanExporter spanExporter;

    @Autowired
    private MeterRegistry meterRegistry;

    private ListAppender<ILoggingEvent> logAppender;

    @BeforeEach
    void setUp() throws SQLException {
        provisionTenantSchema();
        seedBrowserProfile();

        // Attach Logback ListAppender to capture WalletProfileQueryTelemetry log events
        Logger telemetryLogger = (Logger) LoggerFactory.getLogger(
                "com.eudistack.ebw.wallet.profile.infrastructure.observability.WalletProfileQueryTelemetry");
        logAppender = new ListAppender<>();
        logAppender.start();
        telemetryLogger.addAppender(logAppender);

        spanExporter.reset();
    }

    @AfterEach
    void tearDown() {
        Logger telemetryLogger = (Logger) LoggerFactory.getLogger(
                "com.eudistack.ebw.wallet.profile.infrastructure.observability.WalletProfileQueryTelemetry");
        telemetryLogger.detachAppender(logAppender);
    }

    // -------------------------------------------------------------------------
    // Test Configuration — InMemorySpanExporter
    // -------------------------------------------------------------------------

    /**
     * Overrides the Micrometer Tracing infrastructure with an in-memory exporter
     * so spans can be inspected in-process.
     */
    @TestConfiguration
    static class ObservabilityTestConfig {

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
    // Helpers
    // -------------------------------------------------------------------------

    private String jdbcUrl() {
        return "jdbc:postgresql://" + postgres.getHost() + ":" + postgres.getMappedPort(5432)
                + "/ebw_observability_it";
    }

    private void provisionTenantSchema() throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl(), "test", "test")) {
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE ebw_app_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE config_manager_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute("CREATE SCHEMA IF NOT EXISTS " + BROWSER_SCHEMA);
        }
        Flyway.configure()
                .dataSource(jdbcUrl(), "test", "test")
                .locations("classpath:db/tenant")
                .defaultSchema(BROWSER_SCHEMA)
                .schemas(BROWSER_SCHEMA)
                .table("flyway_schema_history")
                .baselineOnMigrate(true)
                .load()
                .migrate();
    }

    private void seedBrowserProfile() throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl(), "test", "test")) {
            conn.createStatement().execute(
                    "DELETE FROM " + BROWSER_SCHEMA + ".tenant_wallet_profile "
                    + "WHERE tenant = '" + BROWSER_TENANT + "'");
            conn.createStatement().execute(
                    "INSERT INTO " + BROWSER_SCHEMA + ".tenant_wallet_profile "
                    + "(tenant, wallet_mode, key_manager)"
                    + " VALUES ('" + BROWSER_TENANT + "', 'browser', NULL)"
                    + " ON CONFLICT (tenant) DO NOTHING");
        }
    }

    // -------------------------------------------------------------------------
    // AC-07 + NFR-S-413-02 — telemetry emitted for success path
    // -------------------------------------------------------------------------

    @Test
    void getWalletConfigMetadata_success_emitsLogEvent() {
        webClient.get()
                .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                .header("Host", BROWSER_TENANT + ".eudistack.net")
                .exchange()
                .expectStatus().isOk();

        List<ILoggingEvent> events = logAppender.list;
        assertThat(events).as("at least one log event from telemetry on success").isNotEmpty();

        boolean foundQueryLog = events.stream().anyMatch(e ->
                e.getMessage().contains("wallet_profile.query")
                && e.getFormattedMessage().contains("result=success"));
        assertThat(foundQueryLog)
                .as("success path must log wallet_profile.query with result=success")
                .isTrue();
    }

    @Test
    void getWalletConfigMetadata_notFound_emitsLogEvent() {
        webClient.get()
                .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                .header("Host", "unknowntenantobservability.eudistack.net")
                .exchange()
                .expectStatus().isNotFound();

        List<ILoggingEvent> events = logAppender.list;
        assertThat(events).as("at least one log event from telemetry on not-found").isNotEmpty();

        boolean foundQueryLog = events.stream().anyMatch(e ->
                e.getMessage().contains("wallet_profile.query")
                && e.getFormattedMessage().contains("result=not_found"));
        assertThat(foundQueryLog)
                .as("not-found path must log wallet_profile.query with result=not_found")
                .isTrue();
    }

    // -------------------------------------------------------------------------
    // AC-07 + NFR-S-413-02 — OTEL span name and attributes
    // -------------------------------------------------------------------------

    @Test
    void getWalletConfigMetadata_success_emitsSpanWithCorrectAttributes() {
        webClient.get()
                .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                .header("Host", BROWSER_TENANT + ".eudistack.net")
                .exchange()
                .expectStatus().isOk();

        List<SpanData> spans = spanExporter.getFinishedSpanItems().stream()
                .filter(s -> WalletProfileQueryTelemetry.SPAN_NAME.equals(s.getName()))
                .toList();
        assertThat(spans).as("span '%s' emitted on success", WalletProfileQueryTelemetry.SPAN_NAME)
                .isNotEmpty();
        SpanData span = spans.get(0);
        assertThat(span.getAttributes().get(AttributeKey.stringKey(WalletProfileQueryTelemetry.TAG_RESULT)))
                .as("span result attribute").isEqualTo(WalletProfileQueryTelemetry.RESULT_SUCCESS);
    }

    @Test
    void getWalletConfigMetadata_notFound_emitsSpanWithCorrectAttributes() {
        webClient.get()
                .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                .header("Host", "unknowntenantobservability.eudistack.net")
                .exchange()
                .expectStatus().isNotFound();

        List<SpanData> spans = spanExporter.getFinishedSpanItems().stream()
                .filter(s -> WalletProfileQueryTelemetry.SPAN_NAME.equals(s.getName()))
                .toList();
        assertThat(spans).as("span '%s' emitted on not-found", WalletProfileQueryTelemetry.SPAN_NAME)
                .isNotEmpty();
        SpanData span = spans.get(0);
        assertThat(span.getAttributes().get(AttributeKey.stringKey(WalletProfileQueryTelemetry.TAG_RESULT)))
                .as("span result attribute").isEqualTo(WalletProfileQueryTelemetry.RESULT_NOT_FOUND);
    }

    @Test
    void getWalletConfigMetadata_success_incrementsMetricCounter() {
        double before = meterRegistry.find(WalletProfileQueryTelemetry.METRIC_COUNTER)
                .counters().stream()
                .filter(c -> c.getId().getTag(WalletProfileQueryTelemetry.TAG_RESULT) != null
                        && c.getId().getTag(WalletProfileQueryTelemetry.TAG_RESULT)
                                .equals(WalletProfileQueryTelemetry.RESULT_SUCCESS))
                .mapToDouble(io.micrometer.core.instrument.Counter::count)
                .sum();

        webClient.get()
                .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                .header("Host", BROWSER_TENANT + ".eudistack.net")
                .exchange()
                .expectStatus().isOk();

        double after = meterRegistry.find(WalletProfileQueryTelemetry.METRIC_COUNTER)
                .counters().stream()
                .filter(c -> c.getId().getTag(WalletProfileQueryTelemetry.TAG_RESULT) != null
                        && c.getId().getTag(WalletProfileQueryTelemetry.TAG_RESULT)
                                .equals(WalletProfileQueryTelemetry.RESULT_SUCCESS))
                .mapToDouble(io.micrometer.core.instrument.Counter::count)
                .sum();

        assertThat(after)
                .as("success counter must increment by 1 after a successful request")
                .isGreaterThan(before);
    }
}
