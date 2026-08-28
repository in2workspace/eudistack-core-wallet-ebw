package com.eudistack.ebw.keymanager.infrastructure.observability;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;
import java.util.Collection;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for {@link HybridKeyManagerTelemetry} (US-09 / EUDISTACK-541).
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>recordPrfAttempt increments hybrid.prf_gate.attempts.total</li>
 *   <li>recordPrfPass increments hybrid.prf_gate.passes.total</li>
 *   <li>Pass/attempts ratio is consistent with recorded values</li>
 *   <li>updateWrapHandlesTotal updates the wrap_handles gauge</li>
 *   <li>recordSignError increments hybrid.sign.errors.total</li>
 * </ul>
 */
@Tag("integration")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@ActiveProfiles("integration")
@Testcontainers
class HybridKeyManagerTelemetryIT {

    private static final String TENANT = "telemetryit";

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("telemetry_it")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        String host = postgres.getHost();
        int port    = postgres.getMappedPort(5432);
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://" + host + ":" + port + "/telemetry_it");
        registry.add("spring.r2dbc.username", () -> "test");
        registry.add("spring.r2dbc.password", () -> "test");
        registry.add("spring.flyway.url", () ->
                "jdbc:postgresql://" + host + ":" + port + "/telemetry_it");
        registry.add("spring.flyway.user", () -> "test");
        registry.add("spring.flyway.password", () -> "test");
        registry.add("spring.flyway.default-schema", () -> "public");
        registry.add("management.otlp.tracing.endpoint", () -> "http://localhost:14250");
    }

    @Autowired
    private HybridKeyManagerTelemetry telemetry;

    @Autowired
    private MeterRegistry meterRegistry;

    @Test
    void recordPrfAttempt_twice_incrementsAttemptCounterByTwo() {
        double before = sumCounter(HybridKeyManagerTelemetry.METRIC_PRF_ATTEMPTS, TENANT);
        telemetry.recordPrfAttempt(TENANT);
        telemetry.recordPrfAttempt(TENANT);
        double after = sumCounter(HybridKeyManagerTelemetry.METRIC_PRF_ATTEMPTS, TENANT);
        assertThat(after - before).isEqualTo(2.0);
    }

    @Test
    void recordPrfPass_once_incrementsPassCounterByOne() {
        double before = sumCounter(HybridKeyManagerTelemetry.METRIC_PRF_PASSES, TENANT);
        telemetry.recordPrfPass(TENANT);
        double after = sumCounter(HybridKeyManagerTelemetry.METRIC_PRF_PASSES, TENANT);
        assertThat(after - before).isEqualTo(1.0);
    }

    @Test
    void recordPrfAttemptTwiceAndPassOnce_ratioIsOneHalf() {
        String isolatedTenant = "ratiocheck-" + System.nanoTime();
        telemetry.recordPrfAttempt(isolatedTenant);
        telemetry.recordPrfAttempt(isolatedTenant);
        telemetry.recordPrfPass(isolatedTenant);
        double attempts = sumCounter(HybridKeyManagerTelemetry.METRIC_PRF_ATTEMPTS, isolatedTenant);
        double passes   = sumCounter(HybridKeyManagerTelemetry.METRIC_PRF_PASSES,   isolatedTenant);
        assertThat(attempts).isEqualTo(2.0);
        assertThat(passes).isEqualTo(1.0);
        assertThat(passes / attempts).isEqualTo(0.5);
    }

    @Test
    void updateWrapHandlesTotal_setsGaugeValue() {
        String isolatedTenant = "wraphandles-" + System.nanoTime();

        telemetry.updateWrapHandlesTotal(isolatedTenant, 42L);

        Collection<Gauge> gauges = meterRegistry.find(HybridKeyManagerTelemetry.METRIC_WRAP_HANDLES)
                .tag(HybridKeyManagerTelemetry.TAG_TENANT, isolatedTenant)
                .gauges();
        assertThat(gauges).as("hybrid.wrap_handles.total gauge must be registered for the tenant").isNotEmpty();
        assertThat(gauges.iterator().next().value()).isEqualTo(42.0);
    }

    @Test
    void updateWrapHandlesTotal_twoTenants_doNotOverwriteEachOther() {
        String tenantA = "wraphandles-a-" + System.nanoTime();
        String tenantB = "wraphandles-b-" + System.nanoTime();

        telemetry.updateWrapHandlesTotal(tenantA, 5L);
        telemetry.updateWrapHandlesTotal(tenantB, 9L);

        double valueA = meterRegistry.find(HybridKeyManagerTelemetry.METRIC_WRAP_HANDLES)
                .tag(HybridKeyManagerTelemetry.TAG_TENANT, tenantA).gauge().value();
        double valueB = meterRegistry.find(HybridKeyManagerTelemetry.METRIC_WRAP_HANDLES)
                .tag(HybridKeyManagerTelemetry.TAG_TENANT, tenantB).gauge().value();

        assertThat(valueA).isEqualTo(5.0);
        assertThat(valueB).isEqualTo(9.0);
    }

    @Test
    void recordSignError_once_incrementsErrorCounterByOne() {
        String isolatedTenant = "signerr-" + System.nanoTime();
        double before = sumCounter(HybridKeyManagerTelemetry.METRIC_SIGN_ERRORS, isolatedTenant);
        telemetry.recordSignError(isolatedTenant);
        double after = sumCounter(HybridKeyManagerTelemetry.METRIC_SIGN_ERRORS, isolatedTenant);
        assertThat(after - before).isEqualTo(1.0);
    }

    @Test
    void recordSignLatency_recordsDurationInTimer() {
        String isolatedTenant = "signlat-" + System.nanoTime();
        long countBefore = meterRegistry.find(HybridKeyManagerTelemetry.METRIC_SIGN_LATENCY)
                .timers().stream()
                .filter(t -> isolatedTenant.equals(
                        t.getId().getTag(HybridKeyManagerTelemetry.TAG_TENANT)))
                .mapToLong(io.micrometer.core.instrument.Timer::count)
                .sum();
        telemetry.recordSignLatency(Duration.ofMillis(123), isolatedTenant);
        long countAfter = meterRegistry.find(HybridKeyManagerTelemetry.METRIC_SIGN_LATENCY)
                .timers().stream()
                .filter(t -> isolatedTenant.equals(
                        t.getId().getTag(HybridKeyManagerTelemetry.TAG_TENANT)))
                .mapToLong(io.micrometer.core.instrument.Timer::count)
                .sum();
        assertThat(countAfter - countBefore).isEqualTo(1L);
    }

    private double sumCounter(String metricName, String tenant) {
        return meterRegistry.find(metricName).counters().stream()
                .filter(c -> tenant.equals(c.getId().getTag(HybridKeyManagerTelemetry.TAG_TENANT)))
                .mapToDouble(Counter::count)
                .sum();
    }
}
