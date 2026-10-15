package com.eudistack.ebw.keymanager.infrastructure.observability;

import static org.assertj.core.api.Assertions.assertThat;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Duration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class PasskeyPrfKeyManagerTelemetryTest {

    private static final String TENANT = "sandbox";

    private SimpleMeterRegistry registry;
    private PasskeyPrfKeyManagerTelemetry telemetry;

    @BeforeEach
    void setUp() {
        registry = new SimpleMeterRegistry();
        telemetry = new PasskeyPrfKeyManagerTelemetry(registry);
    }

    @Test
    void recordPrfAttempt_incrementsTenantCounter() {
        telemetry.recordPrfAttempt(TENANT);
        telemetry.recordPrfAttempt(TENANT);

        assertThat(registry.counter(PasskeyPrfKeyManagerTelemetry.METRIC_PRF_ATTEMPTS,
                PasskeyPrfKeyManagerTelemetry.TAG_TENANT, TENANT).count()).isEqualTo(2.0);
    }

    @Test
    void recordPrfPass_incrementsTenantCounter() {
        telemetry.recordPrfPass(TENANT);

        assertThat(registry.counter(PasskeyPrfKeyManagerTelemetry.METRIC_PRF_PASSES,
                PasskeyPrfKeyManagerTelemetry.TAG_TENANT, TENANT).count()).isEqualTo(1.0);
    }

    @Test
    void recordSignError_incrementsTenantCounter() {
        telemetry.recordSignError(TENANT);

        assertThat(registry.counter(PasskeyPrfKeyManagerTelemetry.METRIC_SIGN_ERRORS,
                PasskeyPrfKeyManagerTelemetry.TAG_TENANT, TENANT).count()).isEqualTo(1.0);
    }

    @Test
    void recordSignLatency_recordsDurationInTimer() {
        telemetry.recordSignLatency(Duration.ofMillis(40), TENANT);

        assertThat(registry.timer(PasskeyPrfKeyManagerTelemetry.METRIC_SIGN_LATENCY,
                PasskeyPrfKeyManagerTelemetry.TAG_TENANT, TENANT).count()).isEqualTo(1L);
    }

    @Test
    void updateWrapHandlesTotal_registersGaugeOnceAndTracksLatestValue() {
        telemetry.updateWrapHandlesTotal(TENANT, 3);
        telemetry.updateWrapHandlesTotal(TENANT, 7);

        assertThat(registry.get(PasskeyPrfKeyManagerTelemetry.METRIC_WRAP_HANDLES)
                .tag(PasskeyPrfKeyManagerTelemetry.TAG_TENANT, TENANT).gauges()).hasSize(1);
        assertThat(registry.get(PasskeyPrfKeyManagerTelemetry.METRIC_WRAP_HANDLES)
                .tag(PasskeyPrfKeyManagerTelemetry.TAG_TENANT, TENANT).gauge().value()).isEqualTo(7.0);
    }
}
