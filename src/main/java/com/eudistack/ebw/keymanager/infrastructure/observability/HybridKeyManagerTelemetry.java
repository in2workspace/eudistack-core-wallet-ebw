package com.eudistack.ebw.keymanager.infrastructure.observability;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Centralised telemetry helper for the hybrid key-manager adapter (US-09 / EUDISTACK-541).
 *
 * <p>Registers five Micrometer signals (architecture.md §8.2):
 * <ol>
 *   <li>{@code hybrid.prf_gate.attempts.total} — Counter, tag {@code tenant}: every
 *       onboarding {@code init} call, regardless of PRF gate outcome.
 *   <li>{@code hybrid.prf_gate.passes.total} — Counter, tag {@code tenant}: calls where
 *       the PRF salt was successfully generated (gate passed).
 *   <li>{@code hybrid.wrap_handles.total} — Gauge backed by an {@link AtomicLong} updated
 *       each time {@link HybridHealthContributor}
 *       reads {@code WrappedKeyHandleRepository.count()}.
 *   <li>{@code hybrid.sign.latency} — Timer, tag {@code tenant}: full
 *       {@code prepareSign → submitSignedAssertion} handshake latency. Populated by US-04
 *       (EUDISTACK-536) once the signing flow is implemented.
 *   <li>{@code hybrid.sign.errors.total} — Counter, tag {@code tenant}: signing errors.
 *       Populated by US-04 (EUDISTACK-536).
 * </ol>
 *
 * <p>See technical-design.md §3.5 and architecture.md §8.2.
 */
@Component
@RequiredArgsConstructor
public class HybridKeyManagerTelemetry {

    private static final Logger log = LoggerFactory.getLogger(HybridKeyManagerTelemetry.class);

    public static final String METRIC_PRF_ATTEMPTS = "hybrid.prf_gate.attempts.total";
    public static final String METRIC_PRF_PASSES   = "hybrid.prf_gate.passes.total";
    public static final String METRIC_WRAP_HANDLES = "hybrid.wrap_handles.total";
    public static final String METRIC_SIGN_LATENCY = "hybrid.sign.latency";
    public static final String METRIC_SIGN_ERRORS  = "hybrid.sign.errors.total";
    public static final String TAG_TENANT          = "tenant";

    private final MeterRegistry meterRegistry;

    private final AtomicLong wrapHandlesTotal = new AtomicLong(0);

    @PostConstruct
    void registerGauge() {
        Gauge.builder(METRIC_WRAP_HANDLES, wrapHandlesTotal, AtomicLong::get)
                .description("Total rows in hybrid_wrapped_key_handle (updated on each health check)")
                .register(meterRegistry);
    }

    public void recordPrfAttempt(String tenant) {
        meterRegistry.counter(METRIC_PRF_ATTEMPTS, TAG_TENANT, tenant).increment();
        log.debug("hybrid.prf_gate attempt tenant={}", tenant);
    }

    public void recordPrfPass(String tenant) {
        meterRegistry.counter(METRIC_PRF_PASSES, TAG_TENANT, tenant).increment();
        log.debug("hybrid.prf_gate pass tenant={}", tenant);
    }

    public void recordSignLatency(Duration duration, String tenant) {
        Timer.builder(METRIC_SIGN_LATENCY)
                .tags(TAG_TENANT, tenant)
                .register(meterRegistry)
                .record(duration);
    }

    public void recordSignError(String tenant) {
        meterRegistry.counter(METRIC_SIGN_ERRORS, TAG_TENANT, tenant).increment();
        log.debug("hybrid.sign.error tenant={}", tenant);
    }

    public void updateWrapHandlesTotal(long count) {
        wrapHandlesTotal.set(count);
    }
}
