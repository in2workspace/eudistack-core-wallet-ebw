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
