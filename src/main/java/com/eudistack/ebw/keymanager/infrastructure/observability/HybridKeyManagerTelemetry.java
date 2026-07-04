package com.eudistack.ebw.keymanager.infrastructure.observability;

import com.eudistack.ebw.keymanager.domain.port.HybridKeyManagerTelemetryPort;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;

@Component
@RequiredArgsConstructor
public class HybridKeyManagerTelemetry implements HybridKeyManagerTelemetryPort {

    private static final Logger log = LoggerFactory.getLogger(HybridKeyManagerTelemetry.class);

    public static final String METRIC_PRF_ATTEMPTS = "hybrid.prf_gate.attempts.total";
    public static final String METRIC_PRF_PASSES   = "hybrid.prf_gate.passes.total";
    public static final String METRIC_WRAP_HANDLES = "hybrid.wrap_handles.total";
    public static final String METRIC_SIGN_LATENCY = "hybrid.sign.latency";
    public static final String METRIC_SIGN_ERRORS  = "hybrid.sign.errors.total";
    public static final String TAG_TENANT          = "tenant";

    private final MeterRegistry meterRegistry;

    private final ConcurrentMap<String, AtomicLong> wrapHandlesByTenant = new ConcurrentHashMap<>();

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

    public void updateWrapHandlesTotal(String tenant, long count) {
        wrapHandlesByTenant.computeIfAbsent(tenant, this::registerWrapHandlesGauge).set(count);
    }

    private AtomicLong registerWrapHandlesGauge(String tenant) {
        AtomicLong holder = new AtomicLong(0);
        Gauge.builder(METRIC_WRAP_HANDLES, holder, AtomicLong::get)
                .tag(TAG_TENANT, tenant)
                .description("Total rows in hybrid_wrapped_key_handle for this tenant (updated on each health check)")
                .register(meterRegistry);
        return holder;
    }
}
