package com.eudistack.ebw.wallet.profile.infrastructure.observability;

import com.eudistack.ebw.wallet.profile.domain.exception.TenantUnknownException;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.tracing.Span;
import io.micrometer.tracing.Tracer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Centralised telemetry helper for the wallet profile query endpoint.
 *
 * <p>Emits three signals per request (AD-413-3 — single call-site pattern):
 * <ol>
 *   <li><b>OTEL span</b> {@code wallet_profile.read} with attributes {@code tenant} and
 *       {@code result} via {@link Tracer}.
 *   <li><b>Structured log</b> at INFO/WARN level with fields {@code tenant}, {@code result},
 *       and {@code reason} (for not-found paths). No PII is logged (NFR-08).
 *   <li><b>Micrometer metrics</b>: counter {@code wallet_profile_query_total} (tags:
 *       {@code tenant}, {@code result}) and timer {@code wallet_profile_query_latency_ms}.
 * </ol>
 *
 * <p>Three public methods map to the three outcome categories:
 * <ul>
 *   <li>{@link #recordSuccess(String, long)} — 200 OK path.
 *   <li>{@link #recordNotFound(String, TenantUnknownException.Reason, long)} — 404 opaque paths.
 *   <li>{@link #recordError(String, Throwable, long)} — 500/503 paths.
 * </ul>
 *
 * <p>The {@code startNanos} parameter is obtained by the caller with
 * {@link System#nanoTime()} before invoking the use case and passed here for accurate
 * latency recording.
 *
 * <p>See technical-design.md §3.5 AD-413-3 and acceptance-criteria.md AC-07/NFR-S-413-02.
 */
@Component
public class WalletProfileQueryTelemetry {

    private static final Logger log = LoggerFactory.getLogger(WalletProfileQueryTelemetry.class);

    public static final String SPAN_NAME = "wallet_profile.read";
    public static final String METRIC_COUNTER = "wallet_profile_query_total";
    public static final String METRIC_TIMER = "wallet_profile_query_latency_ms";
    public static final String TAG_TENANT = "tenant";
    public static final String TAG_RESULT = "result";
    public static final String RESULT_SUCCESS = "miss_origin"; // AC-07: result ∈ {miss_origin, not_found}
    public static final String RESULT_NOT_FOUND = "not_found";
    public static final String RESULT_ERROR = "error";

    private final Tracer tracer;
    private final MeterRegistry meterRegistry;

    public WalletProfileQueryTelemetry(Tracer tracer, MeterRegistry meterRegistry) {
        this.tracer = tracer;
        this.meterRegistry = meterRegistry;
    }

    /**
     * Records a successful profile query (200 OK).
     *
     * @param tenant     the resolved tenant identifier (from Reactor Context)
     * @param startNanos the value of {@link System#nanoTime()} before the operation started
     */
    public void recordSuccess(String tenant, long startNanos) {
        emitSpan(tenant, RESULT_SUCCESS, null);
        log.info("wallet_profile.query tenant={} result={}", tenant, RESULT_SUCCESS);
        recordMetrics(tenant, RESULT_SUCCESS, startNanos);
    }

    /**
     * Records an opaque 404 response (all three anti-enumeration paths).
     *
     * @param tenant     the resolved tenant identifier, or {@code "unknown"} when absent from context
     * @param reason     the internal reason (logged but never sent to the caller — AD-413-2)
     * @param startNanos the value of {@link System#nanoTime()} before the operation started
     */
    public void recordNotFound(String tenant, TenantUnknownException.Reason reason, long startNanos) {
        emitSpan(tenant, RESULT_NOT_FOUND, null);
        log.info("wallet_profile.query tenant={} result={} reason={}", tenant, RESULT_NOT_FOUND,
                reason != null ? reason.name().toLowerCase() : "unknown");
        recordMetrics(tenant, RESULT_NOT_FOUND, startNanos);
    }

    /**
     * Records a 500/503 error response.
     *
     * @param tenant     the resolved tenant identifier, or {@code "unknown"} when absent from context
     * @param throwable  the caught exception (used for span status; not logged with stack trace
     *                   to avoid leaking internal detail in structured logs)
     * @param startNanos the value of {@link System#nanoTime()} before the operation started
     */
    public void recordError(String tenant, Throwable throwable, long startNanos) {
        emitSpanWithError(tenant, throwable);
        log.warn("wallet_profile.query tenant={} result={} error_type={}", tenant, RESULT_ERROR,
                throwable.getClass().getSimpleName());
        recordMetrics(tenant, RESULT_ERROR, startNanos);
    }

    private void emitSpan(String tenant, String result, Throwable error) {
        Span span = tracer.nextSpan().name(SPAN_NAME);
        try (Tracer.SpanInScope ignored = tracer.withSpan(span.start())) {
            span.tag(TAG_TENANT, tenant);
            span.tag(TAG_RESULT, result);
        } finally {
            span.end();
        }
    }

    private void emitSpanWithError(String tenant, Throwable throwable) {
        Span span = tracer.nextSpan().name(SPAN_NAME);
        try (Tracer.SpanInScope ignored = tracer.withSpan(span.start())) {
            span.tag(TAG_TENANT, tenant);
            span.tag(TAG_RESULT, RESULT_ERROR);
            span.error(throwable);
        } finally {
            span.end();
        }
    }

    private void recordMetrics(String tenant, String result, long startNanos) {
        meterRegistry.counter(METRIC_COUNTER, TAG_TENANT, tenant, TAG_RESULT, result)
                .increment();
        long elapsedNanos = System.nanoTime() - startNanos;
        Timer.builder(METRIC_TIMER)
                .tags(TAG_TENANT, tenant, TAG_RESULT, result)
                .register(meterRegistry)
                .record(elapsedNanos, java.util.concurrent.TimeUnit.NANOSECONDS);
    }
}
