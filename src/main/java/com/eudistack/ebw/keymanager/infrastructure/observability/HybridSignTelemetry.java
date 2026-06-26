package com.eudistack.ebw.keymanager.infrastructure.observability;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.tracing.Span;
import io.micrometer.tracing.Tracer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.concurrent.TimeUnit;

/**
 * Centralised telemetry for the hybrid (Passkey PRF) signing handshake.
 *
 * <p>Emits three signals per operation (mirroring the single call-site pattern from
 * {@code WalletProfileQueryTelemetry}):
 * <ol>
 *   <li><b>OTEL span</b> named {@code hybrid.sign.prepare} or {@code hybrid.sign.submit},
 *       tagged with {@code operation}, {@code correlation_id}, and {@code result}.</li>
 *   <li><b>Structured log</b> at DEBUG/WARN with hashed {@code holder_id} (NFR-S-536-04) and
 *       {@code correlation_id}. No {@code prf_salt}, wrapped-blob, or raw holder key is logged
 *       (NFR-S-536-03).</li>
 *   <li><b>Micrometer metrics</b>: counter {@code hybrid_sign_total} (tags: {@code operation},
 *       {@code result}) and timer {@code hybrid_sign_latency_ms} (same tags).</li>
 * </ol>
 *
 * <p>Holder identifier privacy: the {@code holder_id} is SHA-256-hashed and truncated to
 * 12 hex characters before inclusion in any log or metric tag. The raw value is never
 * recorded in any observability signal (NFR-S-536-04).</p>
 *
 * <p>Spec: EUDISTACK-536 AC-06, NFR-S-536-03, NFR-S-536-04; architecture.md §8.2.</p>
 */
public class HybridSignTelemetry {

    private static final Logger log = LoggerFactory.getLogger(HybridSignTelemetry.class);

    public static final String SPAN_PREPARE = "hybrid.sign.prepare";
    public static final String SPAN_SUBMIT = "hybrid.sign.submit";
    public static final String METRIC_COUNTER = "hybrid_sign_total";
    public static final String METRIC_TIMER = "hybrid_sign_latency_ms";

    static final String OP_PREPARE = "prepare";
    static final String OP_SUBMIT = "submit";
    static final String RESULT_SUCCESS = "success";
    static final String RESULT_SIGNATURE_INVALID = "signature_invalid";
    static final String RESULT_NOT_FOUND = "not_found";
    static final String RESULT_FORBIDDEN = "forbidden";
    static final String RESULT_ERROR = "error";

    private final Tracer tracer;
    private final MeterRegistry meterRegistry;

    public HybridSignTelemetry(Tracer tracer, MeterRegistry meterRegistry) {
        this.tracer = tracer;
        this.meterRegistry = meterRegistry;
    }

    public void recordPrepareSuccess(String correlationId, String holderId, long startNanos) {
        emitSpan(SPAN_PREPARE, OP_PREPARE, correlationId, RESULT_SUCCESS, null);
        log.debug("hybrid.sign.prepare correlation_id={} holder_hash={} result={}",
                correlationId, hashHolder(holderId), RESULT_SUCCESS);
        recordMetrics(OP_PREPARE, RESULT_SUCCESS, startNanos);
    }

    public void recordPrepareError(String correlationId, String holderId, Throwable ex, long startNanos) {
        String result = classifyError(ex);
        emitSpan(SPAN_PREPARE, OP_PREPARE, correlationId, result, ex);
        log.warn("hybrid.sign.prepare correlation_id={} holder_hash={} result={} error_type={}",
                correlationId, hashHolder(holderId), result, ex.getClass().getSimpleName());
        recordMetrics(OP_PREPARE, result, startNanos);
    }

    public void recordSubmitSuccess(String correlationId, String holderId, long startNanos) {
        emitSpan(SPAN_SUBMIT, OP_SUBMIT, correlationId, RESULT_SUCCESS, null);
        log.debug("hybrid.sign.submit correlation_id={} holder_hash={} result={}",
                correlationId, hashHolder(holderId), RESULT_SUCCESS);
        recordMetrics(OP_SUBMIT, RESULT_SUCCESS, startNanos);
    }

    public void recordSubmitError(String correlationId, String holderId, Throwable ex, long startNanos) {
        String result = classifyError(ex);
        emitSpan(SPAN_SUBMIT, OP_SUBMIT, correlationId, result, ex);
        log.warn("hybrid.sign.submit correlation_id={} holder_hash={} result={} error_type={}",
                correlationId, hashHolder(holderId), result, ex.getClass().getSimpleName());
        recordMetrics(OP_SUBMIT, result, startNanos);
    }

    private void emitSpan(String spanName, String operation, String correlationId,
                           String result, Throwable error) {
        Span span = tracer.nextSpan().name(spanName);
        try (Tracer.SpanInScope ignored = tracer.withSpan(span.start())) {
            span.tag("operation", operation);
            span.tag("result", result);
            if (correlationId != null) {
                span.tag("correlation_id", correlationId);
            }
            if (error != null) {
                span.error(error);
            }
        } finally {
            span.end();
        }
    }

    private void recordMetrics(String operation, String result, long startNanos) {
        meterRegistry.counter(METRIC_COUNTER, "operation", operation, "result", result)
                .increment();
        Timer.builder(METRIC_TIMER)
                .tags("operation", operation, "result", result)
                .register(meterRegistry)
                .record(System.nanoTime() - startNanos, TimeUnit.NANOSECONDS);
    }

    private String classifyError(Throwable ex) {
        String name = ex.getClass().getSimpleName();
        return switch (name) {
            case "SignatureInvalidException" -> RESULT_SIGNATURE_INVALID;
            case "PrfSaltNotFoundException", "InvalidSignatureSubmissionException" -> RESULT_NOT_FOUND;
            case "HolderIsolationViolationException", "TenantWalletProfileUnsupportedException" -> RESULT_FORBIDDEN;
            default -> RESULT_ERROR;
        };
    }

    static String hashHolder(String holderId) {
        if (holderId == null) return "unknown";
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(holderId.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash).substring(0, 12);
        } catch (NoSuchAlgorithmException e) {
            return "hash-unavailable";
        }
    }
}
