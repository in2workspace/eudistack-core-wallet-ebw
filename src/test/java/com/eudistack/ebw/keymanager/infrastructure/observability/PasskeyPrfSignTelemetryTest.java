package com.eudistack.ebw.keymanager.infrastructure.observability;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.eudistack.ebw.keymanager.domain.exception.HolderIsolationViolationException;
import com.eudistack.ebw.keymanager.domain.exception.InvalidSignatureSubmissionException;
import com.eudistack.ebw.keymanager.domain.exception.PrfSaltNotFoundException;
import com.eudistack.ebw.keymanager.domain.exception.SignatureInvalidException;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.micrometer.tracing.Span;
import io.micrometer.tracing.Tracer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

class PasskeyPrfSignTelemetryTest {

    private static final String CORRELATION_ID = "corr-1";
    private static final String HOLDER_ID = "holder-1";

    private Tracer tracer;
    private Span span;
    private SimpleMeterRegistry registry;
    private PasskeyPrfSignTelemetry telemetry;

    @BeforeEach
    void setUp() {
        tracer = mock(Tracer.class);
        span = mock(Span.class);
        when(tracer.nextSpan()).thenReturn(span);
        when(span.name(any())).thenReturn(span);
        when(span.start()).thenReturn(span);
        var spanInScope = mock(Tracer.SpanInScope.class);
        when(tracer.withSpan(span)).thenReturn(spanInScope);
        registry = new SimpleMeterRegistry();
        telemetry = new PasskeyPrfSignTelemetry(tracer, registry);
    }

    @Test
    void recordPrepareSuccess_emitsSpanCounterAndTimer() {
        telemetry.recordPrepareSuccess(CORRELATION_ID, HOLDER_ID, System.nanoTime());

        verify(span).name(PasskeyPrfSignTelemetry.SPAN_PREPARE);
        verify(span).tag("operation", "prepare");
        verify(span).tag("result", "success");
        verify(span).tag("correlation_id", CORRELATION_ID);
        verify(span, never()).error(any());
        verify(span).end();
        assertThat(counter("prepare", "success")).isEqualTo(1.0);
        assertThat(timerCount("prepare", "success")).isEqualTo(1L);
    }

    @Test
    void recordSubmitSuccess_nullCorrelationId_omitsCorrelationTag() {
        telemetry.recordSubmitSuccess(null, HOLDER_ID, System.nanoTime());

        verify(span).name(PasskeyPrfSignTelemetry.SPAN_SUBMIT);
        verify(span).tag("operation", "submit");
        verify(span, never()).tag(eq("correlation_id"), any());
        assertThat(counter("submit", "success")).isEqualTo(1.0);
    }

    @Test
    void recordPrepareError_signatureInvalid_isClassifiedAndSpanRecordsError() {
        RuntimeException ex = new SignatureInvalidException();

        telemetry.recordPrepareError(CORRELATION_ID, HOLDER_ID, ex, System.nanoTime());

        verify(span).error(ex);
        verify(span).end();
        assertThat(counter("prepare", "signature_invalid")).isEqualTo(1.0);
    }

    @Test
    void recordSubmitError_classifiesEachKnownException() {
        telemetry.recordSubmitError(CORRELATION_ID, HOLDER_ID, new PrfSaltNotFoundException("c"), System.nanoTime());
        telemetry.recordSubmitError(CORRELATION_ID, HOLDER_ID,
                new InvalidSignatureSubmissionException("x"), System.nanoTime());
        telemetry.recordSubmitError(CORRELATION_ID, HOLDER_ID,
                new HolderIsolationViolationException("c"), System.nanoTime());
        telemetry.recordSubmitError(CORRELATION_ID, HOLDER_ID, new IllegalStateException("x"), System.nanoTime());

        assertThat(counter("submit", "not_found")).isEqualTo(2.0);
        assertThat(counter("submit", "forbidden")).isEqualTo(1.0);
        assertThat(counter("submit", "error")).isEqualTo(1.0);
    }

    @Test
    void hashHolder_isTruncatedSha256_andNullIsUnknown() {
        assertThat(PasskeyPrfSignTelemetry.hashHolder(HOLDER_ID)).hasSize(12).doesNotContain(HOLDER_ID);
        assertThat(PasskeyPrfSignTelemetry.hashHolder(HOLDER_ID))
                .isEqualTo(PasskeyPrfSignTelemetry.hashHolder(HOLDER_ID));
        assertThat(PasskeyPrfSignTelemetry.hashHolder(null)).isEqualTo("unknown");
    }

    @Test
    void recordSuccess_debugEnabled_logsHashedHolderOnly() {
        var logger = (Logger) LoggerFactory.getLogger(PasskeyPrfSignTelemetry.class);
        var previous = logger.getLevel();
        var appender = new ListAppender<ILoggingEvent>();
        appender.start();
        logger.addAppender(appender);
        logger.setLevel(Level.DEBUG);
        try {
            telemetry.recordPrepareSuccess(CORRELATION_ID, HOLDER_ID, System.nanoTime());
            telemetry.recordSubmitSuccess(CORRELATION_ID, HOLDER_ID, System.nanoTime());
        } finally {
            logger.detachAppender(appender);
            logger.setLevel(previous);
        }

        assertThat(appender.list).hasSize(2)
                .allSatisfy(event -> assertThat(event.getFormattedMessage())
                        .contains("correlation_id=corr-1", "holder_hash=")
                        .doesNotContain(HOLDER_ID));
    }

    private double counter(String operation, String result) {
        return registry.counter(PasskeyPrfSignTelemetry.METRIC_COUNTER,
                "operation", operation, "result", result).count();
    }

    private long timerCount(String operation, String result) {
        return registry.timer(PasskeyPrfSignTelemetry.METRIC_TIMER,
                "operation", operation, "result", result).count();
    }
}
