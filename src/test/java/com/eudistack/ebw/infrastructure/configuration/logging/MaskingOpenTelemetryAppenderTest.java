package com.eudistack.ebw.infrastructure.configuration.logging;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static com.eudistack.ebw.infrastructure.configuration.logging.MaskingPatternLayout.REPLACEMENT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class MaskingOpenTelemetryAppenderTest {

    private static final String JWT_SAMPLE =
            "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    private static final String USER_ID = "550e8400-e29b-41d4-a716-446655440000";

    // ─── getFormattedMessage() / getMessage() ─────────────────────────────────

    @Test
    void mask_FormattedMessageWithJwtAndUserId_MasksBoth() {
        ILoggingEvent source = mock(ILoggingEvent.class);
        when(source.getFormattedMessage()).thenReturn("Session " + JWT_SAMPLE + " for userId=" + USER_ID);

        ILoggingEvent masked = MaskingOpenTelemetryAppender.mask(source);

        assertThat(masked.getFormattedMessage())
                .isEqualTo("Session " + REPLACEMENT + " for userId=" + REPLACEMENT);
    }

    @Test
    void mask_MessageTemplateWithEmail_MasksEmail() {
        ILoggingEvent source = mock(ILoggingEvent.class);
        when(source.getMessage()).thenReturn("Verification code sent to holder@empresa.com");

        ILoggingEvent masked = MaskingOpenTelemetryAppender.mask(source);

        assertThat(masked.getMessage()).doesNotContain("holder@empresa.com").contains(REPLACEMENT);
    }

    // ─── getArgumentArray() ─────────────────────────────────────────────────────

    @Test
    void mask_ArgumentArray_IsEmptiedSoOriginalCannotBeReRendered() {
        ILoggingEvent source = mock(ILoggingEvent.class);
        when(source.getArgumentArray()).thenReturn(new Object[]{USER_ID});

        ILoggingEvent masked = MaskingOpenTelemetryAppender.mask(source);

        assertThat(masked.getArgumentArray()).isEmpty();
    }

    // ─── getMDCPropertyMap() / getMdc() ─────────────────────────────────────────

    @Test
    void mask_MdcPropertyMapWithUserIdValue_MasksValueKeepsKey() {
        ILoggingEvent source = mock(ILoggingEvent.class);
        when(source.getMDCPropertyMap()).thenReturn(Map.of("userId", USER_ID));

        ILoggingEvent masked = MaskingOpenTelemetryAppender.mask(source);

        assertThat(masked.getMDCPropertyMap()).containsEntry("userId", REPLACEMENT);
    }

    @Test
    void mask_MdcPropertyMapWithTraceIdsAndTenant_LeavesValuesUnchanged() {
        Map<String, String> mdc = Map.of(
                "traceId", "4bf92f3577b34da6a3ce929d0e0e4736",
                "spanId", "00f067aa0ba902b7",
                "tenantDomain", "sandbox");
        ILoggingEvent source = mock(ILoggingEvent.class);
        when(source.getMDCPropertyMap()).thenReturn(mdc);

        ILoggingEvent masked = MaskingOpenTelemetryAppender.mask(source);

        assertThat(masked.getMDCPropertyMap()).isEqualTo(mdc);
    }

    @Test
    @SuppressWarnings("deprecation")
    void mask_DeprecatedGetMdcWithOtpValue_MasksValueByKeyName() {
        ILoggingEvent source = mock(ILoggingEvent.class);
        when(source.getMdc()).thenReturn(Map.of("otp", "482913"));

        ILoggingEvent masked = MaskingOpenTelemetryAppender.mask(source);

        assertThat(masked.getMdc()).containsEntry("otp", REPLACEMENT);
    }

    @Test
    void mask_NullMdc_ReturnsEmptyMap() {
        ILoggingEvent source = mock(ILoggingEvent.class);
        when(source.getMDCPropertyMap()).thenReturn(null);

        assertThat(MaskingOpenTelemetryAppender.mask(source).getMDCPropertyMap()).isEmpty();
    }

    // ─── Unmasked passthrough ────────────────────────────────────────────────────

    @Test
    void mask_EveryOtherAccessor_IsForwardedUnchanged() {
        ILoggingEvent source = mock(ILoggingEvent.class);
        Instant now = Instant.now();
        when(source.getLoggerName()).thenReturn("com.eudistack.ebw.application.workflow.StoreWorkflow");
        when(source.getThreadName()).thenReturn("reactor-http-nio-3");
        when(source.getLevel()).thenReturn(Level.INFO);
        when(source.getTimeStamp()).thenReturn(now.toEpochMilli());
        when(source.getInstant()).thenReturn(now);
        when(source.getNanoseconds()).thenReturn(42);
        when(source.getSequenceNumber()).thenReturn(7L);
        when(source.hasCallerData()).thenReturn(true);
        when(source.getMarkerList()).thenReturn(List.of());
        when(source.getKeyValuePairs()).thenReturn(List.of());

        ILoggingEvent masked = MaskingOpenTelemetryAppender.mask(source);
        masked.prepareForDeferredProcessing();

        assertThat(masked.getLoggerName()).isEqualTo("com.eudistack.ebw.application.workflow.StoreWorkflow");
        assertThat(masked.getThreadName()).isEqualTo("reactor-http-nio-3");
        assertThat(masked.getLevel()).isEqualTo(Level.INFO);
        assertThat(masked.getTimeStamp()).isEqualTo(now.toEpochMilli());
        assertThat(masked.getInstant()).isEqualTo(now);
        assertThat(masked.getNanoseconds()).isEqualTo(42);
        assertThat(masked.getSequenceNumber()).isEqualTo(7L);
        assertThat(masked.hasCallerData()).isTrue();
        assertThat(masked.getMarkerList()).isEmpty();
        assertThat(masked.getKeyValuePairs()).isEmpty();
        assertThat(masked.getLoggerContextVO()).isNull();
        assertThat(masked.getThrowableProxy()).isNull();
        assertThat(masked.getCallerData()).isNull();
        verify(source).prepareForDeferredProcessing();
    }
}
