package com.eudistack.ebw.infrastructure.configuration.logging;

import ch.qos.logback.classic.spi.ILoggingEvent;
import io.opentelemetry.instrumentation.logback.appender.v1_0.OpenTelemetryAppender;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Exports log records over OTLP with the same PII/secret redaction the console appender
 * applies. {@link OpenTelemetryAppender} reads the raw event, bypassing
 * {@link MaskingPatternLayout#doLayout}, so redaction must happen here or emails, JWTs, tokens
 * and holder identifiers would reach OpenObserve in clear text.
 */
public class MaskingOpenTelemetryAppender extends OpenTelemetryAppender {

    @Override
    protected void append(ILoggingEvent event) {
        super.append(mask(event));
    }

    /** Package-private for direct testing without spinning up the OTel SDK. */
    static ILoggingEvent mask(ILoggingEvent event) {
        return new MaskedLoggingEvent(event);
    }

    /** Masks the rendered message and every MDC value; forwards everything else unchanged. */
    private static final class MaskedLoggingEvent extends DelegatingLoggingEvent {

        private MaskedLoggingEvent(ILoggingEvent delegate) {
            super(delegate);
        }

        @Override
        public String getFormattedMessage() {
            return MaskingPatternLayout.mask(super.getFormattedMessage());
        }

        @Override
        public String getMessage() {
            return MaskingPatternLayout.mask(super.getMessage());
        }

        // Emptied so no downstream consumer re-renders the unmasked original from
        // the message template + arguments instead of using getFormattedMessage().
        @Override
        public Object[] getArgumentArray() {
            return new Object[0];
        }

        @Override
        public Map<String, String> getMDCPropertyMap() {
            return maskValues(super.getMDCPropertyMap());
        }

        @Override
        public Map<String, String> getMdc() {
            return maskValues(super.getMdc());
        }

        private static Map<String, String> maskValues(Map<String, String> source) {
            if (source == null) {
                return Map.of();
            }
            Map<String, String> masked = new LinkedHashMap<>();
            source.forEach((key, value) -> masked.put(key, maskMdcValue(key, value)));
            return masked;
        }

        // MaskingPatternLayout's sensitive-key patterns (otp, refresh_token, password, …) only
        // fire when the key and value appear together as "key=value" in one string — an MDC map
        // hands them over as separate entries. Reassembling "key=value" before masking lets those
        // opaque-by-key-name secrets be caught too, without duplicating the pattern list that is
        // MaskingPatternLayout's single source of truth.
        private static String maskMdcValue(String key, String value) {
            if (value == null) {
                return null;
            }
            String prefix = key + "=";
            String maskedLine = MaskingPatternLayout.mask(prefix + value);
            return maskedLine.startsWith(prefix) ? maskedLine.substring(prefix.length()) : maskedLine;
        }
    }
}
