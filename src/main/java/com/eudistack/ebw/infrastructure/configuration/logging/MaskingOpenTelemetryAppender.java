package com.eudistack.ebw.infrastructure.configuration.logging;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.classic.spi.ThrowableProxyUtil;
import io.opentelemetry.instrumentation.logback.appender.v1_0.OpenTelemetryAppender;
import org.slf4j.event.KeyValuePair;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
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
        super.append(new ExportedLoggingEvent(mask(event)));
    }

    /** Package-private for direct testing without spinning up the OTel SDK. */
    static ILoggingEvent mask(ILoggingEvent event) {
        return new MaskedLoggingEvent(event);
    }

    /** Masks the message, the MDC, the key-value pairs and the exception; forwards everything else. */
    private static final class MaskedLoggingEvent extends DelegatingLoggingEvent {

        private final IThrowableProxy throwableProxy;

        private MaskedLoggingEvent(ILoggingEvent delegate) {
            super(delegate);
            this.throwableProxy = MaskedThrowableProxy.of(delegate.getThrowableProxy());
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

        @Override
        public IThrowableProxy getThrowableProxy() {
            return throwableProxy;
        }

        // Numbers and booleans cannot carry a secret and keep their type in the exported attribute
        @Override
        public List<KeyValuePair> getKeyValuePairs() {
            List<KeyValuePair> source = super.getKeyValuePairs();
            if (source == null) {
                return null;
            }
            return source.stream().map(MaskedLoggingEvent::maskPair).toList();
        }

        private static KeyValuePair maskPair(KeyValuePair pair) {
            if (pair.value == null || pair.value instanceof Number || pair.value instanceof Boolean) {
                return pair;
            }
            return new KeyValuePair(pair.key, maskMdcValue(pair.key, pair.value.toString()));
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

    /**
     * The OpenTelemetry appender skips the masked exception, so it travels as key-value pairs under
     * the attribute names the appender would have used. They need captureKeyValuePairAttributes.
     */
    private static final class ExportedLoggingEvent extends DelegatingLoggingEvent {

        private ExportedLoggingEvent(ILoggingEvent masked) {
            super(masked);
        }

        @Override
        public List<KeyValuePair> getKeyValuePairs() {
            List<KeyValuePair> pairs = super.getKeyValuePairs();
            IThrowableProxy exception = getThrowableProxy();
            if (exception == null) {
                return pairs;
            }
            List<KeyValuePair> exported = pairs == null ? new ArrayList<>() : new ArrayList<>(pairs);
            exported.add(new KeyValuePair("exception.type", exception.getClassName()));
            if (exception.getMessage() != null) {
                exported.add(new KeyValuePair("exception.message", exception.getMessage()));
            }
            exported.add(new KeyValuePair("exception.stacktrace", ThrowableProxyUtil.asString(exception)));
            return exported;
        }
    }
}
