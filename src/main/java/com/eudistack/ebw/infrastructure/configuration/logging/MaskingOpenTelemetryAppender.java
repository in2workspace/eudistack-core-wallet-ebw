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

    /**
     * Masks the message, the MDC, the key-value pairs and the exception; forwards everything else. The
     * message of the key audit events keeps its UUIDs.
     */
    private static final class MaskedLoggingEvent extends DelegatingLoggingEvent {

        private final IThrowableProxy throwableProxy;
        // The key audit events keep their UUIDs (EUD-326 FR-04); every other record masks them
        private final boolean maskUuids;

        private MaskedLoggingEvent(ILoggingEvent delegate) {
            super(delegate);
            this.maskUuids = !MaskingPatternLayout.keepsIdentifiers(delegate);
            this.throwableProxy = MaskedThrowableProxy.of(delegate.getThrowableProxy());
        }

        @Override
        public String getFormattedMessage() {
            return MaskingPatternLayout.mask(MaskingPatternLayout.truncate(super.getFormattedMessage()), maskUuids);
        }

        @Override
        public String getMessage() {
            return MaskingPatternLayout.mask(MaskingPatternLayout.truncate(super.getMessage()), maskUuids);
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

        // A number can be an OTP: it is masked by its key, and keeps its type only if nothing changed
        @Override
        public List<KeyValuePair> getKeyValuePairs() {
            List<KeyValuePair> source = super.getKeyValuePairs();
            if (source == null) {
                return List.of();
            }
            return source.stream().map(MaskedLoggingEvent::maskPair).toList();
        }

        private static KeyValuePair maskPair(KeyValuePair pair) {
            if (pair.value == null) {
                return pair;
            }
            String text = pair.value.toString();
            String masked = maskMdcValue(pair.key, text);
            boolean keepsType = (pair.value instanceof Number || pair.value instanceof Boolean) && masked.equals(text);
            return new KeyValuePair(pair.key, keepsType ? pair.value : masked);
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
            List<KeyValuePair> exported = new ArrayList<>(pairs);
            exported.add(new KeyValuePair("exception.type", exception.getClassName()));
            if (exception.getMessage() != null) {
                exported.add(new KeyValuePair("exception.message", exception.getMessage()));
            }
            exported.add(new KeyValuePair("exception.stacktrace", ThrowableProxyUtil.asString(exception)));
            return exported;
        }
    }
}
