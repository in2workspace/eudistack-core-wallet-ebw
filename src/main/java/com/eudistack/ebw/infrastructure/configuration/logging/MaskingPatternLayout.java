package com.eudistack.ebw.infrastructure.configuration.logging;

import ch.qos.logback.classic.PatternLayout;
import ch.qos.logback.classic.spi.ILoggingEvent;

import java.util.AbstractMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Redacts PII and secrets from every rendered log line: emails, JWTs, bearer tokens, OTPs and
 * tokens or secrets written as {@code key=value} / JSON fields, and every UUID — the user,
 * credential, passkey, key and session identifiers are all UUIDs, and together with the activity
 * type and time they would let anyone rebuild an individual holder's use of the wallet.
 */
public class MaskingPatternLayout extends PatternLayout {

    static final String REPLACEMENT = "***";

    private static final List<Map.Entry<Pattern, String>> MASKS = List.of(
            new AbstractMap.SimpleImmutableEntry<>(
                    Pattern.compile("[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}"),
                    REPLACEMENT),
            new AbstractMap.SimpleImmutableEntry<>(
                    Pattern.compile("eyJ[a-zA-Z0-9_\\-=]+\\.[a-zA-Z0-9_\\-=]+\\.[a-zA-Z0-9_\\-=]+"),
                    REPLACEMENT),
            new AbstractMap.SimpleImmutableEntry<>(
                    Pattern.compile("(?i)(Bearer\\s+)\\S+"),
                    "$1" + REPLACEMENT),
            keyValueMask("tx_code|otp"),
            // The OTP travels as "code": only as a JSON field or code=, since prose such as
            // "Failed to send a verification code: <exception>" is not a secret, and only when the
            // value has a digit, since status names such as gRPC's code=UNAVAILABLE are not either
            new AbstractMap.SimpleImmutableEntry<>(
                    Pattern.compile(
                            "(?i)(?<!\\w)(\"code\"\\s*:\\s*\"?|code\\s*=\\s*)(?=[^\"&\\s,}]*\\d)[^\"&\\s,}]+"),
                    "$1" + REPLACEMENT),
            keyValueMask("token|access_?token|refresh_?token|id_?token"),
            keyValueMask("password|client_?secret|secret"),
            new AbstractMap.SimpleImmutableEntry<>(
                    Pattern.compile(
                            "(?i)\\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\b"),
                    REPLACEMENT)
    );

    // Masks the value of the given keys written as key=value or as a JSON field ("key":"value").
    // The keys must not be the suffix of a longer word: error_code is not code.
    private static Map.Entry<Pattern, String> keyValueMask(String keys) {
        return new AbstractMap.SimpleImmutableEntry<>(
                Pattern.compile("(?i)(?<!\\w)(\"?(?:" + keys + ")\"?\\s*[:=]\\s*\"?)[^\"&\\s,}]+"),
                "$1" + REPLACEMENT);
    }

    @Override
    public String doLayout(ILoggingEvent event) {
        return mask(super.doLayout(event));
    }

    // Shared with MaskingOpenTelemetryAppender, which reads the raw event and bypasses doLayout
    static String mask(final String input) {
        if (input == null || input.isBlank()) {
            return input;
        }
        String result = input;
        for (Map.Entry<Pattern, String> entry : MASKS) {
            result = entry.getKey().matcher(result).replaceAll(entry.getValue());
        }
        return result;
    }
}
