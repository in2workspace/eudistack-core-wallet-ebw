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

    /** Longest message kept. A longer one costs more in every output and is rarely readable. */
    static final int MAX_MESSAGE_LENGTH = 16_384;
    static final String TRUNCATED = "[truncated]";

    private static final List<Map.Entry<Pattern, String>> MASKS = List.of(
            new AbstractMap.SimpleImmutableEntry<>(
                    // %40 is the URL-encoded @: query strings reach the DEBUG logs encoded. The
                    // lengths are the RFC 5321 limits, and keep a long run without @ linear: any
                    // caller can write one through a logged header
                    Pattern.compile("[a-zA-Z0-9._%+\\-]{1,64}(?:@|%40)[a-zA-Z0-9.\\-]{1,253}\\.[a-zA-Z]{2,63}"),
                    REPLACEMENT),
            // The signature may be empty: an unsigned token (alg=none) is still a token. What
            // follows ~ in an SD-JWT is the disclosed claims in Base64 and the key binding JWT. It
            // only starts at a token boundary, which may be a URL-encoded character, and = only ends
            // a segment as padding: otherwise a long run of eyJ or =eyJ scans to the end from each one
            new AbstractMap.SimpleImmutableEntry<>(
                    Pattern.compile("(?:(?<![a-zA-Z0-9_\\-])|(?<=%[0-9a-fA-F]{2}))eyJ[a-zA-Z0-9_\\-]++={0,2}+\\.[a-zA-Z0-9_\\-]++={0,2}+\\.[a-zA-Z0-9_\\-=~.]*+"),
                    REPLACEMENT),
            new AbstractMap.SimpleImmutableEntry<>(
                    Pattern.compile("(?i)((?:Bearer|Basic)\\s+)\\S+"),
                    "$1" + REPLACEMENT),
            // No lookbehind: with a prefix or in camelCase (db_password, jwtSecret, vp_token,
            // txCode) the key still names a secret
            keyValueMask("tx[_-]?code|pre[_-]?authorized[_-]?code|token|password|secret"),
            // Too short to match inside another word: spin= is not pin=
            keyValueMask("(?<![a-zA-Z])(?:otp|pin)"),
            // The OTP travels as "code": only as a JSON field or code=, since prose such as
            // "Failed to send a verification code: <exception>" is not a secret, and only when the
            // value has a digit, since status names such as gRPC's code=UNAVAILABLE are not either
            new AbstractMap.SimpleImmutableEntry<>(
                    Pattern.compile(
                            "(?i)(?<!\\w)(\"code\"\\s*:\\s*\"?|code\\s*=\\s*)(?=[^\"&\\s,}]{0,256}\\d)[^\"&\\s,}]+"),
                    "$1" + REPLACEMENT),
            new AbstractMap.SimpleImmutableEntry<>(
                    Pattern.compile(
                            "(?i)\\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\b"),
                    REPLACEMENT)
    );

    // Masks the value of the given keys written as key=value or as a JSON field ("key":"value"),
    // up to the closing quote when the value is quoted, since it may hold spaces.
    private static Map.Entry<Pattern, String> keyValueMask(String keys) {
        return new AbstractMap.SimpleImmutableEntry<>(
                Pattern.compile("(?i)(\"?(?:" + keys + ")\"?\\s*[:=]\\s*\"?)(?:(?<=\")[^\"]*(?=\")|[^\"&\\s,}]+)"),
                "$1" + REPLACEMENT);
    }

    @Override
    public String doLayout(ILoggingEvent event) {
        return mask(super.doLayout(new TruncatedMessageEvent(event)));
    }

    // Applied before masking, on the message only: the stack trace of the line stays whole. It cuts at
    // the last separator, since half a JWT or email no longer matches any rule and would go out in clear.
    static String truncate(final String message) {
        if (message == null || message.length() <= MAX_MESSAGE_LENGTH) {
            return message;
        }
        int end = MAX_MESSAGE_LENGTH;
        while (end > 0 && !isSeparator(message.charAt(end - 1))) {
            end--;
        }
        return message.substring(0, end) + TRUNCATED;
    }

    private static boolean isSeparator(char character) {
        return Character.isWhitespace(character) || character == '&' || character == ',';
    }

    private static final class TruncatedMessageEvent extends DelegatingLoggingEvent {

        private TruncatedMessageEvent(ILoggingEvent delegate) {
            super(delegate);
        }

        @Override
        public String getFormattedMessage() {
            return truncate(super.getFormattedMessage());
        }
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
