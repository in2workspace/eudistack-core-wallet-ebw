package com.eudistack.ebw.domain.model;

import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Languages of the wallet's emails (EUD-8 FR-38, AD-10): those of the Wallet App, {@code es}, {@code ca} and
 * {@code en}.
 */
public final class EmailLanguage {

    public static final List<String> SUPPORTED = List.of("es", "ca", "en");
    public static final String DEFAULT = "es";

    private EmailLanguage() {}

    /**
     * The supported language the {@code Accept-Language} header prefers, honouring its weights ({@code ca-ES}
     * is {@code ca}). Empty when the header is missing, malformed or names none of them.
     */
    public static Optional<String> fromAcceptLanguage(String header) {
        if (header == null || header.isBlank()) {
            return Optional.empty();
        }
        try {
            var ranges = Locale.LanguageRange.parse(header);
            return Optional.ofNullable(Locale.lookupTag(ranges, SUPPORTED));
        } catch (IllegalArgumentException _) {
            return Optional.empty();
        }
    }

    /** The value if it is a supported language (any case, surrounding blanks ignored), otherwise empty. */
    public static Optional<String> parse(String value) {
        if (value == null) {
            return Optional.empty();
        }
        var language = value.strip().toLowerCase(Locale.ROOT);
        return SUPPORTED.contains(language) ? Optional.of(language) : Optional.empty();
    }
}
