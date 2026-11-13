package com.eudistack.ebw.domain.model;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * Rules of the credential offer sent with an onboarding ticket (design §2.6): an
 * {@code openid-credential-offer://} link by reference ({@code credential_offer_uri}), at most
 * {@link #MAX_LENGTH} characters. Offers by value ({@code credential_offer}) are not accepted. The
 * offer is neither resolved nor parsed further.
 */
public final class CredentialOfferReference {

    public static final int MAX_LENGTH = 2048;
    static final String SCHEME_PREFIX = "openid-credential-offer://";

    private CredentialOfferReference() {}

    public static boolean isValid(String offer) {
        if (offer == null || offer.length() > MAX_LENGTH
                || !offer.toLowerCase(Locale.ROOT).startsWith(SCHEME_PREFIX)) {
            return false;
        }
        var queryStart = offer.indexOf('?');
        if (queryStart < 0 || offer.indexOf('#') >= 0 || offer.chars().anyMatch(Character::isWhitespace)) {
            return false;
        }
        boolean byReference = false;
        for (var parameter : offer.substring(queryStart + 1).split("&")) {
            var separator = parameter.indexOf('=');
            var name = separator < 0 ? parameter : parameter.substring(0, separator);
            var value = separator < 0 ? "" : decode(parameter.substring(separator + 1));
            if ("credential_offer".equals(name) || value == null) {
                return false;
            }
            if ("credential_offer_uri".equals(name)) {
                byReference = !value.isBlank();
            }
        }
        return byReference;
    }

    private static String decode(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException _) {
            return null;
        }
    }
}
