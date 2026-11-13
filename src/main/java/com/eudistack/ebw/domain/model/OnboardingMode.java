package com.eudistack.ebw.domain.model;

import java.util.Locale;

/**
 * Onboarding mode of a tenant (prd §3.3, design §2.7). {@code open}: anyone can create an
 * account with the email and code. {@code restricted}: accounts are only created with an
 * onboarding ticket; the email and code only serve accounts that already exist.
 */
public enum OnboardingMode {
    OPEN,
    RESTRICTED;

    /** Value of {@code tenant_config} and of the wallet metadata. */
    public String value() {
        return name().toLowerCase(Locale.ROOT);
    }

    /**
     * Mode of a {@code tenant_config} value: missing or blank is {@link #OPEN}; any value other
     * than {@code open} or {@code restricted} is {@link #RESTRICTED}, so a configuration error
     * never opens the onboarding.
     */
    public static OnboardingMode parse(String raw) {
        if (raw == null || raw.isBlank()) {
            return OPEN;
        }
        return "open".equalsIgnoreCase(raw.trim()) ? OPEN : RESTRICTED;
    }

    /** Whether {@code raw} is one of the known values (blank counts as known: the default). */
    public static boolean isKnown(String raw) {
        return raw == null || raw.isBlank() || "open".equalsIgnoreCase(raw.trim())
                || "restricted".equalsIgnoreCase(raw.trim());
    }
}
