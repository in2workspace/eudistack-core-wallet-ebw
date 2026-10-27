package com.eudistack.ebw.domain.model;

import java.time.Duration;
import java.util.Objects;

/**
 * Onboarding configuration of a tenant (design §2.6, §2.7, §5).
 *
 * @param enabled         whether authorized systems may request onboarding tickets
 * @param ttl             lifetime of a pre-registration and its ticket
 * @param securityContact email warned when an account holder disavows an onboarding; {@code null} if not set
 * @param mode            onboarding mode
 * @param signupUrl       https address where a user gets the wallet; {@code null} if not set
 */
public record OnboardingSettings(boolean enabled, Duration ttl, String securityContact, OnboardingMode mode,
                                 String signupUrl) {

    public static final Duration DEFAULT_TTL = Duration.ofMinutes(5);
    public static final Duration MAX_TTL = Duration.ofMinutes(10);

    public OnboardingSettings {
        Objects.requireNonNull(ttl, "ttl");
        Objects.requireNonNull(mode, "mode");
    }

    public boolean restricted() {
        return mode == OnboardingMode.RESTRICTED;
    }
}
