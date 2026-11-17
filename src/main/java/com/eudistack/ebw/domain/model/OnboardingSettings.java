package com.eudistack.ebw.domain.model;

import java.time.Duration;
import java.util.Objects;

/**
 * Onboarding configuration of a tenant (design §2.6, §2.7, §5).
 *
 * @param enabled         whether authorized systems may request onboarding tickets
 * @param ttl             lifetime of a pre-registration and its ticket: only the time to open the address
 * @param registrationTtl lifetime of the registration ticket the redemption gives, from the redemption:
 *                        the time to create the passkey
 * @param securityContact email warned when an account holder disavows an onboarding; {@code null} if not set
 * @param mode            onboarding mode
 * @param signupUrl       https address where a user gets the wallet; {@code null} if not set
 * @param walletUrl       https address of the tenant's Wallet App, without userinfo, query, fragment nor the
 *                        trailing slash, where the onboarding address and the "it was not me" link point;
 *                        {@code null} if not set
 */
public record OnboardingSettings(boolean enabled, Duration ttl, Duration registrationTtl, String securityContact,
                                 OnboardingMode mode, String signupUrl, String walletUrl) {

    public static final Duration DEFAULT_TTL = Duration.ofMinutes(5);
    public static final Duration MAX_TTL = Duration.ofMinutes(10);
    /** PROVISIONAL (EUD-315 decision P8): the figure is pending the Tech Lead. */
    public static final Duration DEFAULT_REGISTRATION_TTL = Duration.ofMinutes(30);
    /**
     * PROVISIONAL (EUD-315 decision P8, security finding F2-n): bounds the retention of the email and
     * the life of the registration ticket, a bearer; to be reviewed with the Tech Lead.
     */
    public static final Duration MAX_REGISTRATION_TTL = Duration.ofHours(1);

    public OnboardingSettings {
        Objects.requireNonNull(ttl, "ttl");
        Objects.requireNonNull(registrationTtl, "registrationTtl");
        Objects.requireNonNull(mode, "mode");
    }

    public boolean restricted() {
        return mode == OnboardingMode.RESTRICTED;
    }
}
