package com.eudistack.ebw.infrastructure.adapter.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "ebw.rate-limit")
public record RateLimitProperties(
        int registerPerEmail,
        int registerPerIp,
        int verifyPerEmail,
        int verifyPerIp,
        int refreshPerIp,
        int passkeyRegistrationPerIp,
        int sessionPerIp,
        int passkeyPrfSignPerIp,
        int onboardingRedeemPerIp,
        int onboardingDisavowalPerIp,
        int trustedProxies,
        Duration window
) {

    /** Onboarding ticket redemption and "it was not me": 10 per origin and hour (FR-30, EUD-315). */
    public static final int DEFAULT_ONBOARDING_PER_IP = 10;

    public RateLimitProperties {
        // A configuration that does not set them must not end up with a limit of 0, which would block every request.
        onboardingRedeemPerIp = onboardingRedeemPerIp > 0 ? onboardingRedeemPerIp : DEFAULT_ONBOARDING_PER_IP;
        onboardingDisavowalPerIp = onboardingDisavowalPerIp > 0 ? onboardingDisavowalPerIp : DEFAULT_ONBOARDING_PER_IP;
        if (trustedProxies < 1) {
            throw new IllegalArgumentException("ebw.rate-limit.trusted-proxies must be at least 1");
        }
    }
}
