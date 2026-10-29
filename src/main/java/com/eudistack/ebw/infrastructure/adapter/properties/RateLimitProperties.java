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
        int trustedProxies,
        Duration window
) {

    public RateLimitProperties {
        if (trustedProxies < 1) {
            throw new IllegalArgumentException("ebw.rate-limit.trusted-proxies must be at least 1");
        }
    }
}
